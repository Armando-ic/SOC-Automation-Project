---
status: saved-search-active
technique_id: T1059.001
tactic: Execution
last_run: 2026-04-30
related: [[../subprojects/2026-04-30-detection-foundations/runbook]], [[../architecture/components/sysmon]], [[../architecture/components/splunk]]
---

# T1059.001 — Command and Scripting Interpreter: PowerShell

## Description

T1059.001 is MITRE ATT&CK's sub-technique for adversary use of PowerShell as a scripting interpreter. The variant exercised here is **PowerShell with `-EncodedCommand`** (and its valid PowerShell shortenings `-e`, `-en`, `-enc`), which takes a UTF-16LE-base64-encoded command-line. Attackers use it to obfuscate malicious payloads through several layers (logs show base64 instead of clear-text) and to bypass simple substring-based detections. SwiftOnSecurity's Sysmon config captures the full CommandLine including the encoded blob, which is what makes this detectable end-to-end.

ATT&CK reference: https://attack.mitre.org/techniques/T1059/001/

## ART command

```powershell
# ART module is installed at C:\AtomicRedTeam\invoke-atomicredteam\ (not on default PSModulePath)
Import-Module C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1

# Test 15 = "ATHPowerShellCommandLineParameter -EncodedCommand parameter variations"
# (the "ATH" prefix marks it as an Atomic Test Harness synthetic - benign payload,
#  no external deps, no user prompts, well-defined cleanup)
Invoke-AtomicTest T1059.001 -ShowDetailsBrief                 # preview the catalog
Invoke-AtomicTest T1059.001 -TestNumbers 15 -GetPrereqs       # installs AtomicTestHarnesses module
Invoke-AtomicTest T1059.001 -TestNumbers 15                   # execute
Invoke-AtomicTest T1059.001 -TestNumbers 15 -Cleanup          # cleanup (no-op for this test)
```

## Observations

First run 2026-04-30. The ATH harness wraps each invocation; the headline event is the launched `powershell.exe` itself.

| Field | Value (Phase 4 dev event, captured 2026-04-30 18:01:47 UTC) |
|---|---|
| `EventCode` | `1` (Process Create) |
| `Image` | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| `CommandLine` | `powershell.exe -NoProfile -E VwByAGkAdABl...AAyADAAOQAAAA==` |
| `ParentImage` | `C:\Windows\System32\wbem\WmiPrvSE.exe` ← high-signal forensic indicator (ATH uses WMI to spawn) |
| `User` | `DESKTOP-VNEF7PC\mydfir` |
| `host` | `DESKTOP-VNEF7PC` |
| `ProcessId` | 4496 |
| `Hashes` | `MD5=2E5A8590CF6848968FC23DE3FA1E25F1, SHA256=9785001B0DCF755EDDB8AF294A373C0B87B2498660F724E76C4D53F9C217C7A3, IMPHASH=3D08F4848535206D772DE145804FF4B6` (all three populated by SwiftOnSecurity) |

The base64 payload decodes (UTF-16LE) to `Write-Host <test-guid>` — the harness signature. Each ATH run uses a fresh GUID, so successive runs produce distinct events.

Splunk indexing lag observed: ~5 seconds from event to searchable.

Saved-search-to-fire delay: bounded by the 5-minute cron tick. Worst case ~5 minutes; typical ~150 seconds.

**ParentImage triage cheat sheet** (the forensic-interesting parents):

| ParentImage | Likely meaning |
|---|---|
| `winword.exe` / `excel.exe` / `outlook.exe` | Phishing macro launched PowerShell |
| `cmd.exe` from interactive logon | Manual analyst use, usually benign |
| `wscript.exe` / `cscript.exe` | Scripted attack chain |
| `WmiPrvSE.exe` | WMI-launched (could be lateral movement OR a synthetic test like ATH) |
| Unknown / non-system parent | Very suspicious |

## SPL

```spl
index=mydfir-project source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*\\powershell.exe"
| regex CommandLine="(?i)\s-e[ncodedommand]*\s"
| stats count, values(CommandLine) as command_lines, values(ParentImage) as parents
        by _time, host, User, Image
```

| Clause | What it does |
|---|---|
| `index=mydfir-project` | Narrows to the project's index. Always specify `index=` — searching all indexes is the #1 SPL beginner mistake. |
| `source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"` | Restricts to Sysmon's channel. Note the `XmlWinEventLog:` prefix (not the bare `WinEventLog:`) — that's the source value the **Splunk Add-on for Microsoft Sysmon** keys its props/transforms on. |
| `EventCode=1` | Sysmon's Process Create event. |
| `Image="*\\powershell.exe"` | Match any path ending in `\powershell.exe`. The leading backslash in the wildcard ensures we don't match `splunk-powershell.exe` or other `*-powershell.exe` filenames. |
| `\| regex CommandLine="..."` | Filter rows whose `CommandLine` matches a regex. Stricter than wildcard match. |
| `(?i)` | Case-insensitive flag. |
| `\s-e[ncodedommand]*\s` | Whitespace-bounded match for `-e` followed by zero-or-more letters from `{n,c,o,d,e,m,a}`. Catches all PowerShell prefix-shortenings of `-EncodedCommand` (`-e`, `-en`, `-enc`, `-encod`, `-encodedcommand`, etc.) while rejecting unrelated flag-shaped fragments like `-eq`, `-ed` (their continuing letters aren't in the alphabet). |
| `\| stats count, values(CommandLine) as command_lines, values(ParentImage) as parents by _time, host, User, Image` | Aggregate to one row per (timestamp, host, user, image), counting hits and collecting unique CommandLines + parents per group. |

**`ParentImage` is the high-signal column for triage** — see ParentImage cheat sheet under Observations.

## Saved search

| Field | Value |
|---|---|
| Name | `T1059.001 - PowerShell Encoded Command` |
| App | `search` (default Splunk Search & Reporting app) |
| Owner | `mydfir` |
| Sharing | `app` (Shared in App) |
| Time Range | `Last 24 hours` (`-24h@h`) |
| Cron | `*/5 * * * *` (every 5 minutes; standard SOC cadence) |
| Trigger | `For each result` (`alert.digest_mode=False`) |
| Threshold | Number of Results > 0 |
| Schedule type | `Run on Cron Schedule` (`realtime_schedule=False` — required to keep `is_scheduled=True` in Splunk 10.2.2; see notes.md gotcha) |
| Throttle | None |
| Trigger Actions | Webhook + Add to Triggered Alerts (severity 5) |
| Webhook URL | `http://192.168.129.132:5678/webhook/db7245f7-8451-4bea-b47d-f6ad35b818cd` (existing v2 production URL) |

### Live-fire validation results (2026-04-30)

Two cron firings produced two Iris alerts (#51 and #52), both with `iocs=[]` — Outcome A (gate-skipped path) confirmed. The architectural promise from D1's spec (§ 2.7) — "Sysmon-shaped alert traverses A2's Test 1 path on real production traffic with no n8n changes" — is validated end-to-end.

**Bonus discovery (Outcome B characteristic):** Claude decoded the base64 payload independently in both alerts (extracted the `Write-Host <GUID>` text). It just didn't find anything IOC-shaped inside, so `iocs_enriched` stayed empty. The base64-decoding capability is "free" without prompt changes — D1.5 hook is unnecessary as a prompt-engineering project for this technique class.

## Notes

- **Splunk's "For each result" + `alert.suppress=False` does NOT dedupe across cron ticks.** The same result row re-triggers the alert action every tick as long as it remains in the Time Range window. For the lab's purposes (learning loop, not production detection) this is acceptable — duplicates flow through the gate-skipped path each time, no IOCs, no cases, just Slack noise. Production tuning options: (1) narrow Time Range to `Last 5 minutes`; (2) set `alert.suppress=True` with `alert.suppress.fields=_time,host,Image,CommandLine`; (3) accept duplicates. See D1 notes.md for full discussion.
- **`realtime_schedule=False` is required** to keep `is_scheduled=True` in Splunk 10.2.2. The "Save As Alert" wizard defaults to "Real-Time Schedule," which silently flips `is_scheduled` back to False after any subsequent edit. The runbook documents this in the Recoveries ladder.
- **Severity stamping is inconsistent.** Claude's prose in the alert description says "medium" or "high" but `alert_severity_id` came back as 1 in alert #51 and 5 in alert #52 (same kind of event). Either Claude's structured `severity` field doesn't match its prose, or A1's `Extract Triage Result` Code node is mis-mapping. Flagged for D1.5 / A3 era investigation.
- **False positives in our environment so far: zero.** The only matches are intentional ART runs.
- If Claude misbehaves on the Sysmon-shaped payload (returns a malformed triage), the standby fix is the one-paragraph system-prompt addendum documented in [[../subprojects/2026-04-30-detection-foundations/runbook]] — *reactive only*; not applied by default. **Was not needed during D1's live-fire — Claude's default behavior on Sysmon payloads is correct.**
- Decoding the base64 payload is **not** done in SPL. Claude does it on the n8n side as part of triage. If the decoded payload contains something IOC-shaped (URL, IP literal, domain, hash), the gate fires (Outcome B). For ATH Test 15 (synthetic GUID payload), no IOCs exist inside the decoded payload — gate stays skipped (Outcome A).
