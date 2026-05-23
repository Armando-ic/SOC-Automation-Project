---
status: active
technique_id: T1059.001
tactic: Execution
last_run: 2026-05-22
v1_counterpart: [[../../vault/detections/t1059-001-powershell-encoded]]
related: [[../infrastructure/vm-soc-v2-win]], [[../README]]
---

# T1059.001 — PowerShell Encoded Command (v2-Azure port)

KQL port of the v1 Splunk detection at [`../../vault/detections/t1059-001-powershell-encoded.md`](../../vault/detections/t1059-001-powershell-encoded.md). Same MITRE technique, same SwiftOnSecurity Sysmon config (bit-identical, verified by SHA256), same Atomic Red Team test — different SIEM, different analytics rule engine, different query language. Phase 1 deliverable of the v2-Azure parallel implementation.

This file mirrors the structure of the v1 detection doc so the two read as side-by-side comparisons. The **v1 ↔ v2 comparison section at the bottom** is where this port's unique portfolio value lives.

## Description

T1059.001 is MITRE ATT&CK's sub-technique for adversary use of PowerShell as a scripting interpreter. The variant exercised here is **PowerShell with `-EncodedCommand`** (and its valid PowerShell shortenings `-e`, `-en`, `-enc`), which takes a UTF-16LE-base64-encoded command-line. Attackers use it to obfuscate malicious payloads through several layers (logs show base64 instead of clear-text) and to bypass simple substring-based detections. SwiftOnSecurity's Sysmon config captures the full CommandLine including the encoded blob, which is what makes this detectable end-to-end on both v1 and v2.

ATT&CK reference: https://attack.mitre.org/techniques/T1059/001/

## ART command

```powershell
# ART module installed at C:\AtomicRedTeam\invoke-atomicredteam\ (Install-AtomicRedTeam default path)
Import-Module C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1

# Test 15 = "ATHPowerShellCommandLineParameter -EncodedCommand parameter variations"
# (the "ATH" prefix marks it as an Atomic Test Harness synthetic — benign payload,
#  no external deps, well-defined cleanup, GUID-stamped per fire so successive runs
#  are individually distinguishable in logs)
Invoke-AtomicTest T1059.001 -TestNumbers 15 -ShowDetails              # preview
Invoke-AtomicTest T1059.001 -TestNumbers 15 -GetPrereqs               # installs AtomicTestHarnesses
Invoke-AtomicTest T1059.001 -TestNumbers 15                           # execute
Invoke-AtomicTest T1059.001 -TestNumbers 15 -Cleanup                  # cleanup (no-op for this test)
```

Default test inputs: `-CommandLineSwitchType Hyphen -EncodedCommandParamVariation E` — the harness spawns `powershell.exe -E <base64>` (the **shortest** abbreviation of `-EncodedCommand`). This is intentional — it forces the detection to handle abbreviated flag variants, not just the full word.

## Observations

First run on v2 stack: 2026-05-22 8:11:18 PM Eastern.

| Field | Value (2026-05-22 8:11:18 PM Eastern fire) |
|---|---|
| `TimeGenerated` | `2026-05-22T23:11:18Z` (rendered as 8:11:18 PM Eastern in Defender portal) |
| `EventID` | `1` (Sysmon Process Create) |
| `EventLog` | `Microsoft-Windows-Sysmon/Operational` |
| `Image` | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| `CommandLine` | `powershell.exe -NoProfile -E VwByAGkAdABlAC0ASABvAHMAdAAg AGQAZAA3ADgANwAxADcAYgAt...` |
| `ParentImage` | `C:\Windows\System32\wbem\WmiPrvSE.exe` ← **identical to v1's 2026-04-30 observation, ATH still uses WMI to spawn the test process under harness module 1.12.0.0** |
| `User` | `vm-soc-v2-win\soc-azure-win-vm` |
| `Hashes` | MD5+SHA256+IMPHASH all populated (SwiftOnSecurity config `<HashAlgorithms>` block emitting all three, matching v1) |
| `ProcessId` | `6632` (matches the TestSuccess output from the `Invoke-AtomicTest` invocation — definitive linkage) |
| `TestGuid` (from `Invoke-AtomicTest` output) | `dd78717b-3d1f-4c0d-ad4c-ce65a977a51a` |

The base64 payload decodes (UTF-16LE) to `Write-Host dd78717b-3d1f-4c0d-ad4c-ce65a977a51a` — same harness signature v1 documented. Each ATH run uses a fresh GUID, so successive runs produce distinct events.

LAW ingestion lag observed: ~5–10 minutes from event to KQL-queryable. Compared to v1 Splunk's ~5 second lag, this is a meaningful regression — see [comparison section](#v1--v2-comparison-the-portfolio-value).

Sentinel Analytics Rule first-fire latency: 9 minutes 24 seconds from event (8:11:18 PM) to incident creation (8:20:42 PM). Within the rule's 5-min cron cadence plus the ingestion lag.

**ParentImage triage cheat sheet** (forensic-interesting parents — unchanged from v1):

| ParentImage | Likely meaning |
|---|---|
| `winword.exe` / `excel.exe` / `outlook.exe` | Phishing macro launched PowerShell |
| `cmd.exe` from interactive logon | Manual analyst use, usually benign |
| `wscript.exe` / `cscript.exe` | Scripted attack chain |
| `WmiPrvSE.exe` | WMI-launched (could be lateral movement OR a synthetic test like ATH) |
| Unknown / non-system parent | Very suspicious |

## KQL

Saved as Sentinel Analytics Rule `T1059.001 - PowerShell Encoded Command`. Standalone artifact at [`kql/t1059-001-powershell-encoded.kql`](kql/t1059-001-powershell-encoded.kql).

```kql
Event
| where EventLog == "Microsoft-Windows-Sysmon/Operational"
| where EventID == 1
| extend Image = extract(@"Name=""Image"">([^<]+)</Data>", 1, EventData)
| where Image endswith @"\powershell.exe"  // filter early before more expensive extracts
| extend CommandLine = extract(@"Name=""CommandLine"">([^<]+)</Data>", 1, EventData)
| where CommandLine matches regex @"(?i)\s-e[ncodedommand]*\s"
| extend
    ParentImage = extract(@"Name=""ParentImage"">([^<]+)</Data>", 1, EventData),
    User        = extract(@"Name=""User"">([^<]+)</Data>", 1, EventData),
    Hashes      = extract(@"Name=""Hashes"">([^<]+)</Data>", 1, EventData),
    ProcessId   = extract(@"Name=""ProcessId"">([^<]+)</Data>", 1, EventData)
| project TimeGenerated, Computer, User, Image, CommandLine, ParentImage, Hashes, ProcessId
```

| Clause | What it does |
|---|---|
| `Event` | Sentinel/LAW table that AMA populates when ingesting Windows event channels via Custom XPath in the DCR. (If the DCR used Security-specific data source instead of Custom XPath, Security channel events would route to `SecurityEvent` instead — see [comparison section](#v1--v2-comparison-the-portfolio-value).) |
| `where EventLog == "Microsoft-Windows-Sysmon/Operational"` | Channel filter — Sysmon-only. The `EventLog` column is populated from the Windows Event Log channel name. |
| `where EventID == 1` | Sysmon's Process Create event. |
| `extend Image = extract(...)` | Regex-extracts the `Image` field from the XML blob in `EventData`. AMA delivers Sysmon events as XML in `EventData` — there is no built-in parser equivalent to Splunk's `Splunk_TA_microsoft_sysmon` add-on. Every Sysmon-field-using query has to do this extraction. |
| `where Image endswith @"\powershell.exe"` | Filter rows where Image ends in `\powershell.exe`. Done **before** the more expensive subsequent regex extractions — KQL processes pipes left-to-right, so early filtering reduces downstream work. |
| `extend CommandLine = extract(...)` | Same regex-extraction pattern for CommandLine. |
| `where CommandLine matches regex @"(?i)\s-e[ncodedommand]*\s"` | The detection logic. Case-insensitive (`(?i)`), whitespace-bounded (`\s ... \s`), matches `-e` followed by zero-or-more letters from `{n,c,o,d,e,m,a}`. Catches `-e`, `-en`, `-enc`, `-encod`, `-encodedcommand` while rejecting `-eq`, `-ed`, etc. **Identical semantics to the v1 SPL regex** at `vault/detections/t1059-001-powershell-encoded.md:81`. |
| `extend ParentImage = ..., User = ..., Hashes = ..., ProcessId = ...` | Late-stage extracts for the triage fields. Done after the powershell+encoded filter so only matching rows pay the extraction cost. |
| `project ...` | Select the final triage columns. |

**Verbatim strings (`@"..."`)** are used throughout so we can write literal `\` and `"` without double-escaping.

**No `order by`** — the rule scheduler doesn't need it and some validators object. (The interactive ad-hoc version of this query keeps the `| order by TimeGenerated desc` line for human readability.)

## Sentinel Analytics Rule config

Configured in the Defender portal (Microsoft Sentinel → Analytics). As of 2024–2026 Microsoft is progressively unifying Sentinel into the Microsoft Defender XDR portal at `security.microsoft.com` — the older Azure-portal Sentinel Analytics blade now redirects to the Defender portal. Same KQL, same rule engine, same incidents — different UI shell. Walking through screenshots from older Azure-portal Sentinel docs will increasingly fail because pages have been moved.

| Field | Value | Rationale |
|---|---|---|
| Name | `T1059.001 - PowerShell Encoded Command` | matches the v1 saved-search name verbatim |
| Severity | Medium | matches v1's general severity range |
| MITRE ATT&CK | Execution / T1059.001 | direct technique mapping |
| Status | Enabled | active in lab |
| Rule frequency | 5 minutes | matches v1's `*/5 * * * *` cron |
| Lookback window | 5 minutes | **must match schedule** — initially set to 1 hour, produced duplicate incidents across cron ticks (see [Notes](#notes)) |
| Threshold | results > 0 | trigger any non-empty result set |
| Event grouping | Per result | matches v1's "For each result" behavior |
| Suppression | Off | Phase 1 wants every test fire visible; production would re-enable |
| Entity mapping (Host) | `HostName: Computer` | populates the Sentinel entity graph for the VM |
| Entity mapping (Account) | `Name: User` | populates account entity |
| Entity mapping (Process #1) | `CommandLine: CommandLine` | enables incident-graph pivot on full command-line |
| Entity mapping (Process #2) | `ProcessId: ProcessId` | enables PID pivot |
| Incident creation | Enabled | one incident per matching alert |
| Alert grouping | Disabled | Phase 1 wants each test fire as its own incident for clearer validation |
| Automated response | None | Phase 2 SOAR work — Logic Apps will replace v1's n8n |

## Live-fire validation results

| Date | Generator | Sentinel Incident | Notes |
|---|---|---|---|
| 2026-05-22 ~7:11–7:14 PM Eastern | Synthetic `powershell.exe -NoProfile -EncodedCommand <base64>` × 3 fires (manual paste in RDP) | #1 through #6 (3 fires × 2 cron ticks due to initial 1-hour lookback before tuning) | Confirmed end-to-end pipeline (Sysmon → AMA → LAW → KQL → Analytics Rule → Incident). Surfaced the duplicate-tick gotcha that drove the lookback-window tuning. |
| 2026-05-22 ~7:30 PM Eastern | Analytics Rule tuned (lookback 1 h → 5 min, matching schedule) | — | Eliminated cross-tick duplicate generation. |
| 2026-05-22 8:11:18 PM Eastern | **Atomic Red Team `Invoke-AtomicTest T1059.001 -TestNumbers 15`** (the v1-parity real fire — same test, same harness, same payload shape v1 ran on 2026-04-30) | **#10** (first activity matches event time, created 8:20:42 PM, 9m24s end-to-end latency) | **Phase 1 success criterion met.** ParentImage = `wbem\WmiPrvSE.exe` matches v1 — ATH 1.12.0.0 still uses WMI to spawn the test process. |

## v1 ↔ v2 comparison (the portfolio value)

| Layer | v1 (`main` branch — Splunk + n8n) | v2 (this branch — Sentinel + Logic Apps planned) | Parity status |
|---|---|---|---|
| **Endpoint OS** | Windows 10 VMware VM (private NAT) | Windows Server 2025 Datacenter Azure VM (Central US) | Different OS, both run default PS 5.1 — same encoded-command surface |
| **Sysmon binary** | 15.20 | 15.20 | **Exact version parity** (Sysinternals serves only current; happened to still be 15.20) |
| **Sysmon config** | SwiftOnSecurity, commit `1836897f12fbd6a0a473665ef6abc34a6b497e31`, SHA256 `055FEBC6...87162` | Same commit, **same SHA256 verified at install** | **Bit-identical config** — controls for config variables in the comparison |
| **Endpoint agent** | Splunk Universal Forwarder | Azure Monitor Agent (AMA) 1.42.0.0 | Different vendors, same job |
| **Agent config location** | `inputs.conf` on each host (per-host config) | Data Collection Rule (DCR) cloud-side, associated to VM | **v2 architecturally cleaner** — config decoupled from agent install, edit once apply to many |
| **Transport** | Forwarder → Splunk indexer (TCP 9997) | AMA → LAW via DCR (HTTPS, managed identity) | Both authenticated, both reliable |
| **Ingestion latency observed** | ~5 seconds (per v1 doc) | ~5–10 minutes (per Phase 1) | **v2 regression** — Azure Monitor's ingestion pipeline is meaningfully slower for low-volume single events. Likely tightens with higher event volume / paid SKU. Worth measuring under realistic ingest load before drawing final conclusions. |
| **Event landing** | `index=mydfir-project source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"` | `Event` table, `EventLog == "Microsoft-Windows-Sysmon/Operational"` | Both addressable; different conventions |
| **Field extraction** | `Splunk_TA_microsoft_sysmon` add-on (automatic — Image, CommandLine, ParentImage, Hashes, etc. land as first-class fields) | **Manual XML regex extraction in every query** (no Microsoft-published Sentinel equivalent of the Splunk TA for Sysmon) | **Major friction point in v2.** Each Sysmon-using query has to repeat the extracts, OR a Workspace Function can centralize them (queued as Phase 1.5). |
| **Detection query length** | 5 lines SPL | 12 lines KQL | 2.4× longer in v2 due to extraction overhead; functionally equivalent |
| **Detection regex** | `(?i)\s-e[ncodedommand]*\s` (SPL `regex` command) | `(?i)\s-e[ncodedommand]*\s` (KQL `matches regex`) | **Identical regex string**, equivalent semantics |
| **Saved-search / Analytics Rule schedule** | `*/5 * * * *` cron | Every 5 min (UI), same underlying cron | Identical |
| **Per-result alerting** | "For each result" | "Trigger an alert for each event" | Identical semantics |
| **Lookback ≠ schedule duplicate-incident gotcha** | "`alert.suppress=False` does NOT dedupe across cron ticks" (v1 doc, Notes section) | Same — events within lookback re-match every tick. **Same gotcha, same root cause, same fix options** (narrow lookback to schedule cadence, enable suppression, or accept duplicates) | **Parity confirmed** |
| **Sysmon EventID=1 ParentImage for ATH Test 15** | `C:\Windows\System32\wbem\WmiPrvSE.exe` (v1, 2026-04-30) | `C:\Windows\System32\wbem\WmiPrvSE.exe` (v2, 2026-05-22) | **Parity confirmed** — ATH 1.12.0.0 still WMI-spawns the test process |
| **Hashes (MD5/SHA256/IMPHASH)** | All three populated (per SwiftOnSecurity config `<HashAlgorithms>`) | All three populated | **Parity confirmed** — same config in both produces same hash field shape |
| **Base64 payload decoding** | Not in SPL — done by Claude in n8n triage layer | Not in KQL — TBD Phase 2 SOAR layer | **Same architectural decision in both stacks** — detection matches on the *fact* of encoded-command use, decode is a downstream concern |
| **Alert delivery** | Saved search → webhook → n8n → Claude triage → DFIR-Iris alert | Sentinel Analytics Rule → Sentinel Incident (native) | **v2 simpler at this step** — incident creation is built into the rule; no external SOAR plumbing required for the alert→incident hop. Phase 2 SOAR work is whether external triage enrichment + DFIR-Iris case sync is worth keeping vs migrating to Sentinel-native incident workflow. |
| **Entity graph** | n/a in Splunk (entity is a Splunk Enterprise Security concept, not Splunk Free / Free Trial) | First-class — 4 entities mapped (Host, Account, 2× Process), powers the incident graph and investigation pivots | **v2 advantage** at no extra cost |
| **SecurityEvent table** | n/a (Splunk doesn't have this concept) | **Empty in this v2 setup** because Custom XPath puts everything in `Event` table. Most Microsoft-published Sentinel analytics rule templates query `SecurityEvent`. To use those, would need either (a) a second DCR using the dedicated "Windows Security Events" data source, or (b) rewrite imported rules to query `Event` with `EventLog == "Security"`. | **v2-only consideration** — worth flagging because anyone forking this setup will hit it |

### What translated cleanly
- Detection regex (byte-identical)
- Schedule / cadence / per-result semantics
- ParentImage forensic shape
- Sysmon hash population
- The duplicate-incident-on-tick gotcha (same fix options)
- Base64 decoding as a downstream concern

### What needed re-engineering
- Sysmon field extraction (Splunk TA → manual KQL regex in every query)
- The query grew from 5 to 12 lines

### What changed in v2 that's neither pure win nor pure loss
- Ingestion latency went from ~5s to ~5–10 min (regression)
- Alert→Incident hop became native (simplification, but loses some v1 flexibility of external webhook routing)
- Entity graph + investigation pivots came for free (improvement)
- SecurityEvent vs Event table choice introduces a new variable that doesn't exist in v1 (added complexity)

## Notes

- **Suppression initially set to 5 hours by the Defender portal wizard default** — explicitly disabled before the first save, otherwise testing would have been blocked. Worth knowing as a portal-defaults watch-out.
- **Lookback window must match cron cadence** for clean 1-event = 1-incident semantics. With lookback > cron interval and event grouping = per-result, events re-fire every tick until they age out of the lookback window. Same gotcha v1 Splunk documents.
- **The MITRE ATT&CK picker auto-selects parent technique alongside sub-technique** (T1059 + T1059.001 = 2 selected when only T1059.001 was clicked). Cosmetic; doesn't affect alerting.
- **Process tree visualization "couldn't be generated"** in the Defender Incidents UI for this incident — because process trees are a Microsoft Defender for Endpoint (MDE) feature, not a Sysmon-only feature. We have the raw Sysmon events (Image, CommandLine, ParentImage etc.) but not the MDE-grade visualization. Adding MDE is out of Phase 1 scope; could be revisited if the comparison narrative wants the v1-side gap closed.
- **No false positives during Phase 1** — only matched the 3 synthetic fires and the 1 ATH fire. Same as v1's "false positives in our environment so far: zero" observation.

## References

- v1 counterpart: [`../../vault/detections/t1059-001-powershell-encoded.md`](../../vault/detections/t1059-001-powershell-encoded.md) (Splunk SPL version)
- Standalone KQL: [`kql/t1059-001-powershell-encoded.kql`](kql/t1059-001-powershell-encoded.kql)
- Endpoint spec: [`../infrastructure/vm-soc-v2-win.md`](../infrastructure/vm-soc-v2-win.md)
- v2-Azure branch overview: [`../README.md`](../README.md)
- Architecture diagram: [`../architecture/current-state.md`](../architecture/current-state.md)
- ATT&CK technique: https://attack.mitre.org/techniques/T1059/001/
- Sysmon: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- SwiftOnSecurity config: https://github.com/SwiftOnSecurity/sysmon-config
- Atomic Red Team: https://github.com/redcanaryco/atomic-red-team
- Invoke-AtomicRedTeam: https://github.com/redcanaryco/invoke-atomicredteam
