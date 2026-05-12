---
status: draft
updated: 2026-04-30
sub_project: D1
related: [[README]], [[spec]], [[plan]]
---

# D1 Notes — Detection Foundations

Working notes, gotchas, and learnings captured during D1 implementation. Mirrors the discipline established in A1/A2 notes.md files. Contents are append-only within a phase; corrections supersede earlier text rather than rewriting it.

## Phase 0 captures (2026-04-30)

### Lab VM reachability

- Splunk web (192.168.129.131:8000): HTTP 303 — healthy.
- n8n editor (192.168.129.132:5678): HTTP 200 — healthy.
- Iris UI (https://192.168.129.133): HTTP 302 — healthy.
- Windows 10 VM (192.168.129.130): ICMP echo blocked (Windows Firewall default), but ARP resolved and RDP/3389 open. SSH/22 was firewalled too.

### Windows VM SSH enablement (mid-Phase-0 setup)

The Windows host machine doesn't have `sshpass`/`plink`, so the established workaround is paramiko. But the Windows VM's OpenSSH Server wasn't listening (port 22 firewalled). Resolved by RDP'ing in and running:

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service -Name sshd -StartupType Automatic
New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' \
  -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
```

After this, paramiko works against `192.168.129.130`. PowerShell version on the VM: `5.1.19041.6456`. Admin context confirmed: `mydfir` is in the local Administrators group.

### Sysmon baseline (clean)

`Get-Service Sysmon64` returned `Sysmon64 service NOT present` — confirmed clean baseline. Whatever Sysmon installation D1 produces is the first one on this VM.

### Universal Forwarder inputs.conf — pre-existing Sysmon stanza

Path confirmed: `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf` (last modified 2026-04-25 — predates D1 by ~5 days).

**The Sysmon stanza already exists**, with the canonical Splunk Add-on for Microsoft Sysmon configuration:

```ini
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
index = mydfir-project
disabled = false
renderXml = true
source = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
```

This means **plan.md Phase 2 Tasks 2.1/2.2 reduce to verify-only**: no append needed; just restart the forwarder once Sysmon is installed so the dormant stanza binds to the about-to-exist channel. Spec.md Errata E1 + E2 captured the divergence.

The same `inputs.conf` also contains stanzas for:

- `[WinEventLog://Microsoft-Windows-Windows Defender/Operational]` with `blacklist = 1151,1150,2000,1002,1001,1000` and a `source =` override.
- `[WinEventLog://Microsoft-Windows-PowerShell/Operational]` with `blacklist = 4100,4105,4106,40961,40962,53504` and a `source =` override.
- `[WinEventLog://Microsoft-Windows-TerminalServices-LocalSessionManager/Operational]` (no overrides).
- `[WinEventLog://Application]`, `[WinEventLog://Security]`, `[WinEventLog://System]` (no overrides).

The PowerShell/Defender `source =` overrides have **not** taken effect yet — Splunk currently shows their events with the default `WinEventLog:` prefix, meaning the forwarder hasn't been restarted since 2026-04-25. Phase 2's restart will activate them as a side effect. **Vault grep returned zero consumers of the old source strings** (`WinEventLog:Microsoft-Windows-PowerShell/Operational`, `WinEventLog:Microsoft-Windows-Windows Defender/Operational`) — no downstream breakage. Spec.md Errata E3 captured this.

SplunkForwarder service: `Status=Running, StartType=Automatic`.

### Splunk baseline volumes (last 24h, before D1 changes)

Captured via `https://192.168.129.131:8089/services/search/jobs/export` against `index=mydfir-project earliest=-24h | stats count by sourcetype, source`:

| sourcetype | source | count |
|---|---|---|
| WinEventLog | WinEventLog:Application | 153 |
| WinEventLog | WinEventLog:Microsoft-Windows-PowerShell/Operational | 100 |
| WinEventLog | WinEventLog:Microsoft-Windows-TerminalServices-LocalSessionManager/Operational | 8 |
| WinEventLog | WinEventLog:Microsoft-Windows-Windows Defender/Operational | 20 |
| WinEventLog | WinEventLog:Security | 729 |
| WinEventLog | WinEventLog:System | 194 |

**No Sysmon source row**, confirming Sysmon isn't yet emitting (matches the clean Sysmon baseline above).

### Splunk apps — Sysmon Add-on installed mid-Phase-0

User installed **Splunk Add-on for Microsoft Sysmon** (app id `Splunk_TA_microsoft_sysmon`, version 5.0.0, scope Global, Enabled) from Splunkbase during Phase 0, after Phase-0 inspection surfaced the existing `source = XmlWinEventLog:...` override in `inputs.conf` and we needed a way to reconcile it with the spec's source filter.

The add-on's installation makes the existing override the canonical configuration: the add-on's props/transforms are keyed on `source=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` and parse Sysmon's XML into searchable fields when events arrive at that source value. Already-installed: **Splunk Add-on for Microsoft Windows** (`Splunk_TA_windows`, v10.0.1).

D1's plan + spec were globally rewritten (28 occurrences in plan.md, 6 in spec.md) from `source="WinEventLog:Microsoft-Windows-Sysmon/Operational"` to `source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"`. Errata E1 in spec.md documents the change.

This is **ADR-0006 candidate territory**: Sysmon Add-on installation was a late-arriving infrastructure decision driven by Phase-0 discovery. Whether to write the ADR depends on whether the install's rationale is durable enough to record formally — currently leaning yes (it locks in the source-prefix convention for all future detection content).

### Splunk daily license headroom

Captured via `/services/licenser/pools` and `/services/licenser/licenses` REST endpoints:

| pool | quota | used today |
|---|---|---|
| auto_generated_pool_download-trial | MAX (no per-pool cap) | 1.86 MB |
| auto_generated_pool_forwarder | MAX | 0.00 MB |
| auto_generated_pool_free | MAX | 0.00 MB |

License stack: **Splunk Enterprise Download Trial** (500 MB/day, type `download-trial`, VALID — currently active), **Splunk Forwarder** (1 MB, type `forwarder`, VALID — non-indexing), **Splunk Free** (500 MB/day, type `free`, VALID — fallback when trial expires).

**Takeaway:** ~1.86/500 MB consumed today (~0.4%). ART runs are KB-scale; Phase 6 live-fire will not approach the cap. License recovery procedure (runbook Phase 9.6) only matters once trial expires and we fall back to free.

### VMware Workstation snapshot — pending user action

`D1 pre-install baseline` snapshot of the Windows 10 VM not yet taken — user action pending before Phase 1 starts.

### Tooling note: paramiko helper at `scripts/d1_phase0_ssh.py`

To dodge Python escape-sequence headaches with PowerShell paths, the Phase-0 probes were factored into `scripts/d1_phase0_ssh.py`. The script reads the Windows VM password from the gitignored `SOC-Automation-Project.md` at repo root via regex (no plaintext secrets in the script itself). Pattern is reusable for any future paramiko probes; safe to commit.

## Phase 1 captures (2026-04-30)

### Sysmon install metadata

| | |
|---|---|
| SwiftOnSecurity commit SHA | `1836897f12fbd6a0a473665ef6abc34a6b497e31` |
| SwiftOnSecurity commit msg | `Merge pull request #151 from Neo23x0/patch-8` |
| Config file path | `C:\Tools\sysmon-config\sysmonconfig-export.xml` |
| Config file bytes | 123,257 |
| Config file SHA256 | `055FEBC600E6D7448CDF3812307275912927A62B1F94D0D933B64B294BC87162` |
| Config schema version | 4.50 (per SwiftOnSecurity) |
| Sysmon binary | `C:\Tools\Sysmon\Sysmon64.exe` |
| Sysmon version | 15.20 (FileVersion 15.20, ProductName "Sysinternals Sysmon") |
| Sysmon supported schema | 4.91 (loaded the older 4.50 config without issues) |
| Install command | `Sysmon64.exe -accepteula -i sysmonconfig-export.xml` |
| Install exit code | 0 |
| Install date | 2026-04-30 |

### Verification

- **Service:** `Get-Service Sysmon64` → `Status=Running, StartType=Automatic`.
- **Event Log channel:** `Microsoft-Windows-Sysmon/Operational` registered, `IsEnabled=True`, `RecordCount=4` immediately after install (Sysmon's own startup events: `EventCode=4` service-state-changed, plus a couple of EventCode=1 process creates from the install activity).
- **Config loaded:** `Sysmon64.exe -c` confirmed the SwiftOnSecurity config is the running config.

### Gotchas hit

1. **`cmd.exe` 8KB command-line limit.** OpenSSH on Windows wraps inbound commands through `cmd.exe`, which caps at ~8KB. PowerShell `-EncodedCommand` (UTF-16LE base64) inflates a script ~3-4x, so Phase 1's ~3KB script overflowed. Solution: SFTP a `.ps1` to the VM and execute via `powershell -File`. Captured in `scripts/d1_lib.py` as `run_ps_script()`.
2. **Sysmon native stderr crashes strict PowerShell.** With `$ErrorActionPreference = 'Stop'`, Sysmon's banner output to stderr (which is structurally normal) gets wrapped as a `RemoteException` and the script halts. Solution: relax the preference around native command calls and gate on `$LASTEXITCODE` instead. Captured in `scripts/d1_phase1_sysmon_install.py` Step G.
3. **Sysmon `-?` writes the EULA banner to stderr.** Caused the same RemoteException issue. Solution: read version metadata from the file itself (`(Get-Item $exe).VersionInfo`) instead of invoking `-?`.

## Phase 2 captures (2026-04-30)

### UF backup + restart

- `inputs.conf` backed up to `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf.pre-D1.bak` (923 bytes, original 2026-04-25 19:49 mtime preserved on the backup file).
- `Restart-Service SplunkForwarder` succeeded; service back to `Status=Running, StartType=Automatic` within 3 seconds.
- splunkd.log tail captured the modular-input scheme registrations but did not show a Sysmon-specific bind line (the `WinEventLog` channel binding messages may not appear in the default log level — the smoke test below is the authoritative confirmation that the bind happened).

### Tier-1 smoke test #1 — `notepad.exe` end-to-end

- **PASS.** Indexing lag ~30 seconds.
- Spawned: `notepad.exe` PID 7364 at 2026-04-30T13:54:04 EDT.
- Splunk event:
  - `_time`: 2026-04-30 17:54:04.063 UTC (matches spawn timestamp exactly after EDT→UTC conversion)
  - `Image`: `C:\Windows\System32\notepad.exe`
  - `CommandLine`: `"C:\Windows\system32\notepad.exe"`
  - `ParentImage`: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` (the SSH session's PowerShell wrapper around `Start-Process`)
  - `User`: `DESKTOP-VNEF7PC\mydfir`
  - `ProcessId`: 7364 (matches the PowerShell-reported PID)
- Field extraction worked correctly through Splunk Add-on for Microsoft Sysmon.
- `ComputerName` field returned empty when `| table`'d — the add-on may map host to a different field name (`host`, `Computer`, or `dest_host` are common alternatives). Will sort out exact name in Phase 4 SPL development; not blocking.

### Tier-1 smoke test #2 — EventCode coverage in our lab

After seeding varied activity (notepad, calc, Invoke-WebRequest to google.com, file create + delete, registry write):

| EventCode | Name | Count (last 15m) |
|---|---|---|
| 1 | Process Create | 108 |
| 11 | File Create | 4 |
| 13 | Registry Value Set | 4 |
| 3 | Network Connect | 3 |
| 22 | DNS Query | 2 |
| 16 | Sysmon Config Change | 1 |
| 4 | Sysmon Service State Change | 1 |
| 8 | CreateRemoteThread | 1 |

**Notable absences (the SwiftOnSecurity config intentionally filters these):** EventCode 5 (Process Terminate), 23 (File Delete), 12 (Registry Object Add). The `Remove-Item` and `New-Item` (HKCU:\Software\D1Test) seed activities did NOT produce EventCode 23 or 12 events — confirms the filtering in our env.

**Implication:** any future detection that depends on EventCode 5/12/23 will need either a SwiftOnSecurity config tune or a different EventCode pivot. Captured in this notes file so future-fresh-instance doesn't waste time wondering "why didn't I see X." sysmon.md component page (Phase 8) will reference this baseline.

### Phase 2 helper scripts

- `scripts/d1_phase2_uf_restart.py` — backup + restart + smoke-test-#1 seed (notepad spawn). Re-runnable.
- `scripts/d1_phase2_seed_coverage.py` — varied-activity seed for smoke-test-#2. Re-runnable; cleans up after itself (deletes the temp file + registry key).

## Phase 3 captures (2026-04-30)

### ART install metadata

| | |
|---|---|
| Module | `Invoke-AtomicRedTeam` v2.1.0 |
| Module path | `C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psm1` |
| Atomics root | `C:\AtomicRedTeam\atomics\` |
| Technique count | 334 |
| Install command | `Install-AtomicRedTeam -getAtomics -Force` (after IEX-bootstrap of installer) |
| TLS note | Forced `[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12` before bootstrap to ensure GitHub raw download works on Windows 10 |

### Gotcha — module not on default PSModulePath

Red Canary's installer puts the module under `C:\AtomicRedTeam\invoke-atomicredteam\` — **not** under any path in `$env:PSModulePath`. Default PSModulePath on this VM:

```
C:\Users\mydfir\Documents\WindowsPowerShell\Modules
C:\Program Files (x86)\WindowsPowerShell\Modules
C:\Program Files\WindowsPowerShell\Modules
C:\Windows\system32\WindowsPowerShell\v1.0\Modules
C:\Program Files (x86)\AutoIt3\AutoItX
```

`Import-Module Invoke-AtomicRedTeam` therefore fails. **Workarounds:**

1. **Import by full path (used in our scripts):** `Import-Module C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1 -Force`.
2. **Add the path persistently (interactive runbook user pattern):**
   ```powershell
   [Environment]::SetEnvironmentVariable('PSModulePath', $env:PSModulePath + ';C:\AtomicRedTeam\invoke-atomicredteam', 'User')
   ```
   Then `Import-Module Invoke-AtomicRedTeam` works after restarting the shell.

Runbook (Phase 9) will document workaround #2 as the recommended interactive pattern.

### T1059.001 test catalog (22 tests as of atomics commit pulled 2026-04-30)

```
T1059.001-1   Mimikatz
T1059.001-2   Run BloodHound from local disk
T1059.001-3   Run Bloodhound from Memory using Download Cradle
T1059.001-4   Mimikatz - Cradlecraft PsSendKeys
T1059.001-5   Invoke-AppPathBypass
T1059.001-6   Powershell MsXml COM object - with prompt
T1059.001-7   Powershell XML requests
T1059.001-8   Powershell invoke mshta.exe download
T1059.001-10  PowerShell Fileless Script Execution
T1059.001-11  NTFS Alternate Data Stream Access
T1059.001-12  PowerShell Session Creation and Use
T1059.001-13  ATHPowerShellCommandLineParameter -Command parameter variations
T1059.001-14  ATHPowerShellCommandLineParameter -Command parameter variations with encoded arguments
T1059.001-15  ATHPowerShellCommandLineParameter -EncodedCommand parameter variations          ← chosen for D1 worked example
T1059.001-16  ATHPowerShellCommandLineParameter -EncodedCommand parameter variations with encoded arguments
T1059.001-17  PowerShell Command Execution
T1059.001-18  PowerShell Invoke Known Malicious Cmdlets
T1059.001-19  PowerUp Invoke-AllChecks
T1059.001-20  Abuse Nslookup with DNS Records
T1059.001-21  SOAPHound - Dump BloodHound Data
T1059.001-22  SOAPHound - Build Cache
```

**Spec drift correction:** the spec § 3.1 working assumption was "Test 2". In the current atomics, Test 2 is BloodHound — not encoded PowerShell. The right test for D1's worked example is **T1059.001-15** ("ATHPowerShellCommandLineParameter -EncodedCommand parameter variations"). The `ATH` prefix denotes Atomic Test Harness — a synthetic test designed for telemetry verification with a benign payload and well-defined cleanup. No external download dependencies, no Defender concerns (Defender is off anyway), no user-interaction prompts. Exactly the right fit.

The spec.md and plan.md "Test 2" placeholders should be updated to "Test 15" during Phase 6 / Phase 7 catalog work, with the spec's Errata section noting this drift. Captured as a follow-up.

### Phase 3 helper scripts

- `scripts/d1_phase3_art_install.py` — bootstrap installer + `Install-AtomicRedTeam -getAtomics`. The Step C (Import-Module by name) inside this script fails because of the PSModulePath gotcha above; it's still the right "install" script, but follow-up verification is `d1_phase3_art_verify.py`.
- `scripts/d1_phase3_art_locate.py` — diagnostic helper that scans common module roots and `$env:PSModulePath`. Used to find where Red Canary's installer landed the module.
- `scripts/d1_phase3_art_verify.py` — imports the module by full `.psd1` path, confirms atomics inventory, dumps `Invoke-AtomicTest T1059.001 -ShowDetailsBrief`. Re-runnable as the "is ART working?" smoke test.

## Phase 4 captures (2026-04-30) — SPL development

### Real T1059.001-15 event captured

After running `Invoke-AtomicTest T1059.001 -TestNumbers 15 -GetPrereqs` then `... -TestNumbers 15`:

| field | value |
|---|---|
| `_time` | 2026-04-30 18:01:47.695 UTC |
| `host` | `DESKTOP-VNEF7PC` |
| `User` | `DESKTOP-VNEF7PC\mydfir` |
| `Image` | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| `CommandLine` | `powershell.exe -NoProfile -E VwByAGkAdABl...AAyADAAOQAAAA==` |
| `ParentImage` | `C:\Windows\System32\wbem\WmiPrvSE.exe` |
| `ProcessId` | `4496` |
| `Hashes` | `MD5=2E5A8590CF6848968FC23DE3FA1E25F1, SHA256=9785001B0DCF755EDDB8AF294A373C0B87B2498660F724E76C4D53F9C217C7A3, IMPHASH=3D08F4848535206D772DE145804FF4B6` |

Indexing lag for the dev event: ~5 seconds (event timestamp 18:01:47, observable in Splunk by ~18:01:52).

### Spec Open Q5 answered: Hashes field IS populated

The spec flagged whether `Hashes` would be populated for `powershell.exe` under SwiftOnSecurity's `<HashAlgorithms>` block. **Confirmed: yes.** All three algorithms (MD5, SHA256, IMPHASH) are populated. This is what the worked-example page records.

### Forensic-interesting tell: ParentImage = `WmiPrvSE.exe`

ATH Test 15 uses WMI as the launch mechanism, so `ParentImage` is `WmiPrvSE.exe` (Windows Management Instrumentation Provider). For real attacks, common `ParentImage` values to flag:

- `winword.exe` / `excel.exe` / `outlook.exe` → phishing-macro launched PowerShell
- `cmd.exe` from interactive logon → manual analyst use, usually benign
- `wscript.exe` / `cscript.exe` → scripted attack chain
- `WmiPrvSE.exe` → WMI-launched (could be lateral movement OR a synthetic test like ATH)
- Unknown / non-system parent → very suspicious

This pattern goes into the worked-example page's "Notes" section.

### SPL iteration — what each clause demonstrably did

Querying Splunk's `/services/search/jobs/export` endpoint with progressive filter widening:

| Step | SPL pipeline | Hits in last 15m |
|---|---|---|
| 1 (broad) | `index=mydfir-project source="XmlWinEventLog:..." EventCode=1 Image="*\\powershell.exe"` | 35 |
| 2 (+regex) | `... \| regex CommandLine="(?i)\s-e[ncodedommand]*\s"` | **1** |
| 3 (final) | `... \| stats count, values(CommandLine) as command_lines, values(ParentImage) as parents by _time, host, User, Image` | 1 row |

The Step 1→2 transition is the value of the regex clause: it cuts 35 generic powershell.exe events down to the 1 that's actually using `-EncodedCommand` (any prefix form).

### Final SPL (verified working against a real ART event)

```spl
index=mydfir-project source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*\\powershell.exe"
| regex CommandLine="(?i)\s-e[ncodedommand]*\s"
| stats count, values(CommandLine) as command_lines, values(ParentImage) as parents
        by _time, host, User, Image
```

### Two corrections to spec/plan SPL the iteration revealed

1. **Regex broadening.** The spec wrote `(?i)\s-(en?c|encodedcommand)\s` — matches `-ec`, `-enc`, `-encodedcommand`. **Misses `-e` and `-en`**, the two shortest valid PowerShell shortenings of `-EncodedCommand`. Real ATH Test 15 uses `-E`, so the spec's regex would have produced zero hits.

   **Updated regex:** `(?i)\s-e[ncodedommand]*\s` — matches `-e` plus zero-or-more letters from the alphabet `{n,c,o,d,e,m,a}`. Catches all valid PowerShell prefix-shortenings of `-EncodedCommand` (`-e`, `-en`, `-enc`, `-encod`, `-encodedcommand`, etc.) while rejecting unrelated `-eq`, `-ed`, `-em` flag-shaped substrings (because those continue with letters NOT in the alphabet, *but* wait `-em` does match — `-em` is allowed because `e` and `m` are both in the set... actually that's a small false-positive risk; `-em` isn't a real PowerShell.exe flag so it's effectively benign; if it ever becomes a problem, narrow to `-e(n(c(o(d(e(d(c(o(m(m(a(n(d)?)?)?)?)?)?)?)?)?)?)?)?)?` for an exact-prefix-of-`encodedcommand` match).

2. **Group-by field rename.** Spec used `by _time, ComputerName, User, Image`. The Splunk Add-on for Microsoft Sysmon's parsing populates `host`, not `ComputerName`. **Use `host`** in the `by` clause. (`ComputerName` returned as empty/null when piped through `stats by ComputerName`.)

Both corrections are reflected in the Phase 4 final SPL above. The spec/plan are not edited inline — the Errata section tracks the divergence post-hoc; the worked-example detection page in `vault/detections/` will carry the corrected SPL as the canonical reference.

## Phase 5 captures (2026-04-30)

### Splunk saved search created

User created the saved search via Splunk web UI (Search & Reporting → Save As → Alert), then verified state via Splunk REST `/servicesNS/-/-/saved/searches/T1059.001%20-%20PowerShell%20Encoded%20Command`:

| Setting | Value |
|---|---|
| Name | `T1059.001 - PowerShell Encoded Command` |
| App | `search` (default Splunk search app) |
| Owner | `mydfir` |
| Sharing | `app` (Shared in App) |
| Disabled | False (enabled) |
| is_scheduled | True |
| cron_schedule | `*/5 * * * *` |
| dispatch.earliest_time | `-24h@h` (Last 24 hours) |
| alert_type | `number of events` |
| alert_threshold | `0` |
| alert_comparator | `greater than` |
| alert.digest_mode | False (= For each result) |
| alert.track | True (Add to Triggered Alerts) |
| alert.severity | 5 (Severe) |
| alert.expires | `24h` |
| action.webhook | 1 (enabled) |
| action.webhook.param.url | `http://192.168.129.132:5678/webhook/db7245f7-8451-4bea-b47d-f6ad35b818cd` |
| Search SPL | (the verified-working SPL from Phase 4) |

### Gotcha — `alert.digest_mode` defaulted to True (Once)

The Splunk web UI's "Save As Alert" wizard defaults `Trigger` to "Once" (`alert.digest_mode=1`). For our pipeline integration we need "For each result" (`alert.digest_mode=0`) so each detected event becomes its own webhook payload (matching A2's Test 1 / Test 2 validation pattern; the n8n `Extract Triage Result` Code node expects per-result webhook payloads).

In the GUI flow, the user must explicitly switch the radio button to **For each result** during the Trigger configuration step. If forgotten, fix via REST:

```bash
curl -sk -u mydfir:<pw> -X POST \
  "https://192.168.129.131:8089/servicesNS/mydfir/search/saved/searches/T1059.001%20-%20PowerShell%20Encoded%20Command" \
  --data-urlencode "alert.digest_mode=0"
```

(Done during Phase 5 — the initial save landed with digest_mode=True; corrected via REST. Future runbook GUI walkthroughs need to call out the radio-button selection explicitly.)

### App scope note

The saved search landed in the `search` app (Splunk's default Search & Reporting app), not in a custom `mydfir-project` app. This is fine — the search is `Shared in App`, so visible to all `search`-app users on this Splunk instance. All admin users (incl. `mydfir`) are in the search app by default. Spec § 2.6 didn't constrain the app; the runbook should note "search app" as the location.

## Phase 6 captures (2026-04-30) — Tier-2 live-fire validation

### Outcome A confirmed end-to-end

The saved search fired once via Splunk cron at **15:25:16 EDT (= 19:25:16 UTC)**, the moment after I successfully POST'd `is_scheduled=true` to the saved-search REST endpoint. Subsequent observation:

**Iris alert #51** auto-created via the v2 production webhook → n8n SOC Triage v2 → Iris pipeline:

| field | value |
|---|---|
| `alert_id` | 51 |
| `alert_title` | `T1059.001 - PowerShell Encoded Command` |
| `alert_severity_id` | 1 (`info`) — see severity-mapping note below |
| `alert_status_id` | 1 (`new`) |
| `iocs count` | **0** (confirms Outcome A — gate-skipped) |
| `alert_creation_time` | 2026-04-30T19:25:16.771073 UTC |
| `alert_source_event_time` | 2026-04-30T19:25:16.671353 UTC |

Claude's triage rendered into Iris's `alert_description`:

> **Summary:** PowerShell on DESKTOP-VNEF7PC executed an encoded (-E) command spawned by WmiPrvSE.exe under user DESKTOP-VNEF7PC\\mydfir. Decoded payload (UTF-16 LE base64) is benign: `Write-Host 5ee4ffb4-f13f-4b52-a4b7-64502faf1209` — appears to be a test/canary or beacon-style probe rather than malicious code. The parent (WMI Provider Host) is the more notable indicator, suggesting WMI was used as the execution vector.
>
> **Severity:** medium — The decoded command itself is harmless (Write-Host of a GUID), which on its own would be low. However, two characteristics elevate concern: (1) use of base64-encoded PowerShell (-E) is a common defense-evasion technique, and (2) the parent process is WmiPrvSE.exe, indicating execution via WMI — a frequent lateral movement / remote execution vector. This pattern matches red-team tooling probes (e.g., Atomic Red Team, Impacket wmiexec test commands). Without corroborating malicious activity, medium is appropriate; escalate to high if additional WMI-spawned PowerShell follows.
>
> **MITRE Techniques:** T1059.001 (PowerShell), T1027 (Obfuscated Files or Information), T1047 (Windows Management Instrumentation)
>
> **Enriched IOCs:** _none_
>
> **Recommended Actions:** _none_
>
> **Investigation Notes:** _none_

Claude **decoded the base64 payload independently** (as Outcome B would predict) — but found nothing IOC-shaped inside the decoded `Write-Host <GUID>`, so `iocs_enriched` came back empty. The gate IF saw `iocs.length == 0` and routed to the FALSE branch. **Outcome A path validated** (matches A2 Test 1 pattern on Sysmon-shaped data) — and as a bonus, also demonstrated Claude's decoding capability on real encoded-PowerShell payloads.

### Architectural promise validated

This proves the spec's central promise (§ 2.7): **a Sysmon-shaped alert can traverse the existing SOC Triage v2 pipeline with no n8n changes.** A1's `Extract Triage Result` Code node accepted Claude's response cleanly, A1's `Create Iris Alert` HTTP node produced alert #51 with HTTP 2xx, A2's `Has Malicious IOCs?` IF gate took the FALSE branch on the empty `iocs` array, A2's plain-Slack-post path executed.

No system-prompt addendum was needed (the standby fix from spec § 2.7 stays as standby, not applied).

### Severity mapping discrepancy — flagged for follow-up

Claude's triage explicitly says **"Severity: medium"** in its narrative, but the Iris `alert_severity_id` was stored as **1 (info)**. The expected mapping per A1's schema (and the Iris severity catalog: 1=info, 2=low, 3=medium, 4=high, 5=critical) means a Claude-stated `medium` should land as `3`. Two possibilities:

1. **Claude returned `severity: "info"` in the structured response** and only used "medium" as descriptive text in the human-prose narrative. (This would mean A1's prompt is producing inconsistent severity signals — the structured field doesn't match the prose. Worth investigating in a follow-up — maybe a system-prompt clarification.)
2. **A1's `Extract Triage Result` Code node is silently defaulting to 1** when the parsing fails or the value is unexpected. (Would mean a regression — A1's Phase 11 verification didn't catch this.)

Either way, **flagged for D1.5 / A3 era investigation**. Doesn't block D1 closeout — the gate-skipped path is what the spec required to validate, and that worked. Captured here as an open follow-up.

### Spec Open Q4 answered: webhook payload schema verification

The successful Iris alert creation IS the answer to Q4 — the v2 webhook accepted the saved-search payload from Splunk and Claude triaged it cleanly. Concrete payload-shape capture is left for the next Phase 6.4 dedup run, which will inspect the n8n execution UI directly with the user.

### Saved-search scheduling gotcha (compounding the Phase 5 digest_mode gotcha)

After Phase 5's `digest_mode=1 → 0` correction, the saved search's `is_scheduled` field kept flipping back to `False` every time I re-queried. Diagnosed at Phase 6 entry: when the saved search has `realtime_schedule = True` (Splunk's default for newly-created scheduled alerts), and you POST a value-update without re-asserting `realtime_schedule`, Splunk's scheduler de-prioritizes the search and `is_scheduled` ends up False on the next read.

**Fix:** explicitly POST `realtime_schedule=false` together with `is_scheduled=true`. Verified working — saved search now reports `next_scheduled_time = 2026-04-30 21:25:00 UTC` after the joint update.

The Splunk web UI's "Schedule" dropdown for alerts has two values: `Run on Cron Schedule` (= `realtime_schedule=False`) and `Run on Real-Time Schedule` (= `realtime_schedule=True`). The "Real-Time Schedule" option is for performance-sensitive workloads where Splunk pulls events from a sliding window in memory — not appropriate for our `Last 24 hours` window. **Runbook should document `Run on Cron Schedule` as the required setting.**

### Manual dispatch did not fire alert actions

When I dispatched the saved search via `POST /saved/searches/<name>/dispatch -d "trigger_actions=1"`, the search ran and returned 1 result, but `performance.alertActionsHandler.duration='-'` indicates the alert action handler did NOT run. The webhook was therefore not POST'd to n8n. This is a Splunk REST API quirk — manual dispatches sometimes don't trigger alert actions even with `trigger_actions=1`.

**Implication for Phase 6.4 (dedup verification):** can't rely on manual REST dispatch as a substitute for cron firing. The cron must be working, which it now is post-`realtime_schedule=false` fix. Phase 6.4 will run a fresh ART invocation and wait for the next */5 cron tick.

### Phase 6.4 — Cross-tick dedup verification (FOUND a real spec-divergence)

After fixing the scheduling at 17:23 EDT, ran T1059.001-15 a second time (TestGuid `3bdda376-e537-4709-90b8-f8c75558e4be`, Sysmon `_time=2026-04-30 19:56:48.911 UTC`, separate event from Phase 4's `5ee4ffb4-...` at `_time=2026-04-30 18:01:47.695 UTC`). At the next cron tick (21:25:00 UTC = 17:25 EDT), Splunk produced **alert #52** in Iris.

The expected behavior (per spec § 2.6 + § Risks): "For each result" + 24h `alert.expires` gives content-hash dedup, so at 21:25 UTC:
- Phase 4 row: hash already triggered alert #51 → SKIP.
- Phase 6.4 row: new hash → fire one webhook.
- Alert #52 should describe Phase 6.4 (GUID `3bdda376-...`).

**Actual behavior:** alert #52 describes Phase 4 (GUID `5ee4ffb4-...`, the SAME event as alert #51). Phase 6.4 produced no alert at all. The manually-run SPL with the same `-24h@h` window confirmed both rows are in scope (2 rows total).

This means **Splunk's "For each result" trigger with `alert.suppress=False` does NOT dedupe across cron ticks the way the spec assumed.** What it actually does:

- Each scheduled cron tick fires the alert action **once** (not once per row).
- The webhook payload carries one `result` object — Splunk picks one row from the search result set (apparently the first / oldest by `_time`).
- Across cron ticks, the SAME event's row triggers the action again on subsequent ticks (no automatic dedup).
- `alert.expires=24h` controls how long Splunk's Triggered Alerts dashboard retains the trigger record, NOT cross-tick dedup.

**Spec § Risks row that's now resolved:** the entry "Splunk's 'For each result' hash-dedup behaves differently for Sysmon-shaped result rows than for brute-force-shaped result rows" was based on a misreading of Splunk's behavior. The real-behavior is: there is no automatic content-hash dedup in this configuration; the spec's fallback ("narrow Time Range to a smaller window e.g. `Last 5 minutes`, or add throttle") is the correct production fix.

**For D1, this is acceptable:** the worked example fires duplicates per cron tick as long as a matching event is in the 24h window. That's noisy but architecturally fine — the duplicates flow through the gate-skipped path each time, no IOCs, no cases, just Slack-noise. Production tuning is a post-D1 task.

**Three follow-up options for the runbook to call out:**

1. **Narrow the Time Range to `Last 5 minutes`** so each cron tick only sees events from the prior cron interval. Eliminates duplicates structurally but loses the "wide look-back for late-indexed events" property.
2. **Set `alert.suppress=True` with `alert.suppress.fields=_time,host,Image,CommandLine`** — Splunk's true cross-tick dedup. Most general; takes effect immediately.
3. **Accept duplicates for the lab.** D1's worked example is a learning loop, not a production detection. Ramping up to many techniques would force decision (1) or (2).

**Recommendation:** Option 2 (`alert.suppress`) for any production detection in this lab. Option 3 stays the D1 default for educational consistency with the brute-force search precedent.

### Phase 6 closeout: PASS with caveats

**Architectural promise** (Sysmon-shaped alert traverses A2's Test 1 path on real production traffic with no n8n changes): **VALIDATED** by alert #51's clean end-to-end flow.

**Outcome A** (gate-skipped path, plain Slack post): **VALIDATED** — both alerts #51 and #52 have iocs=[].

**Bonus discovery — Outcome B characteristic:** Claude *did* decode the base64 payload independently in both alerts (extracted the `Write-Host <GUID>` text). It just didn't find anything IOC-shaped inside, so iocs_enriched stayed empty. The base64-decoding capability is "free" without prompt changes — D1.5 hook is unnecessary as a prompt-engineering project for this technique class.

**Validation gaps captured for future runbook:**

- Splunk's "For each result" + `alert.suppress=False` cross-tick dedup behavior (spec assumption was wrong; documented above).
- Severity stamping: Claude's narrative says "medium" or "high" but the structured `severity_id` values were 1 (alert #51) and 5 (alert #52). Inconsistency between Claude's prose and the structured field; flagged for D1.5/A3 era investigation.
- Saved-search scheduling: needs `realtime_schedule=false` explicitly set; default `True` from "Save As Alert" wizard caused `is_scheduled` to silently flip back to False after configuration changes (Splunk 10.2.2 quirk; documented above).
- Manual REST dispatch with `trigger_actions=1` does NOT reliably fire alert actions on Splunk 10.2.2 — even when the search returns matching results. Only cron-driven dispatches fired the webhook in this session.

## Phase 11 (2026-05-12) — Post-rebuild revalidation on rebuilt lab

Triggered by D1 freeze prep. After the 2026-05-08 OneDrive incident forced rebuilds of Win10 → Win10-v2 and (this session) n8n + IRIS from scratch, the freeze required reproducing the full end-to-end chain. Surfaced four real gotchas, one of which corrects a misdiagnosis from Phase 6.

### Correction to Phase 6 closeout note (line 484)

Phase 6 noted: *"Manual REST dispatch with `trigger_actions=1` does NOT reliably fire alert actions on Splunk 10.2.2 — even when the search returns matching results. Only cron-driven dispatches fired the webhook in this session."*

**That observation had a real root cause we identified in Phase 11.** The saved search the 2026-04-30 UI flow created stored the search string *without* a leading `search` keyword (UI's Save As Alert always strips it). When I recreated the saved search via REST API on 2026-05-12, my SPL string included `search index=mydfir-project ...`. Splunk's REST API stored that verbatim, and at execution time prepended its own implicit `search` — producing `search search index=mydfir-project ...`. The Splunk parser then treated the second `search` as a **literal search term**, filtering the indexed-event stream to only events containing the word "search" somewhere in the raw text. Result: scan_count dropped from ~14110 to ~10, and `result_count=0` because none of those 10 matched the encoded-PS regex.

The Splunk Web UI's parser tolerated the doubled-`search` and still returned 2 events on interactive runs. The scheduler's stricter parsing reduced the dataset and dropped to 0.

**Rule: when creating a Splunk saved search via REST API, omit the leading `search` keyword from the `search` parameter value.** Submit `index=foo source=bar ... | regex ...` not `search index=foo source=bar ... | regex ...`. The UI's Save As Alert flow does this automatically; the REST API does not.

This bug is now documented in the D1 runbook's Recoveries ladder.

### Gotcha: AtomicTestHarnesses module install requires TLS 1.2 enable on Win10

`Invoke-AtomicTest T1059.001 -TestNumbers 15` depends on the `AtomicTestHarnesses` PowerShell module's `Out-ATHPowerShellCommandLineParameter` cmdlet. ART's `-GetPrereqs` flag is supposed to install it. On the freshly rebuilt Win10-v2 (Phase 11) this install silently failed with zero output from `Install-Module`.

Root cause: PowerShell 5.1 on Windows 10 defaults to TLS 1.0/1.1, but PSGallery dropped TLS 1.0/1.1 support in 2020. `Install-Module` silently fails with no useful error.

**Fix before running prereq install:**
```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Install-Module -Name AtomicTestHarnesses -Scope CurrentUser -Force -SkipPublisherCheck -AllowClobber
```

The D1 runbook's Phase 3 install ladder already documented setting TLS 1.2 before bootstrapping ART itself (line 201 of these notes references that). The same fix is required for the AtomicTestHarnesses prereq install, which is a separate `Install-Module` call.

This was missed during the 2026-05-08 Win10-v2 reinstall; the log entry that day documented installing `ART module + atomics 332 techniques + powershell-yaml dependency` but not `AtomicTestHarnesses`. The Phase 11 revalidation surfaced this as a re-install gotcha to add to the runbook.

**Workaround used in Phase 11 (instead of fixing the install):** generated a synthetic `powershell.exe -EncodedCommand` event directly via SSH, bypassing ATH. The SPL filters on Image + CommandLine + regex — it doesn't care which generator produced the encoded command. Same Sysmon event shape, same SPL match.

### Gotcha: Splunk_TA_windows lookup CSV files missing on rebuilt Splunk

Every saved-search dispatch (and many interactive searches) emits three warnings:
```
Could not load lookup=LOOKUP-1severity_for_windows
Could not load lookup=LOOKUP-CategoryString_for_windows
Could not load lookup=LOOKUP-signature_for_windows3
```

The `Splunk_TA_windows` add-on is installed on the indexer (verified in `/opt/splunk/etc/apps/`), but the lookup CSV files those `LOOKUP-` transforms reference aren't present anywhere on disk (verified via recursive grep). Likely an incomplete app install during the 2026-05-08 Splunk snapshot recovery — only `Splunk_TA_microsoft_sysmon` was explicitly reinstalled; `Splunk_TA_windows` may have been left in a half-installed state from the pre-incident lab.

**Impact: cosmetic only.** These lookups apply to `wineventlog` sourcetype (raw Windows event log fields), not `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` (Sysmon events — what D1's detection uses). The warnings appear but searches still return correct results.

**Fix (deferred, not blocking D1 freeze):** Either reinstall `Splunk_TA_windows` from splunkbase to restore the lookups dir, or remove the lookup definitions from `props.conf`/`transforms.conf` since they're not used by any D1 search. Either approach is a Splunk-add-on hygiene pass for a future session, not a freeze blocker.

### Gotcha: severity-stamping inconsistency persists in v3, with new variation

The Phase 6 closeout flagged "Claude's narrative says 'medium' or 'high' but the structured severity_id values were 1 (alert #51) and 5 (alert #52)". Phase 11 confirms this is still present in v3 with a new variation: alert #4 came back as `severity_name=Low (id=4)` with prose mentioning "low" — internally consistent this time but not matching the threat level (PowerShell encoded command should never be "low"; it's a confirmed offensive technique, classification by behavior is medium-or-higher even if the specific decoded payload is benign).

Hypothesis: Claude is severity-rating based on the *decoded payload content* (Write-Host of a GUID — benign) rather than the *technique class* (encoded PowerShell — suspicious). This is a system-prompt tuning issue, not a wiring bug.

**Still deferred to D1.5 / A3 era investigation** as the original Phase 6 note said.

### Cron-driven validation success on rebuilt lab

After fixing the doubled-`search` issue, the very next cron tick (the manual dispatch immediately after the fix) produced **IRIS alert #4** with full Claude triage description:

```
title:    T1059.001 - PowerShell Encoded Command
severity: Low (id=4) — see severity-stamping gotcha above
iocs:     0 (gate-skipped-path-equivalent; Claude found no IOC-shaped data in the decoded payload)
desc:     1250 chars; Claude correctly identified the encoded-PowerShell technique
          and decoded the base64 payload independently as "Write-Host freeze-validation-<guid>"
          - same independent-decoding behavior captured in Phase 6 alerts #51/#52
```

Architectural promise from D1's spec § 2.7 — *Sysmon-shaped alert traverses A2's path on real production traffic with no n8n changes* — **revalidated on the post-Slack-removal v3 workflow** (ADR 0007). Worked example holds across the v2→v3 workflow transition. The detection page's evidence section adds alert #4 alongside #51/#52.

## Open follow-ups

- Confirm Universal Forwarder service uptime > a few seconds (was the restart already performed by something else?). If `(Get-Date) - (Get-Process splunkd).StartTime` shows a process younger than the inputs.conf LastWriteTime, the restart already happened and we can skip Phase 2 Task 2.2 Step 3.
- Decide ADR-0006: install of Splunk Add-on for Microsoft Sysmon. Lean: yes, mid-D1 closeout. **DONE 2026-04-30** (ADR-0006 written).
- Phase 8's `splunk.md` update should add the Sysmon Add-on to the "Apps installed" section. **DONE 2026-04-30.**
- Phase 11 gotchas catalogued above. Items to act on later (not blocking D1 freeze):
  - Fix `Splunk_TA_windows` lookup CSVs (cosmetic).
  - Install `AtomicTestHarnesses` properly on Win10-v2 with TLS 1.2 (so future ATH-based tests work).
  - Investigate severity-stamping inconsistency (D1.5 / A3 era).
