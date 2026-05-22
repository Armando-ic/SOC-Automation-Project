---
status: active
updated: 2026-04-30
sub_project: D1
related: [[README]], [[spec]], [[../../architecture/components/sysmon]], [[../../architecture/components/splunk]], [[../../detections/README]]
---

# D1 Runbook — Detection Foundations

Operational documentation for the detection-engineering observation lab D1 stood up. Covers install (one-time), the run-a-technique loop (every time), the observation toolkit (procedural SPL), recoveries, the security-posture note, and the standby fix for Claude-misbehaves-on-Sysmon.

## Audience

You're either:
- Re-doing the install on a fresh Windows VM (rebuild scenario).
- Running a MITRE technique through the lab (the everyday operational case).
- Debugging "I ran ART and don't see anything in Splunk" (the diagnostic ladder).

## Sections

1. [Install (one-time)](#install-one-time)
2. [The "run a technique" loop](#the-run-a-technique-loop)
3. [Observation toolkit — starter SPL queries](#observation-toolkit--starter-spl-queries)
4. [VMware Workstation snapshot discipline](#vmware-workstation-snapshot-discipline)
5. [Worked example as smoke-test template](#worked-example-as-smoke-test-template)
6. [Security-posture note](#security-posture-note)
7. [Recoveries](#recoveries)
8. [Standby fix — system-prompt addendum](#standby-fix--system-prompt-addendum)

---

## Install (one-time)

These steps install Sysmon, configure the existing Splunk Universal Forwarder, and install Atomic Red Team. **Run only when standing up a fresh Windows VM** — D1's install was on 2026-04-30 and shouldn't be redone unless the VM is rebuilt.

### Prerequisites

- Windows 10 VM with Splunk Universal Forwarder already installed and forwarding to 192.168.129.131:9997.
- Administrator account with PowerShell access (RDP or SSH).
- Defender off, C: drive excluded from any AV scope (intentional lab posture — see [Security-posture note](#security-posture-note)).
- VMware Workstation snapshot taken: name `D1 pre-install baseline`.

### 1. Enable OpenSSH Server (if SSH is needed)

If you'll drive the install from the host via SSH, OpenSSH Server must be installed and the firewall opened. Run from admin PowerShell on the VM (RDP in for this one-time setup):

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service -Name sshd -StartupType Automatic
New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' \
  -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
```

After this, paramiko can SSH from the host. The Windows VM's OpenSSH defaults the user shell to `cmd.exe`; multi-line PowerShell is best driven via `-EncodedCommand` or, for scripts longer than ~3 KB, by SFTP'ing a `.ps1` and running it with `powershell -File`. See `scripts/d1_lib.py` for the established pattern.

### 2. Install Sysmon

```powershell
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Working directories
New-Item -ItemType Directory -Path C:\Tools -Force | Out-Null
New-Item -ItemType Directory -Path C:\Tools\sysmon-config -Force | Out-Null
New-Item -ItemType Directory -Path C:\Tools\Sysmon -Force | Out-Null

# Capture latest SwiftOnSecurity master commit SHA
$apiResp = Invoke-WebRequest -Uri 'https://api.github.com/repos/SwiftOnSecurity/sysmon-config/branches/master' -UseBasicParsing
$sha = ($apiResp.Content | ConvertFrom-Json).commit.sha
"commit SHA: $sha" | Out-File C:\Tools\sysmon-config\COMMIT_SHA.txt

# Download config at that SHA (immutable URL)
Invoke-WebRequest `
  -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/$sha/sysmonconfig-export.xml" `
  -OutFile C:\Tools\sysmon-config\sysmonconfig-export.xml -UseBasicParsing

# Download Sysmon binary
Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/Sysmon.zip' `
  -OutFile C:\Tools\Sysmon\Sysmon.zip -UseBasicParsing
Expand-Archive -Path C:\Tools\Sysmon\Sysmon.zip -DestinationPath C:\Tools\Sysmon -Force

# Install Sysmon as a service
$ErrorActionPreference = 'Continue'  # Sysmon prints to stderr on success, don't trip
& C:\Tools\Sysmon\Sysmon64.exe -accepteula -i C:\Tools\sysmon-config\sysmonconfig-export.xml
$ErrorActionPreference = 'Stop'

# Verify
Get-Service Sysmon64                                                              # Status: Running expected
Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' | Select IsEnabled, RecordCount
```

Capture the SwiftOnSecurity commit SHA, the config file SHA256, and the Sysmon binary version in [[../../architecture/components/sysmon]].

**Hand-off to the executor:** the Phase 1 install runner is `scripts/d1_phase1_sysmon_install.py` — same flow, paramiko-driven, with capture-summary JSON output for notes.md.

### 3. Configure Universal Forwarder for the Sysmon channel

**Check first whether the stanza already exists** (D1's lab had it pre-existing from prior tutorial setup):

```powershell
Get-Content 'C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf' |
  Select-String -Pattern 'Microsoft-Windows-Sysmon' -Context 0,5
```

**If the Sysmon stanza is present** (with `source = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`), skip the append; just restart the forwarder.

**If absent**, append:

```ini
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = false
index = mydfir-project
renderXml = true
source = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
```

The `source = XmlWinEventLog:...` override is the canonical convention when the **Splunk Add-on for Microsoft Sysmon** is installed on the indexer (its props/transforms are keyed on this source value).

Then restart the forwarder:

```powershell
$inputs = 'C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf'
Copy-Item $inputs "$inputs.pre-D1.bak" -Force   # defensive backup
Restart-Service SplunkForwarder
Get-Service SplunkForwarder    # Status: Running expected
```

**Smoke test:** spawn `notepad.exe`, then in Splunk:

```spl
index=mydfir-project source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*\\notepad.exe" earliest=-5m
| table _time, host, User, Image, CommandLine
```

Expected: ≥1 row within 60 seconds.

If fields don't extract (Image/CommandLine empty while `_raw` has them), confirm the **Splunk Add-on for Microsoft Sysmon** is installed and enabled on the indexer (Settings → Apps → search for "Microsoft Sysmon"). D1 installed it from Splunkbase during Phase 0.

### 4. Install Atomic Red Team

```powershell
Set-ExecutionPolicy Bypass -Scope CurrentUser -Force
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$installerUrl = 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1'
Invoke-Expression (Invoke-WebRequest -Uri $installerUrl -UseBasicParsing).Content
Install-AtomicRedTeam -getAtomics -Force
```

**Gotcha:** Red Canary's installer drops the module under `C:\AtomicRedTeam\invoke-atomicredteam\` — **not** on any default `$env:PSModulePath`. So `Import-Module Invoke-AtomicRedTeam` (by name) **fails**.

Two fixes:

1. **Import by full path** (used in our scripts):
   ```powershell
   Import-Module C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1 -Force
   ```
2. **Add the path persistently** (recommended for interactive analyst sessions):
   ```powershell
   [Environment]::SetEnvironmentVariable(
     'PSModulePath',
     $env:PSModulePath + ';C:\AtomicRedTeam\invoke-atomicredteam',
     'User')
   ```
   Then `Import-Module Invoke-AtomicRedTeam` works after restarting the shell.

Verify:

```powershell
Import-Module C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1
Invoke-AtomicTest T1059.001 -ShowDetailsBrief    # confirms catalog loaded
```

Atomics library lands at `C:\AtomicRedTeam\atomics\` (~334 technique directories).

### 5. Create the worked-example saved search

In Splunk web UI: **Search & Reporting → run the SPL from [[../../detections/t1059-001-powershell-encoded]] → Save As → Alert**. Configure per spec § 2.6 / plan Phase 5. Critical settings:

- **Schedule type:** "Run on Cron Schedule" (NOT "Run on Real-Time Schedule"). Real-Time causes `is_scheduled` to silently flip back to False after any saved-search edit. See [[#recoveries]] if scheduling stops working.
- **Trigger:** "For each result" (not "Once"). The webhook payload format requires per-result delivery for the n8n pipeline.
- **Webhook URL:** the v2 production URL. See [[../../runbooks/secrets-management]] for where it's documented.

---

## The "run a technique" loop

The everyday operational case. Use this for any MITRE technique you want to run + observe in Splunk.

### Step 1: Pick a technique

Browse https://attack.mitre.org/matrices/enterprise/ — pick a technique relevant to what you're learning (Execution, Credential Access, Lateral Movement, etc.). Note the T-id (e.g., `T1003`, `T1059.003`).

### Step 2: Take a VMware Workstation snapshot

VMware Workstation: right-click VM → Snapshot → Take Snapshot. Name: `before-T<id>-run-YYYY-MM-DD`. Description: which technique, what test number.

**Why:** ART's `-Cleanup` is best-effort. If a test leaves residue (registry keys, files, scheduled tasks, accounts), the snapshot is your safety net.

### Step 3: Preview the test catalog

```powershell
Import-Module C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1
Invoke-AtomicTest T<id> -ShowDetailsBrief
```

Read each test description before running. Pick the one that matches what you're trying to observe. **Look for `ATH`-prefixed tests first** — those are Atomic Test Harness synthetics with benign payloads, well-defined cleanup, and no external download dependencies.

### Step 4: Install prereqs (if any) + run the test

```powershell
Invoke-AtomicTest T<id> -TestNumbers <N> -GetPrereqs    # auto-installs PS modules
Invoke-AtomicTest T<id> -TestNumbers <N>
```

Note the wall-clock time. Many tests print a `TestSuccess: True/False` summary on completion.

### Step 5: Observe in Splunk

Use the [observation toolkit](#observation-toolkit--starter-spl-queries) below. Start with "What just ran?" and drill down by EventCode based on what the technique should be doing (network connect → EventCode 3, file write → 11, registry → 12-14, DNS → 22).

### Step 6: Update the catalog page

In `vault/detections/`:
1. If a page for this T-id doesn't exist, copy `_template.md` to `t<id-with-dots-as-dashes>-<short-name>.md` (e.g., `t1003-credential-dumping.md`).
2. Populate the **Description**, **ART command**, **Observations** sections.
3. Set frontmatter: `status: observed`, `last_run: YYYY-MM-DD`, `tactic: <from MITRE>`.
4. Update `vault/detections/README.md`'s coverage table — add a row.
5. Commit.

### Step 7: Cleanup

```powershell
Invoke-AtomicTest T<id> -TestNumbers <N> -Cleanup
```

Then either revert the snapshot (clean slate) or carry on. Snapshot revert in VMware Workstation: VM → Snapshot → Revert to Snapshot...

### Step 8 (optional): Lift to a saved search

If the technique is one you want to detect on an ongoing basis:
1. Hand-craft an SPL against the real ART event (see [[plan]] Phase 4 for the iterative pattern).
2. Save As → Alert with the same settings as the T1059.001 worked example (cron `*/5 * * * *`, Time Range `Last 24 hours`, Schedule type **Run on Cron Schedule**, Trigger "For each result", webhook to v2 production URL).
3. Update the page's frontmatter to `status: spl-drafted` then `status: saved-search-active`.
4. **Decide on cross-tick dedup** (see [Recoveries → Saved search produces duplicate alerts](#recoveries) below). For most production detections, set `alert.suppress=True` with `alert.suppress.fields=_time,host,Image,CommandLine`. For the lab default, accept duplicates.
5. Commit.

---

## Observation toolkit — starter SPL queries

Seven starter queries for the everyday "I ran something on the Windows VM, what happened?" investigation. Each is annotated inline. Reference catalogs (full Sysmon EventCode list + field reference) live in [[../../architecture/components/sysmon]].

### 1. "What just ran?" — recent process creates

```spl
index=mydfir-project source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 earliest=-15m
| table _time, host, User, Image, CommandLine, ParentImage
| sort -_time
```

- `EventCode=1` — Sysmon's Process Create event.
- `earliest=-15m` — last 15 minutes (adjust as needed).
- `| table ...` — flat output of just the columns you care about. Like SQL's `SELECT col1, col2`.
- `| sort -_time` — most recent first. The `-` means descending.

### 2. "What network connections happened?" — recent EventCode=3

```spl
index=mydfir-project source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=3 earliest=-15m
| table _time, host, User, Image, DestinationIp, DestinationPort
| sort -_time
```

- `EventCode=3` — Sysmon's Network Connect event.
- `DestinationIp` / `DestinationPort` — Sysmon's fields for the connection target. (`DestinationHostname` is also populated when the resolver had a name.)

### 3. "What files got written?" — recent EventCode=11

```spl
index=mydfir-project source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=11 earliest=-15m
| table _time, Image, TargetFilename, User
| sort -_time
```

- `EventCode=11` — File Create.
- `TargetFilename` — the file path being written.
- `Image` — the process that wrote it.

### 4. "Did anything modify the registry?" — recent EventCode IN (12, 13, 14)

```spl
index=mydfir-project source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
(EventCode=12 OR EventCode=13 OR EventCode=14) earliest=-15m
| table _time, EventCode, Image, User, TargetObject, Details
| sort -_time
```

- `(EventCode=12 OR EventCode=13 OR EventCode=14)` — Registry Create / Set / Rename. Parens group the OR; without them, SPL parses left-to-right and breaks the filter.
- `TargetObject` — the registry key or value path.
- `Details` — the new value (for EventCode=13, the `Set Value` event).

**Lab observation:** SwiftOnSecurity filters EventCode=12 aggressively, so most registry activity surfaces as 13 (Set Value). If you expect a 12 and don't see it, that's the filtering, not a Sysmon failure.

### 5. "What DNS lookups happened?" — recent EventCode=22

```spl
index=mydfir-project source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=22 earliest=-15m
| table _time, Image, QueryName, QueryStatus
| sort -_time
```

- `EventCode=22` — DNS Query.
- `QueryName` — the DNS name. `QueryStatus` is the resolver's result code (0 = success).

### 6. "What's the process tree for PID X?"

Replace `<PID>` with the process ID you want to trace.

```spl
index=mydfir-project source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
(ProcessId=<PID> OR ParentProcessId=<PID>) earliest=-15m
| table _time, EventCode, Image, ParentImage, CommandLine, ProcessId, ParentProcessId
| sort _time
```

- `(ProcessId=<PID> OR ParentProcessId=<PID>)` — events where the PID is either the process itself or its parent. You'll see both the spawn event for the PID *and* spawn events for its children.
- `| sort _time` (no `-`) — chronological order. Useful for reading a process tree top-down.

### 7. "What Sysmon EventCodes have I received in the last hour?" — meta query

```spl
index=mydfir-project source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
earliest=-1h
| stats count by EventCode | sort -count
```

Confirms the Sysmon config is capturing what you expect. If an EventCode you wanted is missing, either (a) nothing in the lab triggered it, or (b) the SwiftOnSecurity config filters it. Cross-check against the [[../../architecture/components/sysmon]] EventCode reference + the lab's baseline distribution captured in [[notes]].

---

## VMware Workstation snapshot discipline

Always snapshot the Windows VM before any ART session. Always.

- **Take:** VMware Workstation → right-click VM → Snapshot → Take Snapshot. Name `before-<short>-YYYY-MM-DD`.
- **List:** VM → Snapshot → Snapshot Manager.
- **Revert:** VM → Snapshot → Revert to Snapshot... (then optionally power back on).
- **Delete (cleanup):** Snapshot Manager → select → Delete. Disk space lives in `.vmsd`/`.vmsn` files alongside the VM's `.vmx`.

ART's `-Cleanup` is best-effort. Some tests leave registry keys, scheduled tasks, accounts, or files behind. The snapshot is the safety net.

If you're operating headlessly via `vmrun`:

```bash
vmrun snapshot "<path-to-.vmx>" "before-T<id>-YYYY-MM-DD"
vmrun listSnapshots "<path-to-.vmx>"
vmrun revertToSnapshot "<path-to-.vmx>" "before-T<id>-YYYY-MM-DD"
```

---

## Worked example as smoke-test template

The T1059.001 live-fire from D1's Phase 6 is the smoke test for any technique reaching `status: saved-search-active`. To validate a new saved search:

1. Take a snapshot.
2. Run `Invoke-AtomicTest T<id> -TestNumbers <N>`.
3. Within ~5 minutes (the cron tick), confirm:
   - Splunk indexed the event (toolkit query #1 above).
   - n8n executions tab shows a new SOC Triage v2 execution.
   - Iris received the alert (https://192.168.129.133/alerts).
   - Slack `#alerts` got the post (plain for gate-skipped; Approve/Deny for gated).
4. Update the technique's vault page with the run timestamp and observed outcome.
5. Cleanup.

If any step fails, see [Recoveries](#recoveries).

---

## Security-posture note

The Windows 10 VM runs with **Defender off and the C: drive excluded from any AV scope**. This is **intentional lab setup** — not an oversight. Reasons:

- Many ART tests trip Defender's heuristics; running with Defender on means measuring "is Defender catching this technique?" instead of "is our detection catching this technique?".
- The lab is isolated to the 192.168.129.0/24 NAT network with no inbound from the internet.
- The Windows VM is treated as ephemeral — snapshots before ART sessions, revert if needed.

If you're in a working session and Defender alerts pop up unexpectedly, that's a regression — Defender shouldn't be running. Check `Get-MpPreference | Select DisableRealtimeMonitoring` (expected `True`) and `Get-MpPreference | Select ExclusionPath` (expected to include `C:\`).

**Future-fresh-instance reading this:** the security posture is the user's deliberate lab choice, not an attack surface they didn't know about. D1 doesn't re-litigate it.

---

## Recoveries

The diagnostic ladder for common failures. Try in order; stop when symptoms clear.

### "I ran ART, no event in Splunk"

1. **Sysmon emitting locally?** On the Windows VM:
   ```powershell
   Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 5 |
     Select-Object TimeCreated, Id
   ```
   Expected: a recent EventCode=1 from the ART run. If empty, Sysmon isn't capturing — restart the service: `Restart-Service Sysmon64`.

2. **Forwarder running?** `Get-Service SplunkForwarder` — expected `Running`. If stopped: `Start-Service SplunkForwarder`.

3. **Forwarder log shows no errors?**
   ```powershell
   Get-Content 'C:\Program Files\SplunkUniversalForwarder\var\log\splunk\splunkd.log' -Tail 50 |
     Select-String -Pattern 'ERROR|WARN|Sysmon'
   ```
   Expected: no recent ERROR-level entries. If you see "WinEventLog binding failed" or similar, the stanza name is wrong — check `inputs.conf` against the channel name in step 1.

4. **Splunk receiving events at all?**
   ```spl
   index=mydfir-project earliest=-5m | stats count by source
   ```
   Expected: rows for each Windows channel including the Sysmon source. If only Security/App/System show up, the forwarder restarted but the Sysmon stanza didn't load — check `inputs.conf` and re-restart.

5. **Field extraction works?**
   ```spl
   index=mydfir-project source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
   earliest=-5m | head 1
   ```
   In the resulting event, expand the `_raw` blob — check `Image=...` and `CommandLine=...` are present. If `_raw` has them but the search-time fields don't extract, confirm **Splunk Add-on for Microsoft Sysmon** is installed and enabled (Settings → Apps → search "Microsoft Sysmon").

### "Saved search isn't firing on schedule"

This was D1's most surprising gotcha. **The fix is `realtime_schedule=False`** plus `is_scheduled=True`:

```bash
curl -sk -u mydfir:<pw> -X POST \
  "https://192.168.129.131:8089/servicesNS/mydfir/search/saved/searches/<URL-encoded-name>" \
  -d "is_scheduled=true&realtime_schedule=false"
```

Or in the web UI: **Settings → Searches, reports, and alerts → \<your search\> → Edit → Scheduling section → set "Schedule type" to "Run on Cron Schedule"** (NOT "Run on Real-Time Schedule"). Save.

Verify:

```bash
curl -sk -u mydfir:<pw> \
  "https://192.168.129.131:8089/servicesNS/mydfir/search/saved/searches/<URL-encoded-name>?output_mode=json" |
  python -c "import json,sys; c=json.load(sys.stdin)['entry'][0]['content']; \
             print(f\"is_scheduled={c['is_scheduled']} realtime={c['realtime_schedule']} next={c['next_scheduled_time']}\")"
```

Expected: `is_scheduled=True realtime=False next=<UTC timestamp ~5min away>`.

**Why this matters:** Splunk's "Run on Real-Time Schedule" assumes a real-time-search-pipeline workload. Combined with `cron_schedule=*/5 * * * *`, the scheduler may de-prioritize the search and silently flip `is_scheduled` to False. Setting `realtime_schedule=False` puts the search on the traditional cron path where it stays scheduled.

### "Saved search produces duplicate alerts on the same event"

D1's other surprising gotcha. With Trigger="For each result" and `alert.suppress=False`, **Splunk does NOT dedupe across cron ticks** — the same result row re-fires every tick as long as it stays in the Time Range window. To dedupe, two options:

**Option A — narrow the Time Range:**

Edit the saved search → Settings → Time Range → change `Last 24 hours` to `Last 5 minutes` (or whatever matches your cron interval). This scopes each tick's results to events from the previous interval only.

Trade-off: loses the wide look-back for late-indexed events.

**Option B — enable `alert.suppress`** (recommended for production):

```bash
curl -sk -u mydfir:<pw> -X POST \
  "https://192.168.129.131:8089/servicesNS/mydfir/search/saved/searches/<URL-encoded-name>" \
  -d "alert.suppress=true&alert.suppress.fields=_time,host,Image&alert.suppress.period=86400"
```

This tells Splunk to suppress (deduplicate) on the combined value of those fields for 24 hours (86400 seconds). Same row won't re-fire within the suppression window.

**Gotcha — suppress field list must reference fields that exist in the SPL's output rows.** The T1059.001 SPL ends with `| stats count, values(CommandLine) as command_lines, values(ParentImage) as parents by _time, host, User, Image`. After that `stats` step, the output rows have these field names: `_time, host, User, Image, count, command_lines, parents`. **There is no `CommandLine` field in the output** (it was renamed to `command_lines`). An earlier version of this section recommended `alert.suppress.fields=_time,host,Image,CommandLine` — that's broken, because `CommandLine` resolves to empty for every row, which breaks the suppress key. The correct recipe is **`_time,host,Image`** (sufficient because `_time` is per-event-unique). Surfaced 2026-05-19 during demo-recording prep; see `log.md` 2026-05-19 entry for the debugging arc.

**UI gotcha — the suppress-fields textbox only appears when Trigger = "For each result".** In the Splunk web UI's Edit Alert dialog, when the Trigger row is set to "Once" (digest mode), the Throttle section shows only `Suppress triggering for: <duration>` — the per-row "Suppress results containing field value" textbox is **hidden**. Switching Trigger to "For each result" reveals the textbox. If you set Throttle without that textbox, the entire saved search is suppressed for the period (only one alert can fire per period, regardless of how many distinct events match), which is rarely what you want for per-event detections. **You can confirm which mode you're in at runtime** by checking the **Mode** column in Activity → Triggered Alerts: `Per Result` is correct; `Digest` means the saved search is in "Once" mode and the per-row suppress is inactive.

**For D1's worked example (T1059.001), neither option was originally applied** — the lab accepted duplicates as a learning-loop trade-off. **For T1059.003 (added 2026-05-20), Option B with the corrected key was applied from the start.** See [[../../detections/t1059-003-cmd-suspicious-ioc-references]] for the configuration as deployed.

### "Splunk daily license cap hit"

Symptom: indexer shows the "Indexer License Volume" warning banner; new events queued but not searchable.

Recovery: free-tier license resets at midnight UTC. The forwarder will buffer events; once the indexer accepts again, they'll all be searchable.

If you can't wait, options are:
- Disable noisy forwarder stanzas temporarily (e.g., `disabled = 1` on the Application channel) and restart the forwarder.
- Pause Sysmon: `Stop-Service Sysmon64` (resume with `Start-Service Sysmon64`).
- Switch to dev license / paid Splunk / move to ELK — bigger decision; not D1.

### "Claude misbehaves on a Sysmon-shaped alert"

Symptoms:
- `Extract Triage Result` Code node throws (visible in n8n executions).
- Iris alert created with garbage severity / empty fields.
- Workflow fails partway through.

Apply the [standby fix below](#standby-fix--system-prompt-addendum). **Reactive only — don't apply unless an actual live-fire shows misbehavior.** D1's Phase 6 validated this behavior is correct without the addendum.

### "ART left residue on the VM"

Revert to the pre-run snapshot. VMware Workstation → Snapshot Manager → select the `before-T<id>-...` snapshot → Revert.

If the snapshot is gone (forgot to take one, or already deleted):

- Check `C:\AtomicRedTeam\atomics\T<id>\T<id>.yaml` — the test definition has a `cleanup_command` that's authoritative for what the test created.
- Run it manually if `-Cleanup` failed.

### "ART module won't import by name"

The Red Canary installer puts the module under `C:\AtomicRedTeam\invoke-atomicredteam\` — not on default `$env:PSModulePath`. **Workaround:**

```powershell
Import-Module C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1 -Force
```

Or persist the path:

```powershell
[Environment]::SetEnvironmentVariable(
  'PSModulePath',
  $env:PSModulePath + ';C:\AtomicRedTeam\invoke-atomicredteam',
  'User')
```

(Then restart the shell.)

### "ART test errors with `Out-ATHPowerShellCommandLineParameter not recognized`"

The test depends on the **AtomicTestHarnesses** PowerShell module (a separate Red Canary repo, not bundled with the Invoke-AtomicRedTeam installer). Run with `-GetPrereqs` first:

```powershell
Invoke-AtomicTest T<id> -TestNumbers <N> -GetPrereqs
Invoke-AtomicTest T<id> -TestNumbers <N>
```

`-GetPrereqs` auto-installs missing modules from PowerShell Gallery.

**TLS 1.2 gotcha (surfaced 2026-05-12 on Win10-v2 rebuild):** `Install-Module` silently fails with no output on Windows 10 default PowerShell 5.1 because PSGallery dropped TLS 1.0/1.1 support in 2020. If `-GetPrereqs` produces zero output, run this **before** retrying:

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Install-Module -Name AtomicTestHarnesses -Scope CurrentUser -Force -SkipPublisherCheck -AllowClobber
```

Then retry `Invoke-AtomicTest`. Verify the module loaded with `Get-Module -ListAvailable AtomicTestHarnesses`. If you can't (or won't) fix the install, a synthetic `powershell.exe -EncodedCommand` invocation produces the same Sysmon event shape and matches the same SPL — see Phase 11 of notes.md for the inline pattern.

### "Saved search returns 0 results when dispatched, but the same SPL works ad-hoc" (REST-API trap)

Symptoms:
- Saved search created via REST API (`POST /servicesNS/<user>/<app>/saved/searches`).
- `dispatch` returns `resultCount=0` and `scanCount` is tiny (~10) despite the index containing thousands of matching events.
- Same SPL run interactively in the Search & Reporting UI returns events correctly (possibly with a yellow "show errors" warning about lookups — that's unrelated and harmless).
- The cron-fired scheduled instances are also returning 0 (`run_time=0.062` in scheduler.log — way too fast for a 24h scan).

Root cause (surfaced 2026-05-12): the `search` parameter posted to the saved-search REST endpoint should NOT include a leading `search` keyword. The REST API stores it verbatim, then Splunk's runtime parser prepends its own implicit `search` — producing `search search index=...`. The second `search` becomes a **literal search term**, filtering events to only those containing the word "search" in raw text (~10 of them across the whole index in our case).

**Fix:** delete and recreate the saved search with the SPL starting with `index=` (or `source=`, or `host=`, or any other field-value filter), NOT with `search ...`. The UI's Save As Alert flow strips the leading `search` automatically; the REST API does not.

```python
# Wrong (this was the bug):
data = {'search': 'search index=mydfir-project source=... EventCode=1 | ... '}

# Right:
data = {'search': 'index=mydfir-project source=... EventCode=1 | ... '}
```

Diagnostic: dispatch the search and look at `/opt/splunk/var/run/splunk/dispatch/<sid>/info.csv`. The `_base_lispy` field shows the parsed lispy form. If you see `search` appearing as an AND-clause term (e.g., `[ AND index::mydfir-project search source::... ]`), that's the doubled-`search` signature.

---

## Standby fix — system-prompt addendum

**Apply only if** a live-fire run shows Claude returning malformed responses to Sysmon-shaped alerts. **Default state: not applied.** D1's worked example validated the pipeline without this addendum — Claude's default behavior on Sysmon-shaped payloads is correct (it correctly identifies the WMI parent as a forensic signal, decodes the base64, returns schema-compliant triage).

If applied, this becomes ADR-worthy (probably 0006). Append a one-paragraph addendum to the SOC Triage v2 workflow's system prompt (the `Anthropic` node's `Options → System Message` field):

```markdown
**Sysmon process-create alert family:** Some alerts arrive from Splunk saved searches against Sysmon's `Microsoft-Windows-Sysmon/Operational` channel — typically `result.search_name` matching `T<MITRE-id>`-prefixed names. These alerts describe a process being launched (EventCode=1). Triage them by:

1. Treating `Image` and `CommandLine` as the highest-signal fields.
2. Looking at `ParentImage` for context (a phishing-launched PowerShell vs. an admin shell).
3. If `CommandLine` contains `-EncodedCommand` (or `-e`/`-en`/`-enc`) followed by base64, do not attempt to decode the payload. The triage is "encoded PowerShell observed; out-of-band investigation required" rather than "what's inside the payload."
4. `iocs_enriched` typically empty for this family — Sysmon process-create events have no network IOCs structurally.
```

After applying, export the updated workflow and commit:

```bash
git add JSON/SOC-Triage-v2-with-sysmon-addendum.json
git commit -m "feat(D1+): system prompt addendum for Sysmon-shaped alert family"
```

And write ADR 0006 documenting the addition (the fact of adding *was* a non-obvious decision; future-fresh-instance needs to know why).

The addendum's "do not decode the payload" guidance preserves the gate-skipped Outcome A path even if Claude is otherwise capable of decoding (D1's Phase 6 showed Claude DOES decode by default). If you want Outcome B as the default (gate-fired path on decoded IOCs), invert that bullet to "decode the payload and extract any IPs/domains/URLs/hashes you find as IOCs"; this couples D1 more tightly to A1's prompt and is itself an architectural decision (would deserve its own ADR).
