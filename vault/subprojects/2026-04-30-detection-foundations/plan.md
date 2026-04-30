---
status: draft
updated: 2026-04-30
sub_project: D1
spec: [[spec]]
related: [[README]], [[../../architecture/components/splunk]], [[../../architecture/target-state]]
---

# D1 Detection Foundations — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **For humans:** Work through tasks in order. Each task has 3–7 small steps. Run the verify step after each implementation step before moving on. Commit after each task that produces a vault file change.

**Goal:** Stand up a detection-engineering observation lab on top of the existing SOC pipeline — Sysmon + ART installed on the Windows 10 VM, the existing Universal Forwarder picking up the Sysmon channel into `mydfir-project`, one worked-example saved search (T1059.001 PowerShell encoded command) firing the existing v2 webhook end-to-end, and a `vault/detections/` catalog seeded so future technique runs are a runbook routine, not a sub-project.

**Architecture:** Generation half is manual (`Invoke-AtomicTest` on the Windows VM). Detection/response half splits into **manual exploration** (alt-tab to Splunk Search & Reporting, observation-toolkit SPL) and **automated detection** (one saved search → existing v2 webhook → existing n8n SOC Triage v2 workflow → Claude triage → Iris alert → IF gate → Slack). The architectural promise: a Sysmon-shaped alert traverses A2's Test 1 path (gate-skipped) on real production traffic with **no n8n changes**.

**Tech Stack:** Sysmon (Sysinternals) + SwiftOnSecurity `sysmonconfig-export.xml` (off-the-shelf), Splunk Universal Forwarder (existing — config edit only), Atomic Red Team (`Invoke-AtomicRedTeam` PowerShell module), Splunk Enterprise (saved search + observation toolkit SPL), existing n8n SOC Triage v2 workflow, existing DFIR-Iris/Slack endpoints. Vault docs in markdown. No code; no test framework — verification is infrastructure smoke tests + one live-fire integration run.

**Reference docs:**
- Spec: [[spec]]
- README: [[README]]
- A2 spec (predecessor — gate-skipped path is Test 1): [[../2026-04-28-iris-escalation-gate/spec]]
- A2 runbook (operational reference for the gate behavior): [[../2026-04-28-iris-escalation-gate/runbook]]
- Splunk component page: [[../../architecture/components/splunk]]
- n8n component page: [[../../architecture/components/n8n]]
- Existing Universal Forwarder install context: [[../../log.md]] (2026-04-27 backfilled entry)
- Secrets file location: [[../../runbooks/secrets-management]] (`SOC-Automation-Project.md` at repo root, gitignored)
- VM start procedure: [[../../runbooks/starting-the-vms]]
- SwiftOnSecurity Sysmon config (upstream): https://github.com/SwiftOnSecurity/sysmon-config
- Atomic Red Team install docs (upstream): https://github.com/redcanaryco/invoke-atomicredteam
- Microsoft Sysmon docs (upstream): https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

**Working assumptions for the executor:**
- All four VMs are running per [[../../runbooks/starting-the-vms]]: Splunk (192.168.129.131), n8n (192.168.129.132), Iris (192.168.129.133), Windows 10 VM (192.168.129.x — captured in Phase 0).
- The Splunk Universal Forwarder is already installed on the Windows 10 VM and forwarding Windows Security/App/System logs to `mydfir-project` (per the 2026-04-27 backfilled log entry).
- The `SOC Triage v2` n8n workflow is the live, A2-validated pipeline. **No n8n node changes** in D1.
- The Splunk `Test-Brute-Force-External-Spoofed` saved search is currently disabled (per A2 closeout) — D1 doesn't touch it.
- The Splunk Add-on for Microsoft Windows is installed (per `splunk.md`).
- Defender on the Windows 10 VM is intentionally off; C: drive is excluded from any AV scope. This is the documented lab posture; D1 doesn't re-litigate it.
- VMware Workstation hosts all four lab VMs (snapshot terminology, not "checkpoint" / "restore point").
- Lab VM SSH writes for Sysmon/ART install commands are pre-approved per the user calibration dated 2026-04-30. Restarts and `inputs.conf` edits are also in scope of that authorization. Anything outside D1's install path (`docker-compose down`, kernel changes, etc.) still requires confirmation.
- Secrets (Splunk admin password, Iris API key, Windows VM creds, v2 webhook URL) live in `SOC-Automation-Project.md` at project root, gitignored.

**Pair-execution conventions (carried over from A1/A2 — read these before starting):**

D1 is built jointly. The executor (Claude Code) drives bash, paramiko-SSH, git, and vault file edits. The user drives all GUI clicks: VMware Workstation snapshots, Splunk web UI saved-search creation, RDP into the Windows VM if needed, n8n executions inspection, Slack/Iris UI verification. Tasks below tag each step with **[Claude]**, **[User]**, or **[Either]** to make the split explicit.

- **[Claude]** = Claude executes the step directly via tools (bash, paramiko, Edit/Write).
- **[User]** = User performs the step (GUI click, RDP, Splunk web UI, etc.) and reports back what they observed.
- **[Either]** = Either party can do it; usually a verification command that runs the same way from any shell.

**Common gotchas (pre-emptively flagged so the executor doesn't waste time discovering them):**
- **paramiko has no sshpass equivalent baked in** — use the documented paramiko pattern (memory: `reference_paramiko_ssh.md`). The Windows host machine does not have `sshpass`.
- **Splunk free-tier 500MB/day cap.** ART runs are tiny (a few KB each) but a noisy Sysmon config could push volume. If the cap hits, indexing stops until midnight UTC; the runbook documents this as a recoverable, non-data-loss event for the lab.
- **`source=` not `sourcetype=` differentiates Sysmon from Security/App/System** in Splunk. All four channels share `sourcetype=XmlWinEventLog`. Sysmon's channel is filtered with `source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"`.
- **`inputs.conf` in `system\local\` overrides `system\default\`** — always edit the `local\` file, never `default\`.
- **Universal Forwarder service must be restarted** for new `inputs.conf` stanzas to take effect.
- **Splunk's "For each result" trigger dedupes by result-row content hash** across cron ticks. The 24-hour Time Range is therefore safe with the 5-minute cron — see spec § 2.6.
- **PowerShell `-EncodedCommand` flag** can be abbreviated `-e` / `-en` / `-enc`. The SPL `regex` clause matches all four.

---

## Amendments during execution

**2026-04-30 (Phase 0 surfaced two pre-existing realities the spec didn't anticipate):**

1. **UF `inputs.conf` already contains a Sysmon stanza.** Last-modified 2026-04-25, predating D1's brainstorm. Stanza is correct as-is:
   ```ini
   [WinEventLog://Microsoft-Windows-Sysmon/Operational]
   index = mydfir-project
   disabled = false
   renderXml = true
   source = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
   ```
   **Phase 2 Tasks 2.1 (backup) and 2.2 (append stanza) become no-ops.** Phase 2 reduces to: verify stanza unchanged → restart forwarder → smoke test.

2. **Splunk Add-on for Microsoft Sysmon (`Splunk_TA_microsoft_sysmon` v5.0.0) installed during Phase 0.** This is the canonical Splunk integration for Sysmon and rationalizes the `source = XmlWinEventLog:...` override above (the add-on's props/transforms are keyed on that source value). **All SPL filters in this plan and in `spec.md` have been globally rewritten** from `source="WinEventLog:Microsoft-Windows-Sysmon/Operational"` to `source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"`. The spec's Errata section captures the original-vs-amended source value.

3. **Collateral: PowerShell/Defender source values will change on UF restart.** Two other stanzas in the existing inputs.conf (`Microsoft-Windows-PowerShell/Operational`, `Microsoft-Windows-Windows Defender/Operational`) have `source =` overrides that haven't yet taken effect (forwarder hasn't restarted since the 2026-04-25 edit). When we restart in Phase 2, those overrides activate; their source values in Splunk will lose the `WinEventLog:` prefix. Vault grep returned **zero** consumers of the old source strings — no breakage downstream. Phase 8 splunk.md update should note this in passing.

---

## File structure

| File | Action | Purpose |
|---|---|---|
| `vault/detections/` | Create directory | New top-level vault slot for technique pages |
| `vault/detections/README.md` | Create | Coverage index — markdown table of techniques observed |
| `vault/detections/_template.md` | Create | Copy-this skeleton for adding a new technique |
| `vault/detections/t1059-001-powershell-encoded.md` | Create | Worked-example page for D1's integration test |
| `vault/architecture/components/sysmon.md` | Create | New component page (long-lived reference: EventCode + field tables, install metadata, gotchas) |
| `vault/architecture/components/splunk.md` | Modify | Add the new saved search; document Sysmon sourcetype/source distinction; cross-reference to `sysmon.md` |
| `vault/CLAUDE.md` | Modify | Add `vault/detections/` row to the schema's where-to-find-what table |
| `vault/index.md` | Modify | Add the new pages to the catalog |
| `vault/subprojects/2026-04-30-detection-foundations/runbook.md` | Create | Operational runbook: install + run-a-technique loop + observation toolkit (procedural) + standby fix |
| `vault/subprojects/2026-04-30-detection-foundations/notes.md` | Create | Gotchas/learnings record (mirrors A1/A2 discipline) |
| `vault/subprojects/2026-04-30-detection-foundations/README.md` | Modify | Tick status checkboxes as phases complete |
| `vault/log.md` | Append | Milestone entries (one per major phase) |
| Windows 10 VM: `C:\Tools\sysmon-config\sysmonconfig-export.xml` | Create on VM | SwiftOnSecurity config file (downloaded, no edits) |
| Windows 10 VM: Sysmon installed | Service install | Sysinternals `Sysmon64.exe -accepteula -i sysmonconfig-export.xml` |
| Windows 10 VM: `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf` | Modify | Append `[WinEventLog://Microsoft-Windows-Sysmon/Operational]` stanza |
| Windows 10 VM: ART installed | Module install | `Install-AtomicRedTeam -getAtomics` |
| Splunk web UI: saved search `T1059.001 - PowerShell Encoded Command` | Create | Scheduled `*/5 * * * *`, webhook to v2 production URL |

No code/test files — D1 is infrastructure + documentation. "Tests" are the three Tier-1 smoke tests + Tier-2 live-fire run (per spec § Validation strategy).

---

## Phase 0 — Pre-flight verifications

Phase 0 captures values from the running systems that downstream tasks depend on, and confirms environmental assumptions before we start changing things. **Run these before touching any system** — three of them feed values directly into later configuration.

### Task 0.1: Verify all four lab VMs are reachable

**Files:** none on disk; environmental check.

- [ ] **Step 1: [Either] Confirm Splunk, n8n, Iris are responding**

```bash
curl -sk -o /dev/null -w "Splunk web:   %{http_code}\n" http://192.168.129.131:8000
curl -sk -o /dev/null -w "n8n editor:   %{http_code}\n" http://192.168.129.132:5678
curl -sk -o /dev/null -w "Iris UI:      %{http_code}\n" https://192.168.129.133
```

Expected: all three return `200` or `302`. If any return `000` or connection error, the corresponding VM is down — see [[../../runbooks/starting-the-vms]].

- [ ] **Step 2: [User] Identify the Windows 10 VM IP and credentials**

Open `SOC-Automation-Project.md` at the repo root (gitignored). Locate the Windows 10 VM's IP, username, and password. Common pattern: a `192.168.129.x` host on the same NAT network as the other lab VMs. Note the IP for Step 3.

- [ ] **Step 3: [Claude] Ping the Windows VM**

```bash
ping -n 2 <WIN10-IP>
```

Expected: responses with low latency (sub-5ms on the same NAT subnet).

If unreachable, the Windows VM is powered off — boot it from VMware Workstation before proceeding.

- [ ] **Step 4: [Claude] Confirm Sysmon is NOT yet installed on the Windows VM**

We confirm baseline state so D1's "before" is documented and we can't accidentally double-install.

Use the paramiko pattern (memory: `reference_paramiko_ssh.md`) to SSH as the Windows admin user and run:

```powershell
Get-Service Sysmon64 -ErrorAction SilentlyContinue
```

Expected: empty output (service does not exist). If it exists with `Status: Running`, Sysmon is already installed — stop and confirm with the user whether to reuse, reinstall, or back out.

- [ ] **Step 5: [Claude] Note the baseline values in notes.md draft**

Create `vault/subprojects/2026-04-30-detection-foundations/notes.md` with frontmatter and a "Phase 0 captures" section. Append: Windows VM IP, baseline Sysmon state ("not installed, confirmed via Get-Service"), date/time of capture.

- [ ] **Step 6: [Claude] Commit notes.md scaffold**

```bash
git add vault/subprojects/2026-04-30-detection-foundations/notes.md
git commit -m "docs(D1): Phase 0 baseline captures recorded"
```

---

### Task 0.2: Verify Splunk is healthy and `mydfir-project` is receiving events

**Files:** none on disk.

This task confirms the destination side of the pipeline is functional before we add new ingest. Uses the Splunk MCP if available, otherwise a manual web-UI check.

- [ ] **Step 1: [Either] Run a baseline volume query against `mydfir-project` for the last 24 hours**

Via the Splunk MCP (preferred — see [[../../architecture/components/splunk-mcp]]) or directly in Splunk's Search & Reporting bar:

```spl
index=mydfir-project earliest=-24h | stats count by sourcetype, source
```

**SPL annotation (for the user — currently learning SPL):**
- `index=mydfir-project` — narrow to the project's index. Without this, Splunk searches everything (slow + expensive).
- `earliest=-24h` — relative time bound; "last 24 hours" up to now. `latest=` defaults to now.
- `| stats count by sourcetype, source` — group results by the *combination* of `sourcetype` and `source`, count rows per group. This shows us which channels are alive.

Expected: a non-empty result with rows for `sourcetype=XmlWinEventLog` and source values like `WinEventLog:Security`, `WinEventLog:System`, `WinEventLog:Application`. **Note** what's there before D1 — after Phase 2, a new row for `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` should appear.

- [ ] **Step 2: [Claude] Capture this baseline snapshot in notes.md**

Append the result table to notes.md under "Phase 0 captures → Splunk baseline volumes". This is the "before" we'll diff against after Sysmon ingestion starts.

- [ ] **Step 3: [Either] Check Splunk's daily license usage**

In the Splunk web UI, navigate: **Settings → Licensing**. Note the current day's indexed volume against the 500MB/day free-tier quota.

If usage is already >400MB, runbook posture flips — be conservative on Phase 4 SPL iteration (use `head 10` on every search to avoid unbounded scans). Document the headroom in notes.md.

- [ ] **Step 4: [Claude] Commit**

```bash
git add vault/subprojects/2026-04-30-detection-foundations/notes.md
git commit -m "docs(D1): Phase 0 Splunk baseline + license headroom captured"
```

---

### Task 0.3: Capture the Universal Forwarder `inputs.conf` path and existing stanzas

**Files:** none on disk; reads remote VM file.

The spec assumes the path is `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf` but flags it as Phase-0 to verify. We also need to know what stanzas already exist before we append.

- [ ] **Step 1: [Claude] SSH to the Windows VM, list the system\local directory**

```powershell
Get-ChildItem 'C:\Program Files\SplunkUniversalForwarder\etc\system\local'
```

Expected: at least `inputs.conf` and `outputs.conf` present.

If `system\local\` doesn't exist or `inputs.conf` is missing there, fall back to `system\default\inputs.conf` — but **do not edit the `default\` file**. The runbook mandates we copy default → local first if local doesn't exist, then edit local. (This is standard Splunk forwarder hygiene; `default\` gets overwritten by upgrades.)

- [ ] **Step 2: [Claude] Read the current `inputs.conf`**

```powershell
Get-Content 'C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf'
```

Capture the full output. Expected stanzas: `[default]` (with `host = ...`), `[WinEventLog://Security]`, `[WinEventLog://System]`, `[WinEventLog://Application]`. Confirm the existing stanzas use `index = mydfir-project` (or that default `index` resolves to `mydfir-project`).

- [ ] **Step 3: [Claude] Capture the path and current contents in notes.md**

Append to notes.md under "Phase 0 captures → Universal Forwarder":
- Confirmed path: `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`
- Existing stanzas (paste the file contents, redact `host =` if it's an internal hostname).
- Confirm Sysmon stanza is NOT already present.

- [ ] **Step 4: [Claude] Commit**

```bash
git add vault/subprojects/2026-04-30-detection-foundations/notes.md
git commit -m "docs(D1): Phase 0 Universal Forwarder path + stanzas captured"
```

---

### Task 0.4: Confirm SSH-write authorization for the install steps

**Files:** none on disk; sanity check.

User memory: `feedback_windows_vm_ssh_d1.md` — Windows VM SSH writes are pre-approved for D1 install steps (Sysmon, ART, forwarder). This task confirms the authorization is still in place and the SSH session has admin context.

- [ ] **Step 1: [Claude] Verify the SSH session lands as an admin user**

```powershell
[bool](([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
```

Expected: `True`.

If `False`: the SSH user is not in the Administrators group. Either escalate via `Start-Process powershell -Verb RunAs` (interactive — won't work over non-interactive SSH) or have the user RDP and run privileged commands by hand. Pause and confirm the fallback with the user before proceeding.

- [ ] **Step 2: [Claude] Sanity-check that we can write to a test path**

```powershell
"test" | Out-File -FilePath C:\Tools\d1-write-test.txt -Encoding utf8
Get-Content C:\Tools\d1-write-test.txt
Remove-Item C:\Tools\d1-write-test.txt
```

Expected: writes file, reads back `test`, deletes cleanly. If `C:\Tools` doesn't exist, create it first: `New-Item -ItemType Directory -Path C:\Tools -Force`.

- [ ] **Step 3: [Claude] No commit — this is a runtime check.**

---

### Task 0.5: Take a VMware Workstation snapshot of the Windows VM (pre-D1 baseline)

**Files:** none on disk; user GUI action.

This is the safety net. If anything goes sideways during install, we revert to this snapshot and start over. VMware Workstation calls this a "snapshot" (not "checkpoint" or "restore point").

- [ ] **Step 1: [User] Take the snapshot**

In VMware Workstation:
1. Right-click the Windows 10 VM in the library pane.
2. **Snapshot → Take Snapshot...**
3. Name: `D1 pre-install baseline`
4. Description: `Before Sysmon + ART install, after A2 closeout. Revert here if D1 install needs do-over.`
5. Click **Take Snapshot**.

- [ ] **Step 2: [User] Confirm the snapshot appears in the snapshot manager**

**VM → Snapshot → Snapshot Manager...** — verify `D1 pre-install baseline` appears as a child of the current state.

- [ ] **Step 3: [Claude] Record the snapshot in notes.md**

Append under "Phase 0 captures → VMware snapshots":
- `D1 pre-install baseline` taken YYYY-MM-DD HH:MM (revert here if Sysmon/ART install needs do-over).

- [ ] **Step 4: [Claude] Commit**

```bash
git add vault/subprojects/2026-04-30-detection-foundations/notes.md
git commit -m "docs(D1): Phase 0 pre-install snapshot recorded"
```

---

## Phase 1 — Install Sysmon with SwiftOnSecurity config

### Task 1.1: Download SwiftOnSecurity config and capture commit SHA

**Files:**
- Create on Windows VM: `C:\Tools\sysmon-config\sysmonconfig-export.xml`

The spec calls for **off-the-shelf SwiftOnSecurity config, no edits**. We capture the commit SHA at install time so the runbook records exactly what we deployed.

- [ ] **Step 1: [Claude] Create the working directory and clone the SwiftOnSecurity repo**

```powershell
New-Item -ItemType Directory -Path C:\Tools -Force
Set-Location C:\Tools
git clone https://github.com/SwiftOnSecurity/sysmon-config.git
```

Expected: `Cloning into 'sysmon-config'...` followed by progress lines, ends with no error.

If `git` is not installed: `winget install Git.Git --silent` (or have the user install Git for Windows manually). Re-attempt the clone.

- [ ] **Step 2: [Claude] Capture the commit SHA**

```powershell
Set-Location C:\Tools\sysmon-config
git rev-parse HEAD
git log -1 --format="%H %s"
```

Capture both the SHA and the one-line commit summary. Append to notes.md under "Phase 0 captures → SwiftOnSecurity":
- Commit SHA: `<full SHA>`
- Commit summary: `<one-line>`
- Cloned to: `C:\Tools\sysmon-config\`

- [ ] **Step 3: [Claude] Verify the config file exists at the expected path**

```powershell
Test-Path C:\Tools\sysmon-config\sysmonconfig-export.xml
Get-FileHash C:\Tools\sysmon-config\sysmonconfig-export.xml -Algorithm SHA256
```

Expected: `True`, then a SHA256 hash. Capture the hash in notes.md alongside the commit SHA — this confirms the file we're installing matches the commit we recorded.

- [ ] **Step 4: [Claude] Commit notes.md update**

```bash
git add vault/subprojects/2026-04-30-detection-foundations/notes.md
git commit -m "docs(D1): SwiftOnSecurity config commit SHA + file hash captured"
```

---

### Task 1.2: Download Sysmon binary

**Files:**
- Create on Windows VM: `C:\Tools\Sysmon\Sysmon64.exe` (and Sysmon binaries for other arches)

- [ ] **Step 1: [Claude] Create the Sysmon directory and download the official Sysinternals package**

```powershell
New-Item -ItemType Directory -Path C:\Tools\Sysmon -Force
Invoke-WebRequest -Uri https://download.sysinternals.com/files/Sysmon.zip -OutFile C:\Tools\Sysmon\Sysmon.zip -UseBasicParsing
```

Expected: download completes, file ~3-5 MB.

- [ ] **Step 2: [Claude] Extract and verify**

```powershell
Expand-Archive -Path C:\Tools\Sysmon\Sysmon.zip -DestinationPath C:\Tools\Sysmon -Force
Get-ChildItem C:\Tools\Sysmon\Sysmon64.exe
& C:\Tools\Sysmon\Sysmon64.exe -? | Select-Object -First 5
```

Expected: `Sysmon64.exe` exists; the help output starts with `System Monitor v<version>` — capture the exact version string.

- [ ] **Step 3: [Claude] Capture Sysmon version in notes.md**

Append: `Sysmon binary version: <version> (download date YYYY-MM-DD)`.

- [ ] **Step 4: [Claude] Commit**

```bash
git add vault/subprojects/2026-04-30-detection-foundations/notes.md
git commit -m "docs(D1): Sysmon binary version captured"
```

---

### Task 1.3: Install Sysmon as a service

**Files:** Sysmon service installed on the Windows VM.

- [ ] **Step 1: [Claude] Run the install command**

```powershell
& C:\Tools\Sysmon\Sysmon64.exe -accepteula -i C:\Tools\sysmon-config\sysmonconfig-export.xml
```

Expected: output ends with `Sysmon64 installed.` and `Sysmon64 started.` (or equivalent). Service is now installed and running.

If the command errors with "access denied," the SSH session is not in admin context — see Task 0.4. If errors with "Sysmon already exists," uninstall first: `& C:\Tools\Sysmon\Sysmon64.exe -u` then re-run the install.

- [ ] **Step 2: [Claude] Verify the service is running**

```powershell
Get-Service Sysmon64
Get-Process Sysmon64 -ErrorAction SilentlyContinue | Select-Object Id, ProcessName, StartTime
```

Expected: `Status: Running`, `StartType: Automatic`. Process exists with a recent `StartTime`.

- [ ] **Step 3: [Claude] Verify the Event Log channel is registered and accepting events**

```powershell
Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' | Format-List LogName, IsEnabled, RecordCount
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 3 |
  Select-Object TimeCreated, Id, MachineName |
  Format-Table -AutoSize
```

Expected: `IsEnabled: True`, `RecordCount` non-zero (Sysmon emits its own self-events on start). Three recent events visible — typically EventCode 4 (Sysmon service state changed) on first install, plus EventCode 1s for recent processes.

If `RecordCount` is 0, the service may not have fully initialized — wait 10 seconds and retry. If still 0, check `Get-EventLog -LogName 'Microsoft-Windows-Sysmon/Operational' -Newest 1 -ErrorAction Stop` to surface a clearer error.

- [ ] **Step 4: [Claude] Sanity-check the running config matches the file**

```powershell
& C:\Tools\Sysmon\Sysmon64.exe -c | Select-Object -First 20
```

Expected: shows the loaded config; first lines include the SwiftOnSecurity comment header. If the config doesn't match (e.g., shows `<EventFiltering>` empty), Sysmon loaded the default minimal config — re-run the install command from Step 1 with the explicit `-i <path>`.

- [ ] **Step 5: [Claude] Capture install completion in notes.md**

Append:
- Sysmon service installed YYYY-MM-DD HH:MM, running.
- Channel `Microsoft-Windows-Sysmon/Operational` registered, IsEnabled=True.
- Initial RecordCount: `<number>`.
- `Sysmon64.exe -c` confirms SwiftOnSecurity config loaded.

- [ ] **Step 6: [Claude] Commit**

```bash
git add vault/subprojects/2026-04-30-detection-foundations/notes.md
git commit -m "docs(D1): Sysmon installed and emitting events on Windows VM"
```

---

## Phase 2 — Configure Universal Forwarder for the Sysmon channel

> **AMENDED 2026-04-30 (per top-of-file Amendments section):** the Sysmon stanza already exists in `inputs.conf` (last modified 2026-04-25, predates D1). Tasks 2.1 (backup) and 2.2 (append stanza) are now **verify-only**. The forwarder still needs a restart to bind the dormant stanza to the about-to-exist Sysmon channel.

### Task 2.1: Backup the existing `inputs.conf` (defensive — file unchanged in D1)

**Files:**
- Backup on Windows VM: `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf.pre-D1.bak`

We're not editing the file, but a defensive backup is still cheap insurance against accidents during the restart.

- [ ] **Step 1: [Claude] Make a timestamped backup**

```powershell
$src = 'C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf'
$bak = "$src.pre-D1.bak"
Copy-Item -Path $src -Destination $bak -Force
Get-ChildItem $bak | Format-List FullName, Length, LastWriteTime
```

Expected: backup file exists at `inputs.conf.pre-D1.bak`, length matches the original.

- [ ] **Step 2: [Claude] Record backup path in notes.md**

Append: `Universal Forwarder inputs.conf backed up to <path> on YYYY-MM-DD HH:MM`. Restoring is `Copy-Item $bak $src -Force; Restart-Service SplunkForwarder` if rollback is needed.

- [ ] **Step 3: [Claude] Commit**

```bash
git add vault/subprojects/2026-04-30-detection-foundations/notes.md
git commit -m "docs(D1): Universal Forwarder inputs.conf backed up"
```

---

### Task 2.2: Verify the existing Sysmon stanza + restart the forwarder

**Files:**
- (No file modification — stanza already exists.)

- [ ] **Step 1: [Claude] Verify the existing Sysmon stanza is correct**

```powershell
$inputs = 'C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf'
Get-Content $inputs | Select-String -Pattern '\[WinEventLog://Microsoft-Windows-Sysmon' -Context 0,5
```

Expected output (already present, captured in Phase 0 notes):

```
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
index = mydfir-project
disabled = false
renderXml = true
source = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
```

**Why each setting (as already configured):**
- `disabled = false` — equivalent to `disabled = 0`; the channel is enabled.
- `index = mydfir-project` — matches the existing Security/App/System stanzas.
- `renderXml = true` — keeps events as structured XML for the Splunk Add-on for Microsoft Sysmon to parse.
- `source = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` — overrides the default `WinEventLog:` prefix to `XmlWinEventLog:`. The Splunk Add-on for Microsoft Sysmon's props/transforms are keyed on this source value, so the override is what makes the add-on's field extractions fire.

If any setting differs from the expected block above, **stop and consult the user** before proceeding — the stanza may have been edited in a way that conflicts with D1's assumptions.

- [ ] **Step 2: [Claude] (skipped — no append needed)**

- [ ] **Step 3: [Claude] Restart the Universal Forwarder service**

```powershell
Restart-Service SplunkForwarder
Get-Service SplunkForwarder
```

Expected: `Status: Running`. The restart now (a) binds the dormant Sysmon stanza to the newly-installed Sysmon channel from Phase 1, and (b) activates the dormant `source =` overrides on the PowerShell and Defender stanzas (collateral effect, no downstream consumers per Phase-0 vault grep).

- [ ] **Step 4: [Claude] Tail the forwarder's splunkd log to confirm the Sysmon input bound**

```powershell
Get-Content 'C:\Program Files\SplunkUniversalForwarder\var\log\splunk\splunkd.log' -Tail 80 |
  Select-String -Pattern 'Sysmon|inputs\.conf|WinEventLog' |
  Select-Object -Last 25
```

Expected: log lines confirming the `Microsoft-Windows-Sysmon/Operational` channel binding succeeded. ERROR-level lines mentioning `Microsoft-Windows-Sysmon` would indicate the channel still isn't visible to the forwarder — wait 30s and retry; if persistent, confirm Phase 1 Step 3's `Get-WinEvent -ListLog` showed `IsEnabled: True`.

- [ ] **Step 5: [Claude] Capture the restart in notes.md**

Append:
- Universal Forwarder restarted YYYY-MM-DD HH:MM, Status Running.
- Sysmon stanza was already present; D1 did not edit `inputs.conf`.
- splunkd.log: <one-line summary of the Sysmon-input-bound confirmation>.

- [ ] **Step 6: [Claude] Commit**

```bash
git add vault/subprojects/2026-04-30-detection-foundations/notes.md
git commit -m "docs(D1): Universal Forwarder restarted; pre-existing Sysmon stanza activated"
```

---

### Task 2.3: Tier-1 smoke test #1 — `notepad.exe` produces an EventCode=1 in Splunk within 60 seconds

**Files:** none on disk; live test.

This is the headline verification of the entire ingest path. If it works, Sysmon + UF + Splunk are wired correctly.

- [ ] **Step 1: [Claude] Spawn `notepad.exe` on the Windows VM**

```powershell
Start-Process notepad.exe
Start-Sleep -Seconds 2
Get-Process notepad -ErrorAction SilentlyContinue | Select-Object Id, StartTime
Stop-Process -Name notepad -ErrorAction SilentlyContinue
```

Note the timestamp from `StartTime` — this is what we'll see in Splunk.

- [ ] **Step 2: [Either] After ~30 seconds, query Splunk for the event**

Via the Splunk MCP or Splunk Search & Reporting:

```spl
index=mydfir-project source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*\\notepad.exe"
earliest=-10m
| table _time, host, User, Image, CommandLine, ParentImage
```

**SPL annotation:**
- `index=mydfir-project` — narrow to the project's index.
- `source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"` — restrict to Sysmon's channel. The double-quoted value is required because the channel name contains `:` and `/`.
- `EventCode=1` — Sysmon's Process Create event.
- `Image="*\\notepad.exe"` — match any path ending in `notepad.exe`. The `\\` is the escaped backslash; SPL's path matching uses backslash separators on Windows-sourced events.
- `earliest=-10m` — last 10 minutes (cushion in case of indexing delay).
- `| table _time, host, User, Image, CommandLine, ParentImage` — output a flat table of just the columns we care about. `table` is the simplest output formatter — like `SELECT col1, col2 FROM ...`.

Expected: at least one row, with `_time` matching the spawn time within ~60 seconds, `Image` ending in `notepad.exe`, `CommandLine` showing `notepad.exe` (or full path), `ParentImage` showing whatever launched it (likely the SSH session's host process or `cmd.exe`).

If no rows: indexing is delayed, the stanza didn't load, or field extraction is broken. Diagnostic ladder:
1. Wait 60 more seconds, retry.
2. Drop the `Image=` filter — `... EventCode=1 earliest=-10m | head 5` — to see if any Sysmon events at all are landing.
3. Drop the `EventCode=1` filter — `... earliest=-10m | head 5` — to see if any Sysmon channel events are landing.
4. If even Step 3 returns nothing, Sysmon events aren't reaching Splunk. Check splunkd.log on the forwarder for binding errors; check the Windows Event Log directly to confirm Sysmon is emitting (`Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 3` on the VM).

- [ ] **Step 3: [Claude] If Sysmon events land in Splunk but fields don't extract**

If Step 2 returns rows but `Image`, `CommandLine`, `ParentImage` columns are empty/null while `_raw` clearly contains them — Splunk's Add-on for Microsoft Windows isn't parsing Sysmon's XML. Spec § 2.4's contingency: install **Splunk Add-on for Microsoft Sysmon** (free Splunkbase app).

Steps:
1. Splunk web UI → **Apps → Find More Apps**.
2. Search "Microsoft Sysmon", install the Splunk Add-on for Microsoft Sysmon.
3. Restart Splunk.
4. Retry Step 2's query — fields should now extract.

If extracting works, append to notes.md: "Splunk Add-on for Microsoft Sysmon installed YYYY-MM-DD as field-extraction fallback. ADR 0006 candidate."

- [ ] **Step 4: [Claude] Capture smoke test #1 result in notes.md**

Append under "Tier-1 smoke tests":
- Smoke test #1 (notepad.exe → EventCode=1 in Splunk): PASS, lag = `<seconds>`s, fields extracted correctly. Add-on for Microsoft Sysmon: not needed / installed (delete the wrong option).

- [ ] **Step 5: [Claude] Commit**

```bash
git add vault/subprojects/2026-04-30-detection-foundations/notes.md
git commit -m "test(D1): Tier-1 smoke test #1 PASS - Sysmon events ingesting end-to-end"
```

---

### Task 2.4: Tier-1 smoke test #2 — EventCode coverage check

**Files:** none on disk; observation query.

This produces the baseline distribution of Sysmon EventCodes the SwiftOnSecurity config emits in *our* environment. Useful for any future "why didn't I see X?" debugging.

- [ ] **Step 1: [Either] Generate some baseline activity on the Windows VM**

To make the coverage check meaningful, do something on the VM that exercises multiple event types — e.g., open and close a few apps, ping a host, write a temp file:

```powershell
Start-Process notepad.exe; Start-Sleep 2; Stop-Process -Name notepad
Start-Process calc.exe; Start-Sleep 2; Stop-Process -Name *calc* -ErrorAction SilentlyContinue
Test-NetConnection google.com -Port 443 | Out-Null   # triggers EventCode=22 DNS + 3 NetConnect
"hello" | Out-File C:\Tools\d1-coverage-test.txt    # triggers EventCode=11 file create
Remove-Item C:\Tools\d1-coverage-test.txt           # triggers EventCode=23 file delete
```

- [ ] **Step 2: [Either] Run the coverage query**

```spl
index=mydfir-project source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
earliest=-1h
| stats count by EventCode
| sort -count
```

**SPL annotation:**
- `| stats count by EventCode` — group events by their `EventCode` field, count rows per group. Same shape as a SQL `SELECT EventCode, COUNT(*) ... GROUP BY EventCode`.
- `| sort -count` — sort descending by `count`. The `-` prefix means descending; no prefix means ascending.

Expected: a list of EventCodes with counts. SwiftOnSecurity's config commonly produces:
- 1 (Process Create) — most volume
- 3 (Network Connect) — dependent on activity
- 5 (Process Terminate)
- 11 (File Create)
- 12/13/14 (Registry events)
- 22 (DNS Query)
- 23 (File Delete)

EventCodes 7 (Image Loaded) and 10 (Process Access) may be present but lower volume; the SwiftOnSecurity config filters these aggressively to keep volume manageable.

- [ ] **Step 3: [Claude] Capture the EventCode distribution in notes.md**

Append the actual table from Step 2 under "Tier-1 smoke tests → EventCode coverage". This becomes the baseline for cross-referencing the EventCode reference table in `sysmon.md` (Phase 8).

- [ ] **Step 4: [Claude] Commit**

```bash
git add vault/subprojects/2026-04-30-detection-foundations/notes.md
git commit -m "test(D1): Tier-1 smoke test #2 PASS - EventCode coverage baseline captured"
```

---

## Phase 3 — Install Atomic Red Team

### Task 3.1: Install the `Invoke-AtomicRedTeam` PowerShell module + atomics library

**Files:** ART module installed on the Windows VM; `C:\AtomicRedTeam\atomics\` populated.

- [ ] **Step 1: [Claude] Set the execution policy and run the bootstrap installer**

```powershell
Set-ExecutionPolicy Bypass -Scope CurrentUser -Force
$installer = (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing).Content
Invoke-Expression $installer
Install-AtomicRedTeam -getAtomics -Force
```

Expected: progress output ending with `Atomic Red Team installation complete`. The atomics library (~hundreds of MB of YAML technique definitions) downloads to `C:\AtomicRedTeam\atomics\`.

If the download stalls or 404s, GitHub may be rate-limiting or transiently down — wait a few minutes and retry. The installer is idempotent.

- [ ] **Step 2: [Claude] Verify module loads and the atomics catalog is present**

```powershell
Import-Module Invoke-AtomicRedTeam
Get-Module Invoke-AtomicRedTeam | Format-List Name, Version, Path
Get-ChildItem C:\AtomicRedTeam\atomics\ -Directory | Measure-Object | Select-Object Count
Get-ChildItem C:\AtomicRedTeam\atomics\T1059.001 -ErrorAction SilentlyContinue
```

Expected:
- Module loads with a version string and path under the user's PowerShell modules dir.
- Atomics directory has hundreds of subdirectories (one per T-id).
- `T1059.001` directory exists with at least a `T1059.001.yaml` and a `src/` folder.

- [ ] **Step 3: [Claude] Tier-1 smoke test #3 — preview T1059.001's test catalog**

```powershell
Invoke-AtomicTest T1059.001 -ShowDetailsBrief
```

Expected: a numbered list of test cases for T1059.001. Each line shows the test number, name, and supported platforms. Capture the full output — we'll pick the right test number for the worked example in Phase 4.

The standard T1059.001 catalog has historically included tests like:
- `1` — Mshta JavaScript
- `2` — PowerShell EncodedCommand (the spec's working assumption)
- `3` — PowerShell -Command in batch
- `4` — Obfuscated alternation
- ...

The exact numbering can drift between atomics releases. **Pick the test whose description matches "EncodedCommand" or "encoded command" verbatim.** That's our worked-example test number.

- [ ] **Step 4: [Claude] Capture chosen test number in notes.md**

Append under "Phase 3 captures":
- Module Invoke-AtomicRedTeam version: `<version>`.
- Atomics root: `C:\AtomicRedTeam\atomics\` (technique count: `<n>`).
- Chosen T1059.001 test number: `<N>` — name: `<exact name from -ShowDetailsBrief>`.
- This is the test the saved search and live-fire will use.

- [ ] **Step 5: [Claude] Commit**

```bash
git add vault/subprojects/2026-04-30-detection-foundations/notes.md
git commit -m "feat(D1): ART installed; T1059.001 worked-example test number captured"
```

---

## Phase 4 — Develop the SPL detection for T1059.001

The spec gives the final SPL (§ 2.5). This phase is about **building it iteratively against a real ART event** so the user (currently learning SPL) sees each clause's effect, and so the final SPL is verified to actually match real data — not just compile.

### Task 4.1: Generate one real T1059.001 event for SPL development

**Files:** none on disk; live event generation.

- [ ] **Step 1: [User] Take a VMware snapshot of the Windows VM before the first ART run**

The runbook will eventually mandate a snapshot before every ART session. Get the discipline started here.

VMware Workstation: right-click VM → Snapshot → Take Snapshot. Name: `D1 pre-T1059.001 first run`. Description: `Snapshot taken for SPL development run; ART has never executed before.`

- [ ] **Step 2: [Claude] Run the chosen T1059.001 test once (no -Cleanup yet — we want the event to persist)**

```powershell
Invoke-AtomicTest T1059.001 -TestNumbers <CHOSEN-N-FROM-3.1>
```

Expected: a few lines of output indicating the test launched `powershell.exe -EncodedCommand <base64>`. The encoded payload typically decodes to a benign command like `Write-Host "Hi"`.

If the test prompts for input (some ART tests do) — answer with the default. Capture the exact PowerShell process's PID if shown.

- [ ] **Step 3: [Either] Confirm the EventCode=1 landed in Splunk**

```spl
index=mydfir-project source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*\\powershell.exe" CommandLine="*EncodedCommand*"
earliest=-15m
| table _time, host, User, Image, CommandLine, ParentImage, ParentCommandLine
```

Expected: at least one row with `CommandLine` containing the full `powershell.exe -EncodedCommand <base64-blob>` and `ParentImage` showing the ART runner's process (typically `powershell.exe` or `pwsh.exe` from the ART invocation).

If no rows: cross-check against the unfiltered query `... EventCode=1 earliest=-15m | head 20` to find where the `powershell.exe -EncodedCommand` event went. The `Image=` filter requires the path to end in `powershell.exe`; if the test invoked PowerShell via `-FilePath` from a different location, the filter may miss. Capture the actual `Image` value seen and update the SPL filter accordingly.

- [ ] **Step 4: [Claude] Capture the real event's field values in notes.md**

Append under "Phase 4 — SPL development":
- T1059.001 test `<N>` ran YYYY-MM-DD HH:MM.
- One Sysmon EventCode=1 captured in Splunk.
- Real-event fields:
  - Image: `<actual value>`
  - CommandLine: `<actual value, truncated if >200 chars>`
  - ParentImage: `<actual value>`
  - User: `<actual value>`

This is the data we're writing the SPL against.

- [ ] **Step 5: [Claude] Commit**

```bash
git add vault/subprojects/2026-04-30-detection-foundations/notes.md
git commit -m "test(D1): T1059.001 dev event generated and captured for SPL iteration"
```

---

### Task 4.2: Build the SPL one clause at a time

**Files:** none on disk; iterative SPL development in Splunk Search & Reporting.

This is the SPL-learning task. Each step adds one clause and shows the effect. The final SPL matches spec § 2.5.

- [ ] **Step 1: [Either] Start with the broadest reasonable filter**

In Splunk Search & Reporting:

```spl
index=mydfir-project source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*\\powershell.exe"
earliest=-15m
```

Expected: the dev event from Task 4.1 plus any other recent powershell.exe spawns (could be many — Windows uses PowerShell internally for various tasks). Note the count.

**SPL annotation (for the user):** four filter clauses, each ANDed implicitly (no `AND` keyword needed — adjacent terms in the search bar AND together).

- [ ] **Step 2: [Either] Add the encoded-command flag-match using `regex`**

```spl
index=mydfir-project source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*\\powershell.exe"
earliest=-15m
| regex CommandLine="(?i)\s-e[ncodedommand]*\s"
```

**SPL annotation:**
- `| regex CommandLine="..."` — the `regex` command filters events whose `CommandLine` field matches the regular expression. Stricter than `CommandLine="*-enc*"` because it anchors on PowerShell's actual flag syntax (whitespace boundaries; not embedded substrings).
- `(?i)` — inline regex flag for case-insensitive matching. PowerShell's parser is case-insensitive for flag names.
- `\s` (the whitespace boundary) — ensures we match `-enc` as a flag preceded and followed by whitespace, not as a substring of `--encoding-like-something-else`.
- `-(en?c|encodedcommand)` — alternation. `en?c` = `e` + optional `n` + `c` → matches `-ec`, `-enc`. `|encodedcommand` adds the long form. Combined: `-ec`, `-enc`, `-encodedcommand` (case-insensitive), with whitespace boundaries.

Expected: count drops sharply — the dev event survives, most innocuous Windows-internal PowerShell invocations are filtered out.

- [ ] **Step 3: [Either] Add the stats aggregation**

```spl
index=mydfir-project source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*\\powershell.exe"
earliest=-15m
| regex CommandLine="(?i)\s-e[ncodedommand]*\s"
| stats count, values(CommandLine) as command_lines, values(ParentImage) as parents
        by _time, host, User, Image
```

**SPL annotation:**
- `stats` is the aggregation command — like SQL's `SELECT ... GROUP BY ...`.
- `count` — number of input rows in each group. (No alias = output column is named `count`.)
- `values(CommandLine) as command_lines` — collect the *unique* values of `CommandLine` from each group into a multi-value field aliased `command_lines`. Useful when the same alert key may have multiple distinct CommandLines.
- `values(ParentImage) as parents` — same for parent process. **`ParentImage` is the high-signal column** for triage — `winword.exe` or `outlook.exe` parents would scream "phishing macro launched PowerShell"; `cmd.exe` from an admin user is benign.
- `by _time, host, User, Image` — group by (timestamp + host + user + image path). Each unique combination becomes one output row.

Expected: one row per unique (`_time`, `host`, `User`, `Image`) combination — typically just one row from the dev event. `command_lines` shows the encoded-command CommandLine; `parents` shows the ART runner.

- [ ] **Step 4: [Either] Sanity-check the SPL across `Last 24 hours`**

Change the time range in Splunk Search & Reporting from `Last 15 minutes` to `Last 24 hours`. Re-run the SPL.

Expected: still one row (or however many T1059.001 dev runs you've done). If the count balloons unexpectedly, there's some other PowerShell-encoded-command activity in the last 24 hours — investigate before saving the search (a noisy detection is a useless detection).

- [ ] **Step 5: [Claude] Save the final SPL to notes.md**

Append under "Phase 4 — SPL development":
- Final SPL (paste exact text used in Step 4).
- Test result: `<N>` rows over `<window>`, all attributable to dev runs.
- Approved for use in the Phase 5 saved search.

- [ ] **Step 6: [Claude] Commit**

```bash
git add vault/subprojects/2026-04-30-detection-foundations/notes.md
git commit -m "feat(D1): T1059.001 SPL detection iterated and verified against real event"
```

---

## Phase 5 — Create the Splunk saved search

### Task 5.1: Capture the v2 production webhook URL

**Files:** none on disk; secrets lookup.

The spec § 2.6 documents the webhook URL as `http://192.168.129.132:5678/webhook/db7245f7-8451-4bea-b47d-f6ad35b818cd` (the existing v2 production URL). Confirm this is still current — A2 may have rotated it during cutover.

- [ ] **Step 1: [Claude] Look up the v2 webhook URL**

Check the A2 runbook for the cutover state. The runbook documents the production webhook URL.

```bash
grep -i "webhook" vault/subprojects/2026-04-28-iris-escalation-gate/runbook.md | head -10
```

If not found there, check the workflow JSON:

```bash
grep -i 'webhook' JSON/SOC-Triage-v2.json | grep -i 'path\|url' | head -5
```

Expected: a path like `db7245f7-8451-4bea-b47d-f6ad35b818cd`. Combine with `http://192.168.129.132:5678/webhook/` for the production URL.

- [ ] **Step 2: [Claude] Capture the URL in notes.md**

Append under "Phase 5 — saved search":
- v2 production webhook URL: `http://192.168.129.132:5678/webhook/<path>`
- Confirmed against: `<source — runbook or JSON>`.
- Date of capture: YYYY-MM-DD.

This URL is what the saved search's webhook alert action will POST to.

- [ ] **Step 3: [Claude] Commit**

```bash
git add vault/subprojects/2026-04-30-detection-foundations/notes.md
git commit -m "docs(D1): v2 production webhook URL confirmed for saved search wiring"
```

---

### Task 5.2: Create the saved search in the Splunk web UI

**Files:** none on disk; Splunk web UI work.

- [ ] **Step 1: [User] Open the Splunk web UI and start a new alert**

Browser → http://192.168.129.131:8000 → log in as `mydfir`.

Navigate: **Search & Reporting → Search bar**. Paste the final SPL from Task 4.2 Step 5. Run it once over `Last 24 hours` to confirm it returns rows (one or more — the dev events from Phase 4).

Then: **Save As → Alert** (top right).

- [ ] **Step 2: [User] Configure the alert (Settings tab)**

| Field | Value | Why |
|---|---|---|
| Title | `T1059.001 - PowerShell Encoded Command` | Spec § 2.6; matches the search-name the n8n workflow's `Extract Triage Result` Code node will see |
| Description | `Sysmon EventCode=1 + powershell.exe + -EncodedCommand flag (or short forms). Worked example for D1 detection foundations.` | Self-documenting |
| Permissions | `Shared in App` | Same as existing brute-force search |
| Alert type | `Scheduled` | Not real-time |
| Time Range | `Last 24 hours` | Matches existing brute-force search; dedup by result-row hash handles repeat-fires |
| Cron Expression | `*/5 * * * *` | Standard SOC cadence (every 5 min); spec § 2.6 |
| Expires | `24 hour(s)` | Triggered Alerts dashboard retention |

- [ ] **Step 3: [User] Configure the alert (Trigger tab)**

| Field | Value |
|---|---|
| Trigger alert when | `Number of Results` `is greater than` `0` |
| Trigger | `For each result` |
| Throttle | (unchecked) |

**Why "For each result":** Splunk emits one webhook POST per result row, with the row in the payload. With "Once" trigger, the analyst gets a single notification with all rows — fine for dashboards, awkward for SOAR pipelines that want one alert per detection. Plus "For each result" is the trigger A2's Test 1 path was validated against.

**Why no throttle:** Splunk's "For each result" already dedupes by row content hash — repeated cron ticks against the same window won't re-fire if the row is identical. Adding throttle would suppress legitimate distinct events that happen close together.

- [ ] **Step 4: [User] Add the trigger actions**

Click **+ Add Actions** twice — add **Webhook** and **Add to Triggered Alerts**.

| Action | Field | Value |
|---|---|---|
| Webhook | URL | `<v2 production URL from Task 5.1>` |
| Add to Triggered Alerts | Severity | `5 - Severe` (mirrors brute-force search) |

Click **Save**.

- [ ] **Step 5: [User] Verify the saved search appears in the alert list**

Navigate: **Settings → Searches, reports, and alerts → mydfir-project app**.

Expected: a row for `T1059.001 - PowerShell Encoded Command`, status `Enabled`, schedule `*/5 * * * *`. Click the title to confirm all settings persisted (Time Range, Trigger, Trigger Actions).

- [ ] **Step 6: [Claude] Capture the saved-search creation in notes.md**

Append:
- Saved search `T1059.001 - PowerShell Encoded Command` created YYYY-MM-DD HH:MM.
- All settings per Task 5.2 Step 2/3/4.
- Webhook URL: `<v2 URL>`.
- Verified in Settings → Searches, reports, and alerts.

- [ ] **Step 7: [Claude] Commit**

```bash
git add vault/subprojects/2026-04-30-detection-foundations/notes.md
git commit -m "feat(D1): Splunk saved search created (T1059.001 - PowerShell Encoded Command)"
```

---

## Phase 6 — Live-fire validation (Tier-2 worked example)

This is the integration test that proves the existing SOAR pipeline accepts a Sysmon-shaped alert without n8n changes.

### Task 6.1: Pre-flight for the live-fire run

**Files:** none on disk; environmental check.

- [ ] **Step 1: [User] Take a fresh VMware snapshot**

VMware Workstation: right-click Windows 10 VM → Snapshot → Take Snapshot. Name: `D1 pre-live-fire`. Description: `Snapshot before live-fire T1059.001 run that exercises the full SOAR pipeline.`

- [ ] **Step 2: [User] Open three browser tabs side-by-side for observation**

1. **Splunk** — http://192.168.129.131:8000 — Search & Reporting tab open with the SPL ready to run.
2. **n8n executions** — http://192.168.129.132:5678 → Executions tab. This is where we'll watch the workflow run.
3. **Slack** — `#alerts` channel. This is where the final post lands.

Iris (https://192.168.129.133/alerts) — also useful as a fourth tab, but Slack post + n8n executions tell us most of what we need.

- [ ] **Step 3: [Either] Confirm the saved search is enabled and on schedule**

```spl
| rest /servicesNS/-/-/saved/searches
| search title="T1059.001 - PowerShell Encoded Command"
| table title, disabled, cron_schedule, dispatch.earliest_time, action.webhook.param.url
```

Expected: `disabled=0`, cron `*/5 * * * *`, webhook URL matches Task 5.1's value.

- [ ] **Step 4: [Claude] Note the wall-clock time of the next expected cron tick**

Cron `*/5 * * * *` fires at HH:00, HH:05, HH:10, ... Note when the next tick is from now. The ART run should happen ≥1 minute before the next tick to give Splunk time to index.

---

### Task 6.2: Run T1059.001 and observe the pipeline end-to-end

**Files:** none on disk; live test.

- [ ] **Step 1: [Claude] Run the chosen T1059.001 test**

```powershell
Import-Module Invoke-AtomicRedTeam
Invoke-AtomicTest T1059.001 -TestNumbers <N>
```

Note the wall-clock timestamp.

- [ ] **Step 2: [Either] Confirm Splunk received the event within 60 seconds**

```spl
index=mydfir-project source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*\\powershell.exe" CommandLine="*EncodedCommand*"
earliest=-5m
| table _time, host, User, Image, CommandLine, ParentImage
```

Expected: one row from this run (plus older dev runs if Last 24 hours is in scope).

- [ ] **Step 3: [User] Wait for the next cron tick and watch the n8n Executions tab**

Within `<= 5 minutes`, a new execution of the SOC Triage v2 workflow should appear. Click it — verify:
1. **Webhook node** input shows the saved search's payload (`result`, `search_name`, `results_link`, etc.).
2. **Anthropic node** completes with a `submit_triage_result` tool call (severity, iocs_enriched, summary).
3. **Extract Triage Result Code node** completes; output includes `alert_iocs` array (likely empty for Outcome A).
4. **Create Iris Alert node** completes with HTTP 200; alert_id present in output.
5. **Has Malicious IOCs? IF node** — check which branch it took. FALSE = Outcome A (gate-skipped, expected). TRUE = Outcome B (gated, acceptable bonus).
6. **Outcome A path:** Slack `Post Slack Alert (plain)` node completes; END.
7. **Outcome B path:** Slack `Post Approval Request` node + Wait node; user must Approve/Deny in Slack.

Capture the n8n execution ID for notes.md.

- [ ] **Step 3a: [User] Capture the exact webhook payload schema from the Webhook node**

Spec Open Q4: confirm the JSON envelope Splunk POSTs for Sysmon-shaped rows matches the brute-force-search envelope shape A1/A2 validated against. In the n8n execution, click the **Webhook** node → **Output** tab → expand the JSON object. Copy the top-level keys (e.g., `result`, `search_name`, `results_link`, `app`, `owner`, `sid`) and any nested keys under `result`.

Append to notes.md under "Phase 6 — webhook payload schema":

```
Top-level keys: <list>
result.* keys for Sysmon T1059.001 row: <list>
```

Compare against the brute-force search's envelope (per A1/A2 notes). Differences should be limited to the **inner `result` object** (different SPL = different result fields); the **envelope** (`result`, `search_name`, `results_link`, etc.) should be identical. If the envelope differs, that's the integration risk the spec flagged — diagnose and reconcile before declaring Phase 6 complete.

- [ ] **Step 4: [User] Verify the Iris alert was created**

Navigate: https://192.168.129.133/alerts. The most recent alert should be titled `T1059.001 - PowerShell Encoded Command` with severity per Claude's triage. Capture the alert ID.

`alert_iocs` tab content: empty (Outcome A) or one IOC (Outcome B).

- [ ] **Step 5: [User] Verify Slack `#alerts` received the post**

For Outcome A: a plain alert message (no buttons). Title, severity, summary, "View in Splunk" link.

For Outcome B: an Approve/Deny gate message. **Click Deny** (this is a known test event; we don't need an Iris case from it). The thread should get a "Decision: Deny" reply.

- [ ] **Step 5a: [Either] Capture the `Hashes` field shape under SwiftOnSecurity**

Spec Open Q5 — record actual behavior for the catalog page.

```spl
index=mydfir-project source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*\\powershell.exe" CommandLine="*EncodedCommand*"
earliest=-30m
| table _time, Hashes
| head 1
```

Append the value (e.g., `MD5=...,SHA256=...,IMPHASH=...` or `(empty)`) to notes.md under "Phase 6 — Hashes field observation". Task 7.3's worked-example page already mentions "`Hashes` populated per SwiftOnSecurity's `<HashAlgorithms>` block" — confirm or correct that statement based on this capture.

- [ ] **Step 6: [User] Run cleanup**

```powershell
Invoke-AtomicTest T1059.001 -TestNumbers <N> -Cleanup
```

Hold off on snapshot revert until **after** Task 6.4 (dedup verification needs the same VM state). Revert only if cleanup leaves residue (encoded PowerShell tests typically have nothing to clean up beyond the process exit).

- [ ] **Step 7: [Claude] Capture the live-fire result in notes.md**

Append under "Phase 6 — Tier-2 live-fire":
- ART invocation: `Invoke-AtomicTest T1059.001 -TestNumbers <N>` at YYYY-MM-DD HH:MM.
- Splunk indexing lag: `<seconds>`s.
- n8n execution ID: `<id>`.
- Cron-to-fire delay: `<seconds>`s.
- Iris alert ID: `<id>`, severity `<value>`.
- alert_iocs count: `<0 or N>`.
- Outcome: **A** (gate-skipped) or **B** (gated, Approve/Deny — chose `<Deny>`).
- Slack post: confirmed in `#alerts` (plain / approve-deny).
- Workflow result: completed within timeout.

- [ ] **Step 8: [Claude] Commit**

```bash
git add vault/subprojects/2026-04-30-detection-foundations/notes.md
git commit -m "test(D1): Tier-2 live-fire PASS - T1059.001 traced end-to-end through SOAR pipeline"
```

---

### Task 6.3: Outcome-handling — what to do depending on Outcome A vs B

**Files:** none on disk; decision branch.

- [ ] **Step 1: [Claude] If Outcome A occurred (expected): no further action**

Move to Phase 7. The architectural promise (Sysmon-shaped alert traverses A2's Test 1 path on real production traffic) is validated.

- [ ] **Step 2: [Claude] If Outcome B occurred (acceptable variance)**

Capture *what* Claude pulled out as an IOC and what its `ioc_type` was. This is interesting data for D1.5 hook (AI base64-decoding) and for the runbook's "live-fire validation" section, which will document Outcome B as an acceptable variance per spec § 6.5.

Append to notes.md:
- Outcome B: Claude extracted `<value>` as `ioc_type=<type>` from `<source field>`.
- Gate fired; Approve/Deny chosen: `<Deny per Phase 6 Step 5>`.
- Variance accepted per spec § 6.5; runbook's validation section will note this.

- [ ] **Step 3: [Claude] If neither outcome occurred — pipeline failure**

If the n8n execution failed (e.g., `Extract Triage Result` threw, or Iris alert creation got non-200, or Claude returned malformed) — diagnose and pause. The standby fix from spec § 2.7 is the system-prompt addendum; the runbook will document it. But don't apply the addendum unless the live-fire actually requires it. Document the failure in notes.md and consult the user on next steps.

- [ ] **Step 4: [Claude] No commit (Phase 6 closed in Task 6.2 Step 8). Outcome A or B is captured there.**

---

### Task 6.4: Verify "For each result" dedup across two ART runs

**Files:** none on disk; verification.

Spec Open Q9 (resolved 2026-04-30): "Phase 0 still observes the live-fire behavior (run ART twice with a 6+ minute gap, confirm two distinct webhooks land) to confirm dedup works for Sysmon-shaped result rows the same way it does for brute-force-shaped result rows." This task does that verification.

- [ ] **Step 1: [Claude] Wait at least 6 minutes after the Task 6.2 ART run**

The 24-hour Time Range means the saved search "sees" the same result row across cron ticks. Splunk's "For each result" dedupes by content hash. For two distinct webhooks to land, the **`_time` value of the result row must differ** — which means the second ART run needs to produce a Sysmon EventCode=1 with a different `_time` than the first. 6 minutes is a generous gap (the cron is `*/5`, so 6 minutes guarantees one tick between).

```bash
# Note the wall-clock time of the first run from Task 6.2 Step 1
# Wait until current time >= first-run-time + 6 minutes before Step 2
```

- [ ] **Step 2: [Claude] Run T1059.001 a second time**

```powershell
Invoke-AtomicTest T1059.001 -TestNumbers <N>
```

Note the wall-clock timestamp.

- [ ] **Step 3: [User] Wait for the next cron tick (≤5 min) and confirm a second n8n execution appeared**

n8n Executions tab → expect a new row, distinct from the Task 6.2 Step 3 execution. Click into it — verify it's a separate execution (different ID), with a `result._time` value distinct from the first execution.

If only **one** execution appears — dedup is over-collapsing. Diagnostic ladder:
1. Confirm both Sysmon events landed in Splunk with distinct `_time`s:
   ```spl
   index=mydfir-project source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
   EventCode=1 Image="*\\powershell.exe" CommandLine="*EncodedCommand*"
   earliest=-15m | table _time, CommandLine | sort -_time
   ```
   Expected: two rows.
2. If two rows → Splunk's saved-search hash dedup over-aggregated. Workaround: narrow the saved search's Time Range from `Last 24 hours` to `Last 5 minutes` (matches cron interval). Spec § Risks calls this out as the contingency.

If **two** executions appear with distinct content — dedup works correctly for Sysmon-shaped rows. ✓

- [ ] **Step 4: [Claude] Capture dedup verification result in notes.md**

Append under "Phase 6 — dedup verification":
- Two ART runs at YYYY-MM-DD HH:MM and YYYY-MM-DD HH:MM (gap: `<minutes>`min).
- n8n executions: two distinct IDs `<id1>`, `<id2>`. Result `_time` values: `<t1>`, `<t2>`.
- Conclusion: "For each result" dedup behaves correctly for Sysmon-shaped rows / over-aggregates and required Time Range narrowing (delete the wrong line).

- [ ] **Step 5: [Claude] Run cleanup for both runs**

```powershell
Invoke-AtomicTest T1059.001 -TestNumbers <N> -Cleanup
```

- [ ] **Step 6: [Claude] Commit**

```bash
git add vault/subprojects/2026-04-30-detection-foundations/notes.md
git commit -m "test(D1): dedup verification PASS - two ART runs produced two distinct webhooks"
```

---

## Phase 7 — Seed the `vault/detections/` catalog

### Task 7.1: Create the `vault/detections/` directory + template

**Files:**
- Create: `vault/detections/_template.md`

- [ ] **Step 1: [Claude] Create the directory and write the template**

The template is a copy-this skeleton for adding a new technique. Spec § 2.8 specifies the structure.

```bash
mkdir -p vault/detections
```

Then write `vault/detections/_template.md`:

```markdown
---
status: untested
technique_id: T<id>
tactic: <Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact>
last_run: YYYY-MM-DD
related: [[../subprojects/2026-04-30-detection-foundations/runbook]], [[../architecture/components/sysmon]]
---

# T<id> — <name>

## Description

<one paragraph: what the technique is, what it looks like in practice, why it matters in a SOC context>

## ART command

```powershell
Import-Module Invoke-AtomicRedTeam
Invoke-AtomicTest T<id> -ShowDetailsBrief                 # preview the test catalog
Invoke-AtomicTest T<id> -TestNumbers <N>                  # execute test N
Invoke-AtomicTest T<id> -TestNumbers <N> -Cleanup         # cleanup after
```

## Observations

<Sysmon EventCodes seen, fields populated, surprises. Update on each run. Lifecycle status moves from `untested` → `observed` → `spl-drafted` → `saved-search-active` as work progresses.>

## SPL

```spl
(none yet)
```

## Saved search

(none yet) — will list name, cron, webhook target when one is created.

## Notes

<false positives, parent-process patterns, tuning observations, references to ATT&CK, Sigma rules, etc.>
```

- [ ] **Step 2: [Claude] Commit**

```bash
git add vault/detections/_template.md
git commit -m "feat(D1): seed vault/detections/ with per-technique template"
```

---

### Task 7.2: Create the coverage-index README

**Files:**
- Create: `vault/detections/README.md`

- [ ] **Step 1: [Claude] Write the index page**

```markdown
---
status: active
updated: 2026-04-30
related: [[_template]], [[../architecture/components/sysmon]], [[../subprojects/2026-04-30-detection-foundations/runbook]]
---

# Detections — coverage index

Per-MITRE-technique catalog of detection content in this lab. Each entry tracks one technique through its lifecycle: `untested` (no evidence yet) → `observed` (ART run, Sysmon captured something) → `spl-drafted` (SPL exists in the page) → `saved-search-active` (Splunk saved search firing the v2 webhook).

To add a technique: copy `_template.md` to `t<id>-<short-name>.md`, populate, link from the table below. See [[../subprojects/2026-04-30-detection-foundations/runbook]] for the operational "run a technique" loop.

## Coverage

| Technique ID | Tactic | Status | Last Run | Page |
|---|---|---|---|---|
| T1059.001 | Execution | saved-search-active | 2026-04-30 | [[t1059-001-powershell-encoded]] |

## Status lifecycle

- **untested** — page exists as a placeholder; no ART run yet, no Sysmon evidence.
- **observed** — ART has been run; Sysmon captured events; observations recorded in the page.
- **spl-drafted** — a hand-written SPL exists in the page that detects the technique against a real ART event.
- **saved-search-active** — a Splunk saved search wraps the SPL and fires the v2 production webhook on a 5-minute cron.

The lifecycle is monotonic for any one technique — pages move forward, not back, unless a saved search is intentionally retired (which becomes its own log entry).

## See also

- [[../architecture/components/sysmon]] — Sysmon EventCode + field reference; install metadata.
- [[../architecture/components/splunk]] — Splunk saved-search inventory and configuration.
- [[../subprojects/2026-04-30-detection-foundations/runbook]] — operational procedure for running a technique and updating its catalog page.
- MITRE ATT&CK matrix: https://attack.mitre.org/matrices/enterprise/
```

- [ ] **Step 2: [Claude] Commit**

```bash
git add vault/detections/README.md
git commit -m "feat(D1): vault/detections/ coverage index page"
```

---

### Task 7.3: Create the worked-example page for T1059.001

**Files:**
- Create: `vault/detections/t1059-001-powershell-encoded.md`

This is the populated worked example. Status starts at `saved-search-active` (we've already done all phases by the time we write this — the page is final form).

- [ ] **Step 1: [Claude] Write the worked-example page**

```markdown
---
status: saved-search-active
technique_id: T1059.001
tactic: Execution
last_run: 2026-04-30
related: [[../subprojects/2026-04-30-detection-foundations/runbook]], [[../architecture/components/sysmon]], [[../architecture/components/splunk]]
---

# T1059.001 — Command and Scripting Interpreter: PowerShell

## Description

T1059.001 is MITRE ATT&CK's sub-technique for adversary use of PowerShell as a scripting interpreter. The variant exercised here is **PowerShell with `-EncodedCommand`** (also abbreviatable `-e`, `-en`, `-enc`), which takes a UTF-16LE-base64-encoded command-line. Attackers use it to obfuscate malicious payloads through several layers (logs show base64 instead of clear-text) and to bypass simple substring-based detections. SwiftOnSecurity's Sysmon config captures the full CommandLine including the encoded blob, which is what makes this detectable end-to-end.

## ART command

```powershell
Import-Module Invoke-AtomicRedTeam
Invoke-AtomicTest T1059.001 -ShowDetailsBrief                 # preview catalog
Invoke-AtomicTest T1059.001 -TestNumbers <N>                  # execute (N captured during D1 install — see notes.md)
Invoke-AtomicTest T1059.001 -TestNumbers <N> -Cleanup         # cleanup after
```

## Observations

First run 2026-04-30 produced one Sysmon EventCode=1 (Process Create) with:
- `Image` ending in `powershell.exe` (full path varies by OS bitness).
- `CommandLine` containing literal `-EncodedCommand <base64>` substring.
- `ParentImage` = the ART runner's PowerShell process.
- `User` = the local admin account ART ran as.
- `Hashes` populated per SwiftOnSecurity's `<HashAlgorithms>` block.

Splunk indexing lag observed: ~`<value from notes.md>` seconds.

Saved-search-to-fire delay: bounded by the 5-minute cron tick. Worst case ~5 minutes; typical ~150 seconds.

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
| `source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"` | Restricts to Sysmon's channel. Excludes Windows Security/App/System events landing in the same index/sourcetype. |
| `EventCode=1` | Sysmon's Process Create event. |
| `Image="*\\powershell.exe"` | Match any path ending in `powershell.exe`. `\\` escapes the backslash. |
| `\| regex CommandLine="..."` | Filter rows whose `CommandLine` matches a regex. Stricter than wildcard match. |
| `(?i)` | Case-insensitive flag. |
| `\s-e[ncodedommand]*\s` | Whitespace-bounded match for `-e` followed by zero or more letters from `{n,c,o,d,e,m,a}`. Catches PowerShell's prefix-shortenings of `-EncodedCommand` (`-e`, `-en`, `-enc`, `-encod`, `-encodedcommand`, etc.) while rejecting unrelated flag-shaped fragments like `-eq` (q is not in the alphabet). |
| `\| stats count, values(CommandLine) as command_lines, values(ParentImage) as parents by _time, host, User, Image` | Aggregate to one row per (timestamp, host, user, image), counting hits and collecting unique CommandLines + parents per group. |

**ParentImage is the high-signal column for triage** — `winword.exe` or `outlook.exe` parents indicate phishing-macro-launched PowerShell; `cmd.exe` from an admin user is benign.

## Saved search

| Field | Value |
|---|---|
| Name | `T1059.001 - PowerShell Encoded Command` |
| App | `mydfir-project` (Search & Reporting) |
| Time Range | `Last 24 hours` |
| Cron | `*/5 * * * *` (every 5 minutes; standard SOC cadence) |
| Trigger | `For each result`, threshold `> 0` |
| Throttle | none |
| Trigger Actions | Webhook + Add to Triggered Alerts |
| Webhook URL | v2 production URL (see [[../architecture/components/n8n]] / D1 notes.md) |
| Outcome (live-fire 2026-04-30) | A (gate-skipped) / B (gated) — see notes.md for which |

## Notes

- The 24-hour Time Range with 5-minute cron does not duplicate-fire because Splunk's "For each result" trigger dedupes by result-row content hash across cron ticks.
- False positives in our environment so far: zero (the only matches are intentional ART runs).
- If Claude misbehaves on the Sysmon-shaped payload (returns a malformed triage), the standby fix is the one-paragraph system-prompt addendum documented in [[../subprojects/2026-04-30-detection-foundations/runbook]] — *reactive only*; not applied by default.
- Decoding the base64 payload is **not** done in SPL. If Claude decodes it during n8n triage and pulls IOCs out (Outcome B), the gate fires and the page's status stays `saved-search-active` regardless.
- ATT&CK reference: https://attack.mitre.org/techniques/T1059/001/
```

- [ ] **Step 2: [Claude] Backfill the `<N>` placeholder and "Outcome" line with the actual values from notes.md**

The page should not contain placeholders by D1 closeout. Replace:
- `<N>` (3 occurrences in the ART command block) with the actual test number captured in Task 3.1 Step 4.
- `<value from notes.md>` (Splunk indexing lag) with the actual seconds captured in Task 6.2 Step 7.
- `A (gate-skipped) / B (gated) — see notes.md for which` with whichever outcome actually occurred.

- [ ] **Step 3: [Claude] Commit**

```bash
git add vault/detections/t1059-001-powershell-encoded.md
git commit -m "feat(D1): worked-example detection page for T1059.001 populated"
```

---

### Task 7.4: Update `vault/CLAUDE.md` schema table

**Files:**
- Modify: `vault/CLAUDE.md`

- [ ] **Step 1: [Claude] Add the `vault/detections/` row**

Find the "Where to find what" markdown table in `vault/CLAUDE.md` (currently has rows for sub-projects, current-state, components, decisions, runbooks, log, index, transcripts, session-notes).

Insert a new row immediately after the `runbooks/` row:

```markdown
| Per-MITRE-technique detection content | `detections/` (one page per T-id; `_template.md` to add new) |
```

- [ ] **Step 2: [Claude] Verify the table renders cleanly**

```bash
grep -A 1 -B 1 "detections" vault/CLAUDE.md
```

Expected: row appears in the table without breaking column alignment.

- [ ] **Step 3: [Claude] Commit**

```bash
git add vault/CLAUDE.md
git commit -m "docs(D1): add vault/detections/ to vault schema table"
```

---

## Phase 8 — Component pages: `sysmon.md` (new) + `splunk.md` (modify)

### Task 8.1: Create `vault/architecture/components/sysmon.md`

**Files:**
- Create: `vault/architecture/components/sysmon.md`

Spec § 2.10 specifies the structure. This is the long-lived reference page; it gets re-read in every future Sysmon-touching session, so keep it tight and fact-dense.

- [ ] **Step 1: [Claude] Write the component page**

```markdown
---
status: active
updated: 2026-04-30
sub_project: D1
related: [[../current-state]], [[splunk]], [[../../subprojects/2026-04-30-detection-foundations/runbook]]
---

# Sysmon

## What it is

[Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) is Sysinternals' Windows system service that logs detailed process / file / network / registry telemetry to a dedicated Windows Event Log channel. It supplements (does not replace) the native Security / Application / System logs. In a SOC, Sysmon is the de-facto endpoint-telemetry fabric for Windows hosts that don't have a full EDR.

## Where it runs

| | |
|---|---|
| Host | Windows 10 VM (192.168.129.x — see [[../current-state]]) |
| Service name | `Sysmon64` |
| Channel | `Microsoft-Windows-Sysmon/Operational` |
| Forwarder | Existing Splunk Universal Forwarder (config edited in D1) |
| Splunk index | `mydfir-project` |
| Splunk sourcetype | `XmlWinEventLog` (shared with Security/App/System) |
| Splunk source filter | `source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"` |

## Configuration

| | |
|---|---|
| Config source | [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) (`master` branch) |
| Config file | `sysmonconfig-export.xml` (off-the-shelf — **no edits**) |
| Config commit SHA | `<from Task 1.1 Step 2>` |
| Config file SHA256 | `<from Task 1.1 Step 3>` |
| Sysmon binary version | `<from Task 1.2 Step 2>` |
| Hash algorithms | Per the config's `<HashAlgorithms>` block (typically MD5, SHA256, IMPHASH) |
| Install command | `Sysmon64.exe -accepteula -i sysmonconfig-export.xml` |
| Install date | 2026-04-30 |

D1 mandate: no edits to the SwiftOnSecurity XML. Tuning is post-D1, driven by observed lab volume.

## EventCode reference

High-yield codes the SwiftOnSecurity config emits in this lab (the full Sysmon catalog is larger; this is the analyst's working set):

| EventCode | Name | When it fires |
|---|---|---|
| 1 | Process Create | A new process is launched. Highest-volume code; the headline event. |
| 3 | Network Connect | A process initiates a network connection. |
| 5 | Process Terminate | A process exits. |
| 7 | Image Loaded | A DLL or driver is loaded into a process. (Filtered aggressively by SwiftOnSecurity.) |
| 10 | Process Access | A process opens a handle into another process. **The LSASS pivot** for credential dumping detection. |
| 11 | File Create | A file is written to disk. |
| 12 / 13 / 14 | Registry events | Registry key created (12) / value set (13) / key renamed (14). |
| 17 / 18 | Pipe events | Named pipe created (17) / connected (18). Useful for lateral-movement detection. |
| 22 | DNS Query | A DNS lookup is performed. |
| 23 | File Delete | A file is deleted. |

EventCode coverage in our lab as of 2026-04-30 (from D1 Tier-1 smoke test #2): see [[../../subprojects/2026-04-30-detection-foundations/notes]].

## Field reference

High-frequency Sysmon fields the SwiftOnSecurity config populates and Splunk Add-on for Microsoft Windows extracts:

| Field | Meaning |
|---|---|
| `_time` | Splunk-assigned event timestamp (parsed from Sysmon's UTC stamp). |
| `EventCode` | The Sysmon event type (1, 3, 7, ...). |
| `host` | The Windows host the event originated from. |
| `User` | Account context the process ran under (e.g., `WIN10VM\admin`). |
| `Image` | Full path to the executable. |
| `CommandLine` | Command-line string the process was invoked with. |
| `ParentImage` | Full path to the parent process's executable. |
| `ParentCommandLine` | Parent process's command line. |
| `ProcessId` / `ParentProcessId` | PIDs. |
| `Hashes` | MD5 / SHA1 / SHA256 / IMPHASH of the executable, per `<HashAlgorithms>` in the config. |
| `TargetFilename` | (EventCode 11/23) the file path being created or deleted. |
| `TargetObject` | (EventCode 12/13/14) the registry key or value path. |
| `QueryName` | (EventCode 22) the DNS name being looked up. |
| `QueryStatus` | (EventCode 22) the DNS resolver result code. |
| `DestinationIp` / `DestinationPort` | (EventCode 3) the network connection target. |
| `SourceImage` / `TargetImage` | (EventCode 10) the calling and called processes for handle access. |

## Why `source=` (not `sourcetype=`) is the channel filter

Splunk's Add-on for Microsoft Windows assigns the same sourcetype (`XmlWinEventLog`) to **every** Windows Event Log channel — Security, Application, System, and Sysmon's Operational channel all share it. The way to filter to Sysmon-only events is the `source=` field, not `sourcetype=`:

```spl
index=mydfir-project source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" ...
```

Quotes are required (the `:` and `/` in the channel name break unquoted SPL parsing). All future SPL against Sysmon should follow this pattern.

## How to verify Sysmon is working

Two queries cover the common diagnostic questions:

**"Is Sysmon emitting at all?"**

```spl
index=mydfir-project source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
earliest=-1h
| stats count by EventCode | sort -count
```

Expected: a non-trivial distribution. If empty, the forwarder isn't picking up the channel — see the runbook's diagnostic ladder.

**"End-to-end smoke test"**

```powershell
Start-Process notepad.exe; Start-Sleep 2; Stop-Process -Name notepad
```

Then in Splunk:

```spl
index=mydfir-project source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*\\notepad.exe" earliest=-5m
| table _time, host, User, Image, CommandLine, ParentImage
```

Expected: at least one row within ~60 seconds.

## References

- [Sysinternals Sysmon docs](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) — official.
- [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) — the config we run.
- [MITRE Sysmon Event Mapping](https://car.mitre.org/wiki/Cyber_Analytic_Repository) — community resource for technique-to-EventCode mapping.
- [[splunk]] — Splunk component page; the consumer of Sysmon events.
- [[../../subprojects/2026-04-30-detection-foundations/runbook]] — the operational runbook.
- [[../../detections/README]] — the detection catalog Sysmon feeds.
```

- [ ] **Step 2: [Claude] Backfill the four placeholders**

The component page should not contain `<from Task ...>` placeholders. Replace:
- `<from Task 1.1 Step 2>` (commit SHA) with the actual SHA captured.
- `<from Task 1.1 Step 3>` (config file SHA256) with the actual hash.
- `<from Task 1.2 Step 2>` (Sysmon binary version) with the actual version string.
- (192.168.129.x with the actual Windows VM IP).

- [ ] **Step 3: [Claude] Commit**

```bash
git add vault/architecture/components/sysmon.md
git commit -m "feat(D1): vault/architecture/components/sysmon.md component page created"
```

---

### Task 8.2: Update `vault/architecture/components/splunk.md`

**Files:**
- Modify: `vault/architecture/components/splunk.md`

The existing page documents one disabled saved search and the Splunk Add-on for Microsoft Windows. We add the new saved search; document the Sysmon source distinction; cross-reference the new `sysmon.md`; bump the `updated` date.

- [ ] **Step 1: [Claude] Update the frontmatter**

Change `updated: 2026-04-27` to `updated: 2026-04-30`. Add `[[components/sysmon]]` to the `related:` line.

- [ ] **Step 2: [Claude] Update the "Apps installed" section**

If Phase 2 Task 2.3 Step 3 required installing **Splunk Add-on for Microsoft Sysmon** as the field-extraction fallback, add it here. Otherwise, leave the section unchanged.

```markdown
## Apps installed

- **Splunk Add-on for Microsoft Windows** — provides field extractions for Windows event logs (notably the `user` field used in detections; also extracts Sysmon-channel fields).
- **Splunk Add-on for Microsoft Sysmon** *(optional; installed only if the base Add-on for Microsoft Windows didn't extract Sysmon XML fields — see D1 notes.md)*.
```

If the optional add-on wasn't installed, drop that bullet.

- [ ] **Step 3: [Claude] Replace the "Saved searches / alerts" section**

Replace the current section with:

```markdown
## Saved searches / alerts

| Name | Status | Cron | Webhook | Notes |
|---|---|---|---|---|
| `Test-Brute-Force-External-Spoofed` | disabled | `* * * * *` (was test value) | v2 production | A1/A2 development; disabled at A2 closeout. |
| `T1059.001 - PowerShell Encoded Command` | enabled | `*/5 * * * *` | v2 production | D1 worked-example detection. See [[../../detections/t1059-001-powershell-encoded]]. |

The brute-force search will be replaced with a properly-thresholded version as part of Phase 2 detection-engineering work; tracking is captured in [[../../subprojects/2026-04-30-detection-foundations/notes]].
```

- [ ] **Step 4: [Claude] Add a "Sysmon ingestion" section before "How to access"**

```markdown
## Sysmon ingestion (D1)

Sysmon events from the Windows 10 VM land in the same `mydfir-project` index as Windows Security/App/System events, under `sourcetype=XmlWinEventLog`. **Differentiate by `source=`, not `sourcetype=`:**

```spl
index=mydfir-project source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
```

See [[components/sysmon]] for the full EventCode + field reference and the upstream config metadata (commit SHA, install date, version).
```

- [ ] **Step 5: [Claude] Verify the page still renders cleanly**

```bash
head -50 vault/architecture/components/splunk.md
```

Expected: clean YAML frontmatter, well-formed sections, no broken markdown.

- [ ] **Step 6: [Claude] Commit**

```bash
git add vault/architecture/components/splunk.md
git commit -m "docs(D1): splunk.md updated with new saved search + Sysmon ingestion section"
```

---

### Task 8.3: Update `vault/index.md`

**Files:**
- Modify: `vault/index.md`

- [ ] **Step 1: [Claude] Add the new pages to the index**

Open `vault/index.md`. Add (under the appropriate sections):

- Under **Architecture → Components**: `[[architecture/components/sysmon]] — Sysmon: install metadata, EventCode + field reference, gotchas`.
- New section **Detections** (or add to an existing catalog section if one exists):
  - `[[detections/README]] — Detection catalog index (per-MITRE-technique pages)`.
  - `[[detections/_template]] — Skeleton for a new technique page`.
  - `[[detections/t1059-001-powershell-encoded]] — T1059.001 PowerShell encoded command (D1 worked example)`.
- Under **Sub-projects** (or wherever D1 is listed): tick D1 from "(active — spec written, awaiting plan)" to "(complete)" — **but only after Phase 10 closes**. For now, just verify the existing entry is there.

- [ ] **Step 2: [Claude] Commit**

```bash
git add vault/index.md
git commit -m "docs(D1): index updated with sysmon component + detections directory pages"
```

---

## Phase 9 — Write the runbook

The runbook is operational documentation — how to install Sysmon if a fresh-instance redoes the lab, how to run a technique, how to read the observation toolkit, how to recover from common failures. Spec § 2.9 mandates the procedural starter SPL queries live here (5–7 of them, annotated inline).

### Task 9.1: Create the runbook scaffold + frontmatter

**Files:**
- Create: `vault/subprojects/2026-04-30-detection-foundations/runbook.md`

- [ ] **Step 1: [Claude] Write the scaffold**

```markdown
---
status: active
updated: 2026-04-30
sub_project: D1
related: [[README]], [[spec]], [[../../architecture/components/sysmon]], [[../../architecture/components/splunk]], [[../../detections/README]]
---

# D1 Runbook — Detection Foundations

Operational documentation for the detection-engineering observation lab D1 stood up. Covers install (one-time), the run-a-technique loop (every time), the observation toolkit (procedural SPL), the security-posture note, common failure recoveries, and the standby fix for Claude-misbehaves-on-Sysmon.

## Audience

You're either:
- Re-doing the install on a fresh Windows VM (rebuild scenario).
- Running a MITRE technique through the lab (the everyday operational case).
- Debugging "I ran ART and don't see anything in Splunk" (the diagnostic ladder).

## Sections

1. [Install (one-time)](#install-one-time)
2. [The "run a technique" loop (every time)](#the-run-a-technique-loop)
3. [Observation toolkit — starter SPL queries](#observation-toolkit--starter-spl-queries)
4. [VMware Workstation snapshot discipline](#vmware-workstation-snapshot-discipline)
5. [Worked example as smoke-test template](#worked-example-as-smoke-test-template)
6. [Security-posture note (Defender off, intentional)](#security-posture-note)
7. [Recoveries](#recoveries)
8. [Standby fix — system-prompt addendum (reactive only)](#standby-fix--system-prompt-addendum)
```

- [ ] **Step 2: [Claude] Commit**

```bash
git add vault/subprojects/2026-04-30-detection-foundations/runbook.md
git commit -m "docs(D1): runbook scaffold + section index"
```

---

### Task 9.2: Runbook — Install (one-time) section

**Files:**
- Modify: `vault/subprojects/2026-04-30-detection-foundations/runbook.md`

- [ ] **Step 1: [Claude] Append the install section**

Append:

```markdown
## Install (one-time)

These steps install Sysmon, configure the existing Splunk Universal Forwarder, and install Atomic Red Team. **Run only when standing up a fresh Windows VM** — D1's install was on 2026-04-30 and shouldn't be redone unless the VM is rebuilt.

### Prerequisites

- Windows 10 VM with Splunk Universal Forwarder already installed and forwarding to 192.168.129.131:9997.
- SSH (OpenSSH Server) running on the VM with an admin user; or RDP fallback.
- Defender off, C: drive excluded from any AV scope (intentional lab posture — see [Security-posture note](#security-posture-note)).
- VMware Workstation snapshot taken: name `D1 pre-install baseline`.

### 1. Install Sysmon

```powershell
# Pull SwiftOnSecurity config + capture commit SHA
New-Item -ItemType Directory -Path C:\Tools -Force
Set-Location C:\Tools
git clone https://github.com/SwiftOnSecurity/sysmon-config.git
Set-Location C:\Tools\sysmon-config
git rev-parse HEAD     # capture this SHA in vault notes

# Download Sysmon binary
New-Item -ItemType Directory -Path C:\Tools\Sysmon -Force
Invoke-WebRequest -Uri https://download.sysinternals.com/files/Sysmon.zip -OutFile C:\Tools\Sysmon\Sysmon.zip -UseBasicParsing
Expand-Archive -Path C:\Tools\Sysmon\Sysmon.zip -DestinationPath C:\Tools\Sysmon -Force

# Install Sysmon as a service with the SwiftOnSecurity config
& C:\Tools\Sysmon\Sysmon64.exe -accepteula -i C:\Tools\sysmon-config\sysmonconfig-export.xml

# Verify
Get-Service Sysmon64                                                                  # Status: Running expected
Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' | Select IsEnabled, RecordCount
```

Capture the SwiftOnSecurity commit SHA, the config file SHA256, and the Sysmon binary version in `vault/architecture/components/sysmon.md`.

### 2. Configure Universal Forwarder for the Sysmon channel

```powershell
# Backup current inputs.conf
$inputs = 'C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf'
Copy-Item $inputs "$inputs.pre-D1.bak" -Force

# Append the Sysmon stanza
$stanza = @'

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = mydfir-project
renderXml = true
'@
Add-Content -Path $inputs -Value $stanza -Encoding utf8

# Restart the forwarder to load the new stanza
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

If fields don't extract (Image/CommandLine empty while `_raw` has them), install **Splunk Add-on for Microsoft Sysmon** from Splunkbase as the fallback.

### 3. Install Atomic Red Team

```powershell
Set-ExecutionPolicy Bypass -Scope CurrentUser -Force
$installer = (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing).Content
Invoke-Expression $installer
Install-AtomicRedTeam -getAtomics -Force

# Verify
Import-Module Invoke-AtomicRedTeam
Invoke-AtomicTest T1059.001 -ShowDetailsBrief    # confirms catalog loaded
```

Atomics library lands at `C:\AtomicRedTeam\atomics\`.

### 4. Create the worked-example saved search

In Splunk web UI: **Search & Reporting → run the SPL from [[../../detections/t1059-001-powershell-encoded]] → Save As → Alert**. Configure per § 2.6 of the [[spec]] (or Phase 5 of the [[plan]]).
```

- [ ] **Step 2: [Claude] Commit**

```bash
git add vault/subprojects/2026-04-30-detection-foundations/runbook.md
git commit -m "docs(D1): runbook install section"
```

---

### Task 9.3: Runbook — "Run a technique" loop

**Files:**
- Modify: `vault/subprojects/2026-04-30-detection-foundations/runbook.md`

- [ ] **Step 1: [Claude] Append the run-a-technique section**

```markdown
## The "run a technique" loop

The everyday operational case. Use this for any MITRE technique you want to run + observe in Splunk.

### Step 1: Pick a technique

Browse https://attack.mitre.org/matrices/enterprise/ — pick a technique relevant to what you're learning (Execution, Credential Access, Lateral Movement, etc.). Note the T-id (e.g., `T1003`, `T1059.003`).

### Step 2: Take a VMware Workstation snapshot

VMware Workstation: right-click VM → Snapshot → Take Snapshot. Name: `before-T<id>-run-YYYY-MM-DD`. Description: which technique, what test number.

**Why:** ART's `-Cleanup` is best-effort. If a test leaves residue (registry keys, files, scheduled tasks, accounts), the snapshot is your safety net.

### Step 3: Preview the test catalog

```powershell
Import-Module Invoke-AtomicRedTeam
Invoke-AtomicTest T<id> -ShowDetailsBrief
```

Read each test description before running. Pick the one that matches what you're trying to observe.

### Step 4: Run the test

```powershell
Invoke-AtomicTest T<id> -TestNumbers <N>
```

Note the wall-clock time.

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
1. Hand-craft an SPL against the real ART event (see Phase 4 of the [[plan]]).
2. Save As → Alert with the same settings as the T1059.001 worked example (cron `*/5 * * * *`, Time Range `Last 24 hours`, Trigger `For each result`, webhook to v2 production URL).
3. Update the page's frontmatter to `status: spl-drafted` then `status: saved-search-active`.
4. Commit.
```

- [ ] **Step 2: [Claude] Commit**

```bash
git add vault/subprojects/2026-04-30-detection-foundations/runbook.md
git commit -m "docs(D1): runbook run-a-technique loop"
```

---

### Task 9.4: Runbook — Observation toolkit (5–7 starter SPL queries, annotated)

**Files:**
- Modify: `vault/subprojects/2026-04-30-detection-foundations/runbook.md`

This is the procedural part of the observation toolkit per spec § 2.9. Each query is annotated inline so the user (currently learning SPL) can read why each clause is there.

- [ ] **Step 1: [Claude] Append the observation-toolkit section**

```markdown
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

Confirms the Sysmon config is capturing what you expect. If an EventCode you wanted is missing, either (a) nothing in the lab triggered it, or (b) the SwiftOnSecurity config filters it. Cross-check against the [[../../architecture/components/sysmon]] EventCode reference.
```

- [ ] **Step 2: [Claude] Commit**

```bash
git add vault/subprojects/2026-04-30-detection-foundations/runbook.md
git commit -m "docs(D1): runbook observation toolkit (7 starter SPL queries, annotated)"
```

---

### Task 9.5: Runbook — VMware snapshot discipline + worked-example smoke-test template + security-posture note

**Files:**
- Modify: `vault/subprojects/2026-04-30-detection-foundations/runbook.md`

- [ ] **Step 1: [Claude] Append three short sections**

```markdown
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

## Security-posture note

The Windows 10 VM runs with **Defender off and the C: drive excluded from any AV scope**. This is **intentional lab setup** — not an oversight. Reasons:
- Many ART tests trip Defender's heuristics; running with Defender on means measuring "is Defender catching this technique?" instead of "is our detection catching this technique?".
- The lab is isolated to the 192.168.129.0/24 NAT network with no inbound from the internet.
- The Windows VM is treated as ephemeral — snapshots before ART sessions, revert if needed.

If you're in a working session and Defender alerts pop up unexpectedly, that's a regression — Defender shouldn't be running. Check `Get-MpPreference | Select DisableRealtimeMonitoring` (expected `True`) and `Get-MpPreference | Select ExclusionPath` (expected to include `C:\`).

**Future-fresh-instance reading this:** the security posture is the user's deliberate lab choice, not an attack surface they didn't know about. D1 doesn't re-litigate it.
```

- [ ] **Step 2: [Claude] Commit**

```bash
git add vault/subprojects/2026-04-30-detection-foundations/runbook.md
git commit -m "docs(D1): runbook snapshot discipline + smoke-test template + security-posture note"
```

---

### Task 9.6: Runbook — Recoveries section

**Files:**
- Modify: `vault/subprojects/2026-04-30-detection-foundations/runbook.md`

- [ ] **Step 1: [Claude] Append the recoveries section**

```markdown
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
   Expected: rows for each Windows channel including the new Sysmon source. If only Security/App/System show up, the forwarder restarted but the new stanza didn't load — check `Get-Content 'C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf'` and re-run Phase 2 Task 2.2.

5. **Field extraction works?**
   ```spl
   index=mydfir-project source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
   earliest=-5m | head 1
   ```
   In the resulting event, expand the `_raw` blob — check `Image=...` and `CommandLine=...` are present. If `_raw` has them but the search-time fields don't extract, install **Splunk Add-on for Microsoft Sysmon**.

### "Saved search fired but n8n didn't get the webhook"

1. **Saved search actually fired?** Splunk: **Activity → Triggered Alerts** — the entry should be there with the alert time matching the cron tick.
2. **Webhook URL correct?** Splunk: **Settings → Searches, reports, and alerts → T1059.001 ...** — the Webhook URL field should match the v2 production URL.
3. **n8n reachable from Splunk?** SSH to Splunk VM: `curl -I http://192.168.129.132:5678/webhook/<path>` — expected 200 or 404 (404 means the path is wrong but reachability is fine).
4. **n8n workflow active?** http://192.168.129.132:5678 → SOC Triage v2 → toggle should be green/Active.

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

Apply the [standby fix below](#standby-fix--system-prompt-addendum). Reactive only — don't apply unless an actual live-fire shows misbehavior.

### "ART left residue on the VM"

Revert to the pre-run snapshot. VMware Workstation → Snapshot Manager → select the `before-T<id>-...` snapshot → Revert.

If the snapshot is gone (forgot to take one, or already deleted):
- Check `C:\AtomicRedTeam\atomics\T<id>\T<id>.yaml` — the test definition has a `cleanup_command` that's authoritative for what the test created.
- Run it manually if `-Cleanup` failed.
```

- [ ] **Step 2: [Claude] Commit**

```bash
git add vault/subprojects/2026-04-30-detection-foundations/runbook.md
git commit -m "docs(D1): runbook recoveries section (5 common failure ladders)"
```

---

### Task 9.7: Runbook — Standby fix (system-prompt addendum)

**Files:**
- Modify: `vault/subprojects/2026-04-30-detection-foundations/runbook.md`

Spec § 2.7: **reactive only**. Don't apply by default. Document so future-fresh-instance has the standby fix ready if needed.

- [ ] **Step 1: [Claude] Append the standby-fix section**

```markdown
## Standby fix — system-prompt addendum

**Apply only if** a live-fire run shows Claude returning malformed responses to Sysmon-shaped alerts. **Default state: not applied.** D1's worked example validated the pipeline without this addendum.

If applied, this becomes ADR-worthy (probably 0006). Append a one-paragraph addendum to the SOC Triage v2 workflow's system prompt (the `Anthropic` node's `Options → System Message` field):

```markdown
**Sysmon process-create alert family:** Some alerts arrive from Splunk saved searches against Sysmon's `Microsoft-Windows-Sysmon/Operational` channel — typically `result.search_name` matching `T<MITRE-id>`-prefixed names. These alerts describe a process being launched (EventCode=1). Triage them by:
1. Treating `Image` and `CommandLine` as the highest-signal fields.
2. Looking at `ParentImage` for context (a phishing-launched PowerShell vs. an admin shell).
3. If `CommandLine` contains `-EncodedCommand` (or `-e`/`-en`/`-enc`) followed by base64, do not attempt to decode the payload. The triage is "encoded PowerShell observed; out-of-band investigation required" rather than "what's inside the payload."
4. `iocs_enriched` typically empty for this family — Sysmon process-create events have no network IOCs structurally.
```

After applying, commit:
```bash
git add JSON/SOC-Triage-v2-with-sysmon-addendum.json
git commit -m "feat(D1+): system prompt addendum for Sysmon-shaped alert family"
```

And write ADR 0006 documenting the addition (the fact of adding *was* a non-obvious decision; future-fresh-instance needs to know why).

The addendum's "do not decode the payload" guidance preserves the gate-skipped Outcome A path even if Claude is otherwise capable of decoding. If you want Outcome B as the default (gate-fired path), invert that bullet to "decode the payload and extract any IPs/domains/URLs/hashes you find as IOCs"; this couples D1 more tightly to A1's prompt and is itself an architectural decision (would deserve its own ADR).
```

- [ ] **Step 2: [Claude] Commit**

```bash
git add vault/subprojects/2026-04-30-detection-foundations/runbook.md
git commit -m "docs(D1): runbook standby fix (system-prompt addendum, reactive only)"
```

---

## Phase 10 — Closeout

### Task 10.1: Update README status checkboxes

**Files:**
- Modify: `vault/subprojects/2026-04-30-detection-foundations/README.md`

- [ ] **Step 1: [Claude] Tick the status checkboxes**

In `README.md` § Status, update the unchecked items to checked:

```markdown
## Status

- [x] Brainstorm completed 2026-04-30
- [x] Spec written 2026-04-30
- [x] Spec approved (user review gate)
- [x] Implementation plan written
- [x] Implementation executed
- [x] Runbook written
- [x] Log entry closing D1
```

- [ ] **Step 2: [Claude] Commit**

```bash
git add vault/subprojects/2026-04-30-detection-foundations/README.md
git commit -m "docs(D1): tick README status checkboxes"
```

---

### Task 10.2: Append D1 closeout to the vault log

**Files:**
- Modify: `vault/log.md`

- [ ] **Step 1: [Claude] Append the closeout entries**

Add to the end of `vault/log.md`:

```
2026-04-30 — Spec approved for D1; implementation plan written at [[subprojects/2026-04-30-detection-foundations/plan]]
2026-04-30 — D1 implementation in progress: Phase 0 captured Windows VM IP + UF inputs.conf path + Splunk baseline volumes + license headroom + pre-install snapshot. Phase 1 installed Sysmon (SwiftOnSecurity config commit `<SHA>`, off-the-shelf, no edits) on the Windows 10 VM. Phase 2 added the Sysmon stanza to UF inputs.conf, restarted forwarder, smoke test #1 (notepad.exe → EventCode=1) PASS, EventCode coverage baseline captured. Phase 3 installed Atomic Red Team. Phase 4 hand-crafted the T1059.001 SPL iteratively against a real ART event. Phase 5 created the Splunk saved search `T1059.001 - PowerShell Encoded Command` (cron `*/5 * * * *`, Time Range Last 24 hours, Trigger For each result, webhook to v2 production URL). Phase 6 live-fire PASS — outcome `<A or B>`, end-to-end pipeline traced through n8n + Iris + Slack with no n8n changes. Phase 7-8 seeded `vault/detections/` (template + index + worked-example page) and created `vault/architecture/components/sysmon.md` as the long-lived reference page; updated splunk.md + CLAUDE.md schema + index. Phase 9 wrote the runbook covering install + run-a-technique loop + 7 starter SPL queries + snapshot discipline + recoveries + security-posture note + standby system-prompt-addendum.
2026-04-30 — D1 complete: Sysmon + ART + observation lab live; one worked-example saved search firing the existing v2 webhook on a 5-minute cron; `vault/detections/` catalog seeded; sysmon.md component page is the long-lived reference. Architectural promise (Sysmon-shaped alert traverses A2's Test 1 path on real production traffic with no n8n changes) validated. See [[subprojects/2026-04-30-detection-foundations/runbook]] for operations and [[subprojects/2026-04-30-detection-foundations/notes]] for the issue/learning record. Successors unlocked: A3 (Splunk lookup blocklist), C (detection-engineering at scale), H (automated purple team), B (EDR layer).
```

Backfill the `<SHA>` and `<A or B>` placeholders with actual values from notes.md.

- [ ] **Step 2: [Claude] Commit**

```bash
git add vault/log.md
git commit -m "docs(D1): append closeout entries to vault log; D1 complete"
```

---

### Task 10.3: Sanity-check the final state with `git log --oneline`

**Files:** none on disk; verification.

- [ ] **Step 1: [Claude] Inspect the D1 commit history**

```bash
git log --oneline --grep "D1\|d1" | head -50
```

Expected: ~30+ commits across Phase 0 through Phase 10, in chronological order, each with a clear conventional-commits-style message.

- [ ] **Step 2: [Claude] Verify there are no untracked/uncommitted vault files**

```bash
git status -uno
```

Expected: `nothing to commit, working tree clean`. If the runbook, notes.md, or any of the vault/detections/ files show up as modified, decide whether they need a final commit.

- [ ] **Step 3: [Claude] Final commit if needed**

If anything's left over, group it into one commit:

```bash
git add <files>
git commit -m "docs(D1): final cleanup before closeout"
```

---

## Self-review checklist (run before declaring D1 done)

Match against the spec's Success criteria (§ Success criteria, items 1–15):

- [ ] **#1 Sysmon installed with SwiftOnSecurity config (off-the-shelf, no edits); commit SHA recorded in runbook/sysmon.md** — Phase 1 (Tasks 1.1–1.3) + Task 8.1.
- [ ] **#2 UF `inputs.conf` Sysmon stanza present + service restarted + smoke test #1 PASS** — Phase 2 (Tasks 2.2, 2.3).
- [ ] **#3 EventCode coverage check produces non-trivial distribution** — Task 2.4.
- [ ] **#4 ART installed; smoke test #3 PASS** — Phase 3 (Task 3.1).
- [ ] **#5 SPL detection for T1059.001 written + verified manually against real ART event** — Phase 4.
- [ ] **#6 Saved search created with all required settings** — Phase 5 (Task 5.2).
- [ ] **#7 Tier-2 live-fire produced Iris alert + Slack post matching Outcome A or B** — Phase 6 (Tasks 6.2, 6.3, 6.4).
- [ ] **Spec Open Q4** (webhook payload schema captured + compared to brute-force envelope) — Task 6.2 Step 3a.
- [ ] **Spec Open Q5** (Hashes field shape under SwiftOnSecurity captured) — Task 6.2 Step 5a.
- [ ] **Spec Open Q9 resolution** (dedup verification across two ART runs) — Task 6.4.
- [ ] **#8 `vault/detections/` directory + README + _template + worked-example page populated and at `status: saved-search-active`** — Phase 7.
- [ ] **#9 `vault/CLAUDE.md` schema table includes the `vault/detections/` row** — Task 7.4.
- [ ] **#10 `vault/architecture/components/splunk.md` updated with new saved search + Sysmon ingestion section** — Task 8.2.
- [ ] **#11 `vault/architecture/components/sysmon.md` exists with all required sections** — Task 8.1.
- [ ] **#12 Runbook covers all required sections (install, run-a-technique, snapshot discipline, 7 starter SPL queries, security-posture note, worked-example smoke test, standby fix)** — Phase 9.
- [ ] **#13 `notes.md` captures gotchas hit during build** — accumulated across all phases (Tasks 0.1, 0.2, 0.3, 0.5, 1.1, 1.2, 1.3, 2.1, 2.2, 2.3, 2.4, 3.1, 4.1, 4.2, 5.1, 5.2, 6.2, 6.3).
- [ ] **#14 Log entry at vault root marks D1 complete** — Task 10.2.
- [ ] **#15 If Outcome B occurred during live-fire, runbook documents it as known acceptable variance** — Task 6.3 + the runbook's `Standby fix` and `Worked example` sections.

Other quality gates:

- [ ] All commits have descriptive conventional-commits-style messages.
- [ ] `git log --oneline | grep -i "D1\|d1" | wc -l` returns ≥30 (the bite-sized-task discipline produced frequent commits).
- [ ] `vault/detections/t1059-001-powershell-encoded.md` contains no `<placeholder>` strings.
- [ ] `vault/architecture/components/sysmon.md` contains no `<from Task ...>` strings.
- [ ] `vault/log.md` D1-complete entry contains no `<SHA>` or `<A or B>` placeholders.
- [ ] Saved search visible in Splunk **Settings → Searches, reports, and alerts**, status Enabled, on schedule.
- [ ] Sysmon service: `Get-Service Sysmon64` returns `Running` from a fresh SSH session.
- [ ] UF service: `Get-Service SplunkForwarder` returns `Running` from a fresh SSH session.
- [ ] No ADR written for D1 by default (per spec § Success criteria); if Splunk Add-on for Microsoft Sysmon was needed (Task 2.3 Step 3), write ADR 0006 documenting the choice.
- [ ] `vault/index.md` lists the three new pages (`detections/README`, `detections/_template`, `detections/t1059-001-powershell-encoded`) and `architecture/components/sysmon.md`.
