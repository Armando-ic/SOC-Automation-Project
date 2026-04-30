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

## Open follow-ups

- Confirm Universal Forwarder service uptime > a few seconds (was the restart already performed by something else?). If `(Get-Date) - (Get-Process splunkd).StartTime` shows a process younger than the inputs.conf LastWriteTime, the restart already happened and we can skip Phase 2 Task 2.2 Step 3.
- Decide ADR-0006: install of Splunk Add-on for Microsoft Sysmon. Lean: yes, mid-D1 closeout.
- Phase 8's `splunk.md` update should add the Sysmon Add-on to the "Apps installed" section.
