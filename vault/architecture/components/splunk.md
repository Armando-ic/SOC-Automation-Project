---
status: active
updated: 2026-04-30
related: [[architecture/current-state]], [[architecture/components/splunk-mcp]], [[architecture/components/sysmon]]
---

# Splunk

## What it is

The SIEM. Splunk Enterprise running on Ubuntu Server (`MyDFIR-Splunk`, 192.168.129.131).

## Configuration

| | |
|---|---|
| Web UI | http://192.168.129.131:8000 |
| Management API | https://192.168.129.131:8089 |
| Receiver port (forwarders) | 9997 |
| Index for project data | `mydfir-project` |
| Admin user | `mydfir` (password in [[runbooks/secrets-management]]) |
| MCP service user | `mcpuser` (admin role; should be downgraded — tracked) |

Splunk is configured to start at boot via `splunk enable boot-start --user splunk`.

## Apps installed

- **Splunk Add-on for Microsoft Windows** (`Splunk_TA_windows`, v10.0.1) — general Windows Event Log channel parsing; sets `sourcetype=XmlWinEventLog` for the Security/App/System/Sysmon channels.
- **Splunk Add-on for Microsoft Sysmon** (`Splunk_TA_microsoft_sysmon`, v5.0.0) — Sysmon-specific field extractions; props/transforms keyed on `source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"`. Installed during D1 (2026-04-30).

## Saved searches / alerts

| Name | Status | Cron | Trigger | Webhook target | Notes |
|---|---|---|---|---|---|
| `Test-Brute-Force-External-Spoofed` | disabled | `* * * * *` (test value) | For each result | v2 production | A1/A2 development; disabled at A2 closeout 2026-04-30. Known issue: no threshold, fires on a single event. |
| `T1059.001 - PowerShell Encoded Command` | enabled | `*/5 * * * *` | For each result | v2 production | D1 worked-example detection. See [[../../detections/t1059-001-powershell-encoded]]. |

The brute-force search will be replaced with a properly-thresholded version as part of future detection-engineering work; tracking is captured in [[../../subprojects/2026-04-30-detection-foundations/notes]].

## Sysmon ingestion (D1)

Sysmon events from the Windows 10 VM (`DESKTOP-VNEF7PC`, 192.168.129.130) land in the `mydfir-project` index alongside Windows Security/App/System events under `sourcetype=XmlWinEventLog`. **Differentiate by `source=`, not `sourcetype=`:**

```spl
index=mydfir-project source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
```

The `XmlWinEventLog:` prefix (not `WinEventLog:`) is the canonical Sysmon source value when the Splunk Add-on for Microsoft Sysmon is installed; that add-on's parsing is keyed on this exact source.

See [[components/sysmon]] for the full EventCode + field reference, install metadata (commit SHA, version, hashes), and gotchas (e.g., `host` field instead of `ComputerName`, the `realtime_schedule=False` saved-search requirement).

### Side-effects of D1's UF restart on the PowerShell + Defender source values

The pre-existing UF `inputs.conf` had `source =` overrides on the `Microsoft-Windows-PowerShell/Operational` and `Microsoft-Windows-Windows Defender/Operational` stanzas that hadn't taken effect (forwarder hadn't restarted since 2026-04-25). D1's Phase 2 forwarder restart activated them. Their `source` values in Splunk are now **without** the `WinEventLog:` prefix:

- PowerShell channel: `source="Microsoft-Windows-PowerShell/Operational"` (was `"WinEventLog:Microsoft-Windows-PowerShell/Operational"`)
- Defender channel: `source="Microsoft-Windows-Windows Defender/Operational"` (was `"WinEventLog:Microsoft-Windows-Windows Defender/Operational"`)

Vault grep at the time confirmed no downstream consumers of the old strings. Future searches/dashboards against these channels should use the new (no-prefix) form.

## How to access

- Web UI: browser to http://192.168.129.131:8000
- SSH: `ssh mydfir@192.168.129.131` from host PowerShell
- MCP (programmatic): see [[architecture/components/splunk-mcp]]
