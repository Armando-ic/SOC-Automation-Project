---
status: active
updated: 2026-04-27
related: [[architecture/current-state]], [[architecture/components/splunk-mcp]]
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

- **Splunk Add-on for Microsoft Windows** — provides field extractions for Windows event logs (notably the `user` field used in detections)

## Saved searches / alerts

- **Test-Brute-Force** — currently disabled. Fires on `EventCode=4625` (failed Windows logon) under index `mydfir-project`. Triggers webhook to n8n. Known issue: no threshold, fires on a single event. Will be replaced as part of detection engineering work in Phase 2.

## How to access

- Web UI: browser to http://192.168.129.131:8000
- SSH: `ssh mydfir@192.168.129.131` from host PowerShell
- MCP (programmatic): see [[architecture/components/splunk-mcp]]
