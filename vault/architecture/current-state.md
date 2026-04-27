---
status: active
updated: 2026-04-27
related: [[architecture/target-state]], [[workflows/soc-triage-pipeline]]
---

# Current System State

The lab as it exists today after completing the MyDFIR SOC Automation Project 2.0 video plus the DFIR-Iris, VirusTotal, and Splunk MCP bonus sections.

## Hosts

| Host | IP | Role |
|---|---|---|
| MyDfir-Windows-10 | 192.168.129.130 | Endpoint generating telemetry; runs Splunk Universal Forwarder, RDP target |
| MyDFIR-Splunk | 192.168.129.131 | Splunk Enterprise; web UI :8000, management API :8089, receiver :9997 |
| MyDFIR-n8n-VM | 192.168.129.132 | n8n via docker-compose, web UI :5678 |
| MyDFIR-DFIR-IRIS-VM | 192.168.129.133 | DFIR-Iris via docker-compose, web UI :443 (HTTPS, self-signed) |

## Data flow (current)

```
Windows 10 telemetry
    ↓ Universal Forwarder (port 9997)
Splunk (index: mydfir-project)
    ↓ Saved search "Test-Brute-Force" fires alert
    ↓ Webhook POST
n8n workflow
    ├── Anthropic node (Claude Opus 4.7) with tools:
    │     • AbuseIPDB-Enrichment (HTTP request tool)
    │     • VirusTotal-Hash (HTTP request tool)
    └── Branches into:
        ├── Slack (#alerts channel)
        └── DFIR-Iris (POST /alerts/add)
```

## Interactive investigation path

Independent of the alert pipeline:

- Claude Desktop and Claude Code both have a `splunk` MCP server connected to Splunk at `:8089` as `mcpuser`
- Used for ad-hoc queries, validating detections, hunting

See [[architecture/components/splunk-mcp]].

## Known issues in the current workflow

Captured here so they're visible from the architecture overview, not buried in component pages.

1. **System prompt sent in `assistant` role** instead of `system` (workflow JSON line 32). The video tutorial taught it this way.
2. **`JSON.stringify($json.body.result, user, ComputerName, 2)` is malformed** (line 35) — bare identifiers are not a valid replacer arg, so the filter is silently ignored and the full result object is serialized.
3. **AbuseIPDB API key hardcoded inline in the node body** (line 108) instead of being a credential — leaks the moment the workflow JSON is exported.
4. **No structured AI output** — downstream nodes parse `$json.content[0].text` freeform, so severity/IOCs/MITRE techniques can't be programmatically extracted.
5. **No error handling** — if AbuseIPDB or VirusTotal returns an error, the workflow silently degrades.
6. **DFIR-Iris fields hardcoded** — `alert_severity_id` (3), `alert_status_id` (1), `alert_customer_id` (1) all fixed values regardless of alert content.
7. **Webhook is unauthenticated** — security-through-obscurity GUID path only; anyone reachable on the n8n network can POST fake alerts.

Items 1–4 and 6 are addressed by [[subprojects/2026-04-27-structured-outputs/README]]. Item 5 (error handling) is partially addressed there. Item 7 (webhook auth) is deferred.
