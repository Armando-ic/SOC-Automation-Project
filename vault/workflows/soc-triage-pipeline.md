---
status: active
updated: 2026-04-27
related: [[architecture/components/n8n]], [[architecture/components/claude-api]]
---

# SOC Triage Pipeline

The current production n8n workflow.

**Source of truth (JSON export):** [SOC-Automation-Project-Workflow.json](../../JSON/SOC-Automation-Project-Workflow.json)

**n8n internal ID:** `45gQjuH2MFQYrlEx`

## Topology

```
Webhook
   ↓
Message a model (Anthropic, claude-opus-4-7)
   ├── Tools: AbuseIPDB-Enrichment, VirusTotal-Hash
   └── ↓
       ├── DFIR-IRIS HTTP Request (POST /alerts/add)
       └── Send a message (Slack #alerts)
```

## Trigger

Splunk saved search "Test-Brute-Force" calls the webhook URL `http://192.168.129.132:5678/webhook-test/d587bbe6-da1e-4edb-87a6-3d50ad4046b0` whenever it fires.

The webhook path is GUID-based but unauthenticated — anyone reachable on the n8n network can POST fake alerts. Auth hardening is a future concern.

## Pinned test data

A pinned webhook output is saved on the Webhook node so the workflow can be tested without firing a real Splunk alert. Pinned payload represents a single failed-logon event: user `mydfir`, host `DESKTOP-VNEF7PC`, `src_ip` `192.168.129.1`, `count` `1`.

## What the AI does

System prompt (currently in `assistant` role — bug, fixed by A1) asks Claude to act as Tier 1 SOC analyst, summarize the alert, enrich IOCs via the two tools, assess severity against MITRE ATT&CK, recommend next actions, and format output with section headers (Summary, IOC Enrichment, Severity Assessment, Recommended Actions).

User message: alert name + `JSON.stringify(...)` of the result body. The stringify call is malformed (also a bug — fixed by A1).

## What downstream nodes consume

- **Slack** posts `{{ $json.content[0].text }}` directly — Claude's freeform text becomes the message body
- **DFIR-Iris** posts the same freeform text as `alert_description`, with `alert_severity_id`, `alert_status_id`, and `alert_customer_id` hardcoded

A1 changes both consumers to read from a structured JSON object instead of `content[0].text`.

## Known issues

See [[architecture/current-state]] § "Known issues in the current workflow."
