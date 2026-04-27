---
status: active
updated: 2026-04-27
related: [[architecture/current-state]]
---

# DFIR-Iris

## What it is

Open-source incident response case management. Receives alerts from the n8n workflow, organizes them into investigations. Runs in Docker via docker-compose on Ubuntu Server (`MyDFIR-DFIR-IRIS-VM`, 192.168.129.133).

## Configuration

| | |
|---|---|
| Web UI | https://192.168.129.133 (HTTPS, self-signed cert) |
| Version | v2.4.22 |
| Source | https://github.com/dfir-iris/iris-web |
| Run command | `cd ~/iris-web && sudo docker-compose up` |
| Admin user | `administrator` (password in [[runbooks/secrets-management]]) |
| API key | Generated under user settings; currently using admin's key (security debt — should create service account) |

## Setup gotcha

The shipped `docker-compose.base.yaml` has `depends_on` directives that fail under the version of docker-compose available via apt. Workaround applied: comment out the `depends_on` lines. If the project ever upgrades docker-compose to v2 (the plugin form), revisit this.

## API integration

- Used by n8n workflow to create alerts via `POST /alerts/add`
- Full endpoint reference: [DFIR-Iris OpenAPI spec](../../../JSON/IRIS-2.0.4-OpenAPI-specification.json) at project root
- Currently used: `/alerts/add`
- Useful unused endpoints for future work: `/iocs/add`, `/cases/add`, `/cases/{id}/notes/add`

## Required fields when creating an alert

| Field | Current value | Notes |
|---|---|---|
| `alert_title` | Splunk search name | Comes from webhook |
| `alert_description` | AI-generated text | Currently freeform Claude output; becomes structured per A1 |
| `alert_severity_id` | Hardcoded `3` (Medium) | Should be derived from AI severity assessment in A1 |
| `alert_status_id` | Hardcoded `1` (New) | Reasonable default |
| `alert_customer_id` | Hardcoded `1` | Single-tenant lab — fine |
