---
status: active
updated: 2026-04-28
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
- Currently used: `/alerts/add` (with `alert_iocs` body field, A2+); `/alerts/escalate/{alert_id}` (A2 escalation gate)
- `/alerts/add` accepts `alert_iocs` and `alert_assets` arrays at creation time — IOCs ride along with the alert and get UUIDs assigned for later import via escalation
- `/alerts/escalate/{alert_id}` promotes an alert into a new case; body's `iocs_import_list` is an array of those UUIDs to copy into the case-level threat-intel database
- Useful unused endpoints for future work: `/case/ioc/add` (add IOC directly to an existing case), `/manage/cases/add` (create case standalone), `/cases/{id}/notes/add` (case notes)

## Required fields when creating an alert

| Field | Current value | Notes |
|---|---|---|
| `alert_title` | Splunk search name | Comes from webhook |
| `alert_description` | AI-generated text | Currently freeform Claude output; becomes structured per A1 |
| `alert_severity_id` | Hardcoded `3` (Medium) | Should be derived from AI severity assessment in A1 |
| `alert_status_id` | Hardcoded `1` (New) | Reasonable default |
| `alert_customer_id` | Hardcoded `1` | Single-tenant lab — fine |

## IOC type IDs (captured 2026-04-28)

Required by A2's `Extract Triage Result` Code node when building the `alert_iocs` body for `POST /alerts/add`. **Re-capture if Iris is upgraded** — IDs are deployment-specific (the catalog has 160 entries; positions can shift across versions).

| Our schema key | Iris `type_name` | Iris `type_id` |
|---|---|---|
| `ip`     | `ip-src` | **79** |
| `domain` | `domain` | **20** |
| `md5`    | `md5`    | **90** |
| `sha1`   | `sha1`   | **111** |
| `sha256` | `sha256` | **113** |

Source: `GET /manage/ioc-types/list` on the Iris instance at `192.168.129.133`.

Notes on the choices:

- **`ip-src` (79) over `ip-dst` (77).** Splunk alerts deliver the *source* IP of the attacker (the IP attempting failed logons, etc.) — matches `ip-src`'s description "A source IP address of the attacker." If a future detection emits a destination IP (e.g., outbound C2), the Code node's `resolveIrisTypeId` should be extended to handle both — A1's `iocs_enriched.ioc_type` enum currently treats all IPs as a single category.
- **No URL type yet.** Iris has `url` (id 141) but A1's schema doesn't separate URLs from domains. If A3+ adds URL extraction from alerts, register `url` here and extend the schema.
- **No hostname type yet.** Iris has `hostname` (id 69) for "full host/dnsname of an attacker," but A1's `iocs.hosts` array tracks internal hostnames (the affected endpoint), which we don't push to threat intel. Distinct concept; deliberately not mapped.

To re-capture:

```bash
curl -ks -H "Authorization: Bearer <iris-api-key>" \
  https://192.168.129.133/manage/ioc-types/list \
  | python -c "
import json, sys
d = json.load(sys.stdin)['data']
for t in d:
    if t['type_name'] in ('ip-src', 'domain', 'md5', 'sha1', 'sha256'):
        print(t['type_name'], '->', t['type_id'])
"
```
