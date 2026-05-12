---
status: active
updated: 2026-05-12
related: [[architecture/current-state]], [[workflows/soc-triage-pipeline]], [[decisions/0007-remove-slack-iris-native-gate]]
---

# DFIR-Iris

## What it is

Open-source incident response case management. Receives alerts from the n8n workflow, organizes them into investigations. Runs in Docker via docker-compose on Ubuntu Server 24.04 (`MyDFIR-DFIR-IRIS-VM-v2`, 192.168.129.133). VM rebuilt from scratch 2026-05-12 after the 2026-05-08 OneDrive incident.

## Configuration

| | |
|---|---|
| VM | `MyDFIR-DFIR-IRIS-VM-v2` at `C:\VMs\MyDFIR-DFIR-IRIS-VM-v2\` |
| Web UI | https://192.168.129.133 (HTTPS, self-signed cert) |
| Version | v2.4.22 (verified 2026-05-12 against rebuilt instance — IOC type IDs and severity IDs unchanged from 2026-04-28 capture) |
| Source | https://github.com/dfir-iris/iris-web (git tag `v2.4.22`, commit `f75e56fb`) |
| Run command | `cd ~/iris-web && sudo docker-compose up -d` |
| Admin user | `administrator` (password regenerated 2026-05-12 by fresh install; current value in `SOC-Automation-Project.md` at project root) |
| API key | Regenerated 2026-05-12 under user settings; current value in secrets file |
| Containers | `iriswebapp_db` (postgres) · `iriswebapp_app` · `iriswebapp_nginx` · `iriswebapp_rabbitmq` · `iriswebapp_worker` |
| Static IP | Pinned via netplan on the Ubuntu host; cloud-init network config disabled |

## Setup gotchas (validated 2026-05-12 rebuild)

### `depends_on` blocks crash older docker-compose

The shipped `docker-compose.base.yml` has three `depends_on:` directives that fail under the docker-compose-via-apt version (1.29.2). Workaround applied: **comment out the depends_on blocks** (lines 51, 80, 116 at v2.4.22 tag — the directives plus their indented service entries). Confirmed working post-rebuild 2026-05-12.

```bash
# automation-safe sed via awk that comments depends_on: + immediate indented `- "..."` children
awk '
  /depends_on:/ { commenting = 1; print "#" $0; next }
  commenting && /^[[:space:]]+- / { print "#" $0; next }
  commenting { commenting = 0 }
  { print }
' docker-compose.base.yml.bak > docker-compose.base.yml
```

If the project ever upgrades to docker-compose v2 (plugin form), revisit this — v2 handles `depends_on` differently and may not need the workaround.

### `.env` must be fresh-copied from `.env.model` after git clone

The repo at v2.4.22 ships a 36-byte `.env` that's NOT a valid environment file (parses to nothing). Postgres then fails to start with `POSTGRES_PASSWORD not specified`. Fix: explicitly `cp .env.model .env` after `git checkout v2.4.22`, overwriting the shipped stub.

### Admin password displays once on first `docker-compose up`

The `iriswebapp_app` container's first run generates a random admin password and **only prints it once to stdout**. Per the tutorial — *don't clear your terminal until you've copied it*. Or use `docker-compose up -d` and `docker-compose logs app | grep -i "password"` to retrieve after the fact (this is what we did 2026-05-12).

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
| `alert_severity_id` | Looked up from Claude's `severity` via the catalog table below | A2: corrected from A1's wrong table; see "Severity IDs" section |
| `alert_status_id` | Hardcoded `1` — but **maps to "Unspecified" on v2.4.22**, not "New" as previously assumed | Documented inversion — see Alert Status IDs section below; cosmetic for now, fix when next revising the workflow |
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

## Alert status IDs — captured 2026-05-12

| `alert_status_id` | `status_name` |
|---|---|
| 1 | Unspecified |
| (others to be captured when needed) | — |

The workflow currently hardcodes `alert_status_id=1` (per the table in "Required fields"). On v2.4.22 this lands the alert as "Unspecified" status — not what was historically intended. Recapture and pick the appropriate ID (likely "New") in a future workflow revision.

To recapture the full status catalog:

```bash
curl -ks -H "Authorization: Bearer <iris-api-key>" \
  https://192.168.129.133/manage/alert-status/list | python -m json.tool
```

## Severity IDs (captured 2026-04-28, reverified 2026-05-12 — unchanged)

Required by `Extract Triage Result`'s severity-mapping table (`sevId`). **Iris severity IDs are non-linear** — they do not follow severity order. **Re-capture if Iris is upgraded.**

Live catalog from `GET /manage/severities/list`:

| `severity_id` | `severity_name` |
|---|---|
| **1** | Medium |
| **2** | Unspecified |
| **3** | Informational |
| **4** | Low |
| **5** | High |
| **6** | Critical |

Code node mapping from Claude's `severity` enum:

| Claude `severity` | Iris `severity_id` |
|---|---|
| `low`      | 4 |
| `medium`   | 1 |
| `high`     | 5 |
| `critical` | 6 |
| (fallback for any unrecognized value) | 2 (Unspecified) |

**A1 had this wrong.** A1's table mapped `low→2, medium→3, high→4, critical→5`, which on this Iris instance silently produced Unspecified, Informational, Low, and High respectively — every alert was understated. The bug went undetected because A1 didn't capture the alert-creation response (the toggle A2's `alwaysOutputData` enabled, which surfaced `severity.severity_name` in the response body and made the mismatch visible). Fixed in A2 alongside the Code node rewrite.

To re-capture:

```bash
curl -ks -H "Authorization: Bearer <iris-api-key>" \
  https://192.168.129.133/manage/severities/list \
  | python -m json.tool
```

## `/alerts/escalate/{alert_id}` handler bugs (deployment-specific, captured 2026-04-29)

The Iris OpenAPI spec marks `case_tags` and `assets_import_list` as **optional** on the escalate request body. In practice, the handler in our running v2.4.22 deployment crashes with unhandled-`None` errors when either field is omitted:

| Field omitted | Server-side error |
|---|---|
| `case_tags` | `'NoneType' object has no attribute 'split'` — handler calls `.split(',')` on `case_tags` without null-check |
| `assets_import_list` | `'NoneType' object is not iterable` — handler iterates over `assets_import_list` without null-check |

**Always include both fields in the escalate body, even if empty:**

```json
{
  "iocs_import_list": [...],
  "assets_import_list": [],
  "case_tags": "soc-automation,a2,auto-escalated",
  "import_as_event": true,
  "note": "...",
  "case_title": "..."
}
```

`assets_import_list: []` and `case_tags: "anything"` are both safe degenerate values — the handler accepts them and creates a case with no assets and the given tag string. A2's `Build Escalate Body` Code node always includes both, so this isn't a current blocker; the rule is here so future integrators don't trim "optional" fields from the body and silently 500.

This is a Iris-side spec/implementation mismatch, not something we can fix from the integrator's side. Worth tracking against future Iris versions: the handler may pick up null-checks in a later release and the rule may relax. Re-test if Iris is upgraded.
