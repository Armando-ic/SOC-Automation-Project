---
status: active
updated: 2026-04-28
sub_project: A2
approach: Slack URL-button gate + alert→case escalation (Pattern Y from brainstorm)
related: [[README]], [[../2026-04-27-structured-outputs/spec]], [[../../workflows/soc-triage-pipeline]], [[../../architecture/components/dfir-iris]], [[../../architecture/components/n8n]]
---

# Spec — Sub-project A2: Iris Escalation Gate

## Summary

Add a Slack-gated alert→case escalation step to the SOC triage workflow. After Claude triages an alert (A1 unchanged), if Claude judged any IOCs malicious or suspicious, post a Slack message with **Approve / Deny URL buttons**. Clicking Approve escalates the existing Iris alert into a case and imports the malicious/suspicious IOCs into the case-level threat-intel database. Clicking Deny — or letting it time out after 30 min — leaves the alert in the Iris alert queue. All outcomes post a follow-up Slack thread reply for the audit trail.

A2's architectural deliverable is the **human-in-the-loop approval pattern** that all future response actions (A3 Splunk blocklist, future blocking/disabling actions) will reuse. The Iris escalation is the first (and only) gated action in A2 because it's low-risk, semantically meaningful, and exercises the full pattern end-to-end with a single API call.

## Goal

- Establish the gate pattern: Slack URL buttons → analyst's LAN browser → n8n Wait/Resume webhook → branch on `?decision=approve|deny`.
- Promote validated threat intel into Iris's case-level IOC database so future alerts can be cross-referenced ("we've seen this IP in case #N before").
- Modify A1's `/alerts/add` call to natively carry IOCs at creation time via `alert_iocs` — fixes an architectural mismatch in A1 where IOCs lived only in the alert's freeform description, not in Iris's structured IOC fields.

## Scope

### In scope

- **Schema enhancement** (additive, still v1): add `ioc_type` enum (`ip` | `domain` | `file_hash`) to each `iocs_enriched` item in `submit_triage_result`'s input schema. Update system prompt to instruct Claude to populate it.
- **`Extract Triage Result` Code node** extended to also produce an `alert_iocs` payload mapped from `iocs_enriched` (filtered to malicious/suspicious, with hash-type sub-detection and Iris IOC-type-ID lookup) and an `alert_iocs_summary` string for the Slack action prompt.
- **`Create Iris Alert` HTTP Request node** body extended to include `alert_iocs`; "Always Output Data" enabled so the response (`alert_id`, `iocs[].ioc_uuid`) is captured.
- **New `Has Malicious IOCs?` IF node** to branch between gated and ungated paths.
- **Combined Slack message** (Block Kit): A1's existing alert content + a divider + an action prompt section listing the IOCs to be promoted + Approve/Deny URL buttons (only when malicious IOCs are present).
- **New `Wait For Decision` Wait node** in "On Webhook Call" mode with 30-minute timeout, returning a small HTML confirmation page to the browser.
- **New `Decision?` Switch node** branching on `timedOut` and `?decision` query param (`approve` / `deny` / fallback).
- **New `Escalate Iris Alert` HTTP Request node** calling `POST /alerts/escalate/{alert_id}` with `iocs_import_list` of the alert's IOC UUIDs.
- **Four Slack thread reply nodes** (approve-success, approve-fail, deny, timeout) posting to the original alert message's thread.
- **Workflow timeout bumped** from 120s (A1) to 2100s (35 min) to accommodate the 30-min Wait + buffer.
- **One-time documentation task:** capture Iris IOC type IDs from `/manage/ioc-types/list` and document in `vault/architecture/components/dfir-iris.md`.
- **One A1 limitation fixed in passing:** the `[View in Splunk](url)` markdown link in `iris_description` becomes a raw URL (one-line change while we're already editing the Code node).
- **Pin and run four test cases**: gate-skipped, approve, deny, timeout — plus an Iris-down negative-path test (Test 5).
- **End-to-end verification** with a real Splunk alert.
- **An ADR** documenting the additive `ioc_type` schema choice (why it's still v1, not v2).

### Out of scope (deliberately deferred)

- **Splunk lookup blocklist** — A3.
- **Other action types** (block IP, disable user, isolate host) — A3+.
- **Public Slack interactivity / signed payloads** — possible future "A2.5 — Tunnel + signed buttons" sub-project. Acknowledged limitation: anyone with LAN access + the resume URL can approve.
- **Schema v2 / structured `proposed_actions` field on Claude's output** — A1's existing `iocs_enriched` is sufficient for the one action A2 covers. Bump to v2 when A3's second action type makes the structure pay for itself.
- **Webhook auth on Splunk → n8n** — still deferred (same as A1).
- **Custom Iris case templates / case tags driven by alert content** — A2 uses a fixed case_tag (`soc-automation,a2,auto-escalated`) and no template; A3 can refine.
- **Alert deduplication** — if Splunk fires the same alert twice, two Iris alerts are created; acceptable lab behavior.
- **Multi-LLM fallback** (Bedrock, local model) — same deferral as A1.
- **Auto-retry on Iris escalate failure** — manual escalation is the fallback (instruction included in the failure-path Slack thread reply).
- **A1's `investigation_notes` sometimes-omitted issue** — out of scope; existing `|| '_none_'` fallback remains in place.
- **Splunk URL hostname patch** (`replace('mydfir-splunk', '192.168.129.131')`) — out of scope; long-term fix is server-side `serverName` config.

## Approach

**Pattern Y from the brainstorm.** Iris's data model treats alerts as the front-of-queue raw signal and cases as the durable investigation. Escalation is the analyst's "this is real, work this" decision — which is exactly what an approval gate represents.

- Keep A1's flow intact through `Extract Triage Result`.
- Modify `Create Iris Alert` body to natively carry the malicious/suspicious IOCs (data hygiene — every alert has full IOC context for audit trail, even false positives).
- Branch on whether `iocs_enriched` filtered to malicious/suspicious is non-empty:
  - **Empty** (Test-1-style internal brute force, or all-clean enrichment): A1's existing termination — Slack alert post, no buttons, end.
  - **Non-empty**: post Slack with action prompt + URL buttons → Wait → branch on click/timeout.
- On Approve: single API call (`POST /alerts/escalate/{alert_id}` with `iocs_import_list` of UUIDs from the alert response) → Slack thread reply with case link.
- On Deny / Timeout: Slack thread reply only; alert remains in Iris's alert queue for manual handling.

Rejected alternatives (see brainstorm transcript):

- **Pattern X — IOCs always on alert, no gate.** Fails A2's "approval gate" mission.
- **Pattern W — A1 alert untouched, gate on case creation + IOC push to that case.** Two separate Iris entities (alert + case) the analyst must manually correlate; more API calls (1 case + N IOCs); doesn't use Iris's native alert→case promotion.
- **Slack interactivity webhook with public tunnel** (Option 2 in plumbing brainstorm). Adds Cloudflare/ngrok infra to a sub-project that's about the approval workflow itself; deferred to A2.5.
- **Slack Socket Mode + custom Python worker** (Option 3 in plumbing brainstorm). Always-on Python process; less commonly seen in SOAR than Block Kit interactivity; lower portfolio value.
- **n8n Form Trigger** (Option 4 in plumbing brainstorm). Two-click UX (link → form submit); less integrated than buttons.

## Design

### 1. Schema enhancement to A1's `iocs_enriched`

Each item gains a required `ioc_type` enum so Iris IOC-type-ID classification is unambiguous:

```json
"iocs_enriched": {
  "type": "array",
  "items": {
    "type": "object",
    "required": ["value", "ioc_type", "verdict", "source", "summary"],
    "properties": {
      "value":    { "type": "string" },
      "ioc_type": { "type": "string", "enum": ["ip", "domain", "file_hash"] },
      "verdict":  { "type": "string", "enum": ["malicious", "suspicious", "clean", "unknown"] },
      "source":   { "type": "string" },
      "summary":  { "type": "string" }
    }
  }
}
```

System prompt addendum (one bullet under the existing IOC rules):

> When you populate `iocs_enriched`, set `ioc_type` to `ip`, `domain`, or `file_hash` matching the kind of IOC. This is required so downstream automation can route the IOC correctly.

`schema_version` stays `"v1"` because the change is additive — v1 consumers without `ioc_type` would still parse the response; only the new A2 logic requires the field. Documented in an ADR.

### 2. Workflow topology

```
Webhook
   ↓
Message a model  (Anthropic — unchanged)
   ↓
Extract Triage Result  (Code — extended: also builds alert_iocs + alert_iocs_summary)
   ↓
Create Iris Alert  (HTTP Request — body now includes alert_iocs;
                    response captured for alert_id + per-IOC UUIDs)
   ↓
Has Malicious IOCs?  (IF — checks alert_iocs.length > 0)
   ├─ NO  → Post Slack Alert  (Slack — A1-style message, no buttons) → END
   │
   └─ YES → Post Slack Alert + Approve/Deny  (Slack — A1 message + URL buttons)
                ↓
            Wait For Decision  (Wait — On Webhook Call, 1800s timeout)
                ↓
            Decision?  (Switch — branches on timedOut / decision query param)
                ├─ TIMEOUT  → Slack Thread Reply: timeout                 → END
                ├─ DENY     → Slack Thread Reply: denied                  → END
                └─ APPROVE  → Escalate Iris Alert  (HTTP Request)
                                ↓
                              Escalation Succeeded?  (IF — checks status === 'success')
                                ├─ YES → Slack Thread Reply: case #N      → END
                                └─ NO  → Slack Thread Reply: escalation failed → END
```

Net node count: A1 had 8 nodes (incl. tools); A2 has ~17 (most additions are short Slack thread reply nodes; architectural complexity is concentrated in the Wait → Switch fan-out).

**Two key changes from A1:**

1. **Slack and Iris are now sequential (not parallel).** A1 fanned out from `Extract Triage Result` to Slack and Iris in parallel. A2 puts Iris first because the Slack message needs the `alert_id` to link to and the IOC UUIDs for the escalate call. Side benefit: the Slack message now includes a clickable Iris alert link.
2. **`Create Iris Alert` response is captured.** A1 fired-and-forgot. A2 needs `data.alert_id` (path param for escalate) and `data.iocs[].ioc_uuid` (body for escalate's `iocs_import_list`).

### 3. IOC selection & `alert_iocs` payload (in `Extract Triage Result`)

#### 3a. Filter

```javascript
const candidates = (r.iocs_enriched || []).filter(
  i => i.verdict === 'malicious' || i.verdict === 'suspicious'
);
```

`clean` and `unknown` verdicts get dropped — they pollute the IOC database for no value.

#### 3b. Iris IOC type ID catalog (one-time lookup, hardcoded)

Iris's `ioc_type_id` is an integer reference to its IOC types catalog at `/manage/ioc-types/list`. The actual IDs are deployment-specific.

**Strategy:** Phase 0 of the implementation plan calls `curl -k https://192.168.129.133/manage/ioc-types/list -H "Authorization: Bearer <key>"` once, captures IDs for `ip`, `domain`, `md5`, `sha1`, `sha256`, documents them in `vault/architecture/components/dfir-iris.md` (new "IOC type IDs" subsection), and hardcodes them as a constant object in the `Extract Triage Result` Code node.

```javascript
// Iris IOC type IDs — captured from /manage/ioc-types/list on YYYY-MM-DD
// See vault/architecture/components/dfir-iris.md#ioc-type-ids
const IRIS_IOC_TYPE_IDS = {
  ip:     /* Phase 0 — from real catalog */,
  domain: /* Phase 0 */,
  md5:    /* Phase 0 */,
  sha1:   /* Phase 0 */,
  sha256: /* Phase 0 */,
};
```

#### 3c. File hash sub-classification (hex length detection)

| Length | Hash type | Lookup key |
|---|---|---|
| 32  | MD5     | `md5`    |
| 40  | SHA-1   | `sha1`   |
| 64  | SHA-256 | `sha256` |

Values not matching any expected hex length are skipped with a `console.warn` to avoid polluting Iris with malformed entries.

#### 3d. The full payload-building function

```javascript
const TLP_AMBER = 2;

function resolveIrisTypeId(iocType, value) {
  if (iocType === 'ip')     return IRIS_IOC_TYPE_IDS.ip;
  if (iocType === 'domain') return IRIS_IOC_TYPE_IDS.domain;
  if (iocType === 'file_hash') {
    const v = String(value).trim().toLowerCase();
    if (/^[0-9a-f]{32}$/.test(v)) return IRIS_IOC_TYPE_IDS.md5;
    if (/^[0-9a-f]{40}$/.test(v)) return IRIS_IOC_TYPE_IDS.sha1;
    if (/^[0-9a-f]{64}$/.test(v)) return IRIS_IOC_TYPE_IDS.sha256;
  }
  return null;
}

function buildAlertIocs(r) {
  const candidates = (r.iocs_enriched || []).filter(
    i => i.verdict === 'malicious' || i.verdict === 'suspicious'
  );
  const out = [];
  for (const item of candidates) {
    const typeId = resolveIrisTypeId(item.ioc_type, item.value);
    if (typeId === null) {
      console.warn(`Skipping IOC ${item.value} — unresolved type`);
      continue;
    }
    out.push({
      ioc_value:       item.value,
      ioc_description: `${item.source}: ${item.summary}`,
      ioc_tlp_id:      TLP_AMBER,
      ioc_type_id:     typeId,
      ioc_tags:        'soc-automation,a2',
    });
  }
  return out;
}
```

Output of the Code node gains two new fields alongside A1's existing ones:

```javascript
return [{
  json: {
    ...r,                           // A1 fields unchanged
    severity_iris_id, slack_message, iris_description,  // A1 fields unchanged
    splunk_link, alert_name,                            // A1 fields unchanged
    alert_iocs,                     // ← NEW: array of Iris IOC objects
    alert_iocs_summary,             // ← NEW: pre-rendered string for Slack
  }
}];
```

`alert_iocs_summary` is the human-readable list shown in the Slack action prompt:

```javascript
const TYPE_NAMES = { /* reverse map of IRIS_IOC_TYPE_IDS for display */ };
const alert_iocs_summary = alert_iocs.length > 0
  ? alert_iocs.map(i => `• \`${i.ioc_value}\` (${TYPE_NAMES[i.ioc_type_id] || 'unknown'})`).join('\n')
  : '_none_';
```

#### 3e. A1 limitation fixed in passing

While editing `Extract Triage Result`, change the `iris_description` template's `[View in Splunk](${splunkLink})` markdown link to a raw URL (`Splunk: ${splunkLink}`). DFIR-Iris's alert description doesn't render markdown links; A1's runbook captured this as a deferred fix.

### 4. Iris HTTP calls

#### 4a. `Create Iris Alert` — modified body (additive)

| Body parameter | A1 value | A2 value |
|---|---|---|
| `alert_title`         | `={{ $json.alert_name }}` | (unchanged) |
| `alert_description`   | `={{ $json.iris_description }}` | (unchanged) |
| `alert_severity_id`   | `={{ $json.severity_iris_id }}` | (unchanged) |
| `alert_status_id`     | `1` | (unchanged) |
| `alert_customer_id`   | `1` | (unchanged) |
| `alert_iocs`          | *(absent)* | `={{ $json.alert_iocs }}` ← **NEW** |

n8n-side configuration changes:

1. **"Always Output Data"** must be enabled so the response is captured.
2. The `alert_iocs` body parameter must be in **Expression mode** (not Fixed mode) — same gotcha A1 hit at deployment.

#### 4b. Response shape n8n needs to read

```json
{
  "status": "success",
  "data": {
    "alert_id": 3826,
    "iocs": [
      { "ioc_id": 7651, "ioc_uuid": "1c055831-…", "ioc_value": "...", … },
      …
    ]
  }
}
```

(Note: response field is `iocs`, request field is `alert_iocs`.)

n8n field references downstream:

| Need | Expression |
|---|---|
| Alert ID | `{{ $('Create Iris Alert').item.json.data.alert_id }}` |
| IOC UUIDs | `{{ $('Create Iris Alert').item.json.data.iocs.map(i => i.ioc_uuid) }}` |

#### 4c. `Escalate Iris Alert` — new HTTP Request node

| Field | Value |
|---|---|
| Method | `POST` |
| URL | `https://192.168.129.133/alerts/escalate/{{ $('Create Iris Alert').item.json.data.alert_id }}` |
| Authentication | `dfirIrisApi` credential (same as A1) |
| Allow Unauthorized Certs | ON |
| Body type | JSON |
| Continue On Fail | ON |

Body:

```json
{
  "iocs_import_list": "={{ $('Create Iris Alert').item.json.data.iocs.map(i => i.ioc_uuid) }}",
  "assets_import_list": [],
  "import_as_event": true,
  "note": "Auto-escalated by SOC Automation A2 after analyst approval.",
  "case_tags": "soc-automation,a2,auto-escalated",
  "case_title": "=[ALERT #{{ $('Create Iris Alert').item.json.data.alert_id }}] {{ $json.alert_name }} — {{ $json.severity }}"
}
```

#### 4d. Field mapping summary

| Claude (A1 schema, A2-enhanced) | Iris destination |
|---|---|
| `iocs_enriched[].verdict` (filter) | Selects which IOCs become `alert_iocs` |
| `iocs_enriched[].value` | `alert_iocs[].ioc_value` |
| `iocs_enriched[].ioc_type` (NEW) | `alert_iocs[].ioc_type_id` (via lookup + hash sub-detection) |
| `iocs_enriched[].source` + `.summary` | `alert_iocs[].ioc_description` (concatenated) |
| (constant) | `alert_iocs[].ioc_tlp_id = 2` (TLP:Amber) |
| (constant) | `alert_iocs[].ioc_tags = "soc-automation,a2"` |
| (post-approval) | `iocs_import_list` of the alert's IOC UUIDs → case-level threat intel |

### 5. Slack message + URL buttons

#### 5a. Combined Slack message (Block Kit JSON)

Posted on the "Has Malicious IOCs? = YES" branch:

```json
{
  "channel": "C0B0QMQU8QG",
  "blocks": [
    { "type": "section", "text": { "type": "mrkdwn", "text": "{{ $json.slack_message }}" } },
    { "type": "divider" },
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "*ACTION REQUEST: Escalate this alert to a DFIR-Iris case?*\n\nThe following IOCs will be promoted to threat intel:\n{{ $json.alert_iocs_summary }}\n\n_Iris alert: <https://192.168.129.133/alerts?alert_ids={{ $('Create Iris Alert').item.json.data.alert_id }}|#{{ $('Create Iris Alert').item.json.data.alert_id }}>_"
      }
    },
    {
      "type": "actions",
      "elements": [
        {
          "type": "button",
          "text": { "type": "plain_text", "text": "✅ Approve" },
          "url": "{{ $execution.resumeUrl }}?decision=approve",
          "style": "primary"
        },
        {
          "type": "button",
          "text": { "type": "plain_text", "text": "❌ Deny" },
          "url": "{{ $execution.resumeUrl }}?decision=deny",
          "style": "danger"
        }
      ]
    }
  ]
}
```

On the "NO buttons" branch, the Slack node posts a plain message with `text: {{ $json.slack_message }}` only — exactly A1's behavior.

#### 5b. URL button mechanics

`$execution.resumeUrl` resolves to `http://192.168.129.132:5678/webhook-waiting/<execution-id>` — deterministic from `$execution.id`. Slack itself doesn't make a callback; the analyst's LAN browser opens the URL when the button is clicked, n8n receives the GET and resumes the workflow.

If `$execution.resumeUrl` doesn't populate in pre-Wait nodes in this n8n version (open question for Phase 0), fall back to manual construction: `http://192.168.129.132:5678/webhook-waiting/{{ $execution.id }}?decision=approve|deny`.

#### 5c. Capturing the original message timestamp for thread replies

```
{{ $('Post Slack Alert + Approve/Deny').item.json.ts }}
```

becomes the `thread_ts` parameter on all four follow-up Slack reply nodes.

#### 5d. Outcome thread replies (one per branch)

| Branch | Slack thread reply text |
|---|---|
| Approve, escalation succeeded | ✅ *Approved* — Iris case `<https://192.168.129.133/case?cid={case_id}\|#{case_id}>` created with N IOCs imported. |
| Approve, escalation failed   | ❌ *Approval received but escalation failed:* `<error msg>`. Iris alert `#{alert_id}` remains in the alert queue. Manual escalation required. |
| Deny                         | ❌ *Denied* — Iris alert `#{alert_id}` remains in the alert queue. No case opened. |
| Timeout                      | ⏱️ *No response in 30 minutes — auto-treated as Deny.* Iris alert `#{alert_id}` remains in the alert queue. |
| Switch fallback (defensive)  | ⚠️ Unknown decision query — treated as Deny. Iris alert `#{alert_id}` remains in the alert queue. |

#### 5e. Slack credential + channel

- **Credential:** existing `Slack account` (id `IWEqjD1DvRajiKXy`). Required scope: `chat:write` (already configured for A1). **No new scopes needed** — URL buttons are part of standard `chat:write`; we don't use Slack interactivity since clicks don't post back to Slack.
- **Channel:** `#alerts` (id `C0B0QMQU8QG`). All five Slack nodes (alert post + four thread replies) use the same credential and channel.

### 6. Wait/Resume mechanics & branching

#### 6a. `Wait For Decision` configuration

| Setting | Value |
|---|---|
| Resume mode | On Webhook Call |
| HTTP method | GET |
| Authentication | None |
| Response Mode | Respond Immediately |
| Response Code | 200 |
| Response Data | HTML (see 6b) |
| Resume time limit | **1800 seconds (30 minutes)** |

On timeout: continues with `$json.timedOut: true` (verify exact field name during Phase 0).
On webhook call: continues with the request data (query params + headers) accessible as `$json`.

#### 6b. Browser response page

```html
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>SOC Triage — decision recorded</title>
  <style>
    body { font-family: system-ui, sans-serif; text-align: center; padding: 4em; background: #f4f5f7; }
    h1   { color: #2d3748; }
    p    { color: #4a5568; }
    .btn { color: #718096; font-size: 0.9em; }
  </style>
</head>
<body>
  <h1>✓ Decision recorded</h1>
  <p>The workflow is processing your decision. You can close this tab.</p>
  <p class="btn">A confirmation message will appear in the Slack thread within a few seconds.</p>
</body>
</html>
```

Single page (not branched approve/deny variants) keeps configuration simple. The Slack thread reply is the authoritative outcome surface.

#### 6c. `Decision?` Switch node

| Branch | Condition | Output |
|---|---|---|
| `timeout`  | `{{ $json.timedOut }}` is `true` | → Timeout Slack reply |
| `approve`  | `{{ $json.query.decision }}` equals `approve` | → Escalate sub-flow |
| `deny`     | `{{ $json.query.decision }}` equals `deny` | → Deny Slack reply |
| (fallback) | anything else | → Fallback Slack reply (treated as deny) |

#### 6d. Approve sub-flow

```
[approve from Switch]
   ↓
Escalate Iris Alert  (Continue On Fail = ON)
   ↓
Escalation Succeeded?  (IF — $json.status === 'success')
   ├─ YES → Slack: "✅ case #N created"        → END
   └─ NO  → Slack: "❌ escalation failed: …"  → END
```

#### 6e. Operational settings (changes from A1)

| Setting | A1 | A2 | Why |
|---|---|---|---|
| Workflow timeout | 120s | **2100s (35 min)** | 30 min Wait + buffer |
| Save successful executions | All | All | Unchanged |
| Save failed executions | All | All | Unchanged |
| Anthropic node retry | 2 / 5s | 2 / 5s | Unchanged |
| `Create Iris Alert` Always Output Data | (off) | **ON** | Need response fields |
| `Escalate Iris Alert` Continue On Fail | n/a | **ON** | So IF can detect HTTP errors |
| `Wait For Decision` Response Mode | n/a | **Respond Immediately** | Don't block browser on post-wait nodes |

### 7. Error handling (consolidated)

| Failure point | A2 behavior | Surface |
|---|---|---|
| Anthropic API timeout / 429 | A1's existing retry (2 / 5s) | n8n executions |
| Anthropic returns non-tool-call response | A1's diagnostic throw in `Extract Triage Result` | n8n executions |
| Iris `/alerts/add` returns 4xx/5xx | Workflow fails before Slack post | n8n executions |
| `Has Malicious IOCs?` IF errors | Workflow fails between Iris and Slack | n8n executions |
| Slack post fails (token expired) | Workflow fails; Iris alert is orphaned with no Slack notification | n8n executions; analyst spots orphan in next Iris review |
| Analyst doesn't click within 30 min | `timedOut` branch → Slack thread reply: "⏱️ auto-deny" | Slack thread |
| Analyst clicks twice | First click resumes; second hits "execution complete" page | Browser only |
| Iris escalate returns 4xx/5xx | "Continue On Fail" + IF → Slack thread reply: "❌ approved but escalation failed" | Slack thread |
| Malformed `?decision=…` query | Switch fallback → Slack thread reply: "unknown decision, treated as deny" | Slack thread |
| n8n restart during Wait | Paused execution lost; alert stays in Iris queue | (silent — operational hazard) |

### 8. Testing

#### 8a. Pinned-data test cases

| # | Pinned payload | Expected path | Verifies |
|---|---|---|---|
| **1** | A1's Test 1 (internal brute force, RFC1918, count=5) | Gate skipped | `iocs_enriched_filtered` empty → IF takes "no buttons" branch → Slack posts plain alert → Iris alert created with `alert_iocs: []` → workflow ends |
| **2** | A1's Test 2 (external IP, count=47) — fresh AbuseIPDB-flagged IP | Approve path | Slack posts with buttons → click Approve → browser confirmation → workflow resumes → escalate returns 200 → Slack thread reply with case link |
| **3** | Same as Test 2 | Deny path | Slack posts with buttons → click Deny → Slack thread reply: "denied" → no escalate call |
| **4** | Same as Test 2 | Timeout path | Slack posts with buttons → wait 30+ min without clicking → timeout fires → Slack thread reply: "auto-deny" |
| **5** | Same as Test 2; Iris VM stopped | Escalation failure | Click Approve → escalate returns connection error → IF takes failure branch → Slack thread reply: "❌ approved but escalation failed" |

#### 8b. Per-case verification checklist

- Workflow execution completes (or times out) without errors in n8n executions panel
- Iris alert exists for every test (alert is always created)
- Iris case exists **only** for Test 2 approve path
- Case has IOCs in its case-level IOC database (Iris UI: Case → IOCs tab) — not just in the alert's IOC tab
- Slack channel shows one post per alert + thread reply on Tests 2/3/4/5
- URL buttons render and are clickable
- Total execution time within 35-min workflow timeout

#### 8c. End-to-end verification (one-time on deployment)

1. Re-enable Splunk's `Test-Brute-Force` saved search
2. Trigger 5 failed logons on the Windows VM
3. Wait ≤60s for Splunk cron + webhook delivery
4. Confirm Slack alert lands with buttons (modify the alert's `src_ip` in Splunk to spoof an external IP if needed for the gate to fire)
5. Click Approve
6. Verify Iris case is created with imported IOCs in its case-level IOC tab
7. Disable the Splunk saved search

## A1 limitations addressed (and not addressed)

| A1 limitation | Addressed in A2? |
|---|---|
| `investigation_notes` sometimes omitted by Claude | **No** — out of scope; existing fallback OK |
| Iris alert description shows literal markdown link | **Yes** — one-line fix while editing `Extract Triage Result` |
| Splunk URL hostname patch hardcodes lab IP | **No** — server-side fix, out of scope |
| AbuseIPDB inline key in legacy export JSON | **No** — historical artifact; legacy file is rollback-only |

## Open questions for the implementation plan

These are HOW questions to verify at task-step granularity, not WHAT questions for design:

1. **`$execution.resumeUrl` resolution timing.** Does it work in nodes before the Wait node in this n8n version? Fallback: manual construction `http://192.168.129.132:5678/webhook-waiting/{{ $execution.id }}?decision=…`.
2. **Wait node timeout-result field name.** Likely `$json.timedOut`; verify with a manual run.
3. **Wait node "Respond Immediately" behavior.** Confirm browser receives the HTML response without hanging on post-wait nodes.
4. **Iris IOC type ID catalog.** Phase 0 must `curl` `/manage/ioc-types/list` and capture IDs.
5. **n8n Slack node Block Kit support.** Confirm the node accepts `blocks` JSON directly vs requiring a different operation/setting.
6. **Pinning Anthropic node response during downstream development** (same trick A1 used).
7. **Credential carry-over on workflow re-import** (same gotcha A1 hit).

## Success criteria

A2 is "done" when:

1. All five pinned test cases pass per the verification checklists in 8b
2. End-to-end verification with real Splunk alert succeeds for the Approve path
3. Iris **cases** are created from approved alerts; Iris's **case-level IOC database** shows the imported IOCs (not just the alert's IOC tab)
4. Slack thread shows the full audit trail: original alert post + outcome reply (Approve/Deny/Timeout/escalation-failure)
5. URL buttons render in Slack and are clickable from the analyst's LAN browser
6. Timeout fires correctly at 30 min without manual intervention
7. Negative-path test (Test 5) produces the expected "approved but escalation failed" Slack message
8. `runbook.md` for A2 covers deploy / rollback / verify / debug
9. `notes.md` captures gotchas hit during build (mirroring A1's note-taking discipline)
10. ADR written for the `iocs_enriched.ioc_type` schema enhancement (additive; explain why it's still v1)
11. Log entry at vault root marks A2 complete
12. Iris IOC type ID catalog documented in `vault/architecture/components/dfir-iris.md`

## Predecessors

- **A1 — Structured Outputs.** Provides the `iocs_enriched` array A2 reads from. Schema enhancement (`ioc_type`) is additive.

## Successors

- **A3 — Splunk lookup blocklist.** Reuses A2's gate pattern; adds a second action behind it (write IPs to a Splunk KV-store lookup that detection rules query). When A3 introduces a *second* action type, that's the moment to bump A1's schema to v2 with a structured `proposed_actions` array.
- **A2.5 — Tunnel + signed Slack interactivity** (optional, decoupled). Replace URL buttons with real Slack interactivity (Block Kit interactive buttons, signed payloads, audit-trail user identity). Can ship anytime independently.
- **B+ (EDR layer)** — generates richer alerts that A2's gate processes; no architectural change to A2.
