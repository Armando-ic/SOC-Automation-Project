# Notes — Sub-project A2, Iris Escalation Gate

Working notes, gotchas, learnings, open questions discovered during build.

---

## 2026-04-28 (impl) — Phase 0 verifications

### Task 0.1 — Iris IOC type IDs captured
- Live Iris catalog has 160 IOC types; we use 5. Captured IDs:
  - `ip-src` → 79 (chosen over `ip-dst` 77 — Splunk delivers source IPs)
  - `domain` → 20
  - `md5` → 90
  - `sha1` → 111
  - `sha256` → 113
- Documented in [[../../architecture/components/dfir-iris]] under new "IOC type IDs" subsection.
- **Spec/plan placeholder values were guesses (76/20/90/113/114) and several were wrong.** Real values: 79/20/90/111/113. Plan's Task 3.1 example will need the actual numbers when the Code node body is pasted.
- **Stale endpoint reference fixed in passing:** the old vault said `/iocs/add`; the actual Iris endpoint is `/case/ioc/add`. Also surfaced that `/alerts/add` accepts `alert_iocs` natively and `/alerts/escalate/{alert_id}` is the case-promotion path A2 uses.

### Task 0.2 — Wait node behavior probe — DEFERRED
Skipping the standalone probe; will verify `$execution.resumeUrl` resolution + timeout field name inline during Phase 6 (the same execution that wires the Wait node will surface both). Plan's documented fallbacks (manual `$execution.id` URL construction; inspect `$json` shape post-resume) cover both unknowns.

### Phase 3 Code node — Unicode encoding lesson (rediscovered)

A1 ran into clipboard mojibake with em-dashes and emoji (`â€"` etc.). A2 hit it again on the first paste of the Extract Triage Result body. **Permanent fix:** in the source, use only ASCII — encode all user-visible Unicode via JS escape sequences:

- `'\u{1F7E2}'` for emoji (supplementary plane, brace syntax required)
- `'⚪'` / `'•'` / `'—'` for BMP chars (no braces)

The working file at `scratch/extract-triage-result-a2.js` (gitignored) is pure ASCII and pastes through any clipboard pathway without mangling. The JS engine resolves escapes at runtime, so Slack/Iris see the real chars.

**Generalized rule for the runbook:** whenever a Code node will display Unicode to humans (Slack, Iris, web), prefer `\u` escapes over raw Unicode literals in the source. ASCII source = clipboard-safe.

### Task 0.3 — Slack node Block Kit support — CONFIRMED (Branch A)
n8n Slack node v??? exposes Block Kit at:
- Click Slack node → **Message Type** dropdown (default `Simple Text Message`) → select **`Blocks`**
- A **`Blocks`** field appears that accepts raw JSON (Fixed/Expression toggle, Block Kit Builder link inline)
- Other Message Type options seen: `Simple Text Message`, `Blocks`, `Attachments`
- Bonus finding: **"Reply to a Message"** under Add Option carries `thread_ts` — exactly what Phase 8 thread replies need (no HTTP Request fallback for replies either)

**Decision for Phase 5+:** use native Slack nodes throughout. No `chat.postMessage` HTTP Request fallback needed.

---

## 2026-04-28 (impl) — Phase 3 Code node test

Plan Task 3.2 — smoke-test the new `Extract Triage Result` body with Test 2 (external IP / `185.220.101.42` / count=47) pinned data.

- All A1 fields preserved: yes (severity, severity_iris_id, slack_message, iris_description, splunk_link, alert_name, iocs, iocs_enriched, mitre_techniques; `recommended_actions` and `investigation_notes` correctly fall back to `_none_` in rendered strings — Claude omitted both, A1's known pattern)
- `alert_iocs` populated for external-IP test: yes, count = 1
- `alert_iocs[0].ioc_type_id`: 79 — correct live `ip-src` ID from Phase 0.1 (not the stale 76 placeholder from spec)
- `alert_iocs[0].ioc_tlp_id`: 2 (TLP:Amber); `ioc_tags`: `soc-automation,a2`; `ioc_description`: `AbuseIPDB: <summary>` (source/summary concat)
- `alert_iocs_summary` rendered correctly: yes — `• \`185.220.101.42\` (ip)`
- `iris_description` ends in raw `Splunk: <url>` (no markdown link): yes — A1 limitation fixed in passing
- `slack_message` retains Slack mrkdwn link `<url|View in Splunk>` (correct — Slack renders this; only Iris gets the raw URL)

Phase 2 changes also confirmed live in this run: Claude's `iocs_enriched[0].ioc_type` = `"ip"` (system prompt addendum took; schema enum accepted).

**State note:** v2 had no pin data when this session started — n8n's pin data did not carry over from the v1→v2 duplicate (Phase 1.2). Re-established Webhook + `Message a model` pins via one fresh end-to-end of those two nodes (Iris/Slack downstream of Extract did not fire). Pin data now lives in n8n's DB; will be captured in JSON at the next Task that exports v2 (Task 4.1).

---

## 2026-04-28 (impl) — Phase 4 Iris alert response shape + severity bug fix

### Task 4.2 — `Create Iris Alert` live test step

Body now carries `alert_iocs`; "Always Output Data" enabled; isolated Test step against live Iris (192.168.129.133) returned HTTP 200 + `status: "success"`.

Response field paths (verified live, for downstream nodes to reference):

- Alert ID: `data.alert_id` (integer, e.g. `12`, `13` from this session's runs)
- Alert UUID: `data.alert_uuid` (string)
- IOC UUIDs: `data.iocs[].ioc_uuid` (array — A2's `Escalate Iris Alert` will pass this as `iocs_import_list`)
- Per-IOC type round-trip: `data.iocs[].ioc_type.type_name` confirms type_id 79 = `ip-src` exactly as Phase 0.1 captured.

n8n expression for downstream use:

| Need | Expression |
|---|---|
| Alert ID | `{{ $('Create Iris Alert').item.json.data.alert_id }}` |
| IOC UUIDs | `{{ $('Create Iris Alert').item.json.data.iocs.map(i => i.ioc_uuid) }}` |

### Detour — A1 severity-mapping bug discovered and fixed

The first Test 2 alert (`alert_id: 12`) came back with `severity.severity_name: "Low"` despite Claude scoring `"high"`. Confirmed in Iris UI — alert is real, badge says "Low".

Root cause: A1's Code node mapped `{ low: 2, medium: 3, high: 4, critical: 5 }`, assuming linear severity IDs. Live `/manage/severities/list` shows the catalog is **non-linear**:

| `severity_id` | `severity_name` |
|---|---|
| 1 | Medium |
| 2 | Unspecified |
| 3 | Informational |
| 4 | Low |
| 5 | High |
| 6 | Critical |

A1's mapping silently understated every alert: low→Unspecified, medium→Informational, high→Low, critical→High. Bug never surfaced because A1 didn't capture the alert-creation response (the `alwaysOutputData` toggle A2 just enabled is what made it visible).

Fix landed in the same Code node (one-line change to `sevId` table, with new explanatory comment block):

```js
const sevId    = { low: 4, medium: 1, high: 5, critical: 6 }[r.severity] || 2;
```

Catalog documented in [[../../architecture/components/dfir-iris]] under new "Severity IDs" section, alongside the existing IOC type IDs section. Same lesson re-learned: **Iris ID catalogs are non-linear and deployment-specific — always capture from live, never assume.**

Verification after fix: a second Test 2 run produced `alert_id: 13` with `severity.severity_name: "High"` and `alert_severity_id: 5`. Working as intended.

The pre-fix alert #12 in Iris is left in place as a historical artifact (no need to delete; it's harmless and conveniently illustrates what the bug looked like).

**Implication for A1's runbook:** A1 documented `severity_iris_id` as derived from Claude's verdict but never validated round-trip against Iris's catalog. A2's runbook should call out the live-catalog-capture pattern as a required gate.

---

## 2026-04-28 (impl) — Phase 5.1 cross-graph expression gotcha

When rewiring `Send a message` from a direct child of `Extract Triage Result` to a downstream child of `Create Iris Alert`, the original expression `{{ $json.slack_message }}` started rendering as the literal string `"undefined"` in Slack. Cause: `$json` resolves to the *immediate* upstream node's output. Once Iris was inserted in the chain, `$json` became Iris's response — which has no `slack_message` field.

Fix: change to the cross-graph reference form:

```
{{ $('Extract Triage Result').item.json.slack_message }}
```

This pattern reaches a specific named upstream node regardless of intermediate nodes. We'll use it again in Task 5.3 (Block Kit Slack node) and Phase 8 (thread reply nodes).

**Generalized rule for the runbook:** when n8n nodes consume fields from a non-immediate upstream node, always use `$('Source Node').item.json.field`. `$json.field` is a footgun in any non-linear or multi-stage workflow — fine for two-node chains, silently wrong for anything more complex. Same family as A1's "Expression mode auto-prefixes `=`" gotcha — both are n8n syntactic surprises that fail at runtime, not validation time.

The pre-fix Slack post in #alerts (single message, body literal `"undefined"`) is a harmless audit-trail artifact; left in place.

---

## 2026-04-28

- Brainstorm completed; design approved across 7 sections (summary/goal/scope/approach, topology, IOC selection + payload, Iris HTTP calls, Slack message + URL buttons, Wait/Resume + branching, error handling/testing/success criteria).
- Key architectural decisions captured in [[spec]]:
  - Pattern Y: modify A1's `/alerts/add` to carry `alert_iocs`; gate fires on the `/alerts/escalate/{alert_id}` call (alert→case escalation as the gated action).
  - Plumbing: Slack URL buttons → analyst's LAN browser → n8n Wait/Resume webhook (no public tunnel, no Slack interactivity webhook).
  - Source of IOCs to push: `iocs_enriched` filtered to `verdict ∈ {malicious, suspicious}`.
  - Gate trigger: fire only when filtered list is non-empty; otherwise skip (Test 1's path).
  - Timeout: 30 minutes, treated as Deny.
  - Schema: additive `ioc_type` field on `iocs_enriched` items (still v1; ADR to be written).
- Validated against the actual DFIR-Iris OpenAPI spec rather than the vault's component-page summary (which had `/iocs/add` instead of the actual `/case/ioc/add`). The OpenAPI spec is at [`JSON/IRIS-2.0.4-OpenAPI-specification.json`](../../../JSON/IRIS-2.0.4-OpenAPI-specification.json).
- Open verifications for Phase 0 of the implementation plan:
  - `$execution.resumeUrl` resolution timing in pre-Wait nodes
  - Wait node timeout-result field name (likely `$json.timedOut`)
  - Wait node "Respond Immediately" mode behavior
  - Iris IOC type ID catalog (`curl /manage/ioc-types/list`)
  - n8n Slack node Block Kit JSON acceptance
