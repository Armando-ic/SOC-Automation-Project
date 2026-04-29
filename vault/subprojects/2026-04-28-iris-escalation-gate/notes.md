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

## 2026-04-28 (impl) — Phase 5.2 IF strict-type-validation gotcha

The IF node's default `typeValidation: "strict"` mode rejects values whose JS type doesn't match the declared comparison type. After adding the `Has Malicious IOCs?` IF with `Number > 0`, executions failed with:

> Wrong type: '1' is a string but was expecting a number [condition 0, item 0]

Root cause: a trailing `\n` (newline) had been left in the leftValue expression field — `={{ $('Extract Triage Result').item.json.alert_iocs.length }}\n`. The newline coerced n8n's numeric result (`1`) to a string (`'1\n'`) via implicit concatenation, which strict mode then rejected.

Fix: strip the trailing whitespace from the leftValue field. Alternative workaround would be toggling "Convert types where required" ON, but that masks the cause; clean expression is preferable.

**Generalized rule for the runbook:** when typing expressions into n8n condition fields, ensure the value ends with `}}` and nothing after. The field's text editor sometimes inserts a newline on Enter — review by clicking back into the field after pasting.

---

## 2026-04-28 (impl) — Phase 5.3 native Slack node Block Kit support is a dead end

Phase 0.3 confirmed n8n Slack node v2.4 *exposes* a Block Kit JSON field via `Message Type: Blocks` → `Blocks` field. Implementation in Phase 5.3 found that the field accepts JSON input (with no error in either Expression or Fixed mode) but **n8n does not actually translate it to a `blocks` field in the outgoing Slack API request**. Slack receives only the `text` parameter and synthesizes a single `rich_text` block as fallback — buttons, dividers, action prompts never appear.

Verified via two test runs:
1. Real Block Kit JSON with cross-graph expressions and JSON.stringify-wrapped multi-line content (Expression mode): Slack response showed only the text-fallback rich_text block; expected 4 blocks (section + divider + section + actions).
2. Minimal hardcoded diagnostic — three plain blocks (text section, divider, actions block with one URL button to `http://example.com`) in Fixed mode: same result. No buttons rendered.

Slack API responses for both runs returned `ok: true` with `message.blocks` containing one auto-synthesized `rich_text` block. That confirms n8n is sending text-only requests; it isn't a Slack-side rejection.

This invalidates Phase 0.3's "Branch A confirmed" finding for the actual posting behavior. The Block Kit *configuration UI* exists; the *runtime translation* doesn't work in this version (n8n 2.4 Slack node, typeVersion 2.4 in workflow JSON).

**Decision:** abandon Branch A. Switch to the plan's documented **Branch B fallback**: HTTP Request node calling Slack's `chat.postMessage` API directly. This bypasses n8n's Slack node entirely and lets us send the `blocks` array as part of the explicit JSON body — the same approach we already use for DFIR-Iris.

Implementation steps from here:
- Replace the `Post Slack Alert + Approve/Deny` Slack node with an HTTP Request node, keeping the same name and IF-true-branch wiring.
- Use Slack credential reuse via HTTP Request's "Predefined Credential Type → Slack API" option (no need to extract the bot token).
- Body JSON includes `channel`, `text` (fallback for notifications), and `blocks` (the Block Kit array).
- Same Block Kit content as the failed Branch A attempt (section, divider, action prompt, two URL buttons), now safely embedded as a structured JSON body.

The four+ Iris alerts already created during Branch A debugging (#13, #14, #15, etc.) plus the Slack messages without buttons all stay as harmless audit-trail artifacts.

**Update Phase 0.3 finding in retrospect:** the "native Slack node + Block Kit" path looked viable based on UI exploration, but only end-to-end implementation surfaced that the field doesn't wire through. Future Phase-0-style verifications for new node types should always include a minimal end-to-end test (post a hardcoded payload, confirm Slack actually receives it as expected) — UI presence ≠ runtime functionality.

---

## 2026-04-29 (impl) — Phase 6 verified + Phase 0.2 answered live

Three concrete findings, one critical, plus Phase 0.2's deferred questions all answered against a real Wait node.

### 1. CRITICAL — n8n Wait webhooks require a signed token

The plan's documented manual fallback URL form `http://192.168.129.132:5678/webhook-waiting/{{ $execution.id }}?decision=...` **does not work** in this n8n version. Hitting that URL returns `{"error": "Invalid token"}`. n8n's Wait node generates resume URLs of the form:

```
http://192.168.129.132:5678/webhook-waiting/<execution_id>?signature=<token>
```

The `signature` query parameter is computed from execution data using a server secret — it's unguessable and cannot be reconstructed manually.

**Fix:** Slack button URLs must use `{{ $execution.resumeUrl }}` (which n8n populates with the full signed URL during expression resolution, even in nodes BEFORE the Wait). Append `&decision=approve|deny` (using `&` not `?`, since the URL already has `?signature=...`):

```
{{ $execution.resumeUrl }}&decision=approve
{{ $execution.resumeUrl }}&decision=deny
```

This was committed via the Phase 6 bundle alongside the Wait node addition.

**Side benefit (security):** the original spec accepted "anyone with LAN access + the resume URL can approve" as the threat model. With signed URLs, only someone who already received the Slack message can approve — Slack-mediated authorization for free. A2.5 (signed Slack interactivity) gets a smaller scope as a result.

### 2. Phase 0.2 question 1: `$execution.resumeUrl` resolution timing

Confirmed: **`$execution.resumeUrl` populates correctly in the Slack node, before the Wait node runs.** Resolved value at Slack-post time matched the URL n8n's Wait node listened on. Spec section 5b's open question is closed.

### 3. Phase 0.2 question 2: Wait node timeout-result shape — the surprise

Spec assumed `$json.timedOut === true` would be the timeout indicator. **That field does not exist.** The Wait node has TWO distinct output shapes depending on what triggered the resume:

| Case | Wait node output |
|---|---|
| **Click (webhook hit)** | `{ headers, params, query: { signature, decision }, body, webhookUrl, executionMode }` — n8n replaces the item with the resume request's data |
| **Timeout** | Upstream item passes through **unchanged** (the Slack node's `chat.postMessage` response in our case) — no `timedOut` field, no special marker |

Verified live: timeout execution #71 (Wait time set to 30s for the test) completed in 30.329s; Wait node's OUTPUT panel showed the upstream Slack response object, identical to its INPUT panel.

**Implication for Phase 7's `Decision?` Switch design:** branch on **presence/value of `$json.query.decision`**, not on `$json.timedOut`:

- `$json.query.decision === 'approve'` → escalate sub-flow
- `$json.query.decision === 'deny'` → deny reply
- otherwise (undefined when timeout passes through Slack data, or any malformed query) → timeout reply

The original spec section 6c table entries `timeout: $json.timedOut === true` and `(fallback): malformed query → Deny` collapse into a single defensive design where any non-`approve`/non-`deny` value (including undefined-on-timeout) routes to the timeout reply. Cleaner than the spec's three-way + fallback.

### 4. Phase 0.2 question 3: Wait node "Respond Immediately" + custom HTML response — partial

Wait node's **Respond mode = Immediately** is set correctly. The configured `responseData` (HTML page) and `responseHeaders` (Content-Type: text/html) are persisted in the workflow JSON. **However, the response body sent to the analyst's browser is `{"message":"Workflow was started"}`, not our HTML page.** This appears to be a behavior of n8n's Wait node where `responseData`/`responseHeaders` only apply to certain Webhook trigger configurations, not to resume-webhook responses.

**Decision:** defer to a polish task. The functional behavior is fine — workflow resumes correctly; the analyst sees a one-line JSON message for ~1 second before closing the tab; the Slack thread reply (Phase 8) is the authoritative outcome surface. If we later want the pretty page, options are:
- Add a Respond to Webhook node downstream of Wait (probably) — requires changing Wait's Respond mode to "Use Respond Node"
- Accept the JSON response as a known limitation

Captured as a `runbook.md`-worthy known limitation when we get to Phase 12.

### 5. Side observation — Slack interactivity warning on URL buttons

Slack shows a small ⚠️ "This app is not configured to handle interactive responses. Please configure interactivity URL for this app under the app config page." warning next to URL buttons. This is benign — Slack flags `actions` block buttons as interactive elements expecting a Slack interactivity webhook, but URL-only clicks (our pattern) work fine without one. The warning can be eliminated by switching to a different block representation (e.g., a section with mrkdwn links instead of a buttons actions block), at the cost of styled buttons. Acceptable for A2; revisit in A2.5.

### 6. Side bookkeeping

The dev-cycle timeout (30 seconds) was reset to 30 minutes (1800 seconds) before exporting v2 JSON. Iris alerts created during Phase 6 testing (#16-#20+) and corresponding Slack posts in #alerts are harmless audit-trail artifacts.

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
