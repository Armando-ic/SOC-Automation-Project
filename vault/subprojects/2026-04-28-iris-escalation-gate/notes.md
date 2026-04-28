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
