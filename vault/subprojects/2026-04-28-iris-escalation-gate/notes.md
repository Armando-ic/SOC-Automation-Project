# Notes — Sub-project A2, Iris Escalation Gate

Working notes, gotchas, learnings, open questions discovered during build.

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
