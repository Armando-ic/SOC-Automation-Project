---
status: accepted
date: 2026-05-20
related: [[0005-additive-ioc-type-schema-enhancement]], [[../detections/t1059-003-cmd-suspicious-ioc-references]], [[../architecture/components/n8n]]
---

# 0008 — Code-node fallback for `iocs_enriched` when LLM omits the required structured field

## Status

Accepted

## Context

The `submit_triage_result` tool's JSON Schema (set in the Anthropic-node tool definition) declares `iocs_enriched` as a required field — an array of `{value, ioc_type, verdict, source, summary}` objects describing each IOC the LLM enriched via the AbuseIPDB or VirusTotal tools. A1 (Structured Outputs) and the additive enhancement in [[0005-additive-ioc-type-schema-enhancement]] established this as the canonical channel for downstream automation to surface enriched IOCs in DFIR-Iris case tickets.

The `Extract Triage Result` Code node (workflow `SOC-Triage-v3`) was originally written assuming `iocs_enriched` would be populated. It builds two downstream artifacts from it:

1. `alert_iocs[]` — the structured array submitted to IRIS via the `alert_iocs` field of `POST /alerts/add` (rich IOC entries with `ioc_value`, `ioc_type_id`, `ioc_description`, `ioc_tlp_id`, `ioc_tags`).
2. The `Enriched IOCs:` text block rendered into the IRIS alert description and the (legacy v2) Slack message — bullet list of `value — VERDICT (source): summary`.

When `iocs_enriched` is empty or missing, both artifacts collapse: `alert_iocs[]` becomes `[]` and the rendered text becomes `_none_`. Downstream the IRIS alert's IOC tab shows no entries and the description's "Enriched IOCs" section reads `_none_`, even when Claude has the enrichment data.

The 2026-05-19/20 recording-prep test runs surfaced this as a real, reproducible behavior:

- Claude **consistently omits `iocs_enriched` entirely** from `submit_triage_result` calls, even after the system prompt was hardened with imperative instruction (`REQUIRED`, `MUST`, example payload, explicit downstream-consequence note).
- Claude **does populate `iocs`** (the flat categorized object — `iocs.ips[]`, `iocs.file_hashes[]`, `iocs.domains[]`) reliably and accurately.
- Claude **does cite the enrichment data in prose** (`alert_summary` references "100% AbuseIPDB confidence, Tor exit", "EICAR test file"). The data is there; Claude just doesn't translate it into the structured channel.
- **n8n's tool-schema validator does not enforce JSON Schema `required` strictly.** A `submit_triage_result` call that omits a schema-required field is accepted as a successful tool call, and the workflow proceeds. There is no submission-time feedback to the LLM that the call was non-compliant.

Two root causes operating together:

1. **LLM judgment on structured-vs-prose redundancy.** Claude appears to treat in-prose citation as sufficient and judges the structured field as duplicative, optimizing tokens away. This is a generalizable instruction-following gap, not specific to this lab.
2. **No schema enforcement on the consumer side.** The Code node has no validation step before consuming `r.iocs_enriched`. Missing fields silently produce empty downstream artifacts.

Tightening the system prompt did not resolve (1); the prompt change took effect (verified by reading the Anthropic node's saved prompt) and Claude continued to omit the field. Configuring strict-mode schema enforcement at the tool layer was investigated but not pursued — n8n's `toolCode` node type does not expose a strict-mode toggle in the version in use, and patching it would require an upstream change.

## Decision

Update the `Extract Triage Result` Code node to derive `alert_iocs[]` and the `Enriched IOCs:` text block from the flat `r.iocs` object (the reliably-populated channel), attaching `iocs_enriched` metadata when present and falling back to a generic description when not.

Specifically:

- **Source of truth for "what IOCs exist":** `r.iocs.ips[]`, `r.iocs.file_hashes[]`, `r.iocs.domains[]`. Build a flat `rawIocs[]` list of `{value, ioc_type}` entries from these.
- **Source of truth for "enrichment metadata per IOC":** `r.iocs_enriched[]`, indexed by `value` for lookup. Used when present.
- **`alert_iocs[]`** is built by iterating `rawIocs`, resolving each value's IRIS `ioc_type_id` via the existing `resolveIrisTypeId` function, and attaching either the matching `iocs_enriched` entry's `source`/`summary` (rich description) or a generic `"Observed in alert payload; no inline enrichment metadata."` placeholder.
- **`Enriched IOCs:` text block** prefers rendering `iocs_enriched[]` entries (verdict + source + summary format) when the array has items; falls back to listing `rawIocs[]` (value + ioc_type only) when it doesn't.

The verdict-based filter that previously selected only `malicious|suspicious` candidates is dropped: the IRIS alert should surface every IOC observed in the event, regardless of LLM-assigned verdict. Verdict is preserved in the description text when `iocs_enriched` is populated.

Workflow file updated to `SOC-Triage-v3` (no version bump — the schema didn't change, only the consumer's robustness). The change is captured in `JSON/SOC -Triage-v3.json` at the project root.

## Consequences

**Positive**

- IRIS alert's `Enriched IOCs:` section is always populated when the alert has IOCs at all. No more `_none_` rendering for events with observed IOCs.
- IRIS alert's structured `alert_iocs[]` field is populated, which means the IRIS UI's IOCs tab on each alert now shows the IOCs as discrete, type-tagged entries — the original A1/A2 design intent finally lands.
- Workflow is robust to LLM instruction-following variability. The downstream pipeline no longer depends on Claude correctly emitting the `iocs_enriched` field for IOCs to surface.
- When Claude **does** populate `iocs_enriched`, the rich descriptions land automatically — the change is a strict superset of the prior behavior, not a replacement.

**Negative**

- When `iocs_enriched` is missing (the current case), IOC descriptions in IRIS are generic (`"Observed in alert payload; no inline enrichment metadata."`) instead of citing abuse scores, detection ratios, etc. The data is in the alert's prose summary, but not in the structured per-IOC description.
- The `verdict` filter is gone, which means clean/unknown IOCs (if any are ever observed) will also be submitted to IRIS. This was a deliberate trade: surfacing all IOCs is more aligned with real-SOC practice (analyst decides; tooling enumerates) than silently dropping IOCs the LLM judged "clean."

**Relationship to ADR 0005**

ADR 0005 (additive `ioc_type` schema enhancement) is **not superseded**. The `iocs_enriched` schema and `ioc_type` field semantics remain valid and are still consumed when present. This ADR is a downstream robustness fix, not a schema change.

## Open follow-ups

- Investigate why Claude consistently omits `iocs_enriched` despite explicit prompt + schema declaration. Angles to explore: re-framing the system prompt as example-first (lead with a complete worked submission JSON, then describe the schema); configuring n8n's `toolCode` to surface schema-validation feedback to the LLM; switching to Anthropic's structured-outputs feature directly (if available through n8n's Anthropic node). Not blocking — the fallback handles the failure mode — but worth understanding for future schema additions.
- Consider raising a workflow-level error or n8n notice when `iocs_enriched` is missing but `iocs` has entries, to make the "LLM didn't populate structured field" condition visible rather than silent. Logging-only initially.
- If JSON Schema strict-mode enforcement becomes available in a future n8n version, evaluate switching to that as the primary mechanism, keeping the Code-node fallback only as a safety net.

## What this ADR does *not* commit to

- It does **not** change the `submit_triage_result` tool's input schema. The `iocs_enriched` field remains declared as `required`.
- It does **not** prevent the Code node from using `iocs_enriched` when it is populated. The fix is additive (fallback path) not replacing.
- It does **not** modify the IRIS API integration shape — `alert_iocs[]` is still posted to the same endpoint with the same field names.
