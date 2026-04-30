---
status: accepted
date: 2026-04-29
related: [[../subprojects/2026-04-28-iris-escalation-gate/spec]], [[../subprojects/2026-04-27-structured-outputs/spec]]
---

# 0005 — Additive `ioc_type` enhancement to A1's `iocs_enriched` schema (v1, not v2)

## Status

Accepted

## Context

A1 shipped `submit_triage_result` with a `schema_version: "v1"` field on the tool's input schema. Each item in `iocs_enriched` had `value`, `verdict`, `source`, `summary` — no field identifying *what kind* of IOC it was (IP vs domain vs hash). A1 didn't need that distinction because Slack and Iris both received `iocs_enriched` only as freeform display strings; there was no programmatic routing on IOC type.

A2's `Extract Triage Result` Code node needs to map each IOC to a specific Iris `ioc_type_id` integer (79 for `ip-src`, 20 for `domain`, 90/111/113 for `md5`/`sha1`/`sha256`). The mapping requires two pieces of information: the **category** of the IOC (IP / domain / hash) and, for hashes, the **hex length** to pick the right hash algorithm. Hex length is derivable from the value itself; category is not — `1.2.3.4` could be parsed as a domain by a too-permissive regex, and lazy heuristics (presence of dots, colons, hex chars) all have edge cases.

Two ways to add the missing category:

1. **Bump to schema v2.** Add `ioc_type` as a required field, mark the change as a breaking version bump, update `schema_version` enum to include `"v2"`, branch `Extract Triage Result` on `r.schema_version` to handle both v1 and v2 inputs, and update consumers.
2. **Add `ioc_type` to v1 as a new field.** Keep `schema_version: "v1"`. Update the system prompt to instruct Claude to populate it. Update `Extract Triage Result` to read it. Old A1-style outputs without the field would still parse — only the new A2 routing logic depends on the new field; A1's display-only consumers continue to work unchanged.

## Decision

**Option 2 — additive change to v1.** No version bump. `iocs_enriched` items gain an optional-by-shape, required-by-prompt `ioc_type` enum (`ip` | `domain` | `file_hash`).

The schema is still semantically v1: the contract A1 published — "every IOC has `value`, `verdict`, `source`, `summary`" — remains unchanged. Adding `ioc_type` doesn't break that contract. An A1-era consumer that doesn't read the new field continues to function. The A2 Code node is the only consumer that *requires* the new field, and it ships in the same change as the schema enhancement, so there's no producer/consumer skew window.

The `schema_version` field stays `"v1"`. We do not introduce `"v1.1"` or any other intermediate marker — semantic versioning of a tool-call schema is overkill for a single-team, single-deployment lab where the producer and consumer ship together.

## When v2 *will* be triggered

A schema v2 bump becomes necessary when one of these happens:

1. **A second action type appears that needs a different proposed_actions structure.** A3 (Splunk lookup blocklist) is the planned trigger. A3's gated action — write IPs to a Splunk KV-store lookup — surfaces the question of how to cleanly represent multiple proposed actions on a single alert (escalate to case AND add to blocklist, or escalate to case AND disable user, etc.). At that point a structured `proposed_actions` array (each entry typed by action) replaces the implicit "the IOC list is the action input" coupling A2 currently relies on. That's a real shape change — old consumers can't ignore it — so v2.
2. **An existing field's *type* changes.** E.g., if `verdict` becomes a structured object instead of an enum string. A consumer that read it as a string would break.
3. **An existing field's *required* status changes** in a way that an old consumer's null-check would mishandle. E.g., if `summary` becomes optional, an old consumer that always rendered `iocs_enriched[i].summary` would render `undefined`.
4. **The system prompt's interpretation of an existing field changes.** E.g., if `verdict: "suspicious"` starts meaning "needs human review" instead of "AbuseIPDB flagged but below threshold".

When any of these triggers, the version-bump procedure is:

1. Add `"v2"` to the `schema_version` enum on the tool's input schema.
2. Update the system prompt to document the v2 shape.
3. Branch `Extract Triage Result` on `r.schema_version` to handle both v1 and v2 outputs, until A1-style v1 consumers are decommissioned.
4. Write a new ADR documenting what changed and why v2 was needed.

## Consequences

**Positive**

- A2 ships without a version-bump procedure that would have been mostly ceremony — there's only one consumer (`Extract Triage Result`) and it's modified in the same change.
- Keeps the `schema_version` field meaningful: v1 -> v2 will be a real shape change, not "we added a field".
- A3's eventual v2 bump pays for the version-bump cost when the structured-actions change actually justifies it — by then the schema will have one or more real shape changes (proposed_actions array, possibly other refinements) bundled together.

**Negative**

- The system prompt now has an implicit contract that `ioc_type` be populated, but the schema (in the strictest formal sense) doesn't require it. Anthropic's tool-use schema enforcement treats `required` as advisory anyway (A1 already discovered this for `investigation_notes`), so a stricter formal schema wouldn't prevent omission. Code node has no fallback for missing `ioc_type`; an IOC without the field is silently dropped (`resolveIrisTypeId` returns null -> `console.warn` skips it). Acceptable given the field is part of A1's display-only fallback path; missing the field on a malicious IOC means it doesn't make it into the case-level threat-intel database, but the alert is still created and the analyst still sees the Slack notification.
- Slight risk of confusion in a year if someone reads `schema_version: "v1"` and assumes the schema is exactly what A1 shipped. Mitigated by this ADR and by the spec for A2 documenting the addition.

**Neutral**

- No external producer/consumer skew is possible (single-team, single-deployment lab); the negative consequences listed are all internal review/maintainability concerns, not correctness risks.
