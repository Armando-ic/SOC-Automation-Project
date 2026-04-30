---
status: accepted
date: 2026-04-30
related: [[../subprojects/2026-04-30-detection-foundations/spec]], [[../architecture/components/sysmon]], [[../architecture/components/splunk]]
---

# 0006 — Install Splunk Add-on for Microsoft Sysmon; key SPL on `XmlWinEventLog:` source prefix

## Status

Accepted

## Context

D1's brainstorm assumed Sysmon events would land in Splunk under the default `Splunk_TA_windows` (Splunk Add-on for Microsoft Windows) parsing, which is what the existing Security/App/System channels use. Spec § 2.4 wrote the SPL filter as:

```spl
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
```

— matching that default convention.

Phase 0 (2026-04-30) discovered two divergences from that model:

1. **The pre-existing UF `inputs.conf`** (last edited 2026-04-25, before D1 started) **already had a Sysmon stanza with an explicit `source = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` override.** Someone had set up the canonical Splunk-Add-on-for-Microsoft-Sysmon convention before D1 was scoped.
2. **The Splunk Add-on for Microsoft Sysmon** (Splunkbase app id `Splunk_TA_microsoft_sysmon`, v5.0.0) **was not yet installed on the indexer.** Without it, the `XmlWinEventLog:` source override on the forwarder side wouldn't trigger any add-on-specific parsing — events would be parsed by `Splunk_TA_windows` generically, but XML Sysmon events have richer field structure that the Sysmon-specific add-on extracts properly (`Hashes` triple, the full `ParentImage` chain, registry-event `Details`, etc.).

Three forks were available:

1. **Strip the `source =` override** so events land at the default `WinEventLog:Microsoft-Windows-Sysmon/Operational`. Spec wouldn't need editing. Field extraction would be limited to whatever `Splunk_TA_windows` does for Sysmon's XML envelope (less rich).
2. **Keep the override + install the Splunk Add-on for Microsoft Sysmon.** Use `XmlWinEventLog:` as the canonical source value throughout. Spec/plan/SPL all need a global rewrite from `WinEventLog:` to `XmlWinEventLog:`. Field extraction becomes first-class.
3. **Don't restart the forwarder** so the override stays dormant. Defer the decision. Loses the chance to validate end-to-end during D1.

## Decision

**Option 2 — install the Splunk Add-on for Microsoft Sysmon and key all SPL on the `XmlWinEventLog:` source prefix.**

The Add-on was installed during Phase 0 (mid-execution) once the inputs.conf override was discovered. Spec.md and plan.md were globally rewritten (28 occurrences in plan.md, 6 in spec.md) and the change captured in spec.md's Errata section as E1.

Per-reasons:

- **The canonical convention is `XmlWinEventLog:`.** The Splunk Add-on for Microsoft Sysmon is the de-facto industry default for Sysmon parsing in Splunk; SOC professionals encountering this lab in an interview context (D1's design driver) would expect this convention.
- **First-class field extraction** for `Image`, `CommandLine`, `ParentImage`, `Hashes`, registry `Details`, etc. The generic `Splunk_TA_windows` handles Windows Event Log channels but doesn't have Sysmon-specific parsers. Without `Splunk_TA_microsoft_sysmon`, fields would still be present in `_raw` but not search-time-extracted, requiring manual `rex` for every detection.
- **Pre-existing `inputs.conf` was already aligned** with this convention. Someone had set this up without scope-creeping the original D1 brainstorm; respecting that prior decision is cheaper than reverting it.
- **No additional ongoing cost.** The add-on is free, maintained by Splunk LLC, and runs on the indexer (no per-host overhead).

## Consequences

### Positive

- All Sysmon SPL in this lab uses `source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"` consistently (worked-example detection, observation toolkit, smoke tests, `sysmon.md` reference page).
- Field extraction is first-class — `| stats` and `| table` clauses work on `Image`, `CommandLine`, `ParentImage`, `Hashes`, etc., without needing `rex` or `spath`.
- `Hashes` field came back populated with all three algorithms (MD5, SHA256, IMPHASH), enabling future hash-based pivot detections.
- Future detection sub-projects (B EDR, C detection-at-scale, H purple team) inherit the convention with no further decision-making.

### Negative / trade-offs

- **`host` field, not `ComputerName`.** The Sysmon-specific add-on's parsing populates the `host` metadata field with the originating Windows hostname; `ComputerName` is empty/null when piped through `| stats by`. Spec/plan had to be rewritten on this too (Errata E5). Future SPL must remember `host` not `ComputerName`.
- **Lock-in to the Sysmon add-on.** A future Splunk migration that doesn't install this add-on would break our existing SPL — the source value would default to `WinEventLog:` and no current detection would match. Mitigation: the migration runbook would call this out and the SPL is centralized in one technique page per detection (easy to grep + replace).
- **Spec/plan rewrite cost.** 34 line-edits across spec.md and plan.md to switch from `WinEventLog:` to `XmlWinEventLog:` prefix. Moderate one-time cost; documented exhaustively in Errata so future-fresh-instance can audit the change.
- **PowerShell + Defender source values changed as collateral.** The pre-existing UF `inputs.conf` had similar `source =` overrides on `Microsoft-Windows-PowerShell/Operational` and `Microsoft-Windows-Windows Defender/Operational` stanzas that hadn't yet activated. Phase 2's UF restart activated all three at once. Vault grep confirmed zero downstream consumers, but any future search/dashboard against those channels must use the prefix-less form. Documented in `splunk.md`.

## Alternatives considered

**Option 1 (strip the override)** would have been the lowest-edit path, but rejected because:
- It throws away the field-extraction richness the Sysmon-specific add-on provides.
- It diverges from the SOC-industry-canonical convention; future-fresh-instance reading the lab in an interview context would have to explain why this lab is different.
- The override was already in place from prior tutorial setup; reverting it adds a "why was this changed?" question for any future reader.

**Option 3 (defer)** rejected because D1 needs to produce a working end-to-end worked example by closeout. Deferring source-value decisions blocks Phase 4 (SPL development) and Phase 5 (saved search). The decision had to be made during Phase 0 to keep the rest of D1 on track.

## Notes

- This ADR was anticipated by D1's spec.md § Success criteria: *"No ADR is currently planned for D1. ... If one surfaces during implementation — e.g., we discover we need to install the Splunk Add-on for Microsoft Sysmon and want to record that choice — it becomes ADR 0006."*  The exact scenario the spec anticipated occurred and produced this ADR.
- The Add-on's installed version (5.0.0) and `app id` (`Splunk_TA_microsoft_sysmon`) are recorded in `splunk.md`'s "Apps installed" section.
- The convention is also documented in `sysmon.md`'s "Why `source=` (not `sourcetype=`) is the channel filter" section.
