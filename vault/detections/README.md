---
status: active
updated: 2026-04-30
related: [[_template]], [[../architecture/components/sysmon]], [[../subprojects/2026-04-30-detection-foundations/runbook]]
---

# Detections — coverage index

Per-MITRE-technique catalog of detection content in this lab. Each entry tracks one technique through its lifecycle: `untested` (no evidence yet) → `observed` (ART run, Sysmon captured something) → `spl-drafted` (SPL exists in the page) → `saved-search-active` (Splunk saved search firing the v2 webhook).

To add a technique: copy `_template.md` to `t<id>-<short-name>.md` (with dots converted to dashes — `T1003.001` → `t1003-001-...`), populate, link from the table below. See [[../subprojects/2026-04-30-detection-foundations/runbook]] for the operational "run a technique" loop.

## Coverage

| Technique ID | Tactic | Status | Last Run | Page |
|---|---|---|---|---|
| T1059.001 | Execution | saved-search-active | 2026-04-30 | [[t1059-001-powershell-encoded]] |

## Status lifecycle

- **untested** — page exists as a placeholder; no ART run yet, no Sysmon evidence.
- **observed** — ART has been run; Sysmon captured events; observations recorded in the page.
- **spl-drafted** — a hand-written SPL exists in the page that detects the technique against a real ART event.
- **saved-search-active** — a Splunk saved search wraps the SPL and fires the v2 production webhook on a 5-minute cron.

The lifecycle is monotonic for any one technique — pages move forward, not back, unless a saved search is intentionally retired (which becomes its own log entry).

## See also

- [[../architecture/components/sysmon]] — Sysmon EventCode + field reference; install metadata.
- [[../architecture/components/splunk]] — Splunk saved-search inventory and configuration.
- [[../subprojects/2026-04-30-detection-foundations/runbook]] — operational procedure for running a technique and updating its catalog page.
- MITRE ATT&CK matrix: https://attack.mitre.org/matrices/enterprise/
