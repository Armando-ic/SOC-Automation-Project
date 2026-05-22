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
| T1059.001 | Execution | saved-search-active *(currently disabled — see notes)* | 2026-05-12 | [[t1059-001-powershell-encoded]] |
| T1059.003 | Execution | saved-search-active | 2026-05-20 | [[t1059-003-cmd-suspicious-ioc-references]] |

**Note on T1059.001 disable state:** the saved search was temporarily disabled during the 2026-05-19/20 recording-prep session to avoid duplicate-alert noise during the demo (T1059.003 was created as the demo path because it naturally exercises both enrichment tools). The T1059.001 detection itself is still valid; re-enable as part of post-recording cleanup with corrected throttle settings (see [[../subprojects/2026-04-30-detection-foundations/runbook]] §Recoveries).

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
