---
status: draft
updated: 2026-04-27
related: [[architecture/current-state]]
---

# Target State

Where the project is heading. Not a commitment — a direction. Updated as sub-projects ship and priorities evolve.

## Phase 1 — Tighten the foundation (in progress)

- **A1: Structured Outputs** — schema-driven AI responses, fix the known bugs ([[subprojects/2026-04-27-structured-outputs/README]])
- **A2: Response Actions** — Slack approval gate, Splunk lookup blocklist, IOC push to DFIR-Iris

## Phase 2 — Capability expansion

- **B: EDR layer** — LimaCharlie or Velociraptor, generates real endpoint telemetry
- **C: Detection engineering** — Sigma rules, multiple detection types, MITRE coverage map

## Phase 3 — AI sophistication

- **D: Multi-agent triage** — router agent dispatches to specialist agents (malware, identity, network)
- **E: Case memory** — vector DB of historical alerts, RAG retrieval ("this looks like case #47")

## Phase 4 — Operational maturity

- **F: Observability** — Grafana dashboard of automation metrics
- **G: Purple team validation** — automated weekly Atomic Red Team runs verifying detections still fire
- **H: Threat intel** — MISP integration

## Non-goals (for now)

- Production use — this is a lab and portfolio piece, not for processing real customer data
- Scale beyond a single analyst's workflow
- Replacing commercial SOAR — the goal is to *understand* SOAR by building one
