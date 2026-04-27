---
status: active
date: 2026-04-27
---

# 0003 — Split Sub-project A into A1 (Structured Outputs) and A2 (Response Actions)

## Status

Accepted

## Context

In planning, the next sub-project was framed as "Structured Outputs + Response Actions" — a single unit. On closer inspection these are two distinct kinds of work:

- **Structured Outputs** is a refactor of an existing node (Anthropic message), no new external integrations.
- **Response Actions** adds new nodes, new credentials (Slack approval flow, possibly Splunk admin token), and a human-in-the-loop approval pattern.

Their dependencies are asymmetric: A2 needs A1 (response actions need structured fields like severity to make routing decisions), but A1 does not need A2.

## Decision

Treat them as two separate sub-projects. A1 is the next brainstorm. A2 gets its own brainstorm cycle after A1 ships.

## Consequences

**Positive**

- A1 is small enough to actually finish in one or two evenings
- Validates the spec → plan → execute workflow before applying it to bigger work
- Tangible improvement (structured AI output, three bug fixes) shipped sooner
- A2 can be designed knowing the actual shape of A1's output

**Negative**

- Two brainstorm cycles instead of one
- Slightly more vault overhead (two folders vs one)
