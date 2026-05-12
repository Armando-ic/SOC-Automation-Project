---
status: accepted
date: 2026-05-12
related: [[../subprojects/2026-04-28-iris-escalation-gate/spec]], [[../architecture/components/n8n]], [[../architecture/components/dfir-iris]], [[0005-additive-ioc-type-schema-enhancement]]
---

# 0007 — Remove Slack from n8n workflow; move human-approval gate to IRIS-native review

## Status

Accepted

## Context

The 2026-05-08 OneDrive incident forced a from-scratch rebuild of n8n + IRIS. That rebuild surfaced two realities that, together, justify a design pivot:

1. **Slack OAuth re-auth is a recurring high-friction operation.** Every n8n rebuild requires re-doing Slack's OAuth flow against the lab's Slack workspace, re-binding the credential into the workflow, and re-validating that interactive button callbacks reach the Wait-resume URL. The token is per-install — there is no shortcut to restore it from documentation. In a lab that gets rebuilt occasionally (Win10-v2, n8n-v2, IRIS-v2 in the last week), this tax compounds.

2. **The approval gate's natural home is the ticket system, not the chat surface.** A2 shipped a Slack-interactive Wait-resume gate (ADR 0005, subproject 2026-04-28-iris-escalation-gate). The technical pattern works — signed-Slack-button URLs trigger n8n Wait-node resumes, decision branches escalate or close — but reflection on real-SOC practice shows that production SOCs treat the ticket system (IRIS, Jira, Splunk SOAR, etc.) as the system of record for case decisions. Chat is a notification surface, not a workflow surface. Building approval routing through chat puts the system-of-record dependency in the wrong place.

The lab simplification opportunity from (1) aligns with the design-fidelity-to-real-SOCs argument from (2). Both point the same way.

## Decision

`SOC-Triage-v3.json` (new canonical workflow) drops:

- All Slack nodes (`Send a message`, `Post Slack Alert + Approve/Deny`, `Reply: Approved + case`, `Reply: Approved but escalate failed`, `Reply: Denied`, `Reply: Timeout`)
- The Wait node that paused execution for the Slack-decision callback
- The Switch node that routed on approve/deny/timeout
- The `Escalate Iris Alert` HTTP node that auto-promoted the alert to a case on approval

The workflow terminates at **`Create Iris Alert`**. Every triaged event lands in IRIS with status `1` (New) and full IOC + severity payload. The human approval gate moves into IRIS's native alert review UI: an analyst opens the alert in IRIS, reviews enriched context, and clicks **Escalate to Case** (or closes with resolution) directly from the IRIS interface.

The `slackApi` credential type is no longer referenced by the workflow. AbuseIPDB, VirusTotal, DFIR-IRIS, and Anthropic credentials remain.

## Consequences

**Positive**
- Workflow graph reduces from ~14 nodes to ~7. Single linear path, no branching, no waiting.
- One fewer external SaaS dependency to maintain. Rebuild cost drops by the entire Slack re-auth step.
- Design now matches industry practice: ticket system is source of truth; chat is downstream notification (and can be added back later as a fire-and-forget fan-out from the IRIS alert, if desired).
- Eliminates Wait-node and Switch-node failure modes from the gate path (timeout handling, signature mismatch, etc.).

**Negative**
- Loses the real-time chat notification surface. Mitigation: IRIS's own alerts dashboard at `https://192.168.129.133/alerts` serves the same "what's new?" function for an analyst with IRIS open. If chat notification becomes operationally important later, it can be re-added as a parallel fan-out branch from the workflow without restoring the gate machinery.
- Loses the auto-escalation-on-approval ergonomics. Analysts now perform one extra click in IRIS (open alert → Escalate to Case) for each promotion. For a lab/portfolio context this is fine; for a high-volume production SOC it would matter.

**Relationship to ADR 0005 and subproject A2**

ADR 0005 (additive `ioc_type` schema enhancement) is **not superseded** — that decision concerned the `iocs_enriched` schema, which v3 continues to use unchanged when populating IRIS alert's `alert_iocs` field. A1's structured-outputs work (Code node `Extract Triage Result`, severity/IOC-type mapping tables) is preserved verbatim in v3.

Subproject A2 (`2026-04-28-iris-escalation-gate`) shipped a working Slack-interactive escalation gate; v3 retires that pattern from the active workflow but does **not delete the work**. The A2 spec, plan, runbook, ADR 0005, and component-doc captures of the Wait-node signed-URL pattern (`n8n.md` "Wait-node resume URLs are signed" section) remain as canonical documentation of the design. Future work that re-introduces a chat-platform approval surface (Slack, Teams, Matrix) can branch off v3 and re-apply A2's Wait-resume pattern; the learning is preserved in the vault.

**Workflow file naming**

`SOC-Triage-v2.json` (Slack-gated production workflow, frozen at A2-shipped state) remains in `JSON/` as historical reference.
`SOC-Triage-v3.json` becomes the new canonical workflow. The Splunk saved-search webhook URL (`http://192.168.129.132:5678/webhook/db7245f7-8451-4bea-b47d-f6ad35b818cd`) is preserved in v3 — the Webhook node's path is unchanged, so no Splunk-side change is required.

## What this ADR does *not* commit to

- It does **not** rule out re-introducing chat-platform notification later as a non-gate fan-out.
- It does **not** delete A2's design or learning from the vault.
- It does **not** change A1's structured-outputs schema, the IRIS API integration shape, or the IOC type / severity ID mappings.
