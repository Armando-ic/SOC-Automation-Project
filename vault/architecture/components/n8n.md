---
status: active
updated: 2026-04-29
related: [[architecture/current-state]], [[workflows/soc-triage-pipeline]]
---

# n8n

## What it is

Workflow automation engine playing the SOAR role. Runs in Docker via docker-compose on Ubuntu Server (`MyDFIR-n8n-VM`, 192.168.129.132).

## Configuration

| | |
|---|---|
| Web UI | http://192.168.129.132:5678 |
| Default port | 5678 |
| Run command | `cd ~/n8n-compose && sudo docker-compose up -d` |
| Image | `n8nio/n8n:latest` |
| Data volume | `~/n8n-compose/n8n_data/` (chowned to UID:GID 1000:1000) |

## Configured credentials in n8n

(IDs reference the credential within the n8n instance, not secret values.)

| Credential | n8n credential ID | Used by |
|---|---|---|
| Anthropic account | `VozkiMP8QqbykLLj` | Message a model node |
| Slack account | `IWEqjD1DvRajiKXy` | Send a message node |
| VirusTotal account | `MPJtvrtzx8nfI5Ot` | VirusTotal-Hash tool, phishing template |
| DFIR-IRIS account | `rwvgiJMaHqI9hCC9` | DFIR-IRIS HTTP Request node |

AbuseIPDB key is currently inline in the workflow JSON, not a credential — to be migrated as part of [[subprojects/2026-04-27-structured-outputs/README]].

## Workflows

- **My workflow** (id: `45gQjuH2MFQYrlEx`) — the SOC triage pipeline. See [[workflows/soc-triage-pipeline]].
- Two templates imported for reference:
  - `Phishing_analysis__URLScan_io_and_Virustotal_` — pattern reference for iteration, error gating, async waits
  - `My workflow 2` (Zendesk + Qdrant) — pattern reference for structured output parsing and RAG retrieval

## How to access

- Web UI: http://192.168.129.132:5678
- SSH: `ssh mydfir@192.168.129.132`
- See [[runbooks/n8n-workflow-deployment]] for deploying changes

## Wait-node resume URLs are signed (captured 2026-04-29)

n8n's Wait node, when in **On Webhook Call** mode, generates resume URLs of the form:

```
http://192.168.129.132:5678/webhook-waiting/<execution_id>?signature=<token>
```

The `signature` query parameter is computed server-side from execution data using a server secret — it is **unguessable and cannot be reconstructed manually**. Hitting `http://.../webhook-waiting/<execution_id>?decision=approve` (without the signature) returns `{"error": "Invalid token"}`.

**Always use `{{ $execution.resumeUrl }}`** in any node that constructs a resume URL (Slack URL buttons, email approval links, etc.). It populates with the full signed URL during expression resolution — confirmed to work even in nodes **before** the Wait node runs (e.g., a Slack post node upstream of Wait). When appending decision-or-other parameters, use `&` not `?` because the URL already has `?signature=...`:

```
{{ $execution.resumeUrl }}&decision=approve
{{ $execution.resumeUrl }}&decision=deny
```

Discovered while building [[../../subprojects/2026-04-28-iris-escalation-gate/spec]]'s Slack approval gate. The original spec assumed a manual-construction fallback was viable — it isn't, in this n8n version. See [[../../subprojects/2026-04-28-iris-escalation-gate/spec#errata-post-implementation-corrections]] entry E3 for the as-shipped pattern.

**Side benefit (security):** the signed-token requirement makes the access-control surface "anyone with the Slack message" rather than "anyone on the LAN who can guess execution IDs". Sub-project A2.5's signed-Slack-interactivity scope shrinks accordingly.

## Wait-node timeout doesn't set a `timedOut` field (captured 2026-04-29)

When a Wait node times out, n8n does **not** add a `timedOut: true` field to the output item. Instead, the upstream item passes through Wait unchanged — Wait acts as a no-op pass-through on timeout. There is no special marker distinguishing a timed-out resume from an unrelated upstream-data shape.

**Implication for downstream Switch design:** if a workflow's branching depends on whether the Wait timed out, branch on the **presence/value of expected resume-data fields** instead. For A2's approval gate, that means `$json.query.decision === 'approve'` and `=== 'deny'` are the active branches; a fallback (catch-all) branch handles timeout (and any other malformed resume).

Documented in [[../../subprojects/2026-04-28-iris-escalation-gate/runbook]]'s "Build new IOC types or new gated actions" section as the pattern future gated-action sub-projects (A3+) should reuse.
