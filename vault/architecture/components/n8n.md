---
status: active
updated: 2026-04-27
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
