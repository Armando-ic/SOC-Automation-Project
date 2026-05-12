---
status: active
updated: 2026-05-12
related: [[architecture/current-state]], [[workflows/soc-triage-pipeline]], [[decisions/0007-remove-slack-iris-native-gate]]
---

# n8n

## What it is

Workflow automation engine playing the SOAR role. Runs in Docker via docker-compose on Ubuntu Server 24.04 (`MyDFIR-n8n-VM-v2`, 192.168.129.132). VM rebuilt from scratch 2026-05-12 after the 2026-05-08 OneDrive incident — see [[../subprojects/2026-04-30-detection-foundations/notes#phase-11-2026-05-12--post-rebuild-revalidation-on-rebuilt-lab]] for rebuild details.

## Configuration

| | |
|---|---|
| VM | `MyDFIR-n8n-VM-v2` at `C:\VMs\MyDFIR-n8n-VM-v2\` |
| Web UI | http://192.168.129.132:5678 |
| Default port | 5678 |
| Run command | `cd ~/n8n-compose && sudo docker-compose up -d` |
| Image | `n8nio/n8n:latest` (pulled 2026-05-12) |
| Data volume | `~/n8n-compose/n8n_data/` (chowned to UID:GID 1000:1000) |
| Compose env | `N8N_HOST=192.168.129.132`, `N8N_PORT=5678`, `N8N_PROTOCOL=http`, **`N8N_SECURE_COOKIE=false`** (see Known quirks) |
| Docker / compose | Docker 29.1.3, docker-compose 1.29.2 |
| Static IP | Pinned via netplan; cloud-init network config disabled (`/etc/cloud/cloud.cfg.d/99-disable-network-config.cfg`) |

## Configured credentials in n8n (post-2026-05-12 rebuild)

After the 2026-05-12 fresh n8n install, the credential IDs are new (the old IDs `VozkiMP8QqbykLLj`, `IWEqjD1DvRajiKXy`, etc. are v2 artifacts and don't exist on the rebuilt instance). The workflow JSON references the OLD IDs, so each credential must be re-bound to the corresponding node post-import.

| Credential | n8n type | Used by | Notes |
|---|---|---|---|
| Anthropic account | `anthropicApi` | Message a model node | API key from gitignored secrets file |
| VirusTotal account | `virusTotalApi` | lookup_file_hash_virustotal (AI tool) | API key from secrets file |
| AbuseIPDB account | `httpHeaderAuth` (Header Auth) | enrich_ip_abuseipdb (AI tool) | Header name `Key`, value is API key. **Migrated from v0-inline-key to credential during A1.** |
| DFIR-IRIS account | `dfirIrisApi` | Create Iris Alert (HTTP Request) | Host `https://192.168.129.133`, Bearer API key from secrets file. **Enable "Ignore SSL Issues" — IRIS uses self-signed cert.** |

**Slack credential intentionally absent** as of v3 (ADR 0007 — human approval moved to IRIS-native review).

## Workflows

- **SOC Triage v3** — current production workflow on the rebuilt n8n instance. Imported from `JSON/SOC-Triage-v3.json`. See [[workflows/soc-triage-pipeline]].
- Two templates imported for reference (carried forward through rebuild for documentation purposes — re-import them post-rebuild if you want them back; they're not loaded on the v2 VM by default):
  - `Phishing_analysis__URLScan_io_and_Virustotal_` — pattern reference for iteration, error gating, async waits
  - `My workflow 2` (Zendesk + Qdrant) — pattern reference for structured output parsing and RAG retrieval

## Known quirks (post-rebuild 2026-05-12)

### `N8N_SECURE_COOKIE=false` is required for LAN HTTP access

`n8nio/n8n:latest` (current image) defaults to `N8N_SECURE_COOKIE=true`, which blocks any non-localhost HTTP access with a "secure cookie required" wall on `/setup`. Three options:
- HTTPS via TLS reverse proxy (real fix — significant scope, deferred)
- `localhost` only (not viable — we need LAN access from Splunk and host browser)
- `N8N_SECURE_COOKIE=false` (pragmatic; this is what's set)

For a lab on a private NAT-only subnet this is fine. For internet-exposed deployment it would not be.

### docker-compose 1.29.2 `--force-recreate` is broken against newer Docker

`docker-compose up -d --force-recreate` fails with `KeyError: 'ContainerConfig'` in `/usr/lib/python3/dist-packages/compose/service.py` because newer Docker (29.x) deprecated that field in image inspect output. Workaround: `docker-compose down && docker-compose up -d` instead of using `--force-recreate`.

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
