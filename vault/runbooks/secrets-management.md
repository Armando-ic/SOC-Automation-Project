---
status: active
updated: 2026-05-18
related: [[architecture/current-state]]
---

# Secrets Management

Where every secret in this project lives, and how to rotate.

## Current state (post 2026-05-18 public-repo prep)

Two gitignored files at the project root hold secrets:

| File | Purpose | Format |
|---|---|---|
| `.env` | Canonical runtime store consumed by `scripts/d1_*.py` | `KEY=value` lines |
| `SOC-Automation-Project.md` | Human-readable lab runbook (VM IPs, credentials, web-app URLs) | Markdown |

Both are listed in `.gitignore`. **Neither has ever been committed to this repo** (verified by `git log --all --diff-filter=A -- <path>` returning empty for both).

`.env.example` (tracked) documents the variable names without their values.

The `scripts/d1_*.py` helpers load the lab VM password from `.env` first; if missing, they fall back to parsing `SOC-Automation-Project.md` (legacy path). Both paths are gitignored, so a developer can pick whichever format they prefer.

## What lives where

| Secret | `.env` key | Also in |
|---|---|---|
| Lab VM SSH password (all VMs share it currently) | `MYDFIR_VM_PASSWORD` | `SOC-Automation-Project.md` |
| Claude API key | — | `SOC-Automation-Project.md`; n8n credential store (in workflow runtime) |
| VirusTotal API key | — | `SOC-Automation-Project.md`; n8n credential store |
| AbuseIPDB API key | — | `SOC-Automation-Project.md`; n8n credential store |
| DFIR-Iris admin password (web UI) | — | `SOC-Automation-Project.md` only |
| DFIR-Iris API key | — | `SOC-Automation-Project.md`; n8n credential store |
| `mcpuser` Splunk password (currently same as VM password) | — | `claude_desktop_config.json`; `~/.claude.json` project section |

API keys consumed by the n8n workflow at runtime live in the n8n credential store (separate from this repo) — the workflow JSON references them by credential ID, not by value. The `SOC-Automation-Project.md` copies are the human-readable lookup for re-binding credentials after a rebuild.

## Pre-publish remediation (2026-05-18)

Before the first public push, an audit surfaced two literals that had been committed:

1. **AbuseIPDB API key** inlined in `JSON/SOC-Triage-v1.json` between commits `2ebd850` (2026-04-27 16:43) and `c2e05f6` (2026-04-27 16:51) — an 8-minute window before the key was migrated to an n8n credential reference.
2. **Lab VM password literal** (now `[REDACTED]`) in `vault/log.md` (commit `c514c3b`, 2026-05-12) and meta-mentioned in two `vault/subprojects/2026-04-27-structured-outputs/{notes,plan}.md` lines.

Actions taken:

- Working-tree literals replaced with `[REDACTED]` markers + pointers to `SOC-Automation-Project.md`.
- `git filter-repo --replace-text <spec>` rewrote all commits to scrub the same literals from history.
- AbuseIPDB API key rotated on `api.abuseipdb.com` (it had been SaaS-live, not VM-scoped — rotation closes that loop).
- VM passwords + IRIS API token + Claude API + VirusTotal keys **deferred** to the planned Azure migration window. Rationale: those credentials are scoped to powered-off lab VMs (no internet-facing surface); rotating them now would force a needless secrets shuffle that the Azure rebuild will redo anyway.

The vendored `splunk-mcp-main/` directory was also removed from tracking — it's third-party upstream code, kept on disk for local dev but not redistributed by this repo (README links upstream).

## Rotation procedure (full)

Do this before any portfolio publishing (already done for AbuseIPDB on 2026-05-18; the rest done at Azure migration).

1. **Generate new strong passwords** for each VM and the `mcpuser` Splunk account.
2. **Generate new API keys** for Claude API, VirusTotal, AbuseIPDB, and DFIR-Iris service account.
3. **Update `.env`** with the new `MYDFIR_VM_PASSWORD`.
4. **Update `SOC-Automation-Project.md`** with new values for everything else.
5. **Update Claude Desktop config** (`claude_desktop_config.json`) with new `mcpuser` password.
6. **Update Claude Code project MCP config** with new password: `claude mcp remove splunk -s local && claude mcp add splunk -s local ...`.
7. **Update n8n credentials** through the n8n web UI (Settings → Credentials) for each external service.
8. **Verify** every connection — Claude in n8n, the two enrichment tools, the IRIS API node, and the Splunk MCP — before deleting the old credentials at their origin.
9. **Audit shell history** — `Get-History | Select-String -Pattern 'sk-ant|<old-pw-pattern>'` and clear any matches.

## What `.env` does NOT hold

Things explicitly kept out of `.env` because they belong to a separate store:

- **Webhook URLs** — these are configuration, not secrets, and they're already in the workflow JSON (`JSON/SOC-Triage-v3.json` etc.). The webhook GUID is documented in the architecture/components/n8n.md page.
- **VM IPs** — RFC1918 private addresses; documented in architecture/current-state.md.
- **n8n credential IDs** — internal n8n identifiers, not secrets; live in the workflow JSON.
