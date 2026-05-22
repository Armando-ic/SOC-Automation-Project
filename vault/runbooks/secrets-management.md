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
7. **Update n8n credentials** through the n8n web UI (left nav → **Credentials**, NOT a workflow). Enumerate every external service the workflow references — `SOC-Triage-v3` currently has these:
   - **Anthropic API** — paste the new Claude API key into the credential. Test connection (n8n's button) if available.
   - **AbuseIPDB API** — paste the new AbuseIPDB key.
   - **VirusTotal API** — paste the new VirusTotal key. See "VirusTotal account caveat" below.
   - **DFIR-Iris API** — paste the new Iris service-account token, plus the Iris base URL if it changed.

   The Anthropic credential is the one most commonly forgotten — Claude is invoked by the `Message a model` node (not a separately-named HTTP node), and the credential isn't visible from the workflow canvas unless you click into that node. **If `Message a model` fails with "Authorization failed - User is inactive" at runtime, the n8n Anthropic credential is the suspect.**

   Cleanup: in the same Credentials view, remove any stale per-service credentials left over from previous rotation attempts (e.g., `VirusTotal account 2`, `VirusTotal account 3`). Multiple same-typed credentials are an anti-pattern; workflow nodes can end up wired to the wrong one. Keep exactly one credential per service.

8. **Verify** every connection by firing a real synthetic alert through the pipeline:
   - Fire the T1059.003 cmd.exe synthetic on Win10-v2 (see [[../detections/t1059-003-cmd-suspicious-ioc-references]] for the exact command).
   - Wait one cron tick.
   - Check the n8n execution canvas: every node should be green, including the dashed-line tool nodes (`enrich_ip_abuseipdb`, `lookup_file_hash_virustotal`, `submit_triage_result`).
   - Check IRIS for a new alert with populated `Enriched IOCs` section.
   - Splunk MCP separately: run a quick query via Claude Desktop or Claude Code to confirm the MCP connection still works after credential changes.

9. **Audit shell history** — `Get-History | Select-String -Pattern 'sk-ant|<old-pw-pattern>'` and clear any matches.

### VirusTotal account caveat (surfaced 2026-05-19)

VirusTotal's free tier enforces a stricter account-state regime than the other enrichment APIs in this workflow:

- **Accounts can be deactivated** by VT (no warning, surfaced via a "Welcome" + "Deactivated" email pair). Hotmail-account VT was deactivated and unable to re-register (cooldown on the email address).
- **New accounts may not auto-send a verification email** (Gmail signups have been observed not to receive one). The API key from such an account is sometimes still valid — confirm via direct curl before assuming the key is bad.

**Diagnostic curl when VT is the suspect:**

```powershell
# PowerShell on host PC (no VMs needed). Replace KEY with the candidate VT key
# from SOC-Automation-Project.md.
$key  = "PASTE_VT_KEY_HERE"
$hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"  # EICAR SHA-256
try {
    $r = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/files/$hash" `
        -Headers @{ "x-apikey" = $key } -ErrorAction Stop
    $s = $r.data.attributes.last_analysis_stats
    Write-Host "OK - ratio: $($s.malicious)/$($s.malicious + $s.undetected + $s.suspicious + $s.harmless)"
} catch {
    Write-Host "FAILED - Status: $($_.Exception.Response.StatusCode.value__) - $($_.ErrorDetails.Message)"
}
$key = $null; Clear-History
```

- **`OK - ratio: 65/72`** (or similar) → VT account is fine; the failure is on n8n's side (stale credential reference in the workflow, or the wrong credential selected in the VT tool node).
- **`FAILED - Status: 401 - User is inactive`** → VT account itself is dead; create a new one on a different email.

The 2026-05-19 incident: the message "Authorization failed - User is inactive" surfaced inside n8n's `lookup_file_hash_virustotal` node and superficially looked like a VT-side problem. The curl test isolated it as an n8n credential-wiring issue (the VT tool was pointing at an old/deleted credential), not VT itself. **Always run the curl test first when VT fails — it eliminates half the diagnosis tree in 30 seconds.**

## What `.env` does NOT hold

Things explicitly kept out of `.env` because they belong to a separate store:

- **Webhook URLs** — these are configuration, not secrets, and they're already in the workflow JSON (`JSON/SOC-Triage-v3.json` etc.). The webhook GUID is documented in the architecture/components/n8n.md page.
- **VM IPs** — RFC1918 private addresses; documented in architecture/current-state.md.
- **n8n credential IDs** — internal n8n identifiers, not secrets; live in the workflow JSON.
