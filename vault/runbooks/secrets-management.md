---
status: active
updated: 2026-04-27
related: [[architecture/current-state]]
---

# Secrets Management

Where every secret in this project lives, and how to rotate.

## Current state

`f:\Claude_Code\SOC_Automation_Project\SOC-Automation-Project.md` is the master secrets file. **Gitignored.** Contains:

- VM passwords (Splunk, n8n, DFIR-Iris, Windows 10 — all currently the same shared password)
- Claude API key
- VirusTotal API key
- AbuseIPDB API key (after migration from inline workflow JSON during A1)
- DFIR-Iris admin password (long generated string)

## Other locations the same secrets currently live

The `mcpuser` Splunk password (currently the same as the VM passwords) is also in:

1. `C:\Users\Owner\AppData\Local\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\claude_desktop_config.json` (Claude Desktop MCP config)
2. `C:\Users\Owner\.claude.json` (Claude Code MCP config, project-scoped section)

The AbuseIPDB API key is currently in the n8n workflow JSON inline (line 108) — moving it to an n8n credential is part of [[subprojects/2026-04-27-structured-outputs/README]].

## Risk assessment

Acceptable for personal lab use on an isolated host. **Not** acceptable for any of:

- Pushing the project to a public GitHub repo
- Sharing the workflow JSON exports
- Using any of these credentials against systems that hold real data

## Rotation procedure (do before any portfolio publishing)

1. **Generate new strong passwords** for each VM and the `mcpuser` Splunk account
2. **Generate new API keys** for Claude API, VirusTotal, and DFIR-Iris service account
3. **Update master secrets file** with new values
4. **Update Claude Desktop config** with new `mcpuser` password
5. **Update Claude Code config:** `claude mcp remove splunk -s local && claude mcp add splunk -s local ...` with new password
6. **Update n8n credentials** through the web UI (Settings → Credentials)
7. **Migrate AbuseIPDB key from inline JSON to n8n credential** (covered by A1)
8. **Verify everything still works** before deleting the old credentials
9. **Audit shell history** — `history | grep -E 'sk-ant|<old-password-pattern>'` and clear any matches
