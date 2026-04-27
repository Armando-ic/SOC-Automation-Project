---
status: active
date: 2026-04-27
related: [[architecture/components/splunk-mcp]], [[runbooks/splunk-mcp-setup]], [[sources/session-notes/2026-04-27-mcp-mirror-fork]]
---

# 0004 — Mirror Splunk MCP from Claude Desktop to Claude Code

## Status

Accepted

## Context

The video tutorial sets up the Splunk MCP server in Claude Desktop only. The user does most planning and design work inside Claude Code (VS Code). Without mirroring the MCP into Claude Code, fresh Claude Code instances opening this project would have no live access to Splunk and would fall back to "I'd need to query your Splunk to verify this" responses.

A related question came up mid-session whether editing Claude Desktop's config could affect Claude Code's config. Answer: no — different files, different processes, different read paths. The two are fully independent.

## Decision

Add the same Splunk MCP server to Claude Code at **local scope** (tied to the project directory `F:\Claude_Code\SOC_Automation_Project`, private to this machine). Use `claude mcp add` CLI rather than editing JSON.

Working command shape (substitute `<password>` from the gitignored secrets file before running; note the single-quoting required for any password containing `!` or other shell-expansion characters):

```bash
claude mcp add splunk -s local \
  -e SPLUNK_HOST=192.168.129.131 \
  -e SPLUNK_PORT=8089 \
  -e SPLUNK_USERNAME=mcpuser \
  -e 'SPLUNK_PASSWORD=<password>' \
  -e SPLUNK_SCHEME=https \
  -e VERIFY_SSL=false \
  -- uv --directory 'F:/Claude_Code/SOC_Automation_Project/splunk-mcp-main/splunk-mcp-main' run python splunk_mcp.py stdio
```

For the actual command run during the fork session (with the literal password substituted), see [[../sources/session-notes/2026-04-27-mcp-mirror-fork]] — but treat that record as the historical artifact, not the canonical reference.

## Consequences

**Positive**

- Any Claude Code instance opening this project gets live Splunk access
- Designs can be validated against real data without leaving the IDE
- Investigations can happen inside the same context as planning

**Negative**

- The `mcpuser` password is now in three plaintext files (Desktop config, Code config, gitignored secrets file). Acceptable for personal lab; must be rotated before any portfolio publishing. Tracked in [[runbooks/secrets-management]].
