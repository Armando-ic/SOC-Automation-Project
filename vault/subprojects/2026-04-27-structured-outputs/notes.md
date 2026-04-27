# Notes — Sub-project A1, Structured Outputs

Working notes, gotchas, learnings, open questions discovered during build.

---

## 2026-04-27

- Brainstorm started. Key open questions deferred to spec:
  - Use Anthropic native tool-use / structured outputs vs. langchain `outputParserStructured` node?
  - Schema versioning approach (embed `schema_version: "v1"` in the JSON)?
  - How strict to be on schema validation (block on malformed, vs. degrade gracefully)?
- Bug list to fix as part of this sub-project (from analysis of current workflow JSON):
  1. System prompt in `assistant` role (line 32) — move to `system`
  2. `JSON.stringify($json.body.result, user, ComputerName, 2)` malformed (line 35) — fix replacer arg
  3. AbuseIPDB API key inline (line 108) — move to n8n credential
  4. System prompt references tool name `AbuseIPDB-Request` that doesn't exist (actual: `AbuseIPDB-Enrichment`); rename tools and align prompt during refactor

---

## 2026-04-27 (impl)

### Task 0.1 — git init
- Initial commit `b7423fa` covered 59 files: vault scaffold + workflow exports + transcripts + Splunk MCP source.
- AbuseIPDB API key was redacted from `JSON/SOC-Automation-Project-Workflow.json` before commit (placeholder text marks where the value lives in n8n).
- Root `FORK-NOTES-2026-04-27-mcp-mirror-to-vscode.md` deleted; canonical copy lives at `vault/sources/session-notes/2026-04-27-mcp-mirror-fork.md`.
- All literal `***REMOVED***` password references redacted from vault files (substituted with pointers to `SOC-Automation-Project.md`).

### Task 1.1 — AbuseIPDB credential
- Created n8n credential `AbuseIPDB account` (Header Auth type).
  - Header name: `Key`
  - Value: AbuseIPDB API key (also lives in `SOC-Automation-Project.md`)
- **Gotcha:** n8n's Header Auth credential form uses `Name` to mean the HTTP header NAME (e.g. `Key`), not the credential's display name. The credential's display name is set via the editable title at the top of the form. First attempt put `"AbuseIPDB account"` in the Name field, which would have sent `AbuseIPDB account: <key>` as the literal HTTP header — wrong field semantics. Worth flagging in any future "create credential" runbook step.
- AbuseIPDB API uses header-based auth (`Key: <api-key>`), not query parameter — the original workflow JSON had it as a header parameter on the HTTP node, just inline rather than via credential.
