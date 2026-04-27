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

### Task 4.1 — submit_triage_result + first end-to-end test
- Code Tool node added with `schemaType: "manual"` (label "Define using JSON Schema") — this is the right path; "Generate From JSON Example" would have made n8n infer a meta-schema from our schema document.
- **First end-to-end test passed cleanly** with pinned brute-force webhook data (Test 1 from spec):
  - Execution time: 14.65s
  - Claude emitted a `text` block first (thinking out loud), then called `submit_triage_result` ✓
  - Severity assessed as `low` with self-aware rationale (correctly noted that count=1 + internal IP + rule named "Test-Brute-Force" suggests a tuning issue rather than real attack)
  - RFC1918 enrichment skip rule respected — `iocs_enriched` returned empty
  - MITRE T1110 Brute Force / Credential Access correctly identified
  - All four required IOC categories populated (or empty arrays where appropriate)
  - Recommended actions were SOC-analyst-quality: tune the detection rule, correlate with 4624/4625 over 24h, identify asset for the source IP
- Output pinned in n8n for downstream development.
- **Open question:** `investigation_notes` may have been omitted by Claude despite being required in the schema. Could indicate n8n's manual-mode JSON Schema is informational rather than strictly enforced by the Anthropic API call. Code node in Task 5.1 has `|| '_none_'` fallback. Watch in subsequent tests; if persistent, tighten the prompt.

### Tasks 3.1 + 3.2 — System prompt + user message
- **n8n quirk discovered:** the `@n8n/n8n-nodes-langchain.anthropic` node does NOT accept `system` as a role in the messages array. It correctly mirrors the Anthropic API by exposing `system` as a separate parameter — found under **Add Option → System Message** in the node's Options section, stored at `parameters.options.system` in the exported JSON. The original MyDFIR tutorial's `role=assistant` approach was always a hack working around this.
- **Encoding gotcha:** copy-pasting Unicode chars (`→`, `—`, smart quotes) through Windows clipboard can introduce mojibake (`â†'`, `â€"`) in the saved JSON. Use ASCII equivalents (`->`, `--`, straight `'`) when pasting into n8n text fields.
- **Expression-mode double-`=` gotcha:** when the n8n field is in Expression mode, n8n adds a leading `=` as the mode marker. If the pasted content also starts with `=`, the actual sent value is `==...`. Either paste without the leading `=`, or toggle to Fixed and back.

### Task 1.1 — AbuseIPDB credential
- Created n8n credential `AbuseIPDB account` (Header Auth type).
  - Header name: `Key`
  - Value: AbuseIPDB API key (also lives in `SOC-Automation-Project.md`)
- **Gotcha:** n8n's Header Auth credential form uses `Name` to mean the HTTP header NAME (e.g. `Key`), not the credential's display name. The credential's display name is set via the editable title at the top of the form. First attempt put `"AbuseIPDB account"` in the Name field, which would have sent `AbuseIPDB account: <key>` as the literal HTTP header — wrong field semantics. Worth flagging in any future "create credential" runbook step.
- AbuseIPDB API uses header-based auth (`Key: <api-key>`), not query parameter — the original workflow JSON had it as a header parameter on the HTTP node, just inline rather than via credential.
