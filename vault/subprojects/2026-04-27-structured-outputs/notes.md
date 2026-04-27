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
