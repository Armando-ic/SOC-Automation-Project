---
status: active
updated: 2026-04-28
related: [[spec]], [[notes]], [[../../workflows/soc-triage-pipeline]]
---

# Runbook — A1 Structured Outputs

Operational guide for the `SOC Triage v1` workflow that A1 produced.

## Deploy to a fresh n8n environment

1. **Ensure all credentials exist in n8n** (Settings → Credentials):
   - `Anthropic account` (Anthropic API)
   - `Slack account` (Slack OAuth)
   - `DFIR-IRIS account` (DFIR-Iris API)
   - `VirusTotal account` (VirusTotal API)
   - `AbuseIPDB account` (Header Auth — header name `Key`, value from [[../../runbooks/secrets-management]])
2. **Import the workflow JSON:** Workflows → Add Workflow → Import from File → select `JSON/SOC-Triage-v1.json`.
3. **Reattach credentials.** Open each node missing a credential icon; in the Credential dropdown, select the matching named credential.
4. **Publish the workflow** (Publish/Unpublish dropdown in newer n8n; "Activate toggle" in older versions). Production webhook starts listening.
5. **Update Splunk's saved search webhook URL** to point at the production URL of the new workflow's webhook node (visible in the Webhook node's "Production URL" tab).

## Roll back to the legacy workflow

1. **In n8n: Unpublish `SOC Triage v1`** (or toggle inactive).
2. **Publish `SOC Triage (legacy)`** so its webhook starts listening on the legacy URL.
3. **Update Splunk's `Test-Brute-Force` saved search webhook URL** back to the legacy production URL.
4. (Optional) Re-enable the Splunk saved search if it was disabled.

The legacy workflow is preserved untouched — full nodes, full connections, original tool names, original system prompt. If individual nodes were disabled during exploration (some n8n versions allow this and the disable state may persist across exports), re-enable them before rollback.

## Verify production health

1. **n8n → `SOC Triage v1` → Executions tab.** Recent executions should show "Succeeded." Failures should be rare; click into any failed execution to see which node failed.
2. **DFIR-Iris (https://192.168.129.133) → Alerts.** New alerts should have varying severities (2/3/4/5 — *not* all 3). Severity directly reflects Claude's assessment.
3. **Slack `#alerts`.** New messages should display: severity emoji (🟢🟡🟠🔴), structured sections (Summary / Severity Rationale / MITRE / IOCs / Actions), and a `<View in Splunk>` link.

## Key changes from the legacy workflow (what downstream consumers now see)

| Surface | Before A1 | After A1 |
|---|---|---|
| Slack message | Freeform Claude prose | Severity emoji + structured sections + Splunk link |
| DFIR-Iris severity | Always `3` (Medium) | Varies 2/3/4/5 per Claude's assessment |
| DFIR-Iris description | Freeform Claude prose | Markdown-formatted: Summary / Severity / MITRE / IOCs / Actions / Notes |
| AI output | Single text block, downstream parses freeform | Structured JSON via tool-use, downstream reads typed fields |
| AbuseIPDB API key | Inline in workflow JSON | n8n credential (`AbuseIPDB account`) |
| System prompt role | `assistant` (bug) | `system` (correct Anthropic API location) |

## Debug a failed execution

1. **n8n → Executions → click the failed execution → identify the failing node.**
2. **Common failure modes and fixes:**
   - **`Extract Triage Result` throws `"Expected submit_triage_result tool call"`** — Claude returned text instead of calling the tool. Check the actual `content` array in the error. Likely cause: system prompt wasn't clear enough, or `submit_triage_result` tool isn't registered. Verify all three tools (`enrich_ip_abuseipdb`, `lookup_file_hash_virustotal`, `submit_triage_result`) appear under the Anthropic node's Tools section.
   - **Anthropic node times out** — increase the workflow timeout (Workflow Settings → Timeout, currently 120s).
   - **DFIR-Iris `'alert_severity_id': ['Not a valid integer.']`** — body parameter value field is in Fixed mode instead of Expression mode. Toggle each updated body parameter (alert_title, alert_description, alert_severity_id) to Expression and re-paste *without* the leading `=`.
   - **Slack 401 or auth error** — `Slack account` credential's token expired. Regenerate at api.slack.com.
   - **DFIR-Iris connection refused** — Iris VM may be down. SSH and `cd iris-web && sudo docker-compose up`.
   - **`lookup_file_hash_virustotal` "Invalid URL"** — Claude is passing only the hash. Verify tool description includes the URL template and concrete example.
   - **AbuseIPDB 401** — `AbuseIPDB account` credential's header name must be exactly `Key` (capital K) with the API key as value. The credential's *display name* is set via the title at the top of the credential form, NOT the Name field.

## Known limitations (deferred, not blocking)

- **`investigation_notes` field is sometimes omitted by Claude** despite being in the schema's `required` array. Anthropic's tool-use schema enforcement appears to treat `required` as advisory rather than blocking. Code node `|| '_none_'` fallback handles it. If A2 needs this field reliably, tighten the system prompt.
- **DFIR-Iris alert description shows literal markdown link `[View in Splunk](http://...)`** instead of a clickable link. DFIR-Iris doesn't render markdown links. One-line fix for a future sub-project: emit the raw URL in `iris_description`.
- **Splunk's `results_link` artifact expires** after `dispatch_ttl` (~1 hour for scheduled searches). Old links land on Splunk's "search expired — rerun?" page. Acceptable degradation; analyst still gets to Splunk and one click reruns.
- **Splunk URL hostname patch in Code node** (`replace('mydfir-splunk', '192.168.129.131')`) hardcodes the lab IP. Better long-term fix: edit `/opt/splunk/etc/system/local/server.conf` on the Splunk VM to set `serverName = 192.168.129.131` and restart Splunk.
- **AbuseIPDB inline key was removed from `JSON/SOC-Triage-v1.json` exports**, but the legacy export at `JSON/SOC-Automation-Project-Workflow.json` still has the key value redacted with placeholder text. The actual key lives in the gitignored `SOC-Automation-Project.md` for restoration during credential rotation.

## Adding new alert types or evolving the schema

If a future sub-project needs new fields or new tools:

1. **New schema = bump to v2.** Update the `submit_triage_result` tool's input schema and add `"v2"` to the `schema_version` enum.
2. Update the `Extract Triage Result` Code node to handle both v1 and v2 inputs (branch on `r.schema_version`).
3. Update the spec in [[spec]] with v2 schema documentation.
4. Add an ADR if the schema change reflects a non-obvious decision.
