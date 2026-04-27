---
status: active
updated: 2026-04-27
sub_project: A1
approach: Anthropic node + tool-use forcing (Approach 1 from brainstorm)
related: [[README]], [[../../workflows/soc-triage-pipeline]], [[../../architecture/components/claude-api]], [[../../decisions/0003-split-structured-outputs-from-response-actions]]
---

# Spec — Sub-project A1: Structured Outputs

## Summary

Convert the n8n SOC triage workflow's freeform AI output into a schema-conformant JSON object delivered via Anthropic tool-use. Eliminate text parsing in downstream nodes. Fix four known bugs in the existing workflow as natural side effects. Add one new node (a Code node that extracts and reformats Claude's response). Net change: +1 node.

## Goal

Replace the current data flow:

```
Claude returns freeform text → downstream parses $json.content[0].text
```

with:

```
Claude calls submit_triage_result tool with structured input → Code node
extracts and reformats → downstream nodes reference clean fields
```

Doing this:

- Makes severity, IOCs, MITRE techniques, and recommended actions programmatically accessible
- Maps AI-derived severity to DFIR-Iris's 1–5 scale (no longer hardcoded `3`)
- Produces a properly formatted Slack message with severity badges, structured IOCs, and a click-through to Splunk
- Lays the foundation for sub-project A2 (Response Actions) which will iterate over `recommended_actions` to drive automated responses

## Scope

### In scope

- Define and document the v1 JSON output schema
- Add a new tool `submit_triage_result` to the Anthropic node, with the v1 schema as its input definition
- Rewrite the system prompt and move it from `assistant` role to `system` role
- Rewrite the user message to fix the malformed `JSON.stringify` call and pass full webhook context
- Rename existing tool nodes for clarity (`enrich_ip_abuseipdb`, `lookup_file_hash_virustotal`)
- Migrate the AbuseIPDB API key from inline JSON to an n8n credential
- Add a new Code node `Extract Triage Result` after the Anthropic node
- Update the DFIR-Iris HTTP Request node to consume structured fields (severity mapping, structured description)
- Update the Slack node to send the pre-formatted message
- Configure n8n execution settings (save all, retry, timeout)
- Pin three test cases into the webhook node
- Verify end-to-end with real Splunk alert

### Out of scope (deliberately deferred)

- Response actions (sub-project A2)
- Webhook authentication
- Splunk-side detection improvements (thresholding, additional event codes)
- EDR layer
- Vector DB / case memory
- Fallback Slack message on workflow failure (revisit if observed failure rate justifies it)
- Webhook payload schema validation
- Multi-LLM fallback (Bedrock, local model)

## Approach

**Approach 1** from the brainstorm: Anthropic node + tool-use forcing.

Rationale: Anthropic's tool-use API enforces input shape conformance at the API level — Claude's response is rejected if the parameters don't match the schema. This is a hard contract, not a soft "please respond in this format" prompt instruction. Reuses the existing node type and tool-loop machinery (already used for AbuseIPDB and VirusTotal enrichment). One source of truth for the schema (the tool definition).

Rejected alternatives (see brainstorm transcript): LangChain Agent + `outputParserStructured` (soft contract, bigger refactor), and Code-node text parsing (defeats the purpose).

## Design

### 1. The v1 JSON output schema

This is the input schema for the `submit_triage_result` tool. Every downstream consumer reads from this shape.

```json
{
  "schema_version": "v1",

  "alert_summary": "string (1–3 sentences, plain English: what happened, who's affected, why it matters)",

  "severity": "low | medium | high | critical",
  "severity_rationale": "string (one sentence: why this severity)",

  "mitre_techniques": [
    {
      "id": "string (e.g. 'T1110')",
      "name": "string (e.g. 'Brute Force')",
      "tactic": "string (e.g. 'Credential Access')"
    }
  ],

  "iocs": {
    "ips": ["string"],
    "domains": ["string"],
    "file_hashes": ["string"],
    "users": ["string"],
    "hosts": ["string"]
  },

  "iocs_enriched": [
    {
      "value": "string",
      "verdict": "malicious | suspicious | clean | unknown",
      "source": "string (e.g. 'AbuseIPDB', 'VirusTotal')",
      "summary": "string (one sentence on what the enrichment found)"
    }
  ],

  "recommended_actions": [
    {
      "description": "string (specific action, imperative voice)",
      "priority": "low | medium | high | critical"
    }
  ],

  "investigation_notes": "string (markdown-formatted longer narrative for the analyst)"
}
```

**Field rationale:**

| Field | Consumer | Purpose |
|---|---|---|
| `schema_version` | All future code | Lets us evolve to v2 without breaking v1 consumers |
| `alert_summary` | Slack body, Iris description | TL;DR analyst reads first |
| `severity` | DFIR-Iris `alert_severity_id`, Slack badge, A2 routing | Most load-bearing field |
| `severity_rationale` | Slack, audit trail | Forces Claude to justify rather than guess |
| `mitre_techniques` | Slack tags, future detection-engineering | Portfolio talking point + analyst context |
| `iocs` | Future A2 (block IPs, push to Iris IOCs) | Machine-readable, deduplicated |
| `iocs_enriched` | Slack table, Iris notes | Structured form of AbuseIPDB / VirusTotal results |
| `recommended_actions` | Slack, future A2 (each action becomes candidate response) | List A2 iterates over |
| `investigation_notes` | Iris alert description, Slack thread reply | Long-form analyst depth |

**Deliberate exclusions** (YAGNI):

- `alert_classification` (true/false positive) — AI can't make this call from one alert reliably
- Separate `confidence` field — `severity_rationale` captures uncertainty in plain English
- `automation_candidate` flag on actions — defers to A2 where full context exists
- Per-IOC numeric `score` — `verdict` enum is sufficient, scores create false precision
- Detailed action structure (`action_type`, `target`, `parameters`) — A2's job

### 2. AI input side

#### 2a. System prompt (in `system` role — fixes bug #1)

```
You are a Tier 1 SOC analyst processing alerts from Splunk. Your job
is to triage each alert and submit a structured analysis.

Workflow:
1. Read the alert details provided in the user message.
2. For each IOC in the alert, decide whether enrichment would help:
   - Public IPs → call enrich_ip_abuseipdb
   - File hashes → call lookup_file_hash_virustotal
   - Skip enrichment for RFC1918 private IPs (10.x, 172.16-31.x,
     192.168.x) and obvious internal hostnames — they return no
     useful data.
3. Once enrichment is complete (or you've decided no enrichment is
   needed), call submit_triage_result EXACTLY ONCE to deliver your
   findings.

Rules:
- You MUST call submit_triage_result. It is the only valid way to
  respond. Do not return free text after the tool call.
- Pick one severity (low/medium/high/critical). Use severity_rationale
  to express nuance or uncertainty.
- For mitre_techniques, only include techniques you can directly
  justify from the alert data. Do not speculate.
- iocs lists must contain every distinct IOC observed, deduplicated.
  iocs_enriched contains only the subset that was actually looked up.
- recommended_actions should be specific and imperative ("Disable user X
  pending investigation" — not "Consider disabling user X"). Three to
  five actions is typical; more dilutes signal.
- investigation_notes is for nuance you cannot fit into structured
  fields — alternative hypotheses, missing data, MITRE rationale.

Severity calibration:
- low: routine, expected behavior, or false positive likely
- medium: deserves analyst attention but not page-worthy
- high: active threat indicators present, escalate within working hours
- critical: page on-call immediately, suspected active compromise
```

#### 2b. Tool definitions

Three tools registered with the Anthropic node:

**`submit_triage_result`** (NEW — the structured output mechanism)

Description Claude sees:
```
Submit your final SOC triage analysis. You MUST call this tool
exactly once at the end of your investigation to deliver your
structured findings. Do not respond with text after calling this
tool. The structured fields you provide populate downstream Slack
alerts, DFIR-Iris tickets, and future automation actions.
```

Input schema: the v1 schema in section 1, registered as a JSON Schema object.

**`enrich_ip_abuseipdb`** (renamed from `AbuseIPDB-Enrichment`)

Description:
```
Look up an IP address in AbuseIPDB to check if it has been reported
for malicious activity. Returns abuse confidence score, country, ISP,
and recent report counts. Use for any external/public IP encountered
in the alert. Skip for RFC1918 private IPs (10.x, 172.16-31.x,
192.168.x) — they return no useful data.
```

Input: `ipAddress` (string). Implementation: HTTP GET to `https://api.abuseipdb.com/api/v2/check` with `ipAddress` query param and `Key` header from n8n credential (fixing bug #3 — migrating from inline key).

**`lookup_file_hash_virustotal`** (renamed from `VirusTotal - Hash`)

Description:
```
Look up a file hash (MD5, SHA-1, or SHA-256) in VirusTotal to check
antivirus engine verdicts. Returns malicious/suspicious counts and
identified threat names. Use for any file hash present in the alert.
```

Input: `URL` (string, with hash substituted into the VirusTotal URL template). Existing implementation preserved.

#### 2c. User message (fixes bug #2)

```
Splunk alert fired.

Alert Name: {{ $json.body.search_name }}
Splunk Link: {{ $json.body.results_link }}

Event Data:
{{ JSON.stringify($json.body.result, null, 2) }}
```

The `null` replacer arg fixes the malformed `JSON.stringify($json.body.result, user, ComputerName, 2)` from the current workflow. Passing the full result object (instead of trying to filter to a specific subset) makes the workflow generalize across alert types whose result fields aren't known in advance.

### 3. AI output side

#### 3a. Output extraction — `Extract Triage Result` Code node

New node placed between "Message a model" and the downstream Slack/Iris branches. All transformation logic centralized here.

```javascript
// Pull the structured triage result out of Claude's tool call
const content = $input.first().json.content || [];
const toolCall = content.find(
  c => c.type === 'tool_use' && c.name === 'submit_triage_result'
);

if (!toolCall) {
  throw new Error(
    `Expected submit_triage_result tool call but got: ${JSON.stringify(content)}`
  );
}

const r = toolCall.input;

// Severity → Iris ID mapping + emoji for Slack
const sevId    = { low: 2, medium: 3, high: 4, critical: 5 }[r.severity] || 3;
const sevEmoji = { low: '🟢', medium: '🟡', high: '🟠', critical: '🔴' }[r.severity] || '⚪';

// Pre-render the displayable lists once
const mitre = (r.mitre_techniques || [])
  .map(t => `${t.id} (${t.name})`)
  .join(', ') || 'none identified';

const enriched = (r.iocs_enriched || [])
  .map(i => `• \`${i.value}\` — ${i.verdict.toUpperCase()} (${i.source}): ${i.summary}`)
  .join('\n') || '_none_';

const actions = (r.recommended_actions || [])
  .map(a => `• [${a.priority.toUpperCase()}] ${a.description}`)
  .join('\n') || '_none_';

// Webhook context for the link-back
const webhook   = $('Webhook').first().json.body;
const alertName = webhook.search_name;
const splunkLink = webhook.results_link;

// Pre-formatted strings for downstream nodes
const slack_message = `${sevEmoji} *${r.severity.toUpperCase()}* — ${alertName}

${r.alert_summary}

*Severity Rationale:* ${r.severity_rationale}
*MITRE:* ${mitre}

*Enriched IOCs:*
${enriched}

*Recommended Actions:*
${actions}

<${splunkLink}|View in Splunk>`;

const iris_description = `**Summary:** ${r.alert_summary}

**Severity:** ${r.severity} — ${r.severity_rationale}

**MITRE Techniques:** ${mitre}

**Enriched IOCs:**
${enriched}

**Recommended Actions:**
${actions}

**Investigation Notes:**
${r.investigation_notes || '_none_'}

---
[View in Splunk](${splunkLink})`;

return [{
  json: {
    ...r,                       // all schema fields, in case future nodes want raw access
    severity_iris_id: sevId,
    slack_message,
    iris_description,
    splunk_link: splunkLink,
    alert_name: alertName,
  }
}];
```

#### 3b. Severity → Iris ID mapping

| Iris ID | Iris label | Our schema value |
|---|---|---|
| 1 | Informational | *(unused)* |
| 2 | Low | `low` |
| 3 | Medium | `medium` |
| 4 | High | `high` |
| 5 | Critical | `critical` |

#### 3c. Downstream node updates

**Send a message (Slack)** — `text` field becomes:
```
{{ $json.slack_message }}
```

**DFIR-IRIS HTTP Request** — body parameter changes:

| Parameter | Old | New |
|---|---|---|
| `alert_title` | `{{ $('Webhook').item.json.body.search_name }}` | `{{ $json.alert_name }}` |
| `alert_description` | `{{ $json.content[0].text }}` (freeform) | `{{ $json.iris_description }}` (formatted markdown) |
| `alert_severity_id` | `3` (hardcoded) | `{{ $json.severity_iris_id }}` (mapped from severity) |
| `alert_status_id` | `1` | `1` (unchanged) |
| `alert_customer_id` | `1` | `1` (unchanged) |

#### 3d. Final workflow topology

```
Webhook
   ↓
Message a model (Anthropic, claude-opus-4-7)
   ├── Tools: enrich_ip_abuseipdb
   │          lookup_file_hash_virustotal
   │          submit_triage_result   ← NEW
   ↓
Extract Triage Result (Code)        ← NEW (the only structural addition)
   ├── splits into:
   ├── DFIR-IRIS HTTP Request (severity dynamic, description structured)
   └── Send a message (Slack — pre-formatted message)
```

### 4. Error handling

**Built-in via design:**

| Failure mode | Behavior |
|---|---|
| Claude returns text instead of `submit_triage_result` | Code node throws with diagnostic message |
| Claude calls tool with malformed input | Anthropic API rejects, Claude retries internally |
| AbuseIPDB or VirusTotal returns error | Claude sees error in tool result, proceeds without that enrichment, notes in `investigation_notes` |
| Webhook receives malformed payload | Code node throws when accessing `webhook.body.search_name` |

**n8n configuration changes:**

1. Workflow Settings → Save successful production executions: **all** (default keeps only failures; we want full traces during early operation)
2. Workflow Settings → Save failed executions: **all**
3. Workflow Settings → Workflow timeout: **120 seconds**
4. Anthropic node → Retry on Fail: **2 attempts, 5s delay** (handles transient 429 / 529)

**Deferred (acknowledged, not addressed in v1):**

- Fallback Slack message on workflow failure
- Webhook payload schema validation
- Multi-LLM fallback (Bedrock, local model)
- Auto-retry to DFIR-Iris on failure

### 5. Testing

**Three test cases pinned into the webhook node:**

**Test 1 — Internal brute force (preserves current pinned data)**
```json
{
  "search_name": "Test-Brute-Force",
  "result": { "ComputerName": "DESKTOP-VNEF7PC", "user": "mydfir", "src_ip": "192.168.129.1", "count": "5" }
}
```
Expected: severity `low` or `medium`, no AbuseIPDB enrichment (RFC1918 skip), MITRE T1110.

**Test 2 — External brute force**
```json
{
  "search_name": "Test-Brute-Force-External",
  "result": { "ComputerName": "DESKTOP-VNEF7PC", "user": "mydfir", "src_ip": "<fresh-ip-from-abuseipdb>", "count": "47" }
}
```
Expected: severity `high` or `critical`, AbuseIPDB enrichment showing high abuse confidence, MITRE T1110. Use a fresh IP from abuseipdb.com/statistics at test time — featured IPs rotate.

**Test 3 — Suspicious file hash (EICAR)**
```json
{
  "search_name": "Suspicious-File-Hash",
  "result": { "ComputerName": "DESKTOP-VNEF7PC", "user": "mydfir", "file_hash": "44d88612fea8a8f36de82e1278abb02f", "file_path": "C:\\Users\\mydfir\\Downloads\\eicar.exe" }
}
```
Expected: severity `critical`, VirusTotal enrichment showing 60+ malicious detections, no MITRE technique inferred (file detection alone).

**Verification checklist (run after each test):**

- [ ] Code node executes without throwing
- [ ] `severity` matches expected level (within ±1 bucket — Claude has judgment latitude)
- [ ] `severity_iris_id` matches the mapping table
- [ ] DFIR-Iris case created with correct severity, title, structured description
- [ ] Slack message renders with correct emoji, summary, MITRE, IOCs, actions, clickable Splunk link
- [ ] Total execution time under 120s
- [ ] Anthropic API spend per test logged (informal cost tracking)

**End-to-end verification (one-time on deployment):**

1. Re-enable the Splunk saved search "Test-Brute-Force"
2. RDP to Windows VM, trigger 5 failed logons
3. Watch n8n execution log — alert should arrive within ~10s
4. Verify DFIR-Iris and Slack outputs match Test 1's expected shape
5. Disable the saved search again

## Bug fixes resolved by A1

| # | Bug | Fix |
|---|---|---|
| 1 | System prompt in `assistant` role | Move to `system` role (rewritten, see § 2a) |
| 2 | Malformed `JSON.stringify(..., user, ComputerName, 2)` | Replace with `JSON.stringify(..., null, 2)` (see § 2c) |
| 3 | AbuseIPDB API key inline in workflow JSON | Migrate to n8n credential (see § 2b under `enrich_ip_abuseipdb`) |
| 4 | System prompt references `AbuseIPDB-Request` tool that doesn't exist | Renamed tool to `enrich_ip_abuseipdb`; system prompt updated to match (see § 2b) |

## Open questions for the implementation plan

These are HOW questions for the writing-plans skill, not WHAT questions for design:

- Exact n8n syntax for declaring the `submit_triage_result` tool input schema in the `@n8n/n8n-nodes-langchain.anthropic` node — needs verification against the node's UI / docs at implementation time.
- Whether the Anthropic node's Tool nodes require the JSON Schema in a specific format (e.g., as a JSON Schema object vs. a Zod schema vs. an example object).
- Order of operations during deployment: build new workflow alongside the old, or modify in place? (Recommendation: rename the old workflow to `My workflow (legacy)` and build A1 as a new workflow, switch Splunk webhook target once verified.)
- Any rate-limit considerations for the test-3 EICAR hash that VirusTotal community accounts hit frequently.

## Success criteria

A1 is "done" when:

1. All three pinned test cases execute end-to-end without errors and produce schema-conformant output
2. End-to-end verification with real Splunk alert succeeds (Slack + Iris outputs match expectations)
3. DFIR-Iris severity is no longer always `3` — it varies by alert
4. Slack message displays the new format with severity badge, structured IOCs, and Splunk link
5. AbuseIPDB API key is no longer present in any exported workflow JSON
6. The four bug fixes are verified in the running workflow
7. `runbook.md` in this folder is written and covers deploy / rollback / verify
8. `notes.md` in this folder captures any gotchas discovered during build
9. `log.md` at vault root has an entry marking A1 complete
