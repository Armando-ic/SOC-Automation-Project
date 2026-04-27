---
status: active
updated: 2026-04-27
sub_project: A1
spec: [[spec]]
related: [[README]], [[../../workflows/soc-triage-pipeline]]
---

# A1 Structured Outputs — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **For humans:** Work through tasks in order. Each task has 3–6 small steps. Run the verify step after each implementation step before moving on. Commit after each task.

**Goal:** Convert the n8n SOC triage workflow's freeform AI output into schema-conformant JSON via Anthropic tool-use, fix four known bugs as side effects, with one new node added.

**Architecture:** Anthropic node uses three tools (existing `enrich_ip_abuseipdb`, `lookup_file_hash_virustotal`, plus a NEW `submit_triage_result` no-op tool whose input schema is the v1 output shape). A new Code node `Extract Triage Result` pulls the tool-use input, computes severity mapping, and pre-formats Slack and DFIR-Iris payloads.

**Tech Stack:** n8n (web UI driven), `@n8n/n8n-nodes-langchain.anthropic` node, `@n8n/n8n-nodes-langchain.toolCode` for the no-op tool, n8n Code node (JavaScript).

**Reference docs:**
- Spec: [[spec]]
- Current workflow JSON: [SOC-Automation-Project-Workflow.json](../../../JSON/SOC-Automation-Project-Workflow.json)
- DFIR-Iris API: [IRIS-2.0.4-OpenAPI-specification.json](../../../JSON/IRIS-2.0.4-OpenAPI-specification.json)
- Component pages: [[../../architecture/components/n8n]], [[../../architecture/components/claude-api]], [[../../architecture/components/dfir-iris]]
- Secrets: [[../../runbooks/secrets-management]]

**Working assumptions for the executor:**
- All four VMs are running (see [[../../runbooks/starting-the-vms]])
- n8n is reachable at http://192.168.129.132:5678
- The current workflow `My workflow` (id `45gQjuH2MFQYrlEx`) exists in n8n and is in the state shown in the exported JSON
- The user is logged in to n8n in a browser tab on the host machine
- A terminal is available at the project root `f:\Claude_Code\SOC_Automation_Project\`

**Conventions for n8n GUI tasks:**
- "In n8n, do X" means open the n8n web UI in your browser and perform X
- "Execute the workflow" means click the "Execute Workflow" button in the editor (uses pinned/manual data, not a real Splunk alert)
- "Export workflow JSON" means: workflow three-dot menu → Download → save to `JSON/<name>.json`
- "Verify Y in n8n" means: look at the node's output panel after execution and confirm Y

---

## File structure

| File | Action | Purpose |
|---|---|---|
| `.git/` | Create | Initialize git repo so we can commit progress |
| `JSON/SOC-Automation-Project-Workflow-v0-baseline.json` | Create | Backup of pre-A1 workflow for rollback |
| `JSON/SOC-Triage-v1.json` | Create | Exported state of the new workflow at each milestone |
| n8n credential `AbuseIPDB account` | Create | Replace inline API key (bug #3) |
| n8n workflow `SOC Triage v1` | Create (duplicate of current) | The new workflow we build A1 in |
| n8n workflow `My workflow` | Rename | Becomes `SOC Triage (legacy)` for rollback |
| `vault/subprojects/2026-04-27-structured-outputs/runbook.md` | Modify | Replace placeholder with deploy/rollback/verify instructions |
| `vault/subprojects/2026-04-27-structured-outputs/notes.md` | Append | Capture gotchas as we hit them |
| `vault/subprojects/2026-04-27-structured-outputs/README.md` | Modify | Tick off status checkboxes |
| `vault/log.md` | Append | Mark A1 implementation start and completion |

No separate test files — n8n's testing model is "pin data + execute + visually verify."

---

## Phase 0 — Hygiene and safety net

### Task 0.1: Initialize git repository

**Files:**
- Create: `.git/` (via `git init`)

- [ ] **Step 1: Verify project state before init**

Run from project root:
```bash
ls -la f:/Claude_Code/SOC_Automation_Project/.git 2>/dev/null && echo "already a repo" || echo "not yet a repo"
```
Expected: `not yet a repo`

- [ ] **Step 2: Initialize**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git init
```
Expected: `Initialized empty Git repository in ...`

- [ ] **Step 3: Verify .gitignore protects secrets**

```bash
cat f:/Claude_Code/SOC_Automation_Project/.gitignore | grep "SOC-Automation-Project.md"
```
Expected: line `SOC-Automation-Project.md` present

- [ ] **Step 4: Stage everything except gitignored**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git add .
```

- [ ] **Step 5: Confirm secrets file is NOT staged**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git status | grep "SOC-Automation-Project.md"
```
Expected: no output (file is gitignored, not in staged list)

If it appears, STOP and fix `.gitignore` before continuing.

- [ ] **Step 6: Initial commit**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git commit -m "chore: initial commit — vault scaffold, workflow exports, transcripts"
```

---

### Task 0.2: Back up current workflow as baseline

**Files:**
- Create: `JSON/SOC-Automation-Project-Workflow-v0-baseline.json`

- [ ] **Step 1: In n8n, open `My workflow`**

Browser to http://192.168.129.132:5678, click the workflow.

- [ ] **Step 2: Export the current state**

Three-dot menu (top right) → Download. Save as `SOC-Automation-Project-Workflow-v0-baseline.json` to `f:\Claude_Code\SOC_Automation_Project\JSON\`.

- [ ] **Step 3: Verify the file exists and is valid JSON**

```bash
cd f:/Claude_Code/SOC_Automation_Project && python -c "import json; json.load(open('JSON/SOC-Automation-Project-Workflow-v0-baseline.json')); print('valid')"
```
Expected: `valid`

- [ ] **Step 4: Commit the baseline**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git add JSON/SOC-Automation-Project-Workflow-v0-baseline.json && git commit -m "chore: snapshot pre-A1 workflow as baseline"
```

---

## Phase 1 — Pre-work: credentials

### Task 1.1: Create AbuseIPDB credential in n8n (fixes bug #3)

**Files:** None on disk; n8n credential store only.

- [ ] **Step 1: Retrieve AbuseIPDB API key**

Open `f:\Claude_Code\SOC_Automation_Project\SOC-Automation-Project.md` (gitignored). Note: this file does not currently store the AbuseIPDB key — it's currently inline in the workflow JSON. Get the key from the workflow JSON instead:

```bash
cd f:/Claude_Code/SOC_Automation_Project && grep -A1 '"name": "Key"' JSON/SOC-Automation-Project-Workflow-v0-baseline.json | head -5
```

Copy the value (looks like `***REMOVED***`).

- [ ] **Step 2: Add the AbuseIPDB key to the secrets file**

Edit `f:\Claude_Code\SOC_Automation_Project\SOC-Automation-Project.md`. Add a line:
```
* AbuseIPDB API Key: <paste-here>
```

(The file is gitignored. This makes the key recoverable for future credential rotation per [[../../runbooks/secrets-management]].)

- [ ] **Step 3: Create the n8n credential**

In n8n: Settings (gear icon, bottom left) → Credentials → New Credential → search for "Header Auth" → Continue.

- Name: `AbuseIPDB account`
- Header Auth → Name: `Key`
- Header Auth → Value: paste the API key
- Save.

- [ ] **Step 4: Verify the credential exists**

In n8n Credentials list, confirm `AbuseIPDB account` appears.

- [ ] **Step 5: Note this in vault notes**

Append to `vault/subprojects/2026-04-27-structured-outputs/notes.md`:
```
## 2026-04-27 (impl)
- Created n8n credential `AbuseIPDB account` (Header Auth, header name `Key`).
  AbuseIPDB API uses header-based auth, not query param.
```

- [ ] **Step 6: Commit notes update**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git add vault/subprojects/2026-04-27-structured-outputs/notes.md && git commit -m "chore: note AbuseIPDB credential creation"
```

---

## Phase 2 — Duplicate workflow and prepare tools

### Task 2.1: Duplicate the workflow, rename original to legacy

**Files:** None on disk; n8n workflow store only.

- [ ] **Step 1: In n8n, duplicate `My workflow`**

Workflows list → right-click `My workflow` → Duplicate. The copy will be named `My workflow copy`.

- [ ] **Step 2: Rename the original**

Open `My workflow` (the original). Click the workflow name at top → rename to `SOC Triage (legacy)`. Save.

- [ ] **Step 3: Rename the copy**

Open `My workflow copy`. Rename to `SOC Triage v1`. Save.

- [ ] **Step 4: Verify both workflows exist with correct names**

Workflows list shows both `SOC Triage (legacy)` and `SOC Triage v1`.

- [ ] **Step 5: Confirm `SOC Triage (legacy)` is INACTIVE**

Open it. Top-right toggle should show "Inactive." This prevents accidental double-firing once we cut over.

- [ ] **Step 6: Export `SOC Triage v1` as starting state**

In `SOC Triage v1`: three-dot menu → Download. Save as `JSON/SOC-Triage-v1.json`.

- [ ] **Step 7: Commit**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git add JSON/SOC-Triage-v1.json && git commit -m "chore: duplicate workflow as SOC Triage v1, original renamed to legacy"
```

All subsequent edits happen in `SOC Triage v1`. The legacy workflow is untouched as a rollback.

---

### Task 2.2: Migrate AbuseIPDB tool to credential and rename it

**Files:**
- Modify (via n8n GUI): `enrich_ip_abuseipdb` tool in `SOC Triage v1`

- [ ] **Step 1: Open `SOC Triage v1` and find the AbuseIPDB-Enrichment node**

It's the HTTP Request Tool branching from the "Message a model" node.

- [ ] **Step 2: Rename it**

Click the node name → rename to `enrich_ip_abuseipdb`. Save.

- [ ] **Step 3: Update the tool description**

In the node settings, find the "Tool Description" or equivalent field. Replace with:

```
Look up an IP address in AbuseIPDB to check if it has been reported for malicious activity. Returns abuse confidence score, country, ISP, and recent report counts. Use for any external/public IP encountered in the alert. Skip for RFC1918 private IPs (10.x, 172.16-31.x, 192.168.x) — they return no useful data.
```

- [ ] **Step 4: Replace inline auth with credential**

In the node's Headers section, REMOVE the existing manual `Key` header parameter (the one with the inline API key). Then in the Authentication dropdown, set:
- Authentication: `Generic Credential Type`
- Generic Auth Type: `Header Auth`
- Credential: select `AbuseIPDB account`

The existing `Accept: application/json` header should remain.

- [ ] **Step 5: Test the tool in isolation**

In the node, click "Execute step" or use the node's "Test step" feature. Provide a test IP via the node's parameter input — use `8.8.8.8` (Google DNS, definitely in AbuseIPDB).

Expected: HTTP 200, response body containing `data.abuseConfidenceScore`, `data.countryCode`, etc. The presence of the `data` field confirms credential auth worked.

If it fails with 401: check the credential is named exactly `AbuseIPDB account` and the header name in the credential is `Key` (capital K).

- [ ] **Step 6: Export and commit**

Export `SOC Triage v1` to `JSON/SOC-Triage-v1.json` (overwriting). Then:

```bash
cd f:/Claude_Code/SOC_Automation_Project && git add JSON/SOC-Triage-v1.json && git commit -m "feat(workflow): rename AbuseIPDB tool to enrich_ip_abuseipdb, migrate to credential"
```

---

### Task 2.3: Rename and re-describe VirusTotal tool

**Files:**
- Modify (via n8n GUI): `lookup_file_hash_virustotal` tool in `SOC Triage v1`

- [ ] **Step 1: Find the `VirusTotal - Hash` node and rename**

In `SOC Triage v1`, click the `VirusTotal - Hash` node → rename to `lookup_file_hash_virustotal`.

- [ ] **Step 2: Update tool description**

Replace with:
```
Look up a file hash (MD5, SHA-1, or SHA-256) in VirusTotal to check antivirus engine verdicts. Returns malicious/suspicious counts and identified threat names. Use for any file hash present in the alert.
```

- [ ] **Step 3: Verify the URL parameter is still set to `let the model define this parameter`**

The URL field should show the parameter icon indicating "AI provides this." The credential `VirusTotal account` should still be attached.

- [ ] **Step 4: Test the tool in isolation**

Execute the tool with a test URL: `https://www.virustotal.com/api/v3/files/44d88612fea8a8f36de82e1278abb02f` (EICAR hash, guaranteed match).

Expected: HTTP 200, response body containing `data.attributes.last_analysis_stats.malicious` with a value > 50.

- [ ] **Step 5: Export and commit**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git add JSON/SOC-Triage-v1.json && git commit -m "feat(workflow): rename VirusTotal tool to lookup_file_hash_virustotal, update description"
```

(Re-export the workflow before the git add.)

---

## Phase 3 — System prompt and user message

### Task 3.1: Move system prompt to `system` role and rewrite (fixes bug #1)

**Files:**
- Modify (via n8n GUI): `Message a model` node in `SOC Triage v1`

- [ ] **Step 1: Open the `Message a model` node**

Click it in the canvas.

- [ ] **Step 2: Locate the messages array**

You'll see two messages currently:
- One with role `=assistant` containing the long Tier 1 SOC analyst prompt (BUG: should be `system`)
- One with no explicit role (defaults to user) containing `Alert: ... Alert Details: ...`

- [ ] **Step 3: Change the first message's role**

Click the role dropdown on the first message. Change from `assistant` to `system`.

- [ ] **Step 4: Replace the system message content**

Delete the existing prompt. Paste this exactly:

```
You are a Tier 1 SOC analyst processing alerts from Splunk. Your job is to triage each alert and submit a structured analysis.

Workflow:
1. Read the alert details provided in the user message.
2. For each IOC in the alert, decide whether enrichment would help:
   - Public IPs → call enrich_ip_abuseipdb
   - File hashes → call lookup_file_hash_virustotal
   - Skip enrichment for RFC1918 private IPs (10.x, 172.16-31.x, 192.168.x) and obvious internal hostnames — they return no useful data.
3. Once enrichment is complete (or you've decided no enrichment is needed), call submit_triage_result EXACTLY ONCE to deliver your findings.

Rules:
- You MUST call submit_triage_result. It is the only valid way to respond. Do not return free text after the tool call.
- Pick one severity (low/medium/high/critical). Use severity_rationale to express nuance or uncertainty.
- For mitre_techniques, only include techniques you can directly justify from the alert data. Do not speculate.
- iocs lists must contain every distinct IOC observed, deduplicated. iocs_enriched contains only the subset that was actually looked up.
- recommended_actions should be specific and imperative ("Disable user X pending investigation" — not "Consider disabling user X"). Three to five actions is typical; more dilutes signal.
- investigation_notes is for nuance you cannot fit into structured fields — alternative hypotheses, missing data, MITRE rationale.

Severity calibration:
- low: routine, expected behavior, or false positive likely
- medium: deserves analyst attention but not page-worthy
- high: active threat indicators present, escalate within working hours
- critical: page on-call immediately, suspected active compromise
```

- [ ] **Step 5: Save the node** (no need to test yet — `submit_triage_result` doesn't exist)

- [ ] **Step 6: Export and commit**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git add JSON/SOC-Triage-v1.json && git commit -m "fix(workflow): move system prompt to system role, rewrite for tool-use forcing"
```

(Re-export `SOC Triage v1` before the add.)

---

### Task 3.2: Fix the user message JSON.stringify (fixes bug #2)

**Files:**
- Modify (via n8n GUI): `Message a model` node in `SOC Triage v1`

- [ ] **Step 1: Find the user message in the messages array**

The second message in the messages array. Currently:
```
=Alert: {{ $json.body.search_name }}
Alert Details:{{ JSON.stringify($json.body.result,user, ComputerName,2)}}
```

The `, user, ComputerName,` part is malformed (bare identifiers as JSON.stringify replacer arg).

- [ ] **Step 2: Replace with the corrected user message**

```
=Splunk alert fired.

Alert Name: {{ $json.body.search_name }}
Splunk Link: {{ $json.body.results_link }}

Event Data:
{{ JSON.stringify($json.body.result, null, 2) }}
```

The leading `=` keeps n8n's expression mode active.

- [ ] **Step 3: Verify role is unset (defaults to user)**

The role dropdown should be empty / default. n8n treats an empty role as `user`.

- [ ] **Step 4: Test the user message rendering with pinned data**

The Webhook node already has pinned test data (the brute-force payload). Click the Webhook node → confirm pinned data is present (look for the pin icon or "Pinned data" indicator).

In the `Message a model` node, click "Test step." It will fail because `submit_triage_result` doesn't exist yet, BUT before the failure you should see Claude's request payload in the input panel — verify the user message renders to:

```
Splunk alert fired.

Alert Name: Test-Brute-Force
Splunk Link: http://mydfir-splunk:8000/app/search/...

Event Data:
{
  "_time": "1777162287.929",
  "ComputerName": "DESKTOP-VNEF7PC",
  "user": "mydfir",
  "src_ip": "192.168.129.1",
  "count": "1"
}
```

- [ ] **Step 5: Export and commit**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git add JSON/SOC-Triage-v1.json && git commit -m "fix(workflow): repair JSON.stringify replacer arg, include results_link in user message"
```

---

## Phase 4 — Add the submit_triage_result tool

### Task 4.1: Create the no-op `submit_triage_result` Code Tool

**Files:**
- Modify (via n8n GUI): `SOC Triage v1` workflow — add new node

**Concept:** `submit_triage_result` is registered as a tool so Claude is forced to use the schema. Functionally it's a no-op — when Claude calls it, the tool just returns success. The actual structured data lives in Claude's tool-use call, which we extract in Task 5.1.

- [ ] **Step 1: Add a new tool node**

In `SOC Triage v1`, click the `+` icon under the `Message a model` node (in the Tools section, where AbuseIPDB and VirusTotal tools attach). Search for `Code` → select `Code Tool` (`@n8n/n8n-nodes-langchain.toolCode`).

- [ ] **Step 2: Configure the tool name**

Set the tool name to: `submit_triage_result`

- [ ] **Step 3: Configure the tool description**

Set description to:
```
Submit your final SOC triage analysis. You MUST call this tool exactly once at the end of your investigation to deliver your structured findings. Do not respond with text after calling this tool. The structured fields you provide populate downstream Slack alerts, DFIR-Iris tickets, and future automation actions.
```

- [ ] **Step 4: Define the input schema**

In the Code Tool's input schema configuration (look for "Schema" or "Input Schema" — UI varies by n8n version), set the JSON Schema:

```json
{
  "type": "object",
  "required": [
    "schema_version", "alert_summary", "severity", "severity_rationale",
    "mitre_techniques", "iocs", "iocs_enriched", "recommended_actions",
    "investigation_notes"
  ],
  "properties": {
    "schema_version": { "type": "string", "enum": ["v1"] },
    "alert_summary": { "type": "string" },
    "severity": { "type": "string", "enum": ["low", "medium", "high", "critical"] },
    "severity_rationale": { "type": "string" },
    "mitre_techniques": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["id", "name", "tactic"],
        "properties": {
          "id": { "type": "string" },
          "name": { "type": "string" },
          "tactic": { "type": "string" }
        }
      }
    },
    "iocs": {
      "type": "object",
      "required": ["ips", "domains", "file_hashes", "users", "hosts"],
      "properties": {
        "ips": { "type": "array", "items": { "type": "string" } },
        "domains": { "type": "array", "items": { "type": "string" } },
        "file_hashes": { "type": "array", "items": { "type": "string" } },
        "users": { "type": "array", "items": { "type": "string" } },
        "hosts": { "type": "array", "items": { "type": "string" } }
      }
    },
    "iocs_enriched": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["value", "verdict", "source", "summary"],
        "properties": {
          "value": { "type": "string" },
          "verdict": { "type": "string", "enum": ["malicious", "suspicious", "clean", "unknown"] },
          "source": { "type": "string" },
          "summary": { "type": "string" }
        }
      }
    },
    "recommended_actions": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["description", "priority"],
        "properties": {
          "description": { "type": "string" },
          "priority": { "type": "string", "enum": ["low", "medium", "high", "critical"] }
        }
      }
    },
    "investigation_notes": { "type": "string" }
  }
}
```

- [ ] **Step 5: Configure the tool's code body (the no-op)**

Set the code body (JavaScript):

```javascript
return {
  success: true,
  message: "Triage analysis received. Workflow will route to downstream consumers."
};
```

- [ ] **Step 6: Save the node**

- [ ] **Step 7: Verify the tool appears in the Anthropic node's tool list**

Click the `Message a model` node. Confirm three tools are listed: `enrich_ip_abuseipdb`, `lookup_file_hash_virustotal`, `submit_triage_result`.

- [ ] **Step 8: Test the workflow (Webhook + Anthropic only — Slack and Iris will fail downstream, that's expected)**

Click `Execute Workflow` (top right). The Webhook fires with pinned data, Anthropic processes, calls tools as needed, and finishes by calling `submit_triage_result`.

Verify in the `Message a model` output:
- The output JSON has a `content` array
- One element of `content` has `type: "tool_use"` and `name: "submit_triage_result"`
- The `input` of that tool_use contains a JSON object matching the v1 schema (schema_version, severity, etc.)

If Claude returned text instead of calling the tool: review the system prompt for clarity. Confirm the tool description clearly says "MUST call."

If Claude called `submit_triage_result` with malformed input: the Anthropic API will have rejected the call internally and Claude should have retried. If you see persistent failures, capture the error and add to notes.

- [ ] **Step 9: Pin Claude's response (so we can develop downstream nodes without re-burning API tokens)**

In the `Message a model` node output panel, click the pin icon to pin the current response. This caches it for downstream development.

- [ ] **Step 10: Export and commit**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git add JSON/SOC-Triage-v1.json && git commit -m "feat(workflow): add submit_triage_result no-op Code Tool with v1 schema"
```

---

## Phase 5 — Add the Code extraction node

### Task 5.1: Add `Extract Triage Result` Code node

**Files:**
- Modify (via n8n GUI): `SOC Triage v1` workflow — add new node

- [ ] **Step 1: Add a Code node between `Message a model` and the downstream branches**

Click the `+` between `Message a model` and the existing branches (Slack and DFIR-IRIS HTTP Request). Search for `Code` → select `Code` (`n8n-nodes-base.code`, NOT `Code Tool`).

- [ ] **Step 2: Name the node**

Rename to: `Extract Triage Result`

- [ ] **Step 3: Set the code mode**

Mode: `Run Once for All Items`. Language: `JavaScript`.

- [ ] **Step 4: Paste the extraction code**

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
    ...r,
    severity_iris_id: sevId,
    slack_message,
    iris_description,
    splunk_link: splunkLink,
    alert_name: alertName,
  }
}];
```

- [ ] **Step 5: Test the node in isolation**

Click "Test step" on `Extract Triage Result`. Because `Message a model`'s output is pinned (Task 4.1 step 9), this runs without burning API tokens.

Verify the output JSON contains:
- All v1 schema fields (severity, alert_summary, mitre_techniques, etc.)
- `severity_iris_id` matching the mapping (e.g., 3 for medium)
- `slack_message` (multi-line string with emoji, summary, etc.)
- `iris_description` (markdown-formatted)
- `splunk_link` and `alert_name` from the webhook

If it throws "Expected submit_triage_result tool call but got: ...", inspect the actual content array in the error message — Claude may have failed to call the tool, or the n8n LangChain wrapper may have flattened the response differently than expected.

- [ ] **Step 6: Verify the Code node is wired correctly in the canvas**

The flow should be:
```
Webhook → Message a model → Extract Triage Result → (splits to) Send a message + DFIR-IRIS HTTP Request
```

The two existing downstream nodes (Slack, Iris) should still be connected, but now they consume from `Extract Triage Result` instead of `Message a model`.

If they're still wired to `Message a model`, drag the connections to come from `Extract Triage Result` instead.

- [ ] **Step 7: Export and commit**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git add JSON/SOC-Triage-v1.json && git commit -m "feat(workflow): add Extract Triage Result Code node for structured output"
```

---

## Phase 6 — Update downstream consumers

### Task 6.1: Update Slack node to use pre-formatted message

**Files:**
- Modify (via n8n GUI): `Send a message` node in `SOC Triage v1`

- [ ] **Step 1: Open `Send a message`**

- [ ] **Step 2: Replace the text expression**

Currently: `={{ $json.content[0].text }}`

Change to: `={{ $json.slack_message }}`

- [ ] **Step 3: Verify channel is still `alerts`**

Channel should still be the `alerts` channel (channel ID `C0B0QMQU8QG` per the existing workflow JSON).

- [ ] **Step 4: Test the node**

Click "Test step" — should post a real Slack message. Open Slack and verify:
- Severity emoji at the top
- Alert name in the header
- Summary, MITRE, IOCs, Actions sections
- "View in Splunk" link at the bottom is clickable

- [ ] **Step 5: Export and commit**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git add JSON/SOC-Triage-v1.json && git commit -m "feat(workflow): Slack node consumes pre-formatted slack_message"
```

---

### Task 6.2: Update DFIR-Iris node to use structured fields

**Files:**
- Modify (via n8n GUI): `DFIR-IRIS HTTP Request` node in `SOC Triage v1`

- [ ] **Step 1: Open the node**

- [ ] **Step 2: Update the body parameters**

For each parameter, change the value:

| Parameter | Old value | New value |
|---|---|---|
| `alert_title` | `{{ $('Webhook').item.json.body.search_name }}` | `={{ $json.alert_name }}` |
| `alert_description` | `{{ $json.content[0].text }}` | `={{ $json.iris_description }}` |
| `alert_severity_id` | `3` | `={{ $json.severity_iris_id }}` |
| `alert_status_id` | `1` | (unchanged: `1`) |
| `alert_customer_id` | `1` | (unchanged: `1`) |

- [ ] **Step 3: Confirm the rest of the node config is unchanged**

- Method: `POST`
- URL: `https://192.168.129.133/alerts/add`
- Authentication: `dfirIrisApi` credential
- Options → Allow Unauthorized Certs: ON

- [ ] **Step 4: Test the node**

Click "Test step." Should return a success response with an alert ID.

Open DFIR-Iris (https://192.168.129.133) → Alerts. Verify a new alert appeared with:
- Title: `Test-Brute-Force`
- Severity matching what Claude assessed (NOT always `Medium`/3)
- Description with the formatted markdown content (Summary, Severity, MITRE, etc.)

- [ ] **Step 5: Export and commit**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git add JSON/SOC-Triage-v1.json && git commit -m "feat(workflow): DFIR-Iris node uses structured fields, severity dynamic"
```

---

## Phase 7 — Configure operational settings

### Task 7.1: Configure workflow execution and retry settings

**Files:** None on disk; n8n workflow settings only.

- [ ] **Step 1: Open `SOC Triage v1` settings**

Three-dot menu (top right) → Workflow settings.

- [ ] **Step 2: Set execution save settings**

- "Save successful production executions": **All**
- "Save failed executions": **All**

- [ ] **Step 3: Set workflow timeout**

- Workflow timeout: **120 seconds**

- [ ] **Step 4: Save settings**

- [ ] **Step 5: Configure Anthropic node retry**

Open `Message a model` node → Settings tab → Retry on Fail: **ON**, Max Retries: **2**, Wait Between Retries: **5000ms**.

- [ ] **Step 6: Save and export**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git add JSON/SOC-Triage-v1.json && git commit -m "chore(workflow): configure execution save, 120s timeout, Anthropic retry"
```

(Re-export `SOC Triage v1` first.)

---

## Phase 8 — Test cases

### Task 8.1: Test 1 — Internal brute force (preserves current pinned data)

- [ ] **Step 1: Confirm pinned webhook data matches Test 1**

Open the Webhook node. Pinned data should be:
```json
{
  "body": {
    "search_name": "Test-Brute-Force",
    "results_link": "http://mydfir-splunk:8000/app/search/...",
    "result": {
      "ComputerName": "DESKTOP-VNEF7PC",
      "user": "mydfir",
      "src_ip": "192.168.129.1",
      "count": "5"
    }
  }
}
```

If `count` is `1` (the original pinned value), update it to `5` to match Test 1 of the spec. Click "Edit Output" → modify → save.

- [ ] **Step 2: Unpin `Message a model` output (so Claude gets called fresh)**

Open `Message a model` → click the pin icon to unpin the cached response.

- [ ] **Step 3: Execute the workflow**

Click "Execute Workflow."

- [ ] **Step 4: Verify Claude's response**

In `Extract Triage Result` output, confirm:
- `severity` is `low` or `medium` (per spec — within ±1 bucket of expected)
- `iocs.ips` includes `192.168.129.1`
- `iocs.users` includes `mydfir`
- `iocs.hosts` includes `DESKTOP-VNEF7PC`
- `iocs_enriched` is empty OR contains `192.168.129.1` with verdict `unknown` (private IP — the system prompt says skip enrichment, but Claude may have ignored that guidance)
- `mitre_techniques` includes T1110 (Brute Force)
- `severity_iris_id` is 2 or 3 matching severity

- [ ] **Step 5: Verify Slack message posted**

Check Slack `#alerts`. Should see a yellow or green badge, summary mentioning brute force, MITRE T1110.

- [ ] **Step 6: Verify DFIR-Iris alert created**

Open https://192.168.129.133 → Alerts. Should see `Test-Brute-Force` with severity matching Claude's assessment.

- [ ] **Step 7: Capture results in notes**

Append to `vault/subprojects/2026-04-27-structured-outputs/notes.md`:
```
## 2026-04-27 (impl) — Test 1 (internal brute force)
- Severity: <observed>
- Enrichment skipped for 192.168.129.1: <yes/no>
- MITRE T1110 detected: <yes/no>
- Slack rendered correctly: <yes/no>
- DFIR-Iris alert created: <yes/no>
- Total execution time: <seconds>s
- Notes: <anything surprising>
```

- [ ] **Step 8: Commit notes**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git add vault/subprojects/2026-04-27-structured-outputs/notes.md && git commit -m "test: A1 Test 1 results — internal brute force"
```

---

### Task 8.2: Test 2 — External brute force

- [ ] **Step 1: Get a fresh malicious IP from AbuseIPDB**

Browser to https://www.abuseipdb.com/statistics. Pick any IP from the "Recently Reported" list with high abuse confidence (>80%). Copy it.

- [ ] **Step 2: Modify pinned webhook data**

In the Webhook node, edit the pinned data → change `src_ip` to the IP you just copied, change `count` to `47`, change `search_name` to `Test-Brute-Force-External`.

- [ ] **Step 3: Execute the workflow**

- [ ] **Step 4: Verify**

- `severity` should be `high` or `critical`
- `iocs_enriched` should include the external IP with `verdict: malicious`, `source: AbuseIPDB`
- DFIR-Iris severity should be 4 or 5
- Slack should show 🟠 or 🔴

- [ ] **Step 5: Capture in notes (same template as Test 1)**

- [ ] **Step 6: Commit**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git add vault/subprojects/2026-04-27-structured-outputs/notes.md && git commit -m "test: A1 Test 2 results — external brute force with AbuseIPDB hit"
```

---

### Task 8.3: Test 3 — EICAR file hash

- [ ] **Step 1: Modify pinned webhook data**

In the Webhook node, edit pinned data:

```json
{
  "body": {
    "search_name": "Suspicious-File-Hash",
    "results_link": "http://mydfir-splunk:8000/app/search/...",
    "result": {
      "ComputerName": "DESKTOP-VNEF7PC",
      "user": "mydfir",
      "file_hash": "44d88612fea8a8f36de82e1278abb02f",
      "file_path": "C:\\Users\\mydfir\\Downloads\\eicar.exe"
    }
  }
}
```

- [ ] **Step 2: Execute the workflow**

- [ ] **Step 3: Verify**

- `severity` should be `critical`
- `iocs.file_hashes` should include `44d88612fea8a8f36de82e1278abb02f`
- `iocs_enriched` should include the hash with `verdict: malicious`, `source: VirusTotal`
- The summary in `iocs_enriched` should mention 60+ engines flagging it (EICAR is universally detected)
- DFIR-Iris severity should be 5
- Slack should show 🔴 CRITICAL

- [ ] **Step 4: Capture in notes**

- [ ] **Step 5: Restore pinned data to Test 1 (the default)**

So the workflow's saved pinned state matches what's documented in the spec.

- [ ] **Step 6: Commit**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git add JSON/SOC-Triage-v1.json vault/subprojects/2026-04-27-structured-outputs/notes.md && git commit -m "test: A1 Test 3 results — EICAR hash with VirusTotal hit"
```

---

## Phase 9 — Cutover

### Task 9.1: Cut Splunk webhook over to the new workflow

**Files:**
- Modify: Splunk saved search "Test-Brute-Force" webhook URL
- Modify: `SOC Triage v1` activation state

- [ ] **Step 1: Get the new workflow's webhook URL**

In `SOC Triage v1`, open the Webhook node. Note the **production** webhook URL (NOT the test URL). Format: `http://192.168.129.132:5678/webhook/<guid>`.

If the GUID is the same as the legacy workflow's webhook (which it would be if the duplicate preserved the webhook ID), the new workflow can take over without changing the Splunk side. Verify: compare the GUID in `SOC Triage v1`'s Webhook node URL to the one in `SOC Triage (legacy)`'s Webhook node URL. If different, you need to update Splunk.

- [ ] **Step 2: Activate `SOC Triage v1`**

In `SOC Triage v1`, top-right toggle → Active.

- [ ] **Step 3: Confirm `SOC Triage (legacy)` is still inactive**

Open `SOC Triage (legacy)` — toggle should still show "Inactive."

- [ ] **Step 4: If webhook GUIDs differ, update Splunk**

Open Splunk → Settings → Searches, reports, and alerts → `Test-Brute-Force` → Edit. Find the webhook trigger action, update the URL to the production webhook URL of `SOC Triage v1`.

If GUIDs match, skip this step.

- [ ] **Step 5: Re-enable the Splunk saved search**

In Splunk's saved search list, toggle `Test-Brute-Force` to enabled.

---

### Task 9.2: End-to-end verification with real Splunk

- [ ] **Step 1: Trigger failed logons**

RDP to the Windows VM (192.168.129.130). Open another RDP client and attempt logon to the same machine 5 times with a wrong password.

Or from the host machine: `mstsc /v:192.168.129.130` and use a wrong password 5 times.

- [ ] **Step 2: Wait ~60 seconds for Splunk's saved search to fire**

The cron is `* * * * *` (every minute), so within 60s the search should run, detect the events, and call the webhook.

- [ ] **Step 3: Check n8n execution log**

In `SOC Triage v1` → Executions tab. A new execution should appear with status `Success`.

If it's `Failed`, click into it to see which node failed. Common failures:
- Anthropic API timeout → already configured to retry
- DFIR-Iris cert issue → already accepting unauthorized certs
- Slack auth → check the credential

- [ ] **Step 4: Verify Slack message**

Check `#alerts` in Slack — should see a new structured message.

- [ ] **Step 5: Verify DFIR-Iris alert**

Open DFIR-Iris → Alerts. Should see a new alert with severity matching Claude's assessment, structured description.

- [ ] **Step 6: Disable the Splunk saved search**

In Splunk → saved search list → toggle `Test-Brute-Force` to disabled. Otherwise it will keep firing every minute.

- [ ] **Step 7: Capture end-to-end results in notes**

Append to `vault/subprojects/2026-04-27-structured-outputs/notes.md`:
```
## 2026-04-27 (impl) — End-to-end verification
- Splunk → n8n delay: <seconds>
- Slack message arrived: <yes/no>
- DFIR-Iris alert created: <yes/no>
- Severity assessment: <observed>
- Splunk saved search disabled after test: yes
```

- [ ] **Step 8: Commit**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git add vault/subprojects/2026-04-27-structured-outputs/notes.md && git commit -m "test: A1 end-to-end verification with real Splunk alert"
```

---

## Phase 10 — Documentation closure

### Task 10.1: Write the runbook

**Files:**
- Modify: `vault/subprojects/2026-04-27-structured-outputs/runbook.md`

- [ ] **Step 1: Replace the placeholder runbook**

Open `f:\Claude_Code\SOC_Automation_Project\vault\subprojects\2026-04-27-structured-outputs\runbook.md` and replace its contents with:

````markdown
---
status: active
updated: 2026-04-27
related: [[spec]], [[../../workflows/soc-triage-pipeline]]
---

# Runbook — A1 Structured Outputs

## How to deploy this change to a fresh environment

1. Import `JSON/SOC-Triage-v1.json` into n8n: Workflows → Add Workflow → Import from File.
2. Reattach credentials: open each node missing a credential icon and select the matching credential. Required credentials: `Anthropic account`, `Slack account`, `VirusTotal account`, `DFIR-IRIS account`, `AbuseIPDB account`.
3. If the AbuseIPDB credential doesn't exist, create it: Settings → Credentials → New → Header Auth → name `AbuseIPDB account`, header name `Key`, value from [[../../runbooks/secrets-management]].
4. Activate the workflow (top-right toggle).
5. Confirm the Splunk saved search `Test-Brute-Force` webhook URL points to the workflow's production webhook (Webhook node URL).

## How to roll back to the legacy workflow

1. In n8n: deactivate `SOC Triage v1` (top-right toggle → Inactive).
2. Activate `SOC Triage (legacy)`.
3. (Only if webhook GUIDs differ — see Task 9.1) Update Splunk's `Test-Brute-Force` saved search webhook URL back to the legacy workflow's URL.
4. Re-enable the Splunk saved search.

## How to verify production health

1. n8n → `SOC Triage v1` → Executions tab. Recent executions should show "Success."
2. DFIR-Iris → Alerts. New alerts should appear with varying severities (not all `3`).
3. Slack `#alerts`. New messages should have severity emoji, structured sections, clickable Splunk link.

## What downstream consumers see (changed from legacy)

| Surface | Before A1 | After A1 |
|---|---|---|
| Slack message | Freeform Claude prose | Severity emoji + structured sections + clickable Splunk link |
| DFIR-Iris severity | Always `3` (Medium) | Varies by alert (2/3/4/5) per Claude's assessment |
| DFIR-Iris description | Freeform Claude prose | Markdown-formatted with Summary, Severity, MITRE, IOCs, Actions, Notes |

## How to debug a failed execution

1. n8n → Executions → click the failed execution → identify the failing node.
2. Common cases:
   - **`Extract Triage Result` throws "Expected submit_triage_result tool call"** — Claude returned text instead of calling the tool. Check the actual `content` array in the error. Likely cause: system prompt wasn't clear enough, or `submit_triage_result` tool isn't registered.
   - **Anthropic node times out** — increase the workflow timeout (Workflow Settings → Workflow timeout). Currently 120s.
   - **Slack 401** — `Slack account` credential's token expired. Regenerate at api.slack.com.
   - **DFIR-Iris connection refused** — Iris VM may be down. SSH and `sudo docker-compose up`.

## How to add a new tool or modify the schema

If A2 or later phases add a new tool or change the v1 schema:

1. **New schema = bump to v2.** Update the `submit_triage_result` tool's input schema and add `"v2"` to the `schema_version` enum.
2. Update the `Extract Triage Result` Code node to handle both v1 and v2 inputs (branch on `r.schema_version`).
3. Update the spec in [[spec]] with v2 schema documentation.
4. Add an ADR if the schema change reflects a non-obvious decision.
````

- [ ] **Step 2: Commit**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git add vault/subprojects/2026-04-27-structured-outputs/runbook.md && git commit -m "docs(A1): write runbook covering deploy, rollback, verify, debug"
```

---

### Task 10.2: Update README status and log

**Files:**
- Modify: `vault/subprojects/2026-04-27-structured-outputs/README.md`
- Modify: `vault/log.md`

- [ ] **Step 1: Update README status checkboxes**

Edit the Status section of `vault/subprojects/2026-04-27-structured-outputs/README.md`:

```markdown
## Status

- [x] Brainstorm completed 2026-04-27
- [x] Spec written 2026-04-27
- [x] Spec approved 2026-04-27
- [x] Implementation plan written 2026-04-27
- [x] Implementation executed 2026-04-27
- [x] Runbook written 2026-04-27
- [x] Verification: workflow run end-to-end with real test alert, structured output observed in DFIR-Iris and Slack
```

- [ ] **Step 2: Append to vault log**

Append to `vault/log.md`:

```
2026-04-27 — A1 (Structured Outputs) implementation complete; new workflow `SOC Triage v1` active, legacy workflow preserved as `SOC Triage (legacy)`; see [[subprojects/2026-04-27-structured-outputs/runbook]]
```

- [ ] **Step 3: Commit**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git add vault/subprojects/2026-04-27-structured-outputs/README.md vault/log.md && git commit -m "docs(A1): mark sub-project complete, update log"
```

---

## Self-review checklist (run before declaring A1 done)

Match against spec § "Success criteria":

- [ ] All three pinned test cases execute end-to-end without errors and produce schema-conformant output (Tests 8.1, 8.2, 8.3 all passed)
- [ ] End-to-end verification with real Splunk alert succeeded (Task 9.2)
- [ ] DFIR-Iris severity is no longer always `3` — verified across the three test cases
- [ ] Slack message displays new format with severity badge, structured IOCs, Splunk link
- [ ] AbuseIPDB API key is no longer present in any exported workflow JSON — verify:
  ```bash
  cd f:/Claude_Code/SOC_Automation_Project && grep -i "abuseipdb" JSON/SOC-Triage-v1.json | grep -E '"value"|"Key"'
  ```
  Expected: no API key value visible (only credential reference).
- [ ] All four bug fixes verified:
  1. System prompt role is `system` not `assistant` — check JSON: `grep -A1 '"role"' JSON/SOC-Triage-v1.json | head -5`
  2. `JSON.stringify` uses `null` replacer — check JSON: `grep "JSON.stringify" JSON/SOC-Triage-v1.json`
  3. AbuseIPDB credential reference, not inline key — covered above
  4. System prompt references `enrich_ip_abuseipdb` (not `AbuseIPDB-Request`)
- [ ] `runbook.md` is written and covers deploy / rollback / verify / debug
- [ ] `notes.md` captures gotchas from each test case
- [ ] `log.md` has an entry marking A1 complete
- [ ] All commits have descriptive messages
- [ ] `git log --oneline` shows the full A1 implementation history

If any item fails, return to the relevant task and complete it before declaring done.
