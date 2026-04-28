---
status: active
updated: 2026-04-28
sub_project: A2
spec: [[spec]]
related: [[README]], [[../../workflows/soc-triage-pipeline]]
---

# A2 Iris Escalation Gate — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **For humans:** Work through tasks in order. Each task has 3–6 small steps. Run the verify step after each implementation step before moving on. Commit after each task.

**Goal:** Add a Slack-gated alert→case escalation step to the n8n SOC triage workflow. Modify A1's alert creation to natively carry IOCs; gate the alert→case escalation on URL-button approval; route timeout/deny outcomes to Slack thread replies. One additive A1 schema enhancement (`ioc_type` on `iocs_enriched` items). One A1 limitation fix in passing (Iris description's markdown link → raw URL).

**Architecture:** Build the gate pattern as `Webhook → Anthropic → Extract Triage Result → Create Iris Alert → IF (Has Malicious IOCs?) → Slack with URL buttons → Wait → Switch (Decision?) → branches`. Approve branch makes one HTTP call to `/alerts/escalate/{alert_id}`. All outcomes post a Slack thread reply on the original alert message. Single-action (Iris escalation only) — Splunk blocklist deferred to A3.

**Tech Stack:** n8n (web UI driven), `@n8n/n8n-nodes-langchain.anthropic`, n8n stock nodes (HTTP Request, Slack, Wait, IF, Switch, Code), DFIR-Iris API v2.4.22 (`/alerts/add`, `/alerts/escalate/{alert_id}`, `/manage/ioc-types/list`), Slack Block Kit (URL buttons only — no interactivity webhook).

**Reference docs:**
- Spec: [[spec]]
- A1 spec (predecessor): [[../2026-04-27-structured-outputs/spec]]
- A1 runbook (operational reference): [[../2026-04-27-structured-outputs/runbook]]
- A1 notes (gotchas to watch for): [[../2026-04-27-structured-outputs/notes]]
- DFIR-Iris OpenAPI: [`JSON/IRIS-2.0.4-OpenAPI-specification.json`](../../../JSON/IRIS-2.0.4-OpenAPI-specification.json)
- Current workflow JSON: [`JSON/SOC-Triage-v1.json`](../../../JSON/SOC-Triage-v1.json)
- Component pages: [[../../architecture/components/n8n]], [[../../architecture/components/claude-api]], [[../../architecture/components/dfir-iris]]
- Secrets: [[../../runbooks/secrets-management]]

**Working assumptions for the executor:**
- All four VMs are running (see [[../../runbooks/starting-the-vms]])
- n8n reachable at http://192.168.129.132:5678; DFIR-Iris reachable at https://192.168.129.133
- `SOC Triage v1` workflow exists and is the live workflow per A1's runbook
- The Splunk `Test-Brute-Force` saved search is currently disabled (per A1 closeout)
- A terminal is available at the project root `f:\Claude_Code\SOC_Automation_Project\`
- DFIR-Iris admin API key is in `SOC-Automation-Project.md` (gitignored)

**Conventions for n8n GUI tasks (carried over from A1):**
- "In n8n, do X" means open the n8n web UI and perform X
- "Execute the workflow" = click "Execute Workflow" button (uses pinned data, not a real Splunk alert)
- "Export workflow JSON" = workflow three-dot menu → Download → save to `JSON/<name>.json`
- "Verify Y in n8n" = look at the node's output panel after execution

**Common n8n quirks (rediscovered during A1; pre-emptively flagged):**
- **Body parameter Fixed-vs-Expression mode.** When pasting an expression like `={{ ... }}` into a body parameter field, the field must be in **Expression** mode. If pasted into Fixed mode, the literal string is sent. Toggle the field type before pasting; or paste *without* the leading `=` if the field is already in Expression mode (n8n auto-prefixes).
- **Unicode mojibake on Windows clipboard paste.** Smart quotes, em-dashes, arrows can become `â€"` etc. Use ASCII (`-->`, `--`, straight quotes) when typing into n8n text fields.
- **"Active/Inactive" toggle is "Publish/Unpublish" in newer n8n.** Functionally equivalent.
- **Webhook node "Test URL / Production URL" toggle is purely a display preference.** Both URLs always listen; the toggle only changes which one is shown.
- **Stale "Credentials are not set" warnings persist after credential reattachment.** Cosmetic; doesn't reflect runtime state.

---

## File structure

| File | Action | Purpose |
|---|---|---|
| `JSON/SOC-Triage-v1-pre-A2.json` | Create | Backup of `SOC Triage v1` state immediately before A2 work, for rollback |
| `JSON/SOC-Triage-v2.json` | Create | Exported state of the new workflow at each milestone |
| `vault/architecture/components/dfir-iris.md` | Modify | Append "IOC type IDs" subsection with IDs captured in Phase 0 |
| `vault/decisions/0005-additive-ioc-type-schema-enhancement.md` | Create | ADR for the `iocs_enriched.ioc_type` schema decision |
| `vault/subprojects/2026-04-28-iris-escalation-gate/runbook.md` | Modify | Replace placeholder with deploy/rollback/verify/debug |
| `vault/subprojects/2026-04-28-iris-escalation-gate/notes.md` | Append | Gotchas as we hit them |
| `vault/subprojects/2026-04-28-iris-escalation-gate/README.md` | Modify | Tick off status checkboxes |
| `vault/log.md` | Append | Milestone entries |
| n8n workflow `SOC Triage v1` | Rename | → `SOC Triage v1 (legacy)` for rollback |
| n8n workflow `SOC Triage v2` | Create (duplicate) | The new workflow we build A2 in |

No separate test files — n8n's testing model is "pin data + execute + visually verify."

---

## Phase 0 — Pre-flight verifications

Phase 0 captures information from running systems (n8n, Iris) that the rest of the plan depends on. **Run these before touching the workflow** — three of them feed values directly into Code-node constants and HTTP node URLs.

### Task 0.1: Capture Iris IOC type IDs

**Files:**
- Modify: `vault/architecture/components/dfir-iris.md`

- [ ] **Step 1: Get the Iris admin API key**

```bash
grep -i "iris" f:/Claude_Code/SOC_Automation_Project/SOC-Automation-Project.md | head -10
```

Note the API key value (looks like a long hex string). The file is gitignored.

- [ ] **Step 2: Query Iris IOC types catalog**

```bash
curl -k -H "Authorization: Bearer <PASTE-IRIS-API-KEY>" \
  https://192.168.129.133/manage/ioc-types/list \
  | python -m json.tool > /tmp/iris-ioc-types.json
cat /tmp/iris-ioc-types.json | head -100
```

Expected: a JSON object with `data` array, each element has `type_id` (integer) and `type_name` (string).

If 401: the API key is wrong. If connection refused: Iris VM is down — `ssh mydfir@192.168.129.133` and `cd iris-web && sudo docker-compose up`.

- [ ] **Step 3: Extract the five IDs we need**

```bash
python -c "
import json
data = json.load(open('/tmp/iris-ioc-types.json'))['data']
wanted = {
    'ip-src': 'ip',
    'ip-dst': 'ip',
    'domain': 'domain',
    'md5': 'md5',
    'sha1': 'sha1',
    'sha256': 'sha256',
}
for t in data:
    if t['type_name'] in wanted:
        print(f\"{wanted[t['type_name']]:8s} -> id={t['type_id']:3d}  (Iris name: {t['type_name']})\")
"
```

Expected output (numbers will differ):
```
ip       -> id=76   (Iris name: ip-src)
ip       -> id=77   (Iris name: ip-dst)
domain   -> id=20   (Iris name: domain)
md5      -> id=90   (Iris name: md5)
sha1     -> id=113  (Iris name: sha1)
sha256   -> id=114  (Iris name: sha256)
```

If `ip-src` and `ip-dst` are both present, **prefer `ip-src`** (the source IP from the alert is what we have). Note the chosen ID for `ip`.

If `type_name` values differ (e.g., `IP` vs `ip-src`), capture whatever the catalog actually contains and adjust the `wanted` dict.

- [ ] **Step 4: Document the IDs in the vault**

Open `vault/architecture/components/dfir-iris.md`. Append a new subsection:

```markdown
## IOC type IDs (captured 2026-04-28)

Required by A2's `Extract Triage Result` Code node. Re-capture if Iris is upgraded — IDs are deployment-specific.

| Our key | Iris `type_name` | Iris `type_id` |
|---|---|---|
| `ip`     | `ip-src` | (FILL IN FROM STEP 3) |
| `domain` | `domain` | (FILL IN FROM STEP 3) |
| `md5`    | `md5`    | (FILL IN FROM STEP 3) |
| `sha1`   | `sha1`   | (FILL IN FROM STEP 3) |
| `sha256` | `sha256` | (FILL IN FROM STEP 3) |

Source: `GET /manage/ioc-types/list` on the Iris instance at 192.168.129.133.
```

Replace `(FILL IN FROM STEP 3)` with the integers captured in Step 3.

- [ ] **Step 5: Commit**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git add vault/architecture/components/dfir-iris.md && git commit -m "docs(A2): capture Iris IOC type IDs for Phase 0"
```

---

### Task 0.2: Verify n8n Wait node behavior

**Files:** none on disk; manual experiment in n8n.

This task confirms two open questions from the spec: whether `$execution.resumeUrl` resolves in pre-Wait nodes, and the exact field name for the Wait timeout result.

- [ ] **Step 1: Open `SOC Triage v1` in n8n; do not save anything yet**

This task only experiments — no changes get saved.

- [ ] **Step 2: Add a temporary Set node before any other node, no incoming connection**

Click `+` on an empty area of the canvas. Search for `Set` (a.k.a. `Edit Fields`). Configure: Mode = Manual, add a string field `resume_url` with value `={{ $execution.resumeUrl }}`.

- [ ] **Step 3: Add a Wait node downstream of the Set node**

Connect Set → Wait. In Wait config: Resume = `On Webhook Call`, HTTP Method = `GET`, Resume time limit = `60 seconds`. Save.

- [ ] **Step 4: Click "Execute Workflow"**

The Set node should run, then the workflow should pause at the Wait node.

In the Set node's output panel, verify `resume_url` rendered to a non-empty URL like `http://192.168.129.132:5678/webhook-waiting/<execution-id>`.

**If it rendered correctly:** spec's primary path (`$execution.resumeUrl` in pre-Wait nodes) works. Note this in `notes.md`.

**If it rendered as empty/null:** fall back to manual construction. Test that `={{ $execution.id }}` *does* render. The plan's later tasks will use `http://192.168.129.132:5678/webhook-waiting/{{ $execution.id }}` instead.

- [ ] **Step 5: While the workflow is paused, hit the resume URL in a browser**

Open the resume URL in a browser tab. The workflow should resume with the request data.

In the Wait node's output panel, inspect the JSON shape. Note where `query` parameters land (likely `$json.query`) and whether headers / body are visible.

- [ ] **Step 6: Re-execute and let the Wait time out (don't hit the URL)**

After 60 seconds, the Wait should resume on timeout. Inspect the Wait node's output panel — note the exact field that indicates timeout (likely `$json.timedOut` boolean, or maybe nested under `$json.body`). Record the exact field path.

- [ ] **Step 7: Capture findings in `notes.md`**

Append to `vault/subprojects/2026-04-28-iris-escalation-gate/notes.md`:

```markdown
## 2026-04-28 (impl) — Phase 0 Wait node verification

- `$execution.resumeUrl` in pre-Wait Set node: RENDERED / NOT-RENDERED (pick one)
- Resume URL pattern: `<paste actual URL>`
- After webhook call, query params accessible at: `<paste actual JSON path>`
- After timeout, the timeout indicator field is: `<paste actual path, e.g. $json.timedOut>`
- Decision for plan: USE `$execution.resumeUrl` / USE manual `$execution.id` construction
```

- [ ] **Step 8: Delete the temporary nodes; do not save the workflow**

Click each temporary node → Delete. Verify `SOC Triage v1` is back to its A1-shipped state. **Do not click Save** — this preserves the production workflow.

- [ ] **Step 9: Commit**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git add vault/subprojects/2026-04-28-iris-escalation-gate/notes.md && git commit -m "docs(A2): Phase 0 Wait node behavior captured in notes"
```

---

### Task 0.3: Verify n8n Slack node Block Kit support

**Files:** none on disk; manual experiment in n8n.

Confirms the Slack node accepts `blocks` JSON before we build the real message.

- [ ] **Step 1: In `SOC Triage v1`, locate the existing Slack node `Send a message`**

(Don't modify it yet. We'll inspect its UI.)

- [ ] **Step 2: Click into the node and look for a Block Kit toggle**

In the node's parameters: look for "Operation" dropdown. Look for an option like "Send Message" → and within that, fields like "Use Block Kit", "Blocks", "Add Block", or a JSON input field. Some n8n versions expose this under "Add Option → Blocks" or similar.

- [ ] **Step 3: Note the field-path in `notes.md`**

```markdown
## Slack Block Kit support in this n8n version

- Block Kit field exposed at: `<paste path, e.g. Add Option → Blocks (JSON)>`
- Field accepts: <raw JSON / individual block builder UI / both>
```

If Block Kit is **not exposed** in the Slack node UI, the fallback is to use a generic HTTP Request node calling `https://slack.com/api/chat.postMessage` directly with the bot token. Plan would route this branch through HTTP Request nodes instead. Capture this finding now so Phase 5 picks the right path.

- [ ] **Step 4: Don't save any changes**

Close the node without saving. Workflow remains untouched.

- [ ] **Step 5: Commit notes update**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git add vault/subprojects/2026-04-28-iris-escalation-gate/notes.md && git commit -m "docs(A2): Phase 0 Slack Block Kit support captured"
```

---

## Phase 1 — Workflow scaffolding (backup + duplicate)

### Task 1.1: Backup `SOC Triage v1` as pre-A2 baseline

**Files:**
- Create: `JSON/SOC-Triage-v1-pre-A2.json`

- [ ] **Step 1: In n8n, open `SOC Triage v1`**

- [ ] **Step 2: Export the current state**

Three-dot menu (top right) → Download. Save as `JSON/SOC-Triage-v1-pre-A2.json` to `f:\Claude_Code\SOC_Automation_Project\JSON\`.

- [ ] **Step 3: Verify the file is valid JSON**

```bash
cd f:/Claude_Code/SOC_Automation_Project && python -c "import json; json.load(open('JSON/SOC-Triage-v1-pre-A2.json')); print('valid')"
```

Expected: `valid`

- [ ] **Step 4: Verify the export contains the A1 schema (sanity check before duplicating)**

```bash
grep -c "submit_triage_result" JSON/SOC-Triage-v1-pre-A2.json
```

Expected: a number > 0 (the tool name appears multiple times — in tool definition, system prompt, etc.).

- [ ] **Step 5: Commit the baseline**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git add JSON/SOC-Triage-v1-pre-A2.json && git commit -m "chore(A2): snapshot SOC Triage v1 pre-A2 baseline for rollback"
```

---

### Task 1.2: Duplicate workflow → `SOC Triage v2`; rename v1 → legacy

**Files:** None on disk; n8n workflow store only.

- [ ] **Step 1: In n8n Workflows list, right-click `SOC Triage v1` → Duplicate**

The copy will be named `SOC Triage v1 copy`.

- [ ] **Step 2: Rename the original**

Open `SOC Triage v1` (the original). Click the workflow name at top → rename to `SOC Triage v1 (legacy)`. Save.

- [ ] **Step 3: Rename the copy**

Open `SOC Triage v1 copy`. Rename to `SOC Triage v2`. Save.

- [ ] **Step 4: Verify both workflows exist with correct names**

Workflows list shows both `SOC Triage v1 (legacy)` and `SOC Triage v2`.

- [ ] **Step 5: Confirm `SOC Triage v1 (legacy)` is the currently active production workflow**

Open it. Top-right toggle should show "Active" / "Published" (whichever this n8n version uses). The Splunk webhook is currently routing to it.

`SOC Triage v2` should be **inactive**. Don't activate it yet — the Splunk webhook would race against v1 if both are active.

- [ ] **Step 6: Export `SOC Triage v2` as starting state**

Three-dot menu → Download. Save as `JSON/SOC-Triage-v2.json`.

- [ ] **Step 7: Commit**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git add JSON/SOC-Triage-v2.json && git commit -m "chore(A2): duplicate workflow as SOC Triage v2; v1 renamed to legacy"
```

All subsequent edits happen in `SOC Triage v2`. The legacy workflow is untouched as a rollback target.

---

## Phase 2 — Schema enhancement to `submit_triage_result`

A1's `submit_triage_result` tool input schema gets one additive change: `ioc_type` enum on each `iocs_enriched` item. The system prompt gets one additional bullet instructing Claude to populate it.

### Task 2.1: Add `ioc_type` to `submit_triage_result` schema

**Files:**
- Modify (via n8n GUI): `submit_triage_result` tool node in `SOC Triage v2`

- [ ] **Step 1: In `SOC Triage v2`, open the `submit_triage_result` Code Tool node**

It's one of the tool sub-nodes hanging off `Message a model`.

- [ ] **Step 2: Locate the input schema (JSON Schema)**

Find the field where the v1 schema is configured (per A1's plan it's "Schema" or "Input Schema").

- [ ] **Step 3: Update the `iocs_enriched` items schema**

Find this block in the existing schema:

```json
"iocs_enriched": {
  "type": "array",
  "items": {
    "type": "object",
    "required": ["value", "verdict", "source", "summary"],
    "properties": {
      "value":   { "type": "string" },
      "verdict": { "type": "string", "enum": ["malicious", "suspicious", "clean", "unknown"] },
      "source":  { "type": "string" },
      "summary": { "type": "string" }
    }
  }
}
```

Replace it with:

```json
"iocs_enriched": {
  "type": "array",
  "items": {
    "type": "object",
    "required": ["value", "ioc_type", "verdict", "source", "summary"],
    "properties": {
      "value":    { "type": "string" },
      "ioc_type": { "type": "string", "enum": ["ip", "domain", "file_hash"] },
      "verdict":  { "type": "string", "enum": ["malicious", "suspicious", "clean", "unknown"] },
      "source":   { "type": "string" },
      "summary":  { "type": "string" }
    }
  }
}
```

The diff: `ioc_type` added to `required`; `ioc_type` property added with enum.

- [ ] **Step 4: Save the node**

- [ ] **Step 5: Export and commit**

Re-export `SOC Triage v2` to `JSON/SOC-Triage-v2.json` (overwrite). Then:

```bash
cd f:/Claude_Code/SOC_Automation_Project && git add JSON/SOC-Triage-v2.json && git commit -m "feat(A2): add ioc_type enum to iocs_enriched in submit_triage_result schema"
```

---

### Task 2.2: Update system prompt with one-line `ioc_type` instruction

**Files:**
- Modify (via n8n GUI): `Message a model` node's system message in `SOC Triage v2`

- [ ] **Step 1: Open the `Message a model` node**

- [ ] **Step 2: Find the system message**

Per A1's plan, the system message lives under **Add Option → System Message** (parameter path `parameters.options.system`).

- [ ] **Step 3: Locate the IOC rules section in the system prompt**

Find this paragraph (from A1's spec):

```
- iocs lists must contain every distinct IOC observed, deduplicated. iocs_enriched contains only the subset that was actually looked up.
```

- [ ] **Step 4: Insert one new bullet right after it**

```
- iocs lists must contain every distinct IOC observed, deduplicated. iocs_enriched contains only the subset that was actually looked up.
- For each item in iocs_enriched, set ioc_type to "ip", "domain", or "file_hash" matching what kind of IOC it is. This is required so downstream automation can route the IOC correctly.
```

(The new bullet starts with `- For each item in iocs_enriched`.)

- [ ] **Step 5: Save the node**

- [ ] **Step 6: Export and commit**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git add JSON/SOC-Triage-v2.json && git commit -m "feat(A2): system prompt instructs Claude to populate iocs_enriched.ioc_type"
```

---

### Task 2.3: Smoke-test the schema change with pinned data

**Files:** none.

- [ ] **Step 1: Confirm the Webhook node still has Test 2 pinned data (external IP)**

If A1 left Test 1 (RFC1918) pinned, that's fine for this smoke test — even with no enrichment, the schema change must not break parsing. Otherwise paste the external-IP variant from A1's notes.

- [ ] **Step 2: Unpin `Message a model` if pinned (so Claude is called fresh)**

In `Message a model`, click the pin icon to clear any cached response.

- [ ] **Step 3: Click Execute Workflow**

A1's downstream `Extract Triage Result` will probably **succeed** because the new field is optional in practice (Claude may or may not populate it). If `Extract Triage Result` fails: Claude returned malformed input and Anthropic rejected it; investigate.

- [ ] **Step 4: Inspect the `Message a model` output**

In its output panel, find the `submit_triage_result` tool_use entry. Look at `input.iocs_enriched`. If Claude returned `ioc_type` populated (e.g., `"ioc_type": "ip"`), the schema is being honored.

If `iocs_enriched` is empty (Test 1 / RFC1918 case), this test is uninformative — re-run with Test 2's external-IP pinned data.

- [ ] **Step 5: Capture finding in notes**

```markdown
## 2026-04-28 (impl) — Phase 2 smoke test
- Schema enhancement accepted by Anthropic API: yes/no
- ioc_type populated by Claude on iocs_enriched items: yes/no/N-A (empty)
```

- [ ] **Step 6: Commit notes**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git add vault/subprojects/2026-04-28-iris-escalation-gate/notes.md && git commit -m "test(A2): smoke-test schema enhancement"
```

---

## Phase 3 — Extend `Extract Triage Result` Code node

The Code node gains the IOC type ID catalog, the `buildAlertIocs` function, the `alert_iocs_summary` string, and the one-line markdown→raw URL fix to `iris_description`.

### Task 3.1: Replace `Extract Triage Result` body with the A2 version

**Files:**
- Modify (via n8n GUI): `Extract Triage Result` Code node in `SOC Triage v2`

This is one big paste — the entire Code node body is rewritten in one step. Below the code is what's new vs A1.

- [ ] **Step 1: Open `Extract Triage Result` in `SOC Triage v2`**

- [ ] **Step 2: Replace the entire JavaScript body with the following**

```javascript
// =====================================================================
// Extract Triage Result — A2 version
// (extends A1: pulls IOCs into structured `alert_iocs` for Iris;
// drops the markdown link in iris_description; keeps all A1 fields.)
// =====================================================================

// Pull the structured triage result out of Claude's tool call ----------
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

// Iris IOC type IDs ----------------------------------------------------
// Captured from /manage/ioc-types/list during Phase 0 of A2 plan.
// See vault/architecture/components/dfir-iris.md#ioc-type-ids
const IRIS_IOC_TYPE_IDS = {
  ip:     /* PHASE-0 */,
  domain: /* PHASE-0 */,
  md5:    /* PHASE-0 */,
  sha1:   /* PHASE-0 */,
  sha256: /* PHASE-0 */,
};

// Reverse map for the human-readable Slack action prompt ---------------
const TYPE_NAMES = Object.fromEntries(
  Object.entries(IRIS_IOC_TYPE_IDS).map(([name, id]) => [id, name])
);

// TLP:Amber — internal-team-shareable threat intel ---------------------
const TLP_AMBER = 2;

// Resolve our (ioc_type, value) → Iris ioc_type_id integer -------------
function resolveIrisTypeId(iocType, value) {
  if (iocType === 'ip')     return IRIS_IOC_TYPE_IDS.ip;
  if (iocType === 'domain') return IRIS_IOC_TYPE_IDS.domain;
  if (iocType === 'file_hash') {
    const v = String(value).trim().toLowerCase();
    if (/^[0-9a-f]{32}$/.test(v)) return IRIS_IOC_TYPE_IDS.md5;
    if (/^[0-9a-f]{40}$/.test(v)) return IRIS_IOC_TYPE_IDS.sha1;
    if (/^[0-9a-f]{64}$/.test(v)) return IRIS_IOC_TYPE_IDS.sha256;
  }
  return null;
}

// Build alert_iocs from Claude's iocs_enriched (malicious/suspicious only)
const candidates = (r.iocs_enriched || []).filter(
  i => i.verdict === 'malicious' || i.verdict === 'suspicious'
);
const alert_iocs = [];
for (const item of candidates) {
  const typeId = resolveIrisTypeId(item.ioc_type, item.value);
  if (typeId === null) {
    console.warn(`Skipping IOC ${item.value} — unresolved type ${item.ioc_type}`);
    continue;
  }
  alert_iocs.push({
    ioc_value:       item.value,
    ioc_description: `${item.source}: ${item.summary}`,
    ioc_tlp_id:      TLP_AMBER,
    ioc_type_id:     typeId,
    ioc_tags:        'soc-automation,a2',
  });
}

// Pre-rendered Slack action-prompt list -------------------------------
const alert_iocs_summary = alert_iocs.length > 0
  ? alert_iocs.map(i => `• \`${i.ioc_value}\` (${TYPE_NAMES[i.ioc_type_id] || 'unknown'})`).join('\n')
  : '_none_';

// ---- BELOW HERE: A1 logic preserved verbatim, with one fix ----------

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
const webhook    = $('Webhook').first().json.body;
const alertName  = webhook.search_name;
// Splunk URL hostname patch (carried over from A1; long-term server-side fix deferred)
const splunkLink = (webhook.results_link || '').replace('mydfir-splunk', '192.168.129.131');

// Slack message body — unchanged from A1
const slack_message = `${sevEmoji} *${r.severity.toUpperCase()}* — ${alertName}

${r.alert_summary}

*Severity Rationale:* ${r.severity_rationale}
*MITRE:* ${mitre}

*Enriched IOCs:*
${enriched}

*Recommended Actions:*
${actions}

<${splunkLink}|View in Splunk>`;

// Iris description — A2 fix: raw URL instead of markdown link
// (DFIR-Iris's alert description doesn't render markdown links, per A1 runbook.)
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
Splunk: ${splunkLink}`;

return [{
  json: {
    ...r,
    severity_iris_id:   sevId,
    slack_message,
    iris_description,
    splunk_link:        splunkLink,
    alert_name:         alertName,
    alert_iocs,
    alert_iocs_summary,
  }
}];
```

- [ ] **Step 3: Fill in the Phase 0 IOC type IDs**

Find the `IRIS_IOC_TYPE_IDS` block. Replace each `/* PHASE-0 */` with the integer captured in Task 0.1 Step 4.

Example:
```javascript
const IRIS_IOC_TYPE_IDS = {
  ip:     76,
  domain: 20,
  md5:    90,
  sha1:   113,
  sha256: 114,
};
```

- [ ] **Step 4: Save the node**

- [ ] **Step 5: Export and commit**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git add JSON/SOC-Triage-v2.json && git commit -m "feat(A2): extend Extract Triage Result with alert_iocs builder + Iris markdown fix"
```

---

### Task 3.2: Test `Extract Triage Result` with pinned data

**Files:** none.

- [ ] **Step 1: Re-pin the `Message a model` output if necessary**

If `Message a model` was unpinned in Task 2.3, run the workflow once with the external-IP pinned webhook payload to regenerate Claude's response, then pin it. This avoids burning API tokens during downstream development.

- [ ] **Step 2: Click "Test step" on `Extract Triage Result`**

- [ ] **Step 3: Inspect the output JSON**

Verify these fields exist:

- All A1 fields preserved: `severity`, `severity_iris_id`, `slack_message`, `iris_description`, `splunk_link`, `alert_name`, `iocs`, `iocs_enriched`, `mitre_techniques`, `recommended_actions`, `investigation_notes` (or fallback)
- `alert_iocs` — array (may be empty if Test 1 / RFC1918 pinned data; non-empty for Test 2 / external IP)
- `alert_iocs_summary` — string (e.g., `"• \`185.220.101.42\` (ip)"` or `"_none_"`)
- `iris_description` — verify the last line is `Splunk: http://192.168.129.131:8000/...` (raw URL, **not** `[View in Splunk](...)`)

- [ ] **Step 4: If `alert_iocs` is empty when expecting non-empty**

Check Claude's response: did it populate `iocs_enriched[].ioc_type`? If no, Phase 2 didn't take — re-verify the schema change saved.

If `ioc_type` is populated but `alert_iocs` is empty: the Phase 0 type IDs may be wrong, or the verdict isn't `malicious`/`suspicious`. Inspect Claude's response body.

- [ ] **Step 5: Capture finding in notes**

```markdown
## 2026-04-28 (impl) — Phase 3 Code node test

- All A1 fields preserved: yes/no
- alert_iocs populated for external-IP test: yes/no, count = N
- alert_iocs_summary rendered correctly: yes/no
- iris_description ends in raw `Splunk: <url>` (no markdown link): yes/no
```

- [ ] **Step 6: Commit notes**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git add vault/subprojects/2026-04-28-iris-escalation-gate/notes.md && git commit -m "test(A2): Extract Triage Result A2 fields verified"
```

---

## Phase 4 — Modify `Create Iris Alert` HTTP Request node

(In the v1 workflow this node is named `DFIR-IRIS HTTP Request`. In A2 we rename it to `Create Iris Alert` for clarity since A2 introduces a second Iris HTTP node.)

### Task 4.1: Rename and add `alert_iocs` body parameter

**Files:**
- Modify (via n8n GUI): `DFIR-IRIS HTTP Request` node in `SOC Triage v2`

- [ ] **Step 1: Open the `DFIR-IRIS HTTP Request` node in `SOC Triage v2`**

- [ ] **Step 2: Rename it to `Create Iris Alert`**

Click the node name → rename. Save.

- [ ] **Step 3: Locate the body parameters section**

The node has body parameters: `alert_title`, `alert_description`, `alert_severity_id`, `alert_status_id`, `alert_customer_id` (from A1).

- [ ] **Step 4: Add a new body parameter `alert_iocs` (Expression mode)**

Click "Add Parameter". Name = `alert_iocs`. **Toggle the value field to Expression mode** (look for the `=` icon or "Expression" toggle).

In the value field, enter:
```
{{ $json.alert_iocs }}
```

(Note: enter `{{ ... }}`, **not** `={{ ... }}`. n8n auto-prefixes the `=` in Expression mode. If you paste with the leading `=`, the actual sent value becomes `==...` per the A1 gotcha.)

- [ ] **Step 5: Verify Expression mode took**

The value field should display `{{ $json.alert_iocs }}` with a small expression badge / colored highlight. If it's plain black text in a Fixed-mode field, toggle to Expression and re-paste.

- [ ] **Step 6: Save the node**

- [ ] **Step 7: Export and commit**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git add JSON/SOC-Triage-v2.json && git commit -m "feat(A2): rename Iris HTTP node, add alert_iocs body parameter"
```

---

### Task 4.2: Enable "Always Output Data" so the response is captured

**Files:**
- Modify (via n8n GUI): `Create Iris Alert` node settings in `SOC Triage v2`

- [ ] **Step 1: Open `Create Iris Alert`**

- [ ] **Step 2: Find the Settings tab**

In the node editor, there's usually a "Settings" tab alongside "Parameters". Click it.

- [ ] **Step 3: Enable "Always Output Data"**

Toggle ON. (Some n8n versions label this "Output Data Always", "Continue On Output", or expose it via a separate "Output" toggle. The intent is that the node's output is always available downstream — including the response body for inspection.)

- [ ] **Step 4: Save the node**

- [ ] **Step 5: Test in isolation**

Click "Test step" on `Create Iris Alert`. Provide pinned upstream data (Test 2's external-IP payload).

Expected: HTTP 200 from Iris with body containing `data.alert_id` (integer) and `data.iocs` (array, possibly empty if alert_iocs was empty).

If 400 with `{"data": {"alert_iocs": ["Unknown field."]}}`: the body parameter didn't get accepted. Verify Expression mode + valid JSON.

If 400 with malformed-IOC complaints: cross-check that each `alert_iocs[*].ioc_type_id` matches an integer in Iris's catalog.

- [ ] **Step 6: Capture the response shape in notes**

Note the actual response field paths so subsequent tasks reference them correctly:

```markdown
## 2026-04-28 (impl) — Phase 4 Iris alert response shape

- alert_id field path: data.alert_id (verified)
- IOC UUIDs field path: data.iocs[].ioc_uuid (verified)
- Number of IOCs in response for Test 2: N
```

- [ ] **Step 7: Export and commit**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git add JSON/SOC-Triage-v2.json vault/subprojects/2026-04-28-iris-escalation-gate/notes.md && git commit -m "feat(A2): enable Always Output Data on Create Iris Alert"
```

---

## Phase 5 — `Has Malicious IOCs?` IF + Slack branching

The current A1 wiring has Slack and Iris in parallel after `Extract Triage Result`. A2 needs:
1. Iris first (already wired in Phase 4 since `Create Iris Alert` runs before any Slack post)
2. After Iris, branch on whether `alert_iocs.length > 0`

### Task 5.1: Rewire so that Iris precedes Slack

**Files:**
- Modify (via n8n GUI): connections in `SOC Triage v2`

- [ ] **Step 1: Inspect the current canvas wiring**

In `SOC Triage v2`, the connections likely are:
```
Extract Triage Result ─┬→ Send a message (Slack)
                       └→ Create Iris Alert
```

- [ ] **Step 2: Disconnect Slack from Extract Triage Result**

Hover the connection between `Extract Triage Result` and `Send a message`. Click the small `x` to remove it.

- [ ] **Step 3: Connect Slack downstream of Create Iris Alert (temporary)**

Drag a new connection from `Create Iris Alert` → `Send a message`. Slack now runs after Iris. (This is a temporary wiring — Phase 5.2 inserts the IF in between.)

- [ ] **Step 4: Test the chain still works**

Click "Execute Workflow." Verify both nodes still execute successfully.

- [ ] **Step 5: Export and commit**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git add JSON/SOC-Triage-v2.json && git commit -m "feat(A2): rewire Iris-then-Slack (sequential, was parallel)"
```

---

### Task 5.2: Add `Has Malicious IOCs?` IF node

**Files:**
- Modify (via n8n GUI): add IF node in `SOC Triage v2`

- [ ] **Step 1: Disconnect `Send a message` from `Create Iris Alert`**

(So we can insert the IF in between.)

- [ ] **Step 2: Add an IF node between `Create Iris Alert` and `Send a message`**

Click `+` between them. Search for `IF` → select `IF` (`n8n-nodes-base.if`).

- [ ] **Step 3: Rename to `Has Malicious IOCs?`**

- [ ] **Step 4: Configure the condition**

In the IF node's Conditions configuration:
- Click "Add Condition" → Type = Number
- Value 1: `={{ $json.alert_iocs.length }}`
- Operation: `larger` (greater than)
- Value 2: `0`

(If your n8n version's IF node has a different UI, the equivalent is: condition that evaluates to true when `alert_iocs` has at least one element.)

- [ ] **Step 5: Connect Create Iris Alert → IF**

Drag from `Create Iris Alert` to the new IF node.

- [ ] **Step 6: Connect IF "false" output to the existing `Send a message` (no buttons branch)**

The IF node typically has two outputs labeled "true" and "false" (or 0/1). The "false" output (no malicious IOCs) goes to the existing Slack node.

Drag from IF "false" → `Send a message`. Save.

- [ ] **Step 7: Test the false branch**

With Test 1 (RFC1918) pinned, execute the workflow. The IF should take the false branch; Slack node fires; verify the Slack message in #alerts looks like A1's normal alert.

- [ ] **Step 8: Export and commit**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git add JSON/SOC-Triage-v2.json && git commit -m "feat(A2): add Has Malicious IOCs? IF, false-branch wired to existing Slack"
```

---

### Task 5.3: Add `Post Slack Alert + Approve/Deny` node (Block Kit + URL buttons)

**Files:**
- Modify (via n8n GUI): add Slack node in `SOC Triage v2`

This is the buttoned variant. The Block Kit content depends on Phase 0.3's findings.

**Branch A — Slack node natively supports Block Kit (Phase 0.3 found the field):**

- [ ] **Step 1: Add a new Slack node downstream of the IF "true" output**

Click `+` on the IF "true" branch. Search for `Slack` → select Slack node. Configure:
- Credential: `Slack account` (existing)
- Operation: `Send Message` (or whatever this n8n version calls the chat.postMessage equivalent)
- Channel: by name = `alerts` OR by ID = `C0B0QMQU8QG` (use whichever existing Slack node uses)

- [ ] **Step 2: Rename the node to `Post Slack Alert + Approve/Deny`**

- [ ] **Step 3: Open Block Kit / Blocks JSON field**

(Per Phase 0.3 finding — exact field path varies.)

- [ ] **Step 4: Paste the Block Kit JSON**

```json
[
  { "type": "section", "text": { "type": "mrkdwn", "text": "={{ $json.slack_message }}" } },
  { "type": "divider" },
  {
    "type": "section",
    "text": {
      "type": "mrkdwn",
      "text": "=*ACTION REQUEST: Escalate this alert to a DFIR-Iris case?*\n\nThe following IOCs will be promoted to threat intel:\n{{ $json.alert_iocs_summary }}\n\n_Iris alert: <https://192.168.129.133/alerts?alert_ids={{ $('Create Iris Alert').item.json.data.alert_id }}|#{{ $('Create Iris Alert').item.json.data.alert_id }}>_"
    }
  },
  {
    "type": "actions",
    "elements": [
      {
        "type": "button",
        "text": { "type": "plain_text", "text": "✅ Approve" },
        "url": "={{ $execution.resumeUrl }}?decision=approve",
        "style": "primary"
      },
      {
        "type": "button",
        "text": { "type": "plain_text", "text": "❌ Deny" },
        "url": "={{ $execution.resumeUrl }}?decision=deny",
        "style": "danger"
      }
    ]
  }
]
```

If Phase 0.2 found `$execution.resumeUrl` does **not** resolve in pre-Wait nodes, replace `{{ $execution.resumeUrl }}` with `http://192.168.129.132:5678/webhook-waiting/{{ $execution.id }}` in both URLs.

- [ ] **Step 5: Save the node**

**Branch B — Slack node does NOT support Block Kit (Phase 0.3 didn't find the field):**

Use a generic HTTP Request node instead.

- [ ] **Step 1 (alt): Add HTTP Request node, name `Post Slack Alert + Approve/Deny`**
- [ ] **Step 2 (alt): Configure**
  - Method: `POST`
  - URL: `https://slack.com/api/chat.postMessage`
  - Authentication: `Generic Credential Type → Header Auth`, header name `Authorization`, value `Bearer <slack-bot-token>` (use the same token the existing Slack node's credential holds — extract from the credential view, OR create a new `Slack bearer` credential of type Header Auth)
  - Body type: JSON
  - Body:
```json
{
  "channel": "C0B0QMQU8QG",
  "blocks": [
    { "type": "section", "text": { "type": "mrkdwn", "text": "{{ $json.slack_message }}" } },
    { "type": "divider" },
    { "type": "section", "text": { "type": "mrkdwn", "text": "*ACTION REQUEST: Escalate this alert to a DFIR-Iris case?*\n\nThe following IOCs will be promoted to threat intel:\n{{ $json.alert_iocs_summary }}\n\n_Iris alert: <https://192.168.129.133/alerts?alert_ids={{ $('Create Iris Alert').item.json.data.alert_id }}|#{{ $('Create Iris Alert').item.json.data.alert_id }}>_" } },
    { "type": "actions", "elements": [
      { "type": "button", "text": { "type": "plain_text", "text": "✅ Approve" }, "url": "{{ $execution.resumeUrl }}?decision=approve", "style": "primary" },
      { "type": "button", "text": { "type": "plain_text", "text": "❌ Deny" },    "url": "{{ $execution.resumeUrl }}?decision=deny",    "style": "danger"  }
    ] }
  ]
}
```

(Same `$execution.resumeUrl` fallback applies if Phase 0.2 indicated.)

**Continuing both branches:**

- [ ] **Step 6: Connect IF "true" → `Post Slack Alert + Approve/Deny`**

- [ ] **Step 7: Test with Test 2 pinned data**

Pin Test 2 (external IP, count=47) into the Webhook node. Execute. The IF should take "true"; this node should fire. Check Slack #alerts: a message with severity badge + alert details + divider + action prompt + IOC list + Approve / Deny buttons should appear.

If the buttons don't render: re-check the Block Kit JSON syntax — Slack is strict about required fields (`type`, `text.type`, etc.).

- [ ] **Step 8: Export and commit**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git add JSON/SOC-Triage-v2.json && git commit -m "feat(A2): add Slack message with URL buttons (Block Kit)"
```

---

## Phase 6 — `Wait For Decision` node + browser response

### Task 6.1: Add and configure the Wait node

**Files:**
- Modify (via n8n GUI): add Wait node in `SOC Triage v2`

- [ ] **Step 1: Add Wait node downstream of `Post Slack Alert + Approve/Deny`**

Click `+` after the Slack-with-buttons node. Search `Wait` → select.

- [ ] **Step 2: Rename to `Wait For Decision`**

- [ ] **Step 3: Configure**

| Setting | Value |
|---|---|
| Resume | On Webhook Call |
| HTTP Method | GET |
| Authentication | None |
| Response Mode | Respond Immediately (look for the field "Response Mode" or similar) |
| Response Code | 200 |
| Response Data | (will set in Step 4) |
| Resume time limit (or "Wait time" / "Max wait") | 1800 seconds (30 minutes) |

- [ ] **Step 4: Configure the HTML response body**

Find "Response Data" field. Paste:

```html
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>SOC Triage — decision recorded</title>
  <style>
    body { font-family: system-ui, sans-serif; text-align: center; padding: 4em; background: #f4f5f7; }
    h1   { color: #2d3748; }
    p    { color: #4a5568; }
    .btn { color: #718096; font-size: 0.9em; }
  </style>
</head>
<body>
  <h1>✓ Decision recorded</h1>
  <p>The workflow is processing your decision. You can close this tab.</p>
  <p class="btn">A confirmation message will appear in the Slack thread within a few seconds.</p>
</body>
</html>
```

If the field expects a content-type header to be set explicitly: set `Content-Type: text/html`.

- [ ] **Step 5: Save the node**

- [ ] **Step 6: Export and commit**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git add JSON/SOC-Triage-v2.json && git commit -m "feat(A2): add Wait For Decision node, 30-min timeout, HTML response"
```

---

### Task 6.2: Test Wait + URL button click flow

**Files:** none.

- [ ] **Step 1: Pin Test 2 webhook data; unpin Anthropic if needed**

- [ ] **Step 2: Execute the workflow**

The workflow should run through Anthropic, Extract, Iris alert create, IF (true branch), Slack post, then **pause at Wait**.

In n8n, the workflow's status should show "Waiting" with the Wait node highlighted.

- [ ] **Step 3: Open Slack #alerts and click ✅ Approve**

Browser opens the resume URL. The HTML page from Step 4 of 6.1 should render: "✓ Decision recorded".

- [ ] **Step 4: Switch back to n8n executions panel**

The execution that was paused should now show "Running" then "Succeeded" (or a downstream-node failure since we haven't built the Switch / branches yet — that's expected).

In the Wait node's output panel, inspect `$json`. Verify:
- Query parameter `decision=approve` is accessible (likely `$json.query.decision === 'approve'` per Phase 0.2 finding)
- Headers visible (informational)

- [ ] **Step 5: Re-execute and let it time out**

Pin again, execute. Don't click anything. Wait ≥ 30 minutes (or temporarily reduce the Wait timeout to 60 seconds during testing — remember to set back to 1800 before continuing).

After timeout, inspect the Wait output. Verify the timeout indicator field (likely `$json.timedOut === true` per Phase 0.2 finding).

- [ ] **Step 6: Reset Wait timeout to 1800 seconds if you reduced it**

- [ ] **Step 7: Capture findings in notes**

```markdown
## 2026-04-28 (impl) — Phase 6 Wait flow verified

- Browser HTML page renders on click: yes/no
- Query param accessible at: $json.query.decision
- Timeout field: $json.timedOut === true
- Wait timeout reset to 1800s after testing: yes
```

- [ ] **Step 8: Commit notes**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git add vault/subprojects/2026-04-28-iris-escalation-gate/notes.md && git commit -m "test(A2): Wait + button click + timeout flows verified"
```

---

## Phase 7 — `Decision?` Switch + branch routing

### Task 7.1: Add Switch node downstream of Wait

**Files:**
- Modify (via n8n GUI): add Switch node in `SOC Triage v2`

- [ ] **Step 1: Add Switch node downstream of `Wait For Decision`**

Click `+` after Wait. Search `Switch` → select.

- [ ] **Step 2: Rename to `Decision?`**

- [ ] **Step 3: Configure as a 3-output Rules-mode Switch**

| Output # | Name | Condition |
|---|---|---|
| 0 | timeout | Boolean: `={{ $json.timedOut }}` is `true` |
| 1 | approve | String: `={{ $json.query.decision }}` equals `approve` |
| 2 | deny | String: `={{ $json.query.decision }}` equals `deny` |

For the **fallback** (anything else), enable the Switch's "Fallback Output" option (some n8n versions: a checkbox; others: a 4th explicit rule). Configure the fallback to route to the same downstream node as the `deny` output (the `Reply: Denied` Slack node we add in Task 8.3 Step 4 — wire fallback there once that node exists).

- [ ] **Step 4: Save the node**

- [ ] **Step 5: Test each Switch branch resolves correctly**

Execute the workflow once with Approve clicked → verify Switch took output 1.
Execute with Deny clicked → verify output 2.
Execute and let timeout fire (use 60s temporarily if needed) → verify output 0.

- [ ] **Step 6: Export and commit**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git add JSON/SOC-Triage-v2.json && git commit -m "feat(A2): add Decision? Switch with 3 outputs + deny fallback"
```

---

## Phase 8 — Approve sub-flow + thread replies

### Task 8.1: Add `Escalate Iris Alert` HTTP Request node

**Files:**
- Modify (via n8n GUI): add HTTP Request node in `SOC Triage v2`

- [ ] **Step 1: Add HTTP Request node downstream of Switch output `approve`**

Click `+` on the `approve` Switch output. Search `HTTP Request` → select.

- [ ] **Step 2: Rename to `Escalate Iris Alert`**

- [ ] **Step 3: Configure**

| Field | Value |
|---|---|
| Method | POST |
| URL | `=https://192.168.129.133/alerts/escalate/{{ $('Create Iris Alert').item.json.data.alert_id }}` |
| Authentication | Generic Credential Type → Header Auth → credential `dfirIrisApi` (or whatever name the existing Iris credential uses) |
| Body Content Type | JSON |
| Specify Body | Using JSON |
| Allow Unauthorized Certs | ON (Options tab) |

Settings tab:
- **Continue On Fail: ON**

- [ ] **Step 4: Configure the JSON body**

Paste:

```json
{
  "iocs_import_list": "={{ $('Create Iris Alert').item.json.data.iocs.map(i => i.ioc_uuid) }}",
  "assets_import_list": [],
  "import_as_event": true,
  "note": "Auto-escalated by SOC Automation A2 after analyst approval.",
  "case_tags": "soc-automation,a2,auto-escalated",
  "case_title": "=[ALERT #{{ $('Create Iris Alert').item.json.data.alert_id }}] {{ $('Extract Triage Result').item.json.alert_name }} — {{ $('Extract Triage Result').item.json.severity }}"
}
```

All references use explicit `$('NodeName').item.json.field` form rather than bare `$json` because by the time this node runs, `$json` resolves to the Wait node's output (the resume HTTP request data), not the upstream business data. The explicit references reach back into specific node outputs regardless of position in the chain.

- [ ] **Step 5: Save the node**

- [ ] **Step 6: Test in isolation**

Pin Test 2 data, execute the workflow, click Approve. The escalate call should fire after Wait resumes.

In the `Escalate Iris Alert` output panel, expect:
- HTTP 200
- Response body: `{ "status": "success", "data": { "case_id": <int>, "case_uuid": "<uuid>", ... } }`

In Iris UI (https://192.168.129.133), navigate to Cases — verify a new case exists with the title formatted from `case_title`.

In that case's IOCs tab — verify the IOCs from the alert are visible.

- [ ] **Step 7: Export and commit**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git add JSON/SOC-Triage-v2.json && git commit -m "feat(A2): add Escalate Iris Alert HTTP node"
```

---

### Task 8.2: Add `Escalation Succeeded?` IF + approve-success / approve-fail Slack replies

**Files:**
- Modify (via n8n GUI): add IF + 2 Slack nodes in `SOC Triage v2`

- [ ] **Step 1: Add IF node downstream of `Escalate Iris Alert`**

Search `IF` → add.

- [ ] **Step 2: Rename to `Escalation Succeeded?`**

- [ ] **Step 3: Configure condition**

- Type: String
- Value 1: `={{ $json.status }}`
- Operation: `equal`
- Value 2: `success`

- [ ] **Step 4: Save and connect**

`Escalate Iris Alert` → `Escalation Succeeded?`.

- [ ] **Step 5: Add Slack node downstream of IF "true" branch — name `Reply: Approved + case`**

Configure:
- Credential: `Slack account`
- Channel: `C0B0QMQU8QG` (same as alert post)
- Operation: Send Message (in thread)
- **Thread TS** parameter: `={{ $('Post Slack Alert + Approve/Deny').item.json.ts }}`
- Text: 
  ```
  =✅ *Approved* — Iris case <https://192.168.129.133/case?cid={{ $('Escalate Iris Alert').item.json.data.case_id }}|#{{ $('Escalate Iris Alert').item.json.data.case_id }}> created with {{ $('Create Iris Alert').item.json.data.iocs.length }} IOCs imported.
  ```

(If your Slack node doesn't have an explicit "Thread TS" field, look for "Other Options → Thread Timestamp" or the JSON `thread_ts` body parameter. If using HTTP Request fallback per Phase 0.3 finding, add `"thread_ts": "..."` to the JSON body.)

- [ ] **Step 6: Add Slack node downstream of IF "false" branch — name `Reply: Approved but escalation failed`**

Configure:
- Credential: `Slack account`
- Channel: `C0B0QMQU8QG`
- Thread TS: `={{ $('Post Slack Alert + Approve/Deny').item.json.ts }}`
- Text:
  ```
  =❌ *Approval received but escalation failed:* {{ $('Escalate Iris Alert').item.json.message || 'unknown error' }}.
  Iris alert <https://192.168.129.133/alerts?alert_ids={{ $('Create Iris Alert').item.json.data.alert_id }}|#{{ $('Create Iris Alert').item.json.data.alert_id }}> remains in the alert queue. Manual escalation required.
  ```

- [ ] **Step 7: Save all three nodes**

- [ ] **Step 8: Test the success path**

Iris VM up; pin Test 2; execute; click Approve. Verify:
- `Escalate Iris Alert` returns 200
- IF takes true branch
- Slack thread reply appears in #alerts under the original alert message
- Reply text contains a clickable link to the new Iris case

- [ ] **Step 9: Export and commit**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git add JSON/SOC-Triage-v2.json && git commit -m "feat(A2): add Escalation Succeeded? IF and approve-success/approve-fail thread replies"
```

---

### Task 8.3: Add Deny + Timeout Slack thread reply nodes

**Files:**
- Modify (via n8n GUI): add 2 Slack nodes in `SOC Triage v2`

- [ ] **Step 1: Add Slack node downstream of Switch output `deny` — name `Reply: Denied`**

Configure:
- Credential: `Slack account`
- Channel: `C0B0QMQU8QG`
- Thread TS: `={{ $('Post Slack Alert + Approve/Deny').item.json.ts }}`
- Text:
  ```
  =❌ *Denied* — Iris alert <https://192.168.129.133/alerts?alert_ids={{ $('Create Iris Alert').item.json.data.alert_id }}|#{{ $('Create Iris Alert').item.json.data.alert_id }}> remains in the alert queue. No case opened.
  ```

- [ ] **Step 2: Add Slack node downstream of Switch output `timeout` — name `Reply: Timeout`**

Configure:
- Credential: `Slack account`
- Channel: `C0B0QMQU8QG`
- Thread TS: `={{ $('Post Slack Alert + Approve/Deny').item.json.ts }}`
- Text:
  ```
  =⏱️ *No response in 30 minutes — auto-treated as Deny.* Iris alert <https://192.168.129.133/alerts?alert_ids={{ $('Create Iris Alert').item.json.data.alert_id }}|#{{ $('Create Iris Alert').item.json.data.alert_id }}> remains in the alert queue.
  ```

- [ ] **Step 3: Save both nodes**

- [ ] **Step 4: Wire the Switch fallback to `Reply: Denied`**

In the `Decision?` Switch node, configure the fallback output to route to `Reply: Denied` (same target as the `deny` rule). Some n8n versions allow drawing a second connection from the fallback to the same target; others require enabling the "Fallback" mode and selecting the output.

- [ ] **Step 5: Test the deny path**

Pin Test 2; execute; click Deny. Verify:
- Switch takes `deny` output
- `Reply: Denied` fires
- Thread reply appears

- [ ] **Step 6: Test the timeout path**

Reduce Wait timeout to 60s temporarily. Pin Test 2; execute; don't click. After 60s:
- Switch takes `timeout` output
- `Reply: Timeout` fires

**Reset Wait timeout to 1800s after this test.**

- [ ] **Step 7: Export and commit**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git add JSON/SOC-Triage-v2.json && git commit -m "feat(A2): add Deny + Timeout thread reply nodes; wire Switch fallback to deny"
```

---

## Phase 9 — Operational settings

### Task 9.1: Bump workflow timeout to 2100s

**Files:** none on disk; n8n workflow settings only.

- [ ] **Step 1: Open `SOC Triage v2` settings**

Three-dot menu (top right) → Workflow settings.

- [ ] **Step 2: Set workflow timeout**

- Workflow timeout: **2100 seconds**

(Why 2100 vs 1800: the Wait node's 30-min timeout consumes 1800s on the timeout path; the post-Wait Switch + Slack thread reply needs ~5–10 more seconds. Plus buffer for the Approve path's escalate call. 2100s = 35 min gives comfortable headroom.)

- [ ] **Step 3: Verify execution-save settings preserved**

- "Save successful production executions": **All**
- "Save failed executions": **All**

(These should already be set from A1; verify they didn't reset on duplicate.)

- [ ] **Step 4: Verify Anthropic node retry preserved**

Open `Message a model` → Settings tab. Confirm **Retry on Fail: ON, 2 retries, 5000ms delay** (A1's setting).

- [ ] **Step 5: Save settings**

- [ ] **Step 6: Export and commit**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git add JSON/SOC-Triage-v2.json && git commit -m "chore(A2): bump workflow timeout 120s -> 2100s for Wait node"
```

---

## Phase 10 — Pinned-data test cases

Each test pins a specific webhook payload (or an action — clicking / not clicking the buttons), executes, and captures the result in `notes.md`. All five must pass before cutover.

### Task 10.1: Test 1 — Gate skipped (internal brute force)

- [ ] **Step 1: Pin webhook data for Test 1**

In the Webhook node, edit pinned data:

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

- [ ] **Step 2: Unpin `Message a model` if pinned**

- [ ] **Step 3: Execute the workflow**

- [ ] **Step 4: Verify**

| Check | Expected |
|---|---|
| `Extract Triage Result.alert_iocs` | `[]` (empty — RFC1918 was not enriched) |
| `Has Malicious IOCs?` | takes **false** branch |
| `Send a message` (no-buttons) | fires |
| Slack #alerts | shows plain alert message, no buttons |
| `Create Iris Alert` | succeeds; Iris UI shows alert with `alert_iocs: []` |
| `Wait For Decision` | NOT reached |
| Total execution time | < 30s |

- [ ] **Step 5: Capture in notes**

```markdown
## Test 1 — Gate skipped (2026-04-28)
| Check | Result |
|---|---|
| alert_iocs empty | ✓/✗ |
| IF false branch | ✓/✗ |
| Plain Slack alert (no buttons) | ✓/✗ |
| Iris alert created with no IOCs | ✓/✗ |
| Execution time | Ns |
```

- [ ] **Step 6: Commit**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git add vault/subprojects/2026-04-28-iris-escalation-gate/notes.md && git commit -m "test(A2): Test 1 — gate skipped"
```

---

### Task 10.2: Test 2 — Approve path (external brute force)

- [ ] **Step 1: Get a fresh malicious IP from AbuseIPDB**

Browser to https://www.abuseipdb.com/statistics. Pick an IP from "Recently Reported" with abuse confidence > 80%.

- [ ] **Step 2: Pin Test 2 webhook data**

```json
{
  "body": {
    "search_name": "Test-Brute-Force-External",
    "results_link": "http://mydfir-splunk:8000/app/search/...",
    "result": {
      "ComputerName": "DESKTOP-VNEF7PC",
      "user": "mydfir",
      "src_ip": "<paste-fresh-IP>",
      "count": "47"
    }
  }
}
```

- [ ] **Step 3: Unpin Anthropic; execute**

- [ ] **Step 4: Click ✅ Approve in Slack**

Browser opens; HTML confirmation page renders.

- [ ] **Step 5: Verify**

| Check | Expected |
|---|---|
| `alert_iocs` has at least 1 item | ✓ |
| `Has Malicious IOCs?` true branch | ✓ |
| Slack message with buttons posted | ✓ |
| Wait paused, then resumed on Approve | ✓ |
| Switch took `approve` | ✓ |
| Escalate returned 200 with `case_id` | ✓ |
| `Escalation Succeeded?` true | ✓ |
| `Reply: Approved + case` thread reply posted | ✓ |
| Iris case visible at `/case?cid=<case_id>` | ✓ |
| Case has IOCs in case-level IOC tab | ✓ |
| Total execution time within 35-min timeout | ✓ |

- [ ] **Step 6: Capture in notes**

(Same template as Test 1.)

- [ ] **Step 7: Commit**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git add vault/subprojects/2026-04-28-iris-escalation-gate/notes.md && git commit -m "test(A2): Test 2 — approve path"
```

---

### Task 10.3: Test 3 — Deny path

- [ ] **Step 1: Keep Test 2 pinned data**

(Same external IP — only the action differs.)

- [ ] **Step 2: Execute the workflow**

- [ ] **Step 3: Click ❌ Deny in Slack**

- [ ] **Step 4: Verify**

| Check | Expected |
|---|---|
| Wait resumed on Deny click | ✓ |
| Switch took `deny` output | ✓ |
| `Escalate Iris Alert` did NOT fire | ✓ |
| `Reply: Denied` thread reply posted | ✓ |
| **No** new Iris case (alert remains in queue, no case) | ✓ |

- [ ] **Step 5: Capture and commit**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git add vault/subprojects/2026-04-28-iris-escalation-gate/notes.md && git commit -m "test(A2): Test 3 — deny path"
```

---

### Task 10.4: Test 4 — Timeout path

- [ ] **Step 1: Keep Test 2 pinned data**

- [ ] **Step 2: (Optional shortcut) Reduce Wait timeout to 90s for this test**

Open `Wait For Decision` → set Resume time limit to `90`. Save.

- [ ] **Step 3: Execute the workflow; do NOT click anything**

- [ ] **Step 4: Wait for the timeout to fire**

After 90s (or 30 min if you didn't shortcut), verify:

| Check | Expected |
|---|---|
| Wait resumed via timeout | ✓ |
| Switch took `timeout` output | ✓ |
| `Reply: Timeout` thread reply posted | ✓ |
| **No** Iris case created | ✓ |

- [ ] **Step 5: Reset Wait timeout to 1800s**

**Critical** — don't ship with the test value.

- [ ] **Step 6: Capture and commit**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git add JSON/SOC-Triage-v2.json vault/subprojects/2026-04-28-iris-escalation-gate/notes.md && git commit -m "test(A2): Test 4 — timeout path; Wait timeout restored to 1800s"
```

---

### Task 10.5: Test 5 — Escalation failure (Iris VM down)

- [ ] **Step 1: SSH to the Iris VM and stop docker**

```bash
ssh mydfir@192.168.129.133
cd iris-web
sudo docker-compose down
```

(Confirm Iris is down: from your host, `curl -k https://192.168.129.133/manage/ioc-types/list` should fail with connection refused.)

- [ ] **Step 2: Keep Test 2 pinned data**

But wait — `Create Iris Alert` will now fail too, because Iris is down. So this test variant must be: bring Iris up, run the test up through the Wait, then bring Iris down before clicking Approve.

Better sequencing:
- Iris up; execute workflow; reaches Wait state
- SSH and `sudo docker-compose down` while the workflow is paused
- Click Approve in Slack
- Now `Escalate Iris Alert` fails

Or simpler: just drop the network temporarily by unplugging or `sudo iptables -A INPUT -p tcp --dport 443 -j DROP` on the Iris VM.

Pick whichever is reliable for your setup.

- [ ] **Step 3: Execute up to the Wait state with Iris up**

Pin Test 2; unpin Anthropic; execute. Confirm the workflow pauses at Wait.

- [ ] **Step 4: Take Iris down**

`sudo docker-compose down` (or block 443/tcp).

- [ ] **Step 5: Click ✅ Approve in Slack**

- [ ] **Step 6: Verify the failure path**

| Check | Expected |
|---|---|
| Wait resumed on Approve click | ✓ |
| Switch took `approve` | ✓ |
| `Escalate Iris Alert` returns connection error / non-success | ✓ (because Continue On Fail = ON, workflow doesn't crash) |
| `Escalation Succeeded?` takes false branch | ✓ |
| `Reply: Approved but escalation failed` thread reply posted | ✓ |
| Reply text mentions the alert is in the queue, manual escalation required | ✓ |

- [ ] **Step 7: Bring Iris back up**

```bash
ssh mydfir@192.168.129.133
cd iris-web
sudo docker-compose up -d
```

(Or remove the iptables rule.)

- [ ] **Step 8: Capture and commit**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git add vault/subprojects/2026-04-28-iris-escalation-gate/notes.md && git commit -m "test(A2): Test 5 — escalation failure (Iris down)"
```

---

## Phase 11 — Cutover to v2

### Task 11.1: Cut Splunk webhook over to `SOC Triage v2`

**Files:**
- Modify: Splunk saved search webhook URL (if v2 has a different webhook GUID)
- Modify: workflow activation states

- [ ] **Step 1: Get v2's production webhook URL**

In `SOC Triage v2`, open the Webhook node. Note the Production URL (`http://192.168.129.132:5678/webhook/<guid>`).

- [ ] **Step 2: Compare to v1's webhook URL**

In `SOC Triage v1 (legacy)`, open its Webhook node. Compare GUIDs.

- **If they match** (n8n preserved the GUID on duplicate): no Splunk change needed.
- **If they differ**: update the Splunk saved search webhook URL in Step 4.

- [ ] **Step 3: Activate `SOC Triage v2`**

In `SOC Triage v2`: top-right toggle → Active (or Publish).

- [ ] **Step 4: Deactivate `SOC Triage v1 (legacy)`**

Open it. Toggle Active off (or Unpublish). This prevents both workflows firing on the same webhook.

- [ ] **Step 5: If GUIDs differed, update Splunk**

Open Splunk → Settings → Searches, reports, and alerts → `Test-Brute-Force` → Edit. Find the webhook trigger action; update the URL to v2's production URL. Save.

- [ ] **Step 6: Verify cutover by checking executions tab**

In `SOC Triage v2`, open the Executions tab. No history yet (this is a fresh activation).

In `SOC Triage v1 (legacy)`, the Executions tab shows historical runs.

---

### Task 11.2: End-to-end with real Splunk alert

- [ ] **Step 1: Re-enable Splunk's `Test-Brute-Force` saved search**

Splunk → saved search list → toggle to enabled.

- [ ] **Step 2: Trigger 5 failed logons**

RDP to 192.168.129.130 with a wrong password 5 times. Or from PowerShell:
```powershell
1..5 | ForEach-Object { mstsc /v:192.168.129.130 }  # then type wrong password each time
```

- [ ] **Step 3: Wait ~60s for Splunk's cron to detect and webhook**

In `SOC Triage v2` → Executions, a new execution should appear with status `Waiting` (paused at Wait node).

- [ ] **Step 4: Slack #alerts should show the alert message**

If the `src_ip` is internal (192.168.129.x), the gate is **skipped** and you see a plain alert. To exercise the gate end-to-end, modify the Splunk saved search query to use a fake external IP, or accept that this e2e test goes through the no-buttons path.

For a fuller e2e: in Splunk, edit `Test-Brute-Force` to project `eval src_ip="185.220.101.42"` (a known-malicious IP, or another fresh AbuseIPDB-flagged one). Re-trigger.

- [ ] **Step 5: If buttons appear, click Approve**

Verify the rest of the flow: Iris case created, Slack thread reply with case link.

- [ ] **Step 6: Disable the Splunk saved search**

Toggle off in saved search list. Otherwise it keeps firing every minute.

- [ ] **Step 7: Capture e2e results**

```markdown
## End-to-end verification (2026-04-28)
- Splunk → n8n delay: Ns
- Slack alert posted: ✓/✗
- Buttons rendered (if external IP used): ✓/✗/N-A
- Approve path executed end-to-end: ✓/✗
- Iris case created with IOCs: ✓/✗
- Splunk saved search disabled after test: ✓
```

- [ ] **Step 8: Commit**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git add vault/subprojects/2026-04-28-iris-escalation-gate/notes.md && git commit -m "test(A2): end-to-end with real Splunk alert"
```

---

## Phase 12 — Documentation closure

### Task 12.1: Write the runbook

**Files:**
- Modify: `vault/subprojects/2026-04-28-iris-escalation-gate/runbook.md`

- [ ] **Step 1: Replace the placeholder runbook**

Open `vault/subprojects/2026-04-28-iris-escalation-gate/runbook.md` and replace its contents with:

````markdown
---
status: active
updated: 2026-04-28
related: [[spec]], [[notes]], [[../../workflows/soc-triage-pipeline]]
---

# Runbook — A2 Iris Escalation Gate

Operational guide for the `SOC Triage v2` workflow that A2 produced.

## Deploy to a fresh n8n environment

1. Ensure all credentials exist (Settings → Credentials):
   - `Anthropic account`, `Slack account`, `DFIR-IRIS account`, `VirusTotal account`, `AbuseIPDB account`.
2. Import the workflow JSON: Workflows → Add Workflow → Import from File → `JSON/SOC-Triage-v2.json`.
3. Reattach credentials on each node missing the icon.
4. **Update the IRIS_IOC_TYPE_IDS in `Extract Triage Result`** if the target Iris instance has a different catalog. Run `curl -k https://<iris-host>/manage/ioc-types/list -H "Authorization: Bearer <key>"` to capture the IDs; paste them into the Code node's constant.
5. **Update IP addresses** in `Escalate Iris Alert` URL and Slack thread reply text if the lab's Iris IP differs from `192.168.129.133`.
6. Activate the workflow.
7. Update Splunk's saved search webhook URL to the v2 production webhook URL.

## Roll back to legacy

1. n8n: Deactivate `SOC Triage v2`.
2. Activate `SOC Triage v1 (legacy)`.
3. (If webhook GUIDs differ) Update Splunk's `Test-Brute-Force` webhook URL back to the v1 URL.
4. Re-enable the Splunk saved search if it was disabled.

`SOC Triage v1 (legacy)` is preserved untouched as the rollback target.

## Verify production health

1. n8n → `SOC Triage v2` → Executions. Recent executions: `Succeeded` for non-gated alerts; `Waiting` while a gated alert awaits analyst decision; `Succeeded` after decision.
2. Slack #alerts: each alert post shows severity emoji + structured sections; gated alerts have Approve/Deny buttons; thread replies show outcomes.
3. DFIR-Iris (https://192.168.129.133):
   - Alerts panel: every n8n execution that completed produces an alert.
   - Cases panel: only approved alerts produce cases. Each case has IOCs in its case-level IOC tab.

## What changed from A1

| Surface | A1 | A2 |
|---|---|---|
| Iris alert IOCs | not attached | malicious/suspicious IOCs attached on creation |
| Iris case | manual escalation only | auto-created on analyst Approve |
| Slack message | one post, no actions | post with Approve/Deny URL buttons (when malicious IOCs present) |
| Slack thread | none | outcome reply (approve/approve-fail/deny/timeout) |
| `iris_description` Splunk link | markdown link `[View in Splunk](url)` | raw `Splunk: <url>` |
| Workflow timeout | 120s | 2100s (35 min) |

## Debug a failed execution

1. n8n → Executions → click the failed execution → identify failing node.
2. Common cases:
   - **`Create Iris Alert` returns 400 `alert_iocs: ["Unknown field."]`** — `alert_iocs` body parameter is in Fixed mode. Toggle to Expression and re-paste without leading `=`.
   - **`Create Iris Alert` returns 400 `ioc_type_id`** — Iris IOC type ID catalog mismatch. Re-run Phase 0.1 lookup; update the Code node constant.
   - **`Escalate Iris Alert` returns 401** — `dfirIrisApi` credential token revoked. Regenerate in Iris → user settings.
   - **`Reply: Approved + case`** doesn't appear in thread — `Thread TS` field references the wrong node. It must be `$('Post Slack Alert + Approve/Deny').item.json.ts`.
   - **Wait node times out unexpectedly fast (e.g., 60s instead of 1800s)** — leftover test setting; reset to `1800` seconds.
   - **Slack buttons render but clicking doesn't resume the workflow** — the URL `$execution.resumeUrl` didn't render; check browser address bar to see what URL was actually generated. Likely fix: replace with manual `http://192.168.129.132:5678/webhook-waiting/{{ $execution.id }}`.

## Known limitations (deferred, not blocking)

- **No signed/auth on the resume URL.** Anyone on the LAN with the URL can approve. Acceptable for single-analyst lab; A2.5 (tunnel + signed Slack interactivity) closes this if needed.
- **Slack reply identity is the bot's, not the human's.** URL buttons don't tell n8n which user clicked. The thread reply says "Approved" but doesn't attribute to a specific person. Real Slack interactivity (A2.5) would fix this.
- **n8n restart loses paused executions.** Any alert in the Wait state at restart time is lost; the alert remains in Iris's queue, but no follow-up Slack reply ever posts. Operational hazard, same severity as A1.
- **`Test 5` requires manual Iris docker-compose-down.** The escalation-failure path is exercised by stopping Iris between Wait and Approve. Not automatable in the lab as-is.

## Adding new actions or evolving the schema

A3 will introduce a second action (Splunk lookup blocklist). When that ships:

1. Bump `schema_version` to v2 — add a structured `proposed_actions` array to `submit_triage_result`'s schema.
2. The gate becomes per-action (or per-action-bundle); the Slack message lists each proposed action separately.
3. The Switch node grows additional branches; each action gets its own HTTP / API node.
4. Update this runbook to describe the new action surface.

Documenting in advance: any *new* IOC type beyond ip / domain / file_hash requires Iris IOC type ID catalog re-capture and an additional branch in `resolveIrisTypeId`.
````

- [ ] **Step 2: Commit**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git add vault/subprojects/2026-04-28-iris-escalation-gate/runbook.md && git commit -m "docs(A2): write runbook (deploy/rollback/verify/debug)"
```

---

### Task 12.2: Write ADR for the additive `ioc_type` schema change

**Files:**
- Create: `vault/decisions/0005-additive-ioc-type-schema-enhancement.md`

- [ ] **Step 1: Write the ADR**

Create `vault/decisions/0005-additive-ioc-type-schema-enhancement.md`:

```markdown
---
status: active
date: 2026-04-28
---

# 0005 — Additive `ioc_type` field on `iocs_enriched`; schema_version stays v1

## Status

Accepted

## Context

A1 shipped a `submit_triage_result` tool with an `iocs_enriched` array of `{value, verdict, source, summary}` items. A2 needs to map each enriched IOC to a DFIR-Iris `ioc_type_id` integer, which requires knowing whether the IOC is an IP, a domain, or a file hash. Cross-referencing against the parallel `iocs.ips/domains/file_hashes` arrays is fragile (depends on exact value matching). The cleanest fix is for Claude to label each `iocs_enriched` item with its type — Claude already knows this because it chose which tool to call.

This is a schema change. The question is: is it a "v2" change requiring `schema_version` bump and dual-version handling, or a v1.x additive change?

## Decision

Add `ioc_type` (enum: `ip` / `domain` / `file_hash`) as a required field on each `iocs_enriched` item. Keep `schema_version: "v1"`. Treat it as an additive enhancement.

## Rationale

The schema is not a wire-protocol contract negotiated between independent teams — it's an internal contract between nodes inside one n8n workflow. We control all producers (Claude via tool definition + system prompt) and all consumers (`Extract Triage Result` Code node) atomically. There is no period during which "old producers + new consumers" or "new producers + old consumers" coexist.

Bumping to v2 would impose dual-version-handling code in `Extract Triage Result` for no benefit. The runbook's "Adding new actions" section documents the *real* v2 trigger: when A3 adds a structured `proposed_actions` array — that's a producer-and-consumer-coordinated change worth a version bump.

## Consequences

**Positive**

- Code node logic is simpler (single code path, no branching on `schema_version`).
- Schema evolution doesn't burn a version number on a low-impact change.

**Negative**

- The "v1" label is slightly elastic — A1's v1 and A2's v1 are not byte-for-byte identical schemas.
- Future readers of A1's spec might wonder why the schema in n8n doesn't match. Mitigation: A1 spec linked to A2 README's Successors section; A2 spec links to this ADR.

## See also

- A1 spec: [[../subprojects/2026-04-27-structured-outputs/spec]]
- A2 spec: [[../subprojects/2026-04-28-iris-escalation-gate/spec]]
```

- [ ] **Step 2: Update the index**

Add to `vault/index.md` under Decisions (ADRs):

```markdown
- [[decisions/0005-additive-ioc-type-schema-enhancement]] — Why `ioc_type` is a v1.x additive field, not a v2 bump
```

- [ ] **Step 3: Commit**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git add vault/decisions/0005-additive-ioc-type-schema-enhancement.md vault/index.md && git commit -m "docs(A2): ADR 0005 — additive ioc_type stays v1"
```

---

### Task 12.3: Update README status checkboxes

**Files:**
- Modify: `vault/subprojects/2026-04-28-iris-escalation-gate/README.md`

- [ ] **Step 1: Tick off completed checkboxes**

Replace the Status section in `vault/subprojects/2026-04-28-iris-escalation-gate/README.md`:

```markdown
## Status

- [x] Brainstorm completed 2026-04-28
- [x] Spec written 2026-04-28
- [x] Spec approved 2026-04-28
- [x] Implementation plan written 2026-04-28
- [x] Implementation executed 2026-04-28
- [x] Runbook written 2026-04-28
- [x] Verification: 5 pinned tests + e2e with real Splunk alert all pass
```

- [ ] **Step 2: Update the index status note**

In `vault/index.md`, change the A2 line from `(active — spec written, awaiting plan)` to `(complete)`:

```markdown
- [[subprojects/2026-04-28-iris-escalation-gate/README]] — A2: Iris Escalation Gate (complete)
```

- [ ] **Step 3: Commit**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git add vault/subprojects/2026-04-28-iris-escalation-gate/README.md vault/index.md && git commit -m "docs(A2): tick status checkboxes; index updated to complete"
```

---

### Task 12.4: Append A2 closeout to the vault log

**Files:**
- Modify: `vault/log.md`

- [ ] **Step 1: Append closeout entries**

Add to `vault/log.md`:

```
2026-04-28 — Spec approved for A2; implementation plan written at [[subprojects/2026-04-28-iris-escalation-gate/plan]]
2026-04-28 — A2 implementation in progress: Phase 0 verifications captured Iris IOC type IDs and n8n Wait/Block-Kit behavior, workflow duplicated as `SOC Triage v2`, schema enhanced (additive `ioc_type` on `iocs_enriched`), `Extract Triage Result` extended for `alert_iocs` payload + summary string + Iris markdown-link fix, `Create Iris Alert` body extended with `alert_iocs` and "Always Output Data" enabled, `Has Malicious IOCs?` IF added, Slack message with Approve/Deny URL buttons (Block Kit), `Wait For Decision` + `Decision?` Switch + 4 thread reply nodes wired, `Escalate Iris Alert` and `Escalation Succeeded?` IF added for Approve sub-flow, workflow timeout bumped to 2100s, all 5 pinned test cases passed, ADR 0005 written for additive schema enhancement
2026-04-28 — A2 cutover completed: Splunk webhook URL pointing to v2 production URL, end-to-end verified with real failed RDP attempts. Slack approval message renders, click-Approve completes the workflow, Iris case auto-created with IOCs imported. Splunk saved search disabled after verification. A2 complete; see [[subprojects/2026-04-28-iris-escalation-gate/runbook]] for operations and [[subprojects/2026-04-28-iris-escalation-gate/notes]] for the issue/learning record.
```

- [ ] **Step 2: Commit**

```bash
cd f:/Claude_Code/SOC_Automation_Project && git add vault/log.md && git commit -m "docs(A2): append closeout entries to vault log"
```

---

## Self-review checklist (run before declaring A2 done)

Match against the spec's "Success criteria":

- [ ] All five pinned test cases pass per the verification checklists in spec § 8b (Tests 10.1–10.5)
- [ ] End-to-end verification with real Splunk alert succeeded for the Approve path (Task 11.2)
- [ ] Iris **cases** are created from approved alerts; case-level IOC tab shows imported IOCs (verified in Task 8.1 Step 6 + Test 2 + e2e)
- [ ] Slack thread shows the full audit trail: original alert post + outcome reply (Tests 2/3/4/5)
- [ ] URL buttons render in Slack and are clickable (Test 2)
- [ ] Timeout fires correctly at 30 min (Test 4 — verify with actual 1800s, not the 60–90s test shortcut)
- [ ] Negative-path test (Test 5 / escalation failure) produced expected Slack message (Test 5)
- [ ] `runbook.md` is written and covers deploy / rollback / verify / debug (Task 12.1)
- [ ] `notes.md` captures gotchas hit during build (cumulative across all phases)
- [ ] ADR 0005 written for `iocs_enriched.ioc_type` additive enhancement (Task 12.2)
- [ ] README status checkboxes ticked (Task 12.3)
- [ ] Log entry at vault root marks A2 complete (Task 12.4)
- [ ] Iris IOC type ID catalog documented in `vault/architecture/components/dfir-iris.md` (Task 0.1 Step 4)
- [ ] All commits have descriptive messages
- [ ] `git log --oneline` shows the full A2 implementation history
- [ ] Quick check: `grep -E "case_template_id" JSON/SOC-Triage-v2.json` returns nothing (we deliberately didn't set one)
- [ ] Quick check: `grep -E "soc-automation,a2" JSON/SOC-Triage-v2.json` finds matches in Code node + Escalate body
- [ ] Manual UI check: `Wait For Decision` Resume time limit is **1800** (not the 60s/90s test shortcut from Phase 10)

If any item fails, return to the relevant task and complete it before declaring done.
