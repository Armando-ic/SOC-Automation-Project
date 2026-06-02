# Phase 3 — Microsoft-native SOAR Layer (`la-soc-v2-triage-claude`) — Runbook

> **Standalone rebuild guide.** This document lets you rebuild the Phase 3 Microsoft-native SOAR layer from scratch without opening the plan or spec. It captures the *verified-working* configuration as shipped on real Sentinel incident #14 (2026-06-02), including the inbound permission grant that is the single most-missed step.
>
> **Numbering note:** This is **Phase 3 (Microsoft-native SOAR)**. The plan/spec *files* are titled "Phase 2" for git-history continuity, but per the 2026-05-23 reversal they are conceptually Phase 3. This runbook uses "Phase 3" throughout. Work lives on branch `v3-microsoft-native`.

## What this builds

The Microsoft-native equivalent of v1's SOC Triage v3 n8n workflow: a single Azure Logic App (Consumption) that triages a Sentinel incident via the Claude tool-use loop (AbuseIPDB + VirusTotal enrichment, structured triage output) and writes the result back to the incident as severity + IOC tags + a markdown comment. A Sentinel automation rule fires the Logic App automatically when the T1059.001 detection raises an incident. Secrets live in Key Vault and are read at runtime via the Logic App's managed identity — no API keys in the workflow JSON.

**v1 baseline being mirrored (`main` branch):** Splunk Enterprise + Sysmon + n8n (docker) + Claude tool-use + DFIR-Iris case management, on local VMware. **This Phase 3 (`v3-microsoft-native`) equivalent:** Sentinel + AMA + Logic App + Claude + Sentinel-native incidents (no DFIR-Iris). Same Claude "brain" and the **identical A1 tool-use schema** — only the orchestration and case-management surfaces change.

---

## Environment / canonical resource names

All resources are in **Central US**, resource group `rg-soc-v2-azure-central-us`, subscription `3718c265-d620-4e68-b344-ac484d2dd3a5`, tenant `analysthotmail.onmicrosoft.com` (owning account `owner@example.com` — **not** the workspace login email).

| Resource | Name | Notes |
|---|---|---|
| Resource group | `rg-soc-v2-azure-central-us` | Central US |
| Log Analytics workspace | `law-soc-v2-azure` | Sentinel onboarded; also Defender-XDR-onboarded (alerts surface as "Microsoft Defender XDR") |
| Windows VM | `vm-soc-v2-win` | `Standard_D4as_v7`, Sysmon64 + AMA. Ops via Azure portal **Run command** (Session 0) |
| Analytics rule | `T1059.001 - PowerShell Encoded Command` | Scheduled, from Phase 1 (already exists) |
| Key Vault | `kv-soc-v2-secrets-<suffix>` | RBAC permission mode; 3 secrets |
| Logic App | `la-soc-v2-triage-claude` | Consumption; system-assigned MI |
| Automation rule | `ar-triage-with-claude` | Standard rule; one rule, two ordered actions |

> The shipped vault is `kv-soc-v2-secrets-1650f9` and the shipped Logic App managed-identity Object ID is `1e04b3fb-ff8b-411e-8113-d2dd1cbb3e22`. When rebuilding you will generate a fresh vault suffix and a fresh MI Object ID — substitute yours wherever `<suffix>` / `<MI-object-id>` appears.

---

## Prerequisites

Before starting, confirm the Phase 1 foundation is live (this runbook does **not** rebuild it):

- **Subscription with Microsoft Sentinel onboarded** to a Log Analytics workspace (`law-soc-v2-azure`).
- **The T1059.001 analytics rule already exists and is enabled** (from Phase 1). It is a scheduled rule (run every 5 min, 5-min lookback, "trigger an alert per event") that reads the `Event` table where `EventLog == "Microsoft-Windows-Sysmon/Operational"` and `EventID == 1`, extracts `Image` / `CommandLine` / etc. from the EventData XML via regex, and matches `CommandLine` against `(?i)\s-e[ncodedommand]*\s` on `powershell.exe`. Entity mappings: **Host** (Computer), **Account** (User), **Process** (CommandLine), **Process** (ProcessId). It *projects* `Hashes` but does **not** map a FileHash entity — note this; it matters for enrichment (see [Known limitation](#known-limitation--next-step)).
- **A Windows endpoint sending Sysmon to the workspace** (`vm-soc-v2-win` with Sysmon64 + AMA) so you can live-fire the detection.
- **Three API keys on hand:** Anthropic (Claude), VirusTotal, AbuseIPDB. (Reuse the v1 keys — they are the same provider accounts. Originals live in the gitignored `SOC-Automation-Project.md` at project root. **Never commit, echo, or paste those values.**)
- **Your account has Owner or User Access Administrator** on the resource group (you will create role assignments) and **Microsoft Sentinel Contributor** on the workspace (you will create the automation rule and grant playbook permissions).

A fresh-fire pre-flight is recommended: live-fire the detection (see [Verify › Fire the detection](#verify-acceptance-run)) and confirm an incident materializes **before** spending portal time provisioning, so you know the upstream AMA → LAW → analytics-rule → incident chain is healthy.

---

## Step 1 — Create the Key Vault (RBAC mode) + load 3 secrets

### 1.1 Pick a globally-unique vault name

Key Vault names are globally unique (3–24 chars, start with a letter, alphanumerics + hyphens). Use `kv-soc-v2-secrets-<6-char-hex-suffix>`. Generate a suffix:

```bash
python -c "import secrets; print(secrets.token_hex(3))"
```

Note the full name (e.g. `kv-soc-v2-secrets-a1b2c3`); you'll reference it throughout.

### 1.2 Create the vault

Portal → search **Key Vaults** → **+ Create**:

- **Subscription:** (your subscription)
- **Resource group:** `rg-soc-v2-azure-central-us`
- **Name:** `kv-soc-v2-secrets-<suffix>`
- **Region:** Central US
- **Pricing tier:** Standard
- **Access configuration → Permission model: `Azure role-based access control`** — **NOT** "Vault access policy." RBAC is the mode this whole runbook assumes; the managed-identity grant in [Step 3](#step-3--grant-rbac-both-directions) depends on it.
- **Networking:** Public endpoint, all networks (lab scope).
- **Review + create.** Deploys in ~30 sec.

### 1.3 Grant *yourself* permission to write secrets

In RBAC mode, even the vault creator cannot read/write secrets without an RBAC role.

Vault → **Access control (IAM)** → **+ Add** → **Add role assignment** → **Key Vault Administrator** → Members: select your user → **Review + assign**.

### 1.4 Load the three secrets

Vault → **Objects → Secrets** → **+ Generate/Import**, once for each row. Upload options = Manual, Content type = blank, Enabled = Yes.

| Secret name | Value |
|---|---|
| `anthropic-api-key` | Anthropic / Claude API key |
| `virustotal-api-key` | VirusTotal API v3 key |
| `abuseipdb-api-key` | AbuseIPDB API v2 key |

### 1.5 Verify

Vault → **Objects → Secrets**: confirm all three (`anthropic-api-key`, `virustotal-api-key`, `abuseipdb-api-key`) are listed and **Enabled**. Click each name and confirm the version row loads without a permission error. You do not need to reveal the values — runtime readability by the Logic App's managed identity is verified in [Step 4's smoke test](#41-verify-the-app-can-read-secrets).

---

## Step 2 — Create the Consumption Logic App with a system-assigned managed identity

### 2.1 Create the Logic App

Portal → search **Logic apps** → **+ Add** → **Consumption**:

- **Subscription:** (your subscription)
- **Resource group:** `rg-soc-v2-azure-central-us`
- **Name:** `la-soc-v2-triage-claude`
- **Region:** Central US
- **Enable log analytics:** Yes → existing workspace `law-soc-v2-azure` (sends Logic App run telemetry into the same workspace).
- **Review + create.** Deploys in ~1 min. Open the resource.

> It must be **Consumption** tier. The workflow JSON uses `addProperty(json('{}'), ...)` rather than `createObject()` precisely because `createObject()` is **not a valid WDL function in Consumption** — see [Engineering lessons](#engineering-lessons).

### 2.2 Turn on the system-assigned managed identity

Logic App blade → **Identity** (left nav, under Settings) → **System assigned** tab → **Status = On** → **Save** → **Yes**.

An **Object (principal) ID** appears. **Note it** (the shipped value was `1e04b3fb-ff8b-411e-8113-d2dd1cbb3e22`; yours will differ). You'll select this identity by the Logic App's name in the role-assignment dialogs in [Step 3](#step-3--grant-rbac-both-directions).

### 2.3 Add the Sentinel incident trigger

Logic App blade → **Logic app designer** → **Blank Logic App** → search **Microsoft Sentinel** → **Triggers** tab → **"Microsoft Sentinel incident"** (the incident-scoped trigger — *not* the alert-scoped one). When prompted, sign in with an account that has Sentinel Reader on the workspace, and save the connection. **Save** the Logic App.

(The full workflow body comes in via Code view in [Step 4](#step-4--import-the-workflow-via-code-view) — you do not hand-build the loop in the designer.)

---

## Step 3 — Grant RBAC (BOTH directions)

There are **two** RBAC concerns, and they are different things. People build the outbound roles, test a manual run, watch it fail with a `400`, and waste an hour — because they missed the **inbound** grant.

### 3.1 Outbound — what the Logic App's managed identity is allowed to do

**(a) Microsoft Sentinel Responder on the resource group** — lets the MI write back to the incident (Update Incident + Add Comment).

`rg-soc-v2-azure-central-us` → **Access control (IAM)** → **+ Add** → **Add role assignment** → **Microsoft Sentinel Responder** → Members → **Managed identity** → select `Logic App (la-soc-v2-triage-claude)` → **Review + assign**.

**(b) Key Vault Secrets User on the vault** — lets the MI read the three secrets at runtime.

`kv-soc-v2-secrets-<suffix>` → **Access control (IAM)** → **+ Add** → **Add role assignment** → **Key Vault Secrets User** → Members → **Managed identity** → select `Logic App (la-soc-v2-triage-claude)` → **Review + assign**.

### 3.2 Inbound — what is allowed to *invoke* the playbook (THE STEP PEOPLE MISS)

This is the unlock for automatic firing. The Microsoft-managed **"Azure Security Insights"** service principal needs **Microsoft Sentinel Automation Contributor** on the resource group so that Sentinel can launch the Logic App.

Grant it the easy way, from inside Sentinel:

Microsoft Sentinel (`law-soc-v2-azure` workspace) → **Settings** → **Playbook permissions** (a.k.a. "Permissions to run playbooks") → **Configure permissions** → select `rg-soc-v2-azure-central-us` → **Apply**.

This assigns *Microsoft Sentinel Automation Contributor* to the *Azure Security Insights* SP scoped to the RG.

> **WITHOUT this grant, both the manual "Run playbook" action AND the automation rule fail** with a toast reading **"Failed to trigger playbook … status code 400."** Despite the `400`, it is a *permission* (403-semantic) rejection — Sentinel cannot invoke the Logic App. This grant is entirely separate from the Logic App MI's outbound roles in 3.1. Both rule-launched and human-launched playbooks run under this same Azure Security Insights identity.

---

## Step 4 — Import the workflow via Code view

The full workflow is committed at `v2-azure/logic-app/workflow.json`. Import it whole rather than rebuilding ~22 actions by hand.

### 4.0 Workflow shape (what you're importing)

```
Microsoft Sentinel incident (trigger)
  ├─ 3× Get secret (Key Vault via MI, secureData-masked) ─┐  (parallel)
  └─ 5× Initialize variable ──────────────────────────────┘
        triage_complete(false), iteration(0), messages([]),
        tool_results_batch([]), incident_tags([]), triage_result({})
  → Compose_initial_messages   (builds Claude user prompt from incident JSON)
  → Set_messages_from_initial  (seeds the messages variable)
  → Compose_tools              (3-tool A1 schema)
  → Until_Claude_agent_loop  { exit when triage_complete==true OR iteration>=10; limit 12 / PT15M }
        Call_Claude            (HTTP POST api.anthropic.com/v1/messages, model claude-opus-4-7)
        Parse_Claude_response
        Append_assistant_message
        Switch_on_stop_reason
          ├─ tool_use:  Reset_tool_results_batch
          │             For_each_tool_use_block (SEQUENTIAL)
          │               Is_tool_use_block → Switch_on_tool_name
          │                 ├─ enrich_ip_abuseipdb        → Call_AbuseIPDB → Compose+Append result
          │                 ├─ lookup_file_hash_virustotal → Call_Virustotal → Compose+Append result
          │                 └─ submit_triage_result        → Set_triage_result → Mark_triage_complete
          │             Append_messages_with_tool_results
          ├─ end_turn:  Compose_error_end_turn → Force_loop_exit_end_turn
          └─ default:   Compose_error_default → Force_loop_exit_default
        Increment_iteration
  → Build_incident_tags          (foreach over triage_result.iocs_enriched → {labelName:'ioc:type:value:verdict'})
  → Conditional_severity_critical_tag  (append {labelName:'severity:critical'} if severity==critical)
  → Update_Sentinel_Incident     (PUT /Incidents: incidentArmId + severity if-chain + labels)
  → Add_Sentinel_Comment         (POST /Incidents/Comment: markdown — severity / MITRE / summary / IOC count)
```

The three tools match v1's n8n "v3" A1 schema **verbatim**: `enrich_ip_abuseipdb`, `lookup_file_hash_virustotal`, `submit_triage_result`. Severity is **lossy**: Sentinel has no Critical tier at the workspace layer, so `critical → High` plus a `severity:critical` label as a fallback.

### 4.1 Paste the definition

Portal → `la-soc-v2-triage-claude` → **Logic app code view** (left nav, under Development Tools) → select all → paste the contents of `workflow.json` → **Save**.

After the first save, open the designer once so the three API connections bind:

- the **keyvault** connection must authenticate as **Managed Service Identity** (the JSON already declares `"authentication": { "type": "ManagedServiceIdentity" }`),
- the two **azuresentinel** connections (`azuresentinel` for the trigger, `azuresentinel-1` for the write-back actions) authenticate with your account.

> The `$connections` parameter block in `workflow.json` hard-codes connection resource IDs scoped to subscription `3718c265-…` and `rg-soc-v2-azure-central-us`. If you rebuild under a different sub/RG, fix those IDs or let the designer recreate the connections.

### 4.2 Verify the import is clean

```bash
python -c "import json; d=json.load(open('workflow.json')); print(f'{len(d[\"definition\"][\"actions\"])} top-level actions')"
grep -iE "api[-_]?key|secret|password|bearer" workflow.json | grep -v "Get_.*_key\|secrets/\|anthropic-api-key\|virustotal-api-key\|abuseipdb-api-key"
```

Expected: a top-level action count printed; the grep returns **empty** (managed identity means no key material in the JSON — the only matches should be secret *names*, which the second grep filters out).

---

## Step 5 — Create the single automation rule `ar-triage-with-claude`

Microsoft Sentinel (`law-soc-v2-azure`) → **Automation** → **+ Create** → **Automation rule** (Standard rule):

| Field | Value |
|---|---|
| **Name** | `ar-triage-with-claude` |
| **Trigger** | When incident is **created** |
| **Conditions** | `Analytic rule name` → **Contains** → `T1059.001 - PowerShell Encoded Command` |
| **Actions (IN ORDER)** | **(1)** Add tags → `automation:claude-triage`  **(2)** Run playbook → `la-soc-v2-triage-claude` |
| **Expiration** | (leave blank — indefinite) |

**Save.** When prompted to grant Sentinel permission to run the playbook, this is the same [Step 3.2 inbound grant](#32-inbound--what-is-allowed-to-invoke-the-playbook-the-step-people-miss) — confirm it's in place.

### Why ONE rule, not two

The original two-rule design (a tag-rule plus a separate playbook-rule, sequenced by manually-assigned **Order** numbers) is fragile: separate rules with hand-set Order numbers can **collide**, producing a random run order. If the playbook-rule evaluates *before* the tag-rule has applied `automation:claude-triage`, the condition is unmet and the playbook **silently no-fires**.

Collapsing both into **one** rule eliminates the race: a single rule's actions always execute **top-to-bottom**, so the tag is added before the playbook runs. The condition keys on the **analytic rule NAME** — which is stable at trigger time — rather than on the tag this rule is itself setting (which would be a chicken-and-egg dependency).

---

## Step 6 — Analytics rule (already exists — no change needed)

The **`T1059.001 - PowerShell Encoded Command`** analytics rule was built in Phase 1 and is a [prerequisite](#prerequisites). You do **not** edit it for Phase 3, and in particular:

- **You do NOT add the `automation:claude-triage` tag as a field on the analytics rule.** The tag is applied at runtime by the automation rule's first action ([Step 5](#step-5--create-the-single-automation-rule-ar-triage-with-claude)). The analytics rule stays detection-only; the automation rule owns the tag. This is what keeps the design generic — any future detection opts into Claude triage by being named in (or tagged by) an automation rule, with no analytics-rule edit.
- Just confirm the rule is **Enabled** (Sentinel → Analytics → Active rules) and its 5-min schedule has not been disabled.

---

## Verify (acceptance run)

This mirrors the real ship gate (Sentinel incident **#14**, 2026-06-02).

### 4.1 Verify the app can read secrets

Designer → **Run** → **Run with payload** → paste a sample Sentinel incident JSON (`test-fixtures/sample-incident.json` if present) → **Run**. Open **Run history** → most recent run → confirm all three **Get secret** actions succeed (their inputs/outputs are masked by `secureData` — that's expected). A `401` from `Call_Claude` means the MI isn't reading Key Vault — re-check the [Key Vault Secrets User grant](#31-outbound--what-the-logic-apps-managed-identity-is-allowed-to-do).

### Fire the detection end-to-end

On `vm-soc-v2-win`, via Azure portal **Run command** (`vm-soc-v2-win` → Operations → **Run command** → `RunPowerShellScript`):

```powershell
$ts  = Get-Date -Format 'HH:mm:ss'
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Write-Host `"Phase3-accept-$ts`""))
"FIRE_UTC_START $([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))"
powershell.exe -NoProfile -EncodedCommand $enc
"Fired."
```

Record the `FIRE_UTC_START`. This is the same shape the T1059.001 KQL matches (Sysmon `EventID=1` + `powershell.exe` + `-EncodedCommand`).

### Expected timeline (from the #14 acceptance run)

| Stage | Observed | Notes |
|---|---|---|
| Sysmon `EventID=1` in LAW `Event` table | sub-second after fire | confirm with a `Event \| where TimeGenerated > ago(15m)` query |
| Incident `T1059.001 - PowerShell Encoded Command` created | ~9 min after fire | the scheduled-rule tick + XDR dispatch dominate this leg |
| Automation rule fired **automatically** | incident **Activity log** shows `Automation rule-ar-triage-with-claude`, Trigger = **Automated**, **Completed** | this row is your proof of automation |
| Logic App run | **one** run, status **Succeeded**, ~30 s | `Update_Sentinel_Incident` ~2.4 s, `Add_Sentinel_Comment` ~0.9 s |
| Write-back on the incident | Severity **Medium**; MITRE `T1059`, `T1059.001`, `T1027`; substantive prose summary; IOCs enriched: **(none)** | the Claude leg itself was 30.58 s |

**End-to-end (event → triaged): ~12 min.** Breakdown: ingestion sub-second; event → incident ~9 min (scheduled rule + XDR dispatch); incident → triaged ~2m40s (automation rule + ~30 s Claude run + write-back).

> **"Manual" trigger-label quirk — don't be fooled.** The playbook's incident-write activity rows show **Trigger = "Manual"** even when the rule launched it automatically. That is *not* manual invocation — Sentinel buckets the playbook's Logic-Apps-connector writes like any discrete API write. **Proof of automation** is the rule's own *Automated / Completed* activity row + the single adjacent Logic App run + the absence of any user-initiated run. Both rule-launched and human-launched playbooks run under the same Azure Security Insights identity, so this label is shared.

### Pass criteria

- Exactly **one** Logic App run, **Succeeded**, ~30 s.
- The incident gains the `automation:claude-triage` tag, a **severity** update, and a **comment** from `la-soc-v2-triage-claude` containing the markdown triage block (severity / MITRE / summary / IOC count).
- The incident's Activity log shows the automation rule as **Automated / Completed**.

---

## Known limitation + next step

Be honest about this in any write-up: **on T1059.001, the enrichment tools are not exercised in production.** The analytics rule *projects* `Hashes` but does **not map a FileHash entity**, and a PowerShell-encoded-command detection carries no IP. So the incident payload Claude receives has **no enrichable IOC** → `iocs_enriched: (none)` → the VirusTotal/AbuseIPDB tool paths never run on this detection. (Those tools were validated in earlier *manual* smoke tests, just not on T1059.001 in production.)

In the #14 run, Claude correctly identified that the only base64 blob present was **Sentinel's own zlib+base64 `compressedRec` result-packaging artifact**, not an attacker payload — a good demonstration of judgment, but still no enrichment call.

**To demonstrate enrichment end-to-end:** edit the T1059.001 analytics rule to **map the SHA256 from `Hashes` as a FileHash entity**. Caveat: `powershell.exe`'s own hash is benign, so VirusTotal returns clean — but it exercises the `lookup_file_hash_virustotal` tool path in production and proves the wiring. A detection that surfaces a genuinely suspicious hash or an IP entity is the cleaner future demo.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| **Playbook greyed-out / not selectable** in the automation rule's "Run playbook" dropdown, or in incident → Actions → Run playbook | Wrong trigger type (the Logic App's trigger isn't the **Microsoft Sentinel incident** trigger), or Sentinel lacks playbook permissions | Confirm the trigger is the *incident-scoped* Sentinel trigger; then grant [Step 3.2 Playbook permissions](#32-inbound--what-is-allowed-to-invoke-the-playbook-the-step-people-miss) |
| **"Failed to trigger playbook … status code 400"** on manual Run *or* automatic fire | **Missing inbound grant** — the *Azure Security Insights* SP lacks *Microsoft Sentinel Automation Contributor* on the RG. (It's a 403-semantic rejection wearing a 400 toast.) | Sentinel → Settings → **Playbook permissions** → configure for `rg-soc-v2-azure-central-us`. This is the step people miss. |
| `Get secret` returns **403** | MI lacks *Key Vault Secrets User* on the vault | [Step 3.1(b)](#31-outbound--what-the-logic-apps-managed-identity-is-allowed-to-do) |
| `Call_Claude` returns **401** | Anthropic key invalid, or header name wrong | Verify the secret value; header must be `x-api-key` (not `Authorization`) |
| **`Update_Sentinel_Incident` returns 400** | `incidentArmId` is null/empty → ARM URL fails to parse (a `400`, *not* a `404` — a `404` would mean a well-formed-but-missing ID) | Confirm the action body uses `@triggerBody()?['object']?['id']` and that the run was launched by a real incident trigger (not a hand-payload missing `object.id`) |
| **`Update_Sentinel_Incident` / comment fails 403** | MI lacks *Microsoft Sentinel Responder* on the RG | [Step 3.1(a)](#31-outbound--what-the-logic-apps-managed-identity-is-allowed-to-do) |
| **Triage written to the wrong / a "folded" incident**, or no new incident on re-fire | Sentinel **incident grouping** folded the new alert into an existing open incident | Close stale `T1059.001` incidents before the acceptance run, or adjust the analytics rule's alert-grouping window so each fire opens a fresh incident |
| **Loop runs to the iteration cap (10)** | `tool_results` not appended back into `messages`, so Claude never sees results and keeps re-calling | Inspect the `Append_messages_with_tool_results` / per-tool `Append_*_to_batch` outputs across iterations; confirm `For_each_tool_use_block` is **Sequential** |
| **`triage_result` is empty / comment shows "(no summary produced)"** | Claude returned `end_turn` or an unexpected `stop_reason` without calling `submit_triage_result` | Check `Switch_on_stop_reason` — was the `end_turn` or `default` branch taken? Those set `triage_complete=true` and exit cleanly with an error compose |

---

## Engineering lessons (worth keeping in the write-up)

These are the non-obvious WDL / Logic Apps gotchas that cost time during the build:

- **`@{expr}` stringifies; `@expr` keeps the type.** A "Capture" Compose using `@{...}` was silently JSON-*stringifying* the triage object. Use bare `@expr` (e.g. `@items('For_each_tool_use_block')?['input']`) to keep it a real object.
- **Reading a foreach-internal action's output from root scope returns an ARRAY** of per-iteration values. The fix is to capture into a **root-level variable** (`Set_triage_result`) inside the loop and make the foreach **Sequential** (so the last write wins deterministically).
- **`createObject()` is not a valid WDL function in Consumption.** Use `addProperty(json('{}'), 'key', value)` chains instead (visible throughout the workflow's tag-building and message-append actions).
- **A null/empty `incidentArmId` yields a `400`, not a `404`.** `400` = ARM URL-parse failure (the value was missing/empty); `404` = a well-formed ID that points at nothing. The distinction tells you whether the bug is upstream (missing value) or a real lookup miss.
- **Inbound vs outbound permissions are two separate worlds.** The Logic App MI's *outbound* roles (Sentinel Responder, KV Secrets User) let the app *act*. The *inbound* Playbook-permissions grant (Azure Security Insights → Sentinel Automation Contributor) is what lets Sentinel *invoke* the playbook. You need both; the inbound one is the one that's easy to forget.

---

## Secrets management

Secrets live in `kv-soc-v2-secrets-<suffix>` (RBAC permission mode):

- `anthropic-api-key`
- `virustotal-api-key`
- `abuseipdb-api-key`

The Logic App reads them at runtime via its system-assigned managed identity — **no API keys appear in `workflow.json`.** Rotate without redeploying:

```bash
az keyvault secret set --vault-name kv-soc-v2-secrets-<suffix> --name anthropic-api-key --value <new-value>
```

The next Logic App run picks up the new version automatically — no restart. Originals are stored in the gitignored `SOC-Automation-Project.md` at project root (also used by v1). **Never commit, echo, or paste the secret values.**

---

## Files

- `v2-azure/logic-app/workflow.json` — the exported workflow definition (source of truth; imported in [Step 4](#step-4--import-the-workflow-via-code-view)).
- `v2-azure/logic-app/test-fixtures/sample-incident.json` — captured trigger payload for `Run with payload` regression replay.
- `v2-azure/detections/t1059-001-powershell-encoded-azure.md` — the Phase 1 detection this SOAR layer triages.
- `main` branch — the v1 baseline (Splunk + n8n + DFIR-Iris) this implementation mirrors.
