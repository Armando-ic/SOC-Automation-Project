# Phase 3 — Microsoft-native SOAR (Logic Apps): Deliverable

> **Numbering note.** This is **Phase 3** of the v2-Azure track — the Microsoft-native rewrite of the v1 SOAR layer. The spec and plan files are titled "Phase 2" for git-history continuity; per the 2026-05-23 phase reversal (an intermediate "Port v1 to Azure IaaS" phase was inserted ahead of this work), read every "Phase 2" in those filenames as "Phase 3." Branch: `v3-microsoft-native`.

This is the portfolio-facing writeup of the v2-Azure SOAR layer: a single Azure Logic App that runs the same Claude tool-use triage loop the v1 n8n workflow runs, fires automatically off a Sentinel incident, and writes the structured triage back into the incident itself. It mirrors the Phase 1 detection doc's discipline — concrete evidence from one acceptance run, an honest v1↔v2 comparison, and the engineering gotchas that cost real time.

---

## 1. What shipped

A Sentinel-triggered Azure Logic App (`la-soc-v2-triage-claude`, Consumption tier) that performs the full v1 `SOC Triage v3` job on Microsoft-native plumbing: a Sentinel incident fires it automatically, it runs a Claude (Opus 4.7) tool-use agent loop with the **same three-tool contract as v1** (`enrich_ip_abuseipdb`, `lookup_file_hash_virustotal`, `submit_triage_result` — schemas preserved verbatim), reads its API keys from Azure Key Vault via a system-assigned managed identity, and terminates by writing Claude's structured triage straight back into the Sentinel incident as a comment, a severity update, and IOC tags. No DFIR-Iris — the Sentinel Incident object *is* the case-management terminal at this tier. The trigger is fully automated through a Sentinel Automation Rule, gated by an inbound RBAC grant that is the actual unlock for Sentinel-invoked playbooks.

**End-to-end pipeline (one line):**
`powershell.exe -EncodedCommand` on `vm-soc-v2-win` → Sysmon EventID=1 → AMA → Log Analytics (`Event` table) → T1059.001 KQL analytics rule → Sentinel incident → Automation Rule (`automation:claude-triage` tag + Run playbook) → Logic App (Key Vault secrets → Claude agent loop + VT/AbuseIPDB enrichment tools → `submit_triage_result`) → Sentinel incident updated (comment + severity + IOC tags).

---

## 2. Architecture

**Components** (all Central US, RG `rg-soc-v2-azure-central-us`, subscription `3718c265-…`, tenant `analysthotmail.onmicrosoft.com`):

| Component | Resource | Role |
|---|---|---|
| Endpoint | `vm-soc-v2-win` (Windows, `Standard_D4as_v7`), Sysmon64 + AMA | Generates the Process-Create telemetry; ops via Azure portal Run Command (Session 0) |
| SIEM | `law-soc-v2-azure` (Log Analytics) + Microsoft Sentinel onboarded; workspace also Defender-XDR-onboarded | Ingest, detection, native incidents (alerts surface as "Microsoft Defender XDR") |
| Detection | Analytics rule `T1059.001 - PowerShell Encoded Command` (scheduled, 5-min run / 5-min lookback, trigger-per-event) | Reads `Event` table, extracts Sysmon fields from EventData XML via regex, matches the encoded-command regex on `powershell.exe`. Entities mapped: Host, Account, Process (CommandLine), Process (ProcessId) |
| Secrets | Key Vault `kv-soc-v2-secrets-1650f9` (RBAC permission mode), 3 secrets: `anthropic-api-key`, `virustotal-api-key`, `abuseipdb-api-key` | No API keys in workflow JSON |
| SOAR | Logic App `la-soc-v2-triage-claude` (Consumption), system-assigned managed identity (Object ID `1e04b3fb-…`) | Trigger + agent loop + terminal, all in one designer |
| Orchestration | Automation Rule `ar-triage-with-claude` (Standard) | Tags the incident and runs the playbook, in order, on incident creation |

**Identity / RBAC** (two distinct grants, both required):
- *Outbound* (Logic App managed identity): `Microsoft Sentinel Responder` on the RG (to write incidents) + `Key Vault Secrets User` on the vault (to read secrets).
- *Inbound* (the unlock for automatic firing): the Microsoft-managed **Azure Security Insights** service principal needs **`Microsoft Sentinel Automation Contributor`** on the RG, granted via *Sentinel → Settings → Playbook permissions*. Without it, both manual Run-playbook **and** automation rules fail with `Failed to trigger playbook … status code 400` — a 403-semantic rejection surfaced behind a 400 toast.

**Data flow:** see the Mermaid component map + runtime sequence (the real incident-#14 run) in [`current-state.md`](../architecture/current-state.md). The design rationale (why Sentinel-native over DFIR-Iris, why a pure Logic App `Until` loop over an Azure Function, why a tag-opt-in trigger) lives in [`v2-azure/specs/2026-05-23-phase-2-soar-logic-app-design.md`](../specs/2026-05-23-phase-2-soar-logic-app-design.md). Committed workflow at [`v2-azure/logic-app/workflow.json`](workflow.json).

**Workflow shape** (committed JSON): `Microsoft Sentinel incident` trigger → [3× Get-secret (Key Vault via MI, `secureData`-masked) + 5× Init variable, in parallel] → `Compose_initial_messages` (builds the Claude user prompt from the incident JSON) → `Set_messages_from_initial` → `Compose_tools` (the 3-tool schema) → `Until_Claude_agent_loop` { `Call_Claude` (HTTP POST `api.anthropic.com`, model `claude-opus-4-7`) → `Parse_Claude_response` → `Switch_on_stop_reason` [ `tool_use`: `For_each_tool_use_block` (Sequential) → `enrich_ip_abuseipdb` / `lookup_file_hash_virustotal` / `submit_triage_result`; `end_turn`/default: compose error + force loop exit ] → `Increment_iteration` } → `Build_incident_tags` (one `ioc:type:value:verdict` label per enriched IOC) → `Conditional_severity_critical_tag` → `Update_Sentinel_Incident` (PUT `/Incidents`: severity if-chain + labels) → `Add_Sentinel_Comment` (POST `/Incidents/Comment`: markdown summary).

---

## 3. Acceptance evidence — Sentinel incident #14 (2026-06-02)

The ship gate was a single real live-fire run, same methodology as Phase 1: fire the technique on the endpoint, let the whole chain run untouched, and read the result out of the incident. Fire initiated via Azure Run Command on `vm-soc-v2-win`: `powershell.exe -NoProfile -EncodedCommand <base64>`.

### Pipeline proof

| Stage | Evidence | Time (UTC) |
|---|---|---|
| Fire | `powershell.exe -NoProfile -EncodedCommand` via Run Command on `vm-soc-v2-win` | `2026-06-02T21:28:45Z` |
| Event in LAW | Sysmon EventID=1 visible in the `Event` table | sub-second after fire |
| Incident created | Incident **#14** `T1059.001 - PowerShell Encoded Command` | `21:37:55Z` (the scheduled-rule tick; ~9m10s after the event) |
| Automation rule fired | Incident Activity log: `Automation rule-ar-triage-with-claude`, **Trigger = Automated, Completed** | on incident creation |
| Logic App run | **one** run, 5:40:37 PM local, status **Succeeded**, **30.58s** (`Update_Sentinel_Incident` 2.4s, `Add_Sentinel_Comment` 0.9s) | post incident |
| Triage written back | Comment + severity update + tags on incident #14 | within the 30.58s run |

The automation was genuinely automatic: the incident's own Activity log shows the rule launching with `Trigger=Automated` and `Completed`, there was exactly one adjacent Logic App run, and there was no user-initiated run. (See §4 for the "Manual" row that looks like — but is not — a manual invocation.)

### Triage output written to incident #14

| Field | Value |
|---|---|
| Severity | **medium** |
| MITRE techniques | **T1059, T1059.001, T1027** |
| Summary | Substantive prose. Notably, Claude correctly identified the base64 blob as **Sentinel's own zlib + base64 `compressedRec` result-packaging artifact** (the rule's projected result wrapped for transport), and distinguished it from an attacker-delivered payload rather than naively flagging "encoded command = malicious." |
| IOCs enriched | **(none)** — see §7 for why, and why this is expected on T1059.001 specifically |

### Latency breakdown (event → triaged ≈ 12m20s)

| Segment | Duration | What dominates it |
|---|---|---|
| Ingestion (event → queryable in LAW) | sub-second | AMA + DCR; faster than the Phase 1 observation at this fire |
| Event → incident | ~9m10s | The scheduled analytics rule's 5-min cron cadence + XDR dispatch — this is the floor for a scheduled rule, not a SOAR cost |
| Incident → triaged | ~2m40s | Automation rule dispatch + **30.58s Claude run** + write-back |
| **Total** | **~12m20s** | Within the spec's "~under 12 min" target band |

The SOAR layer itself — Claude agent loop plus write-back — is the **30.58s** leg. Everything above ~9 minutes is the scheduled-rule cadence, which is a detection-tuning knob (NRT rules or a tighter cron), not a property of the Logic App.

---

## 4. The "Manual" trigger-label caveat (read this before concluding it wasn't automated)

In incident #14's Activity log, the Logic-App-driven **incident-write** rows show `Trigger="Manual"` — even though the playbook was launched automatically by the automation rule. This is not a manual invocation. It is a write-path bucketing quirk:

- Sentinel records each discrete write made through the Logic Apps Sentinel connector (Update Incident, Add Comment) as its own activity entry, and buckets those connector-originated API writes under "Manual" the same way it buckets any direct-API write.
- Both rule-launched **and** human-launched playbooks execute under the same `Azure Security Insights` identity, so the write rows are indistinguishable at the activity-row level.

The proof of automation is therefore **not** that row — it's (a) the automation rule's own `Trigger=Automated / Completed` activity row, (b) the single adjacent Logic App run with no user-initiated run, and (c) no human action between incident creation and triage. If a future reviewer sees "Manual" and concludes the run was hand-triggered, they are reading the wrong row.

---

## 5. v1 ↔ v2 parity & differences

Building on the Phase 1 comparison framing. v1 baseline (`main` branch): Splunk Enterprise + Sysmon + n8n (docker-compose) + Claude tool-use + DFIR-Iris on local VMware. v2/v3 (this branch): Sentinel + AMA + Logic App + Claude + Sentinel-native incidents.

| Dimension | v1 (`main` — Splunk + n8n + Iris) | v2 (this branch — Sentinel + Logic App) | Verdict |
|---|---|---|---|
| **Claude tool contract** | 3 tools, A1 schema (`enrich_ip_abuseipdb`, `lookup_file_hash_virustotal`, `submit_triage_result`) | **Same 3 tools, schemas verbatim** | **Parity — by design.** The comparison never has to apologize for divergence in the AI layer |
| **Agent loop** | n8n `Message a model` LangChain node (loop hidden in the node) | Hand-built Logic App `Until` loop, fully visible in the designer | Different mechanism, same semantics; v2 is more transparent but more verbose |
| **Secrets** | API keys in n8n credentials / plaintext project file (flagged for `.env` migration) | **Key Vault + managed identity**, `secureData`-masked in run history, zero keys in workflow JSON | **v2 win** |
| **Trigger** | Saved search → webhook → n8n (generic public-ish webhook) | Sentinel Automation Rule → playbook, gated by the inbound **Azure Security Insights → Sentinel Automation Contributor** RBAC grant; no public callable endpoint | **v2 win** — RBAC-gated, no exposed ingress |
| **Case-management write-back** | DFIR-Iris alert/case via API (separate product, cross-host plumbing) | **Native Sentinel incident** — comment + severity + IOC tags on the same object the SIEM raised | **v2 win** — one fewer product, write-back lands where analysts already work; also renders in Defender XDR portal |
| **Severity fidelity** | Iris severity scale | Sentinel workspace tier has **no Critical**; `critical → High` **plus** a `severity:critical` tag fallback | **v2 regression (lossy), mitigated** by the tag so hunting queries keep the distinction |
| **Build verbosity** | One LangChain node + a few function nodes | Large `Until`/`Switch`/`Foreach` tree; message-array manipulation via `addProperty(json('{}'),…)` chains | **v2 regression** — the "everything visible in the designer" property is paid for in JSON verbosity |
| **SOAR-layer latency** | n8n run (seconds) | **30.58s** Logic App run (Claude leg) | Comparable; both dominated by Claude tokens, not the SOAR engine |

**What translated cleanly:** the entire Claude contract (tools, schema, system-prompt intent), the structured-triage terminal concept, the enrichment-as-tool pattern, base64 decode as a Claude-side concern.
**What was re-engineered:** the agent loop (LangChain node → hand-built `Until`), the case terminal (Iris API → native incident write), secrets (plaintext/n8n creds → Key Vault + MI).
**Neither pure win nor loss:** designer verbosity (transparency bought with JSON bulk), severity mapping (native simplicity bought with a lossy tier + tag workaround).

---

## 6. Engineering lessons (Logic Apps / WDL gotchas)

These cost real debugging time and are the transferable content of this phase:

- **`@{expr}` string-interpolates and stringifies an object; `@expr` keeps it typed.** A "Capture" Compose using `@{…}` was silently JSON-stringifying the triage object, so downstream property access broke. Use the bare `@expr` form whenever the value must stay an object/array.
- **Reading a Foreach-internal action's output from root scope returns an *array* of per-iteration values.** Pulling the triage out of `For_each_tool_use_block` at root level yielded `[…]`, not the object. Fix: capture into a root-level variable (`Set_triage_result`) inside the loop and make the Foreach **Sequential** so the last write wins deterministically.
- **`createObject()` is not a valid WDL function in Consumption Logic Apps.** Build objects with `addProperty(json('{}'), 'k', v)` chains instead (used throughout the message-array and tag construction).
- **A null/empty `incidentArmId` yields a 400, not a 404.** The 400 is an ARM URL-parse failure (malformed path), whereas a 404 is well-formed-but-missing. When the Update Incident step 400s, suspect the ARM ID expression resolved to empty, not that the incident is gone.
- **Inbound "Playbook permissions" is a separate grant from the Logic App's outbound roles.** The managed identity's `Sentinel Responder` + `Key Vault Secrets User` roles let the *playbook* act; the `Azure Security Insights → Sentinel Automation Contributor` grant is what lets *Sentinel invoke the playbook*. Missing the inbound grant produces the `status code 400` playbook-trigger failure on both manual runs and automation rules.
- **One automation rule beats two.** The plan originally specified two rules (one to add the `automation:claude-triage` tag, one to run the playbook). Separate Standard rules carry manually-assigned **Order** numbers that can collide → nondeterministic run order → the playbook rule can evaluate before the tag exists → silent no-fire. Collapsing to **one rule** whose actions run top-to-bottom (tag, then Run playbook) removes the race. The rule's condition keys on the analytics-rule **name** (`Contains "T1059.001 - PowerShell Encoded Command"`), which is stable at trigger time — not on the tag this same rule is setting.

---

## 7. Security hardening (self-review)

After the pipeline was working, the shipped `workflow.json` was put through an automated security review — the lab is *about* security, so the SOAR app itself has to hold up. Three findings, all valid, all remediated in the committed workflow. The throughline: **treat every model-influenced value as untrusted at its sink, and never let secret material reach run history.**

| # | Severity | Finding | Remediation (in `workflow.json`) |
|---|---|---|---|
| 1 | **High** | `Call_Claude`, `Call_AbuseIPDB`, `Call_Virustotal` lacked `secureData`, so the API keys sat in **plaintext in run-history inputs** (the `Get_*_key` reads were masked, but the HTTP actions that *consume* the keys were not). | Added `runtimeConfiguration.secureData {inputs, outputs}` to all three HTTP actions. **Paired action: rotate the three API keys** — prior runs persisted them before masking, so the old values are considered exposed. |
| 2 | Medium | The VirusTotal hash comes from Claude's tool-call input (which is influenced by attacker-controllable incident content) and was concatenated **into the URL path unencoded** — a prompt-injection → path-injection sink. | Wrapped the hash in `uriComponent(...)` so any injected path characters are encoded (a hostile value degrades to a benign 404, not an injected request). *AbuseIPDB was already safe — it passes the IP as a URL-encoded query parameter.* |
| 3 | Medium | Claude's `summary` and MITRE fields are rendered as **markdown in the analyst-facing incident comment**, so a prompt-injected summary could plant clickable links, images, or raw HTML in the SOC analyst's view. | Sanitized the model-supplied fields in the comment expression: `[`/`]` → `(`/`)` (neutralizes link/image syntax) and `<`/`>` → `&lt;`/`&gt;` (neutralizes HTML), preserving prose readability. |

The transferable point: an LLM-in-the-loop SOAR pipeline has two trust boundaries people forget — the **tool-call arguments** the model emits (they flow into real HTTP requests) and the **prose the model writes into analyst-facing surfaces**. Both are downstream of attacker-influenceable detection content and must be validated/encoded like any other untrusted input.

---

## 8. Known limitation + next step (honest)

**The enrichment tools are not exercised in production on T1059.001.** The acceptance run shows `IOCs enriched: (none)`, and that is expected — not a bug — for this specific detection:

- The T1059.001 analytics rule **projects** `Hashes` but does **not map a FileHash entity**, and the technique carries no IP. So the incident JSON handed to Claude contains no typed, enrichable IOC seed.
- With nothing to enrich, Claude correctly skips `enrich_ip_abuseipdb` / `lookup_file_hash_virustotal` and goes straight to `submit_triage_result`. The two enrichment tool paths were validated in earlier manual smoke tests, but they did not fire in this production acceptance run.

This is an honest gap in the end-to-end demonstration: the headline acceptance run proves the trigger → agent loop → structured-output → native write-back chain, but not the enrichment legs *on this detection*.

**Next step:** map the SHA256 from the rule's `Hashes` projection as a **FileHash entity** in the analytics rule. That hands Claude a real IOC seed and exercises `lookup_file_hash_virustotal` end-to-end. Caveat to state up front: the hash in question is `powershell.exe`'s, which is benign — VirusTotal will return clean — so this proves the *tool path*, not a malicious-verdict path. A detection that carries an attacker-controlled hash or IP (a follow-on detection-engineering item) is what would exercise enrichment against a non-benign verdict.
