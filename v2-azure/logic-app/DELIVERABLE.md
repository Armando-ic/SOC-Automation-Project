# Phase 3 — Microsoft-native SOAR (Logic Apps): What I Built and Proof It Works

> **Quick note on the numbering.** This is **Phase 3** of the v2-Azure track — the Microsoft-native rebuild of the v1 automation layer. The spec and plan files are titled "Phase 2" for git-history reasons; per the 2026-05-23 phase reversal (we slipped an intermediate "Port v1 to Azure IaaS" phase in ahead of this work), read every "Phase 2" in those filenames as "Phase 3." Branch: `v3-microsoft-native`.

Here's the short version of what this doc is: it's the show-and-tell for the v2-Azure automation layer. I built a single workflow in Azure that takes a security alert, has an AI read it and investigate, and then writes the findings back onto the alert automatically — no human in the loop. Below I'll walk through what shipped, prove it actually ran end-to-end with a real example, compare it honestly to the older version I built last year, and call out the gotchas that ate real hours.

A bit of background before we dive in, in case you've never touched any of this:
- **Microsoft Sentinel** is basically a giant security alarm system that watches all the logs from your computers and raises an alert when something looks off.
- An **incident** is just Sentinel's word for "a thing worth a human looking at" — one alert (or a bundle of related alerts) packaged up as a case.
- A **Logic App** is a no-code-ish workflow tool from Microsoft — you wire up steps ("when X happens, do Y, then Z") and it runs them for you. That's the engine doing the automated work here.
- **Claude (Opus 4.7)** is the AI model. I let it run as an agent — meaning it can decide to use "tools" (look something up, then act on what it found) in a loop until it's done. More on that below.

---

## 1. What shipped

The headline: a Logic App named `la-soc-v2-triage-claude` (on Azure's pay-as-you-go "Consumption" tier) that does the entire investigation job automatically. Here's the flow in plain terms. Sentinel raises an incident. That kicks off the Logic App on its own. The Logic App hands the incident to Claude, and Claude works through it like a junior analyst would — investigating, then writing up a verdict. Finally, the workflow writes Claude's findings straight back onto the Sentinel incident: a comment, an updated severity level, and some tags.

A few things worth knowing about how it's wired:

- Claude runs as a **tool-use agent loop** — that's the "think, use a tool, look at the result, think again" cycle. It gets the **same three tools as v1** (the older version): `enrich_ip_abuseipdb` (look up whether an IP address has a bad reputation), `lookup_file_hash_virustotal` (check whether a file is known malware), and `submit_triage_result` (hand back the final verdict). The tool definitions are copied over word-for-word from v1.
- The secret API keys (the passwords the app needs to talk to Claude and the lookup services) live in **Azure Key Vault** — think of it as a locked safe for passwords. The Logic App opens that safe using a **managed identity**, which is a built-in login Azure hands the app so we never have to store an actual password anywhere in the workflow.
- There's no DFIR-Iris here. (In v1, Iris was a separate case-management product where findings got written.) At this tier, the **Sentinel incident itself** is the case file — so the findings land right where a security analyst already works.
- The trigger is fully hands-off, driven by a Sentinel **automation rule** (a "when an incident is created, automatically do these things" rule). Getting that automatic firing to work hinged on one specific permission grant — more on that below, because it was the real unlock.

**The whole pipeline in one line:**
`powershell.exe -EncodedCommand` on `vm-soc-v2-win` → Sysmon EventID=1 → AMA → Log Analytics (`Event` table) → T1059.001 KQL analytics rule → Sentinel incident → Automation Rule (`automation:claude-triage` tag + Run playbook) → Logic App (Key Vault secrets → Claude agent loop + VT/AbuseIPDB enrichment tools → `submit_triage_result`) → Sentinel incident updated (comment + severity + IOC tags).

If that line looks like alphabet soup, here's the gist: I run a sneaky PowerShell command on a test Windows machine; a sensor catches it; it travels up into Sentinel; a detection rule notices it and opens an incident; the automation rule fires the AI workflow; and the workflow writes the verdict back. The glossary below covers the rest of the jargon as it comes up.

---

## 2. Architecture (the moving parts)

What this section is: a parts list and how they connect. Everything lives in Azure's Central US region, in a resource group (a folder for cloud resources) called `rg-soc-v2-azure-central-us`, subscription `3718c265-…`, tenant `analysthotmail.onmicrosoft.com`.

A few terms used in the table:
- **Sysmon** is a free Microsoft sensor that records detailed activity on a Windows machine (like "this program started this other program").
- **AMA** (Azure Monitor Agent) is the little courier installed on the machine that ships those logs up to the cloud.
- **Log Analytics** is the cloud database where all those logs land and can be searched. Sentinel sits on top of it.
- An **analytics rule** is the saved search that runs on a schedule and opens an incident when it finds a match.

| Component | Resource | Role |
|---|---|---|
| Endpoint | `vm-soc-v2-win` (Windows, `Standard_D4as_v7`), Sysmon64 + AMA | Generates the Process-Create telemetry; ops via Azure portal Run Command (Session 0) |
| SIEM | `law-soc-v2-azure` (Log Analytics) + Microsoft Sentinel onboarded; workspace also Defender-XDR-onboarded | Ingest, detection, native incidents (alerts surface as "Microsoft Defender XDR") |
| Detection | Analytics rule `T1059.001 - PowerShell Encoded Command` (scheduled, 5-min run / 5-min lookback, trigger-per-event) | Reads `Event` table, extracts Sysmon fields from EventData XML via regex, matches the encoded-command regex on `powershell.exe`. Entities mapped: Host, Account, Process (CommandLine), Process (ProcessId) |
| Secrets | Key Vault `kv-soc-v2-secrets-1650f9` (RBAC permission mode), 3 secrets: `anthropic-api-key`, `virustotal-api-key`, `abuseipdb-api-key` | No API keys in workflow JSON |
| SOAR | Logic App `la-soc-v2-triage-claude` (Consumption), system-assigned managed identity (Object ID `1e04b3fb-…`) | Trigger + agent loop + terminal, all in one designer |
| Orchestration | Automation Rule `ar-triage-with-claude` (Standard) | Tags the incident and runs the playbook, in order, on incident creation |

A couple more terms for the next bit: **RBAC** (role-based access control) is just Azure's way of saying "who is allowed to do what." A **playbook** is the Sentinel word for a Logic App that Sentinel can fire in response to an incident.

**Identity / RBAC** (two separate permissions, and you need both):
- *Outbound* (what the Logic App is allowed to do): `Microsoft Sentinel Responder` on the resource group (so it can write to incidents) + `Key Vault Secrets User` on the vault (so it can read the secrets out of the safe).
- *Inbound* (the thing that lets it fire automatically): Microsoft's own behind-the-scenes service account, called the **Azure Security Insights** service principal, needs the **`Microsoft Sentinel Automation Contributor`** role on the resource group. You grant it under *Sentinel → Settings → Playbook permissions*. Skip this and *both* the manual "Run playbook" button **and** the automation rules fail with `Failed to trigger playbook … status code 400` — which is really a permission denial (a 403 in spirit) hiding behind a confusing "400" error popup.

**Data flow:** for the visual version — a component map plus the actual step-by-step of the real incident-#14 run — see [`current-state.md`](../architecture/current-state.md). The reasoning behind the design choices (why I went Sentinel-native instead of DFIR-Iris, why a plain Logic App `Until` loop instead of an Azure Function, why the trigger is opt-in via a tag) lives in [`v2-azure/specs/2026-05-23-phase-2-soar-logic-app-design.md`](../specs/2026-05-23-phase-2-soar-logic-app-design.md). The committed workflow is at [`v2-azure/logic-app/workflow.json`](workflow.json).

**Workflow shape** (this is the actual committed JSON, described step by step): `Microsoft Sentinel incident` trigger → [3× Get-secret (Key Vault via MI, `secureData`-masked) + 5× Init variable, in parallel] → `Compose_initial_messages` (builds the Claude user prompt from the incident JSON) → `Set_messages_from_initial` → `Compose_tools` (the 3-tool schema) → `Until_Claude_agent_loop` { `Call_Claude` (HTTP POST `api.anthropic.com`, model `claude-opus-4-7`) → `Parse_Claude_response` → `Switch_on_stop_reason` [ `tool_use`: `For_each_tool_use_block` (Sequential) → `enrich_ip_abuseipdb` / `lookup_file_hash_virustotal` / `submit_triage_result`; `end_turn`/default: compose error + force loop exit ] → `Increment_iteration` } → `Build_incident_tags` (one `ioc:type:value:verdict` label per enriched IOC) → `Conditional_severity_critical_tag` → `Update_Sentinel_Incident` (PUT `/Incidents`: severity if-chain + labels) → `Add_Sentinel_Comment` (POST `/Incidents/Comment`: markdown summary).

In plain words: the loop keeps asking Claude what to do next; if Claude says "use a tool," the workflow runs that tool and feeds the result back; when Claude says "I'm done" (via `submit_triage_result`), the loop ends and the workflow writes the verdict, severity, and tags back onto the incident.

---

## 3. Proof it works — Sentinel incident #14 (2026-06-02)

What this section is: the receipts. The bar I set for calling this "done" was one real live-fire run — same approach as the Phase 1 detection work: trigger the bad behavior on the test machine, let the entire chain run untouched, and read the result out of the incident. I kicked it off via Azure Run Command on `vm-soc-v2-win` with `powershell.exe -NoProfile -EncodedCommand <base64>` (an encoded PowerShell command — the kind of thing attackers use to hide what a command actually does).

### The pipeline, stage by stage

| Stage | Evidence | Time (UTC) |
|---|---|---|
| Fire | `powershell.exe -NoProfile -EncodedCommand` via Run Command on `vm-soc-v2-win` | `2026-06-02T21:28:45Z` |
| Event in LAW | Sysmon EventID=1 visible in the `Event` table | sub-second after fire |
| Incident created | Incident **#14** `T1059.001 - PowerShell Encoded Command` | `21:37:55Z` (the scheduled-rule tick; ~9m10s after the event) |
| Automation rule fired | Incident Activity log: `Automation rule-ar-triage-with-claude`, **Trigger = Automated, Completed** | on incident creation |
| Logic App run | **one** run, 5:40:37 PM local, status **Succeeded**, **30.58s** (`Update_Sentinel_Incident` 2.4s, `Add_Sentinel_Comment` 0.9s) | post incident |
| Triage written back | Comment + severity update + tags on incident #14 | within the 30.58s run |

Here's the cool part: the automation really was automatic. The incident's own activity log shows the rule kicking off with `Trigger=Automated` and `Completed`, there was exactly one Logic App run right next to it, and nobody clicked anything. (See §4 for one row that *looks* like a manual click but isn't.)

A quick note on **T1059.001** — that's a code from **MITRE ATT&CK**, which is basically a public catalog of attacker techniques with ID numbers. T1059.001 means "PowerShell command-line abuse." And an **IOC** ("indicator of compromise") is any concrete clue tied to an attack — an IP address, a file fingerprint, that sort of thing.

### What Claude wrote back onto incident #14

| Field | Value |
|---|---|
| Severity | **medium** |
| MITRE techniques | **T1059, T1059.001, T1027** |
| Summary | Substantive prose. Notably, Claude correctly identified the base64 blob as **Sentinel's own zlib + base64 `compressedRec` result-packaging artifact** (the rule's projected result wrapped for transport), and distinguished it from an attacker-delivered payload rather than naively flagging "encoded command = malicious." |
| IOCs enriched | **(none)** — see §7 for why, and why this is expected on T1059.001 specifically |

In other words, Claude didn't fall for the obvious trap. "Encoded command" sounds scary, but Claude figured out the encoded blob was actually Sentinel's own internal packaging — not something an attacker planted — and rated it medium instead of crying wolf.

### Where the time went (event → triaged ≈ 12m20s)

| Segment | Duration | What dominates it |
|---|---|---|
| Ingestion (event → queryable in LAW) | sub-second | AMA + DCR; faster than the Phase 1 observation at this fire |
| Event → incident | ~9m10s | The scheduled analytics rule's 5-min cron cadence + XDR dispatch — this is the floor for a scheduled rule, not a SOAR cost |
| Incident → triaged | ~2m40s | Automation rule dispatch + **30.58s Claude run** + write-back |
| **Total** | **~12m20s** | Within the spec's "~under 12 min" target band |

Let me be straight about that ~12 minutes, because it sounds slow: almost all of it is just waiting. The detection rule only runs every 5 minutes, so on average an event sits around ~9 minutes before the rule even looks at it. That's a knob I chose, not a flaw in the automation — I could swap in a near-real-time rule or tighten the schedule. The actual AI-does-the-work part — Claude investigating plus writing everything back — is the **30.58s** leg. The automation itself is fast; the schedule is what's slow.

---

## 4. About that "Manual" trigger label (read this before you assume it wasn't automated)

What this section is: heading off a misread. In incident #14's activity log, the rows where the Logic App **wrote to the incident** show `Trigger="Manual"` — even though the workflow was launched automatically by the automation rule. This is *not* a sign someone ran it by hand. It's just a quirk in how Sentinel files away these log entries:

- Every individual write the Logic App makes through Sentinel's connector (Update Incident, Add Comment) gets logged as its own entry, and Sentinel files those connector writes under "Manual" — the same bucket it uses for any direct write to the API.
- Whether a playbook was launched by a rule or by a human, it runs under the same `Azure Security Insights` identity. So at the level of these individual write rows, you genuinely can't tell the two apart.

So the proof that it was automated is **not** that row. It's: (a) the automation rule's own `Trigger=Automated / Completed` row, (b) the single Logic App run right next to it with no user-initiated run, and (c) zero human action between the incident opening and the triage landing. If a future reviewer sees "Manual" and concludes someone hand-triggered it, they're reading the wrong row.

---

## 5. v1 vs. v2 — what carried over and what changed

What this section is: an honest before-and-after. The "v1" I keep mentioning is the version I built last year (on the `main` branch): Splunk + Sysmon + n8n (a different no-code automation tool) + Claude + DFIR-Iris, all running on local VMware virtual machines. The "v2/v3" version (this branch) is the all-Microsoft rebuild: Sentinel + AMA + Logic App + Claude + Sentinel-native incidents.

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

Reading the table in plain terms: the AI brain (the tools, the schema, the prompt intent) carried over unchanged, on purpose — so the comparison is apples-to-apples there. v2 clearly wins on security (passwords in a vault instead of plaintext, and no public web address anyone could poke at) and on convenience (findings land right on the alert, in one fewer product). v2 loses a little on two fronts, and I'm not going to pretend otherwise: this Sentinel tier has no "Critical" severity, so I map critical down to "High" and slap a `severity:critical` tag on as a workaround; and the Logic App is wordier under the hood than the old n8n node, which is the price of being able to see every step.

**What translated cleanly:** the entire Claude contract (tools, schema, system-prompt intent), the structured-triage terminal concept, the enrichment-as-tool pattern, base64 decode as a Claude-side concern.
**What was re-engineered:** the agent loop (LangChain node → hand-built `Until`), the case terminal (Iris API → native incident write), secrets (plaintext/n8n creds → Key Vault + MI).
**Neither pure win nor loss:** designer verbosity (transparency bought with JSON bulk), severity mapping (native simplicity bought with a lossy tier + tag workaround).

---

## 6. Engineering lessons (the Logic Apps gotchas)

What this section is: the stuff that cost me real debugging hours — and the part most likely to help someone else building on Logic Apps. ("WDL" below is the Logic Apps expression language — the little formulas you write inside steps.)

- **`@{expr}` turns a value into text; `@expr` keeps it as a real object.** A "Capture" step using `@{…}` was quietly converting the triage result into a string of text, so every later step that tried to read fields out of it broke. Use the bare `@expr` form whenever the value needs to stay a structured object/array.
- **Reading a loop-internal step's output from outside the loop gives you an *array* of every iteration's value, not the one you want.** Pulling the triage out of `For_each_tool_use_block` from the top level handed me `[…]` instead of the object. Fix: stash it into a top-level variable (`Set_triage_result`) *inside* the loop, and make the loop **Sequential** so the last write reliably wins.
- **`createObject()` isn't a real function in Consumption Logic Apps.** You have to build objects with `addProperty(json('{}'), 'k', v)` chains instead (which I lean on all over the message-array and tag construction).
- **An empty `incidentArmId` throws a 400, not a 404.** The 400 is Azure failing to parse a malformed resource path; a 404 would mean "the path was fine but the thing's missing." So when the Update Incident step throws a 400, suspect that the incident-ID expression came back empty — not that the incident vanished.
- **The inbound "Playbook permissions" grant is a totally separate thing from the Logic App's own outbound roles.** The app's `Sentinel Responder` + `Key Vault Secrets User` roles let the *playbook do its job*; the `Azure Security Insights → Sentinel Automation Contributor` grant is what lets *Sentinel start the playbook in the first place*. Miss the inbound one and you get that `status code 400` trigger failure on both manual runs and automation rules.
- **One automation rule beats two.** I originally planned two rules — one to add the `automation:claude-triage` tag, one to run the playbook. Trouble is, separate Standard rules carry hand-assigned **Order** numbers that can collide, which makes the run order unpredictable, which means the "run playbook" rule can fire before the tag even exists — and then nothing happens, silently. Collapsing it to **one rule** whose actions run top to bottom (tag first, then run playbook) kills the race. And the rule's condition keys off the analytics-rule **name** (`Contains "T1059.001 - PowerShell Encoded Command"`), which is reliably present at trigger time — not off the tag this very rule is in the middle of setting.

---

## 7. Security hardening (self-review)

What this section is: I turned the security lens on my own security tool. Once the pipeline worked, I ran the shipped `workflow.json` through an automated security review — the whole lab is *about* security, so the automation itself had better hold up. Three findings, all legit, all fixed in the committed workflow. The common thread: **treat anything the AI touched as untrusted the moment it hits a real system, and never let a secret end up sitting in the run logs.**

| # | Severity | Finding | Remediation (in `workflow.json`) |
|---|---|---|---|
| 1 | **High** | `Call_Claude`, `Call_AbuseIPDB`, `Call_Virustotal` lacked `secureData`, so the API keys sat in **plaintext in run-history inputs** (the `Get_*_key` reads were masked, but the HTTP actions that *consume* the keys were not). | Added `runtimeConfiguration.secureData {inputs, outputs}` to all three HTTP actions. **Paired action: rotate the three API keys** — prior runs persisted them before masking, so the old values are considered exposed. |
| 2 | Medium | The VirusTotal hash comes from Claude's tool-call input (which is influenced by attacker-controllable incident content) and was concatenated **into the URL path unencoded** — a prompt-injection → path-injection sink. | Wrapped the hash in `uriComponent(...)` so any injected path characters are encoded (a hostile value degrades to a benign 404, not an injected request). *AbuseIPDB was already safe — it passes the IP as a URL-encoded query parameter.* |
| 3 | Medium | Claude's `summary` and MITRE fields are rendered as **markdown in the analyst-facing incident comment**, so a prompt-injected summary could plant clickable links, images, or raw HTML in the SOC analyst's view. | Sanitized the model-supplied fields in the comment expression: `[`/`]` → `(`/`)` (neutralizes link/image syntax) and `<`/`>` → `&lt;`/`&gt;` (neutralizes HTML), preserving prose readability. |

In plain English: the takeaway is that an AI-in-the-loop automation has two danger zones people forget about. One is the **arguments the AI passes to its tools** — those turn into real web requests, so a poisoned value could be used to attack a lookup service. The other is **the text the AI writes into screens a human will read** — a poisoned summary could sneak clickable links or HTML into the analyst's view. Both of those start life as detection content an attacker can influence, so both have to be cleaned up and checked just like any other untrusted input. (A "prompt injection" is when an attacker hides instructions inside the data the AI reads, hoping the AI will follow them.)

---

## 8. Known limitation + next step (being honest)

What this section is: the part the demo *didn't* prove, said plainly. **The lookup/enrichment tools never actually got exercised in this production run on T1059.001.** The acceptance run shows `IOCs enriched: (none)` — and for *this particular* detection, that's expected, not a bug:

- The T1059.001 analytics rule **projects** the file hash but **doesn't map it as a FileHash entity**, and this technique doesn't involve an IP address. So the incident handed to Claude contained no proper, lookup-ready clue to chase.
- With nothing to look up, Claude correctly skipped both `enrich_ip_abuseipdb` and `lookup_file_hash_virustotal` and went straight to `submit_triage_result`. I'd validated both lookup tools in earlier manual smoke tests, but they didn't fire in *this* production run.

So I'll be straight: this is a real gap in the end-to-end demo. The headline run proves the trigger → AI agent loop → structured-verdict → write-back-to-the-incident chain — but it does *not* prove the lookup legs *on this detection*.

**Next step:** map the SHA256 from the rule's `Hashes` projection as a proper **FileHash entity** in the analytics rule. That gives Claude a real clue to chase and exercises `lookup_file_hash_virustotal` end-to-end. One honest caveat up front: the hash here belongs to `powershell.exe` itself, which is harmless — VirusTotal will come back clean — so this proves the *tool path works*, not that it catches something malicious. To exercise enrichment against an actual "this is bad" verdict, I'd need a detection that carries an attacker-controlled hash or IP, which is a follow-on detection-engineering item.
