# SOC_Automation_Project — v2-Azure (the Microsoft Sentinel / Azure version)

> **What is this whole thing?** It's a small but complete "robot security analyst" pipeline. Computers constantly spit out logs (records of what they did). Somewhere in that noise are signs of an attack. This project watches the logs, notices the suspicious stuff, asks an AI to investigate it, and writes up the findings automatically — no human babysitting required. This particular folder is the *second* build of that idea, done entirely with Microsoft's Azure cloud tools so we can compare it against the first build. If you've never touched any of this, don't worry — every bit of jargon gets a plain-language translation the first time it shows up.

> **✅ The automated-investigation layer went live 2026-06-02.** Here's the cool part: an Azure Logic App (a no-code-ish workflow that runs a series of steps for you, like a flowchart that actually executes) named `la-soc-v2-triage-claude` runs the same AI investigation loop the v1 build used, and writes its conclusions straight back into the security alert. We tested the whole thing start-to-finish on a real alert — Sentinel incident #14 — and it ran fully on its own. **Want the details?** [`logic-app/DELIVERABLE.md`](logic-app/DELIVERABLE.md) · **Want to rebuild it yourself?** [`logic-app/runbook.md`](logic-app/runbook.md) · **The actual workflow file:** [`logic-app/workflow.json`](logic-app/workflow.json).
> *(Quick naming note so you're not confused later: this work is tagged **"Phase 3 (Microsoft-native SOAR)"** on the code branch `v3-microsoft-native`. It's the 3rd time the project was built, but only the 2nd phase of *this* Azure roadmap. In between, there was a "Port-to-Azure" phase — basically copying the original setup onto Azure machines as-is — which shipped 2026-05-26. That story lives in [`../SOC-Automation-Project-to-Azure-Port.md`](../SOC-Automation-Project-to-Azure-Port.md).)*

So here's the setup. There are two versions of this project, living as two branches of the same repo. The original (`main` branch) was built with Splunk, n8n, and DFIR-Iris running on virtual machines on a home computer. This branch rebuilds the exact same pipeline using Azure's own tools. Put side by side, they tell one story: *"Here's the same security pipeline built two completely different ways — what carried over cleanly, and what was a pain."*

**Want to see the current wiring?** [architecture/current-state.md](architecture/current-state.md) — a diagram (built with Mermaid) showing what's already running versus what's still under construction. It gets updated as pieces come online.

## The two versions, side by side (what we're aiming for)

A quick map of the jargon in this table, since it's the first time most of it appears:
- **SIEM** = the central log-collecting brain that everything feeds into.
- **Microsoft Sentinel** = Microsoft's SIEM — basically a giant security alarm system that watches all the logs and raises alerts.
- **Log Analytics workspace** = the database underneath Sentinel where all those logs actually get stored.
- **Sysmon** = a free Windows add-on that records detailed activity on a computer (what programs ran, what they talked to) so there's something worth watching.
- **AMA (Azure Monitor Agent)** = a small program installed on a machine whose job is to ship that machine's logs up to the cloud.
- **SOAR** = the automation layer — the part that reacts to alerts and *does* something instead of just paging a human.

| Layer | v1 (`main` branch) | v2-Azure (this branch) |
|---|---|---|
| **SIEM** | Splunk Enterprise 10.2.2 | Microsoft Sentinel (Log Analytics workspace) |
| **Endpoint telemetry** | Sysmon 15.20 + SwiftOnSecurity config + Splunk Universal Forwarder on Win10 VMware VM | Sysmon (same config, TBD install path) + Azure Monitor Agent (AMA) on Azure Windows VM |
| **SOAR** | n8n on Ubuntu Server 24.04 (docker-compose) | **Azure Logic App (Consumption)** — Sentinel-triggered, hand-built Claude tool-use `Until` loop |
| **AI triage** | Claude API (Opus 4.7) with tool-use: VirusTotal + AbuseIPDB enrichment + `submit_triage_result` structured-output schema | Same Claude API contract — only the SOAR invocation layer changes |
| **Case management** | DFIR-Iris v2.4.22 (Ubuntu / docker-compose) | **Sentinel-native incidents** — comment + severity + IOC tags on the incident the SIEM raised; no DFIR-Iris |
| **Lab infrastructure** | VMware Workstation Pro, private NAT subnet `192.168.129.0/24` | Azure subscription on `owner@example.com`, **Central US** region |
| **Working comparison detection** | T1059.001 PowerShell Encoded Command — Splunk saved search → n8n webhook → Claude → IRIS alert #4 (validated 2026-05-12) | T1059.001 ported to KQL — first end-to-end alert firing in v2 is the Phase 1 goal |

A few more terms from that table, in plain words:
- **AI triage** = handing the alert to an AI (here, Anthropic's Claude) to do the first-pass investigation a junior analyst would normally do.
- **tool-use loop** = letting the AI call outside tools (like "look up this suspicious file") and feed the answers back to itself, round after round, until it reaches a conclusion. (More on the `Until` loop below.)
- **incident** = Sentinel's word for a security case it opened because something tripped an alert.
- **IOC** (indicator of compromise) = a concrete clue tied to an attack — a bad IP address, a malicious file fingerprint, etc.
- **MITRE ATT&CK** = an industry-standard catalog of attacker techniques; that `T1059.001` code is its ID for "attacker abuses PowerShell to run hidden commands." It's just a shared label so everyone means the same thing.
- **KQL** = the query language you use to ask Sentinel questions about the logs (Splunk's equivalent is SPL).

## Design decisions we locked in (2026-05-22, with a 2026-05-23 change of heart noted)

These are the "why did we do it that way" calls. Facts unchanged, just talking you through them.

- **How we get endpoint data:** Pure Azure — a brand-new Azure Windows VM that ships its logs via AMA. Not a hybrid setup, and not forwarding from the old on-prem Win10 machine. A clean from-scratch Azure build makes the "two parallel implementations" comparison much cleaner. **(This still holds for the Phase 1 endpoint machine, `vm-soc-v2-win`.)**
- **2026-05-23 — a broader change of plan ("we *are* migrating v1 after all"):** Originally the idea was to leave the entire v1 build on the home VMware machine as the untouched comparison baseline. That got reversed on 2026-05-23: the full v1 stack (Splunk + n8n + DFIR-Iris) is being lifted and shifted onto Azure machines before the Microsoft-native rewrite picks back up. Main reason: free up space on the local C: drive. Bonus reason: more hands-on Azure time. The Phase 1 Azure endpoint (`vm-soc-v2-win`) is untouched by this — the reversal is only about the *other three v1 VMs* the original decision had left out. Full new scope is in [`../SOC-Automation-Project-to-Azure-Port.md`](../SOC-Automation-Project-to-Azure-Port.md).
- **Which Azure region:** Central US. It started as East US (cheaper, lower lag from Northern Virginia, good general-purpose pick) but moved on 2026-05-22 for an annoying reason: the Free Trial subscription had zero vCPU quota in East US across every VM family — meaning Azure literally wouldn't let us spin up a machine there. Microsoft's own Q&A confirms Free Trial subscriptions can't request quota increases, so the only options were change regions or upgrade to pay-as-you-go. Central US was verified to actually have the VM type we wanted before we tore the old setup down. The lag from NoVA is about 10ms worse than East US (totally unnoticeable for lab work), and pricing is identical. We skipped East US 2 — the only reason to pick it would've been federal-region alignment, and this is portfolio work, not tied to a contract.
- **How the repo is organized:** This is a branch (`v2-azure`) of the existing `SOC-Automation-Project` repo, not a separate repo. The comparison story reads way better when both builds sit side by side in one repo's branch view.
- **How beefy the Windows VM is:** `Standard_D4as_v7` (4 vCPU / 16 GiB, AMD EPYC chip). We first aimed for `Standard_D4s_v5` but swapped to the v7-family AMD variant because that's what the Free Trial in Central US actually offered. It's functionally the same for the AMA + Sysmon workload and about 15% cheaper than the Intel equivalent. Full spec at [`infrastructure/vm-soc-v2-win.md`](infrastructure/vm-soc-v2-win.md).

## Phase 1 — Foundation (DONE — 2026-05-22)

**What this phase was:** stand up the bones — get Azure collecting logs from a Windows machine and prove a single detection can fire all the way through. Here's what got checked off:

- [x] Azure subscription confirmed active (owner@example.com tenant)
- [x] Log Analytics workspace created in Central US
- [x] Microsoft Sentinel onboarded to the Log Analytics workspace
- [x] Azure Windows VM provisioned in Central US (2026-05-22) — see [`infrastructure/vm-soc-v2-win.md`](infrastructure/vm-soc-v2-win.md)
- [x] Azure Monitor Agent (AMA) installed on the VM (AzureMonitorWindowsAgent 1.42.0.0 — pushed automatically via DCR association, no manual install)
- [x] Data Collection Rule (DCR) `dcr-soc-v2-windows-events` configured to ship Application + Security + System + Sysmon Operational channels into the Sentinel workspace (Custom XPath data source)
- [x] Confirmed events visible in Sentinel logs (`Event` table; note: Security channel also routes to `Event` rather than `SecurityEvent` because Custom XPath collects everything into the generic table — see Phase 1 detection doc for the SecurityEvent vs Event tradeoff discussion)
- [x] T1059.001 PowerShell Encoded Command detection ported from Splunk SPL → KQL; saved as Sentinel Analytics Rule (5-min schedule, 5-min lookback, per-result alerting, 4 entity mappings)
- [x] Detection fired end-to-end on Atomic Red Team Test 15 (ATH harness) → Sentinel Incident #10 (event 8:11:18 PM → incident 8:20:42 PM, 9m24s latency)
- [x] Documented in [`detections/t1059-001-powershell-encoded-azure.md`](detections/t1059-001-powershell-encoded-azure.md) with full v1↔v2 comparison commentary; reusable KQL artifact at [`detections/kql/t1059-001-powershell-encoded.kql`](detections/kql/t1059-001-powershell-encoded.kql)
- [ ] Natural AZ-900 readiness check at end of phase

(A couple terms from that list: a **DCR (Data Collection Rule)** is just the config that tells AMA *which* logs to ship and where. An **analytics rule** is Sentinel's saved query that runs on a schedule and raises an alert when it finds a match — that's what turns a log entry into an incident.)

## Phase 1 results (2026-05-22)

The honest scorecard — what came out identical between the two builds, and where v2 was clearly better or worse. "Parity" just means "did the two versions match up."

| Parity dimension | v1 (Splunk + n8n) | v2 (Sentinel + AMA Custom XPath) | Verdict |
|---|---|---|---|
| Sysmon binary version | 15.20 | 15.20 | identical |
| Sysmon config (SHA256-verified) | `055FEBC6...87162` | `055FEBC6...87162` | bit-identical |
| Detection regex string | `(?i)\s-e[ncodedommand]*\s` | `(?i)\s-e[ncodedommand]*\s` | identical |
| ATH Test 15 ParentImage | `wbem\WmiPrvSE.exe` | `wbem\WmiPrvSE.exe` | identical (ATH 1.12.0.0 still WMI-spawns) |
| Schedule + per-result + duplicate-tick gotcha | "For each result" with no dedupe | "Trigger an alert for each event" with no dedupe | identical semantics |
| Field extraction | Automatic via `Splunk_TA_microsoft_sysmon` | **Manual XML regex per query** | **major friction in v2** |
| Detection query length | 5 lines SPL | 12 lines KQL | 2.4× longer in v2 |
| Ingestion latency | ~5 sec | ~5–10 min | v2 regression at low volume |
| Alert→Incident hop | Webhook → n8n → Iris | Native (Sentinel Incident) | v2 simpler |
| Entity graph | n/a | first-class (Host, Account, Process×2) | v2 free win |

The short version: the security content (Sysmon, the config, the detection logic) carried over bit-for-bit, which is the point. But v2 made you do more manual work writing the query, was slower to ingest logs, and threw away the extra products — Sentinel handles the alert-to-incident step on its own and even draws a relationship graph of who-did-what for free.

**Full commentary** in [`detections/t1059-001-powershell-encoded-azure.md#v1--v2-comparison-the-portfolio-value`](detections/t1059-001-powershell-encoded-azure.md#v1--v2-comparison-the-portfolio-value).

## Phase 2 — SOAR layer (SHIPPED 2026-06-02 · labeled "Phase 3" on `v3-microsoft-native`)

**What this phase was:** the payoff — wire up the automation so an alert kicks off the AI investigation by itself and the result lands back on the case. Here's what got done:

- [x] Decision: **Logic Apps** (Consumption) over Azure Functions — keeps the agent loop visible in the designer
- [x] Wire Sentinel incident → Automation Rule → Logic App → Claude API call (same 3-tool A1 contract as v1, verbatim)
- [x] Decided: **Sentinel-native incidents** — no DFIR-Iris; the incident object is the case terminal
- [x] Secrets in Key Vault + managed identity (no keys in workflow JSON), `secureData`-masked
- [x] Self-conducted security review + hardening (secret masking, prompt-injection-resistant tool-arg encoding, analyst-comment sanitization)
- [x] Validated end-to-end, fully automatic, on Sentinel incident #14 (2026-06-02)

A few terms from that checklist, since they matter for the table below:
- **automation rule** = Sentinel's "when an incident shows up, automatically do X" trigger.
- **playbook** = the thing it runs — here, our Logic App.
- **Key Vault** = Azure's locked safe for passwords and API keys, so secrets never sit in plain text inside the workflow.
- **managed identity** = a built-in login the Logic App uses to fetch those secrets, so we never have to store a password for it anywhere.
- **RBAC** (role-based access control) = Azure's permission system — who's allowed to do what. (It matters below because the trigger is permission-gated instead of being a wide-open public URL.)

**Deliverable:** [`logic-app/DELIVERABLE.md`](logic-app/DELIVERABLE.md) · **Rebuild runbook:** [`logic-app/runbook.md`](logic-app/runbook.md) · **Workflow JSON:** [`logic-app/workflow.json`](logic-app/workflow.json)

### Phase 2 (SOAR) results — incident #14 (2026-06-02)

Same honest-scorecard idea as before, but for the automation layer:

| Dimension | v1 (Splunk + n8n + IRIS) | v2 (Sentinel + Logic App) | Verdict |
|---|---|---|---|
| Claude tool contract | 3 tools, A1 schema | same 3 tools, **verbatim** | parity (by design) |
| Agent loop | n8n LangChain node | hand-built Logic App `Until` loop | v2 more transparent, more verbose |
| Secrets | n8n creds / plaintext | Key Vault + MI, `secureData`-masked | **v2 win** |
| Trigger | Splunk webhook | RBAC-gated Automation Rule (no public endpoint) | **v2 win** |
| Case write-back | DFIR-Iris API | native Sentinel incident (comment + severity + tags) | **v2 win** (one fewer product) |
| SOAR-layer latency | ~seconds | **30.58s** Logic App run | comparable (Claude-bound) |
| End-to-end (event→triaged) | ~15s | ~12 min | v2 regression — scheduled-rule cadence dominates, not the SOAR engine |

A couple of honest caveats worth calling out in plain English:
- That **~12 minute** end-to-end time looks bad next to v1's ~15 seconds, but it's not the automation being slow — the Logic App itself only runs ~30 seconds. The wait is almost entirely Sentinel's scheduled detection rule, which only checks for new matches every few minutes. The slow part is the polling cadence, not the engine.
- The enrichment tools (the "look up this IP / this file" lookups) are wired in and available, but this particular test incident didn't have indicators that exercised them — so consider that path built-but-not-yet-stress-tested.

Full commentary, engineering lessons, and the security-review writeup in [`logic-app/DELIVERABLE.md`](logic-app/DELIVERABLE.md).

## Phase 3 — Compare, write up, publish (still to come)

**What this phase is:** turn all of the above into something other people can read and learn from.

- [ ] Comparison post (Medium / dev.to / GitHub Pages)
- [ ] Update LinkedIn Featured + GitHub profile with v2 work
- [ ] Natural SC-200 readiness check at end of phase

## Working notes

Day-to-day and weekly notes live in `v2-azure/notes/` (created as needed). KQL queries land in `v2-azure/detections/`. Lab diagrams in `v2-azure/architecture/`.

## Where to start if you just landed here

A suggested reading path, easiest first:

1. This README
2. [../README.md](../README.md) — the main-branch README for the v1 build this whole thing is compared against
3. [../vault/detections/t1059-001-powershell-encoded.md](../vault/detections/t1059-001-powershell-encoded.md) — the v1 worked example we ported over
4. `detections/t1059-001-powershell-encoded-azure.md` (the Phase 1 deliverable) — the v2 KQL port plus the side-by-side comparison commentary
