# SOC_Automation_Project — v2-Azure (Microsoft Sentinel + Azure-native implementation)

> **✅ Microsoft-native SOAR layer SHIPPED 2026-06-02.** A Sentinel-triggered Azure Logic App (`la-soc-v2-triage-claude`) runs the v1 Claude tool-use triage loop natively and writes structured triage straight back into the Sentinel incident — validated end-to-end, fully automatic, on real Sentinel incident #14. **Deliverable:** [`logic-app/DELIVERABLE.md`](logic-app/DELIVERABLE.md) · **Rebuild guide:** [`logic-app/runbook.md`](logic-app/runbook.md) · **Workflow:** [`logic-app/workflow.json`](logic-app/workflow.json).
> *(This SOAR work is labeled **"Phase 3 (Microsoft-native SOAR)"** on its branch `v3-microsoft-native` — it's the 3rd implementation iteration but the 2nd phase of this v2-Azure roadmap. The intermediate **Port-to-Azure** phase — lift-and-shift v1 to Azure IaaS — shipped 2026-05-26; see [`../SOC-Automation-Project-to-Azure-Port.md`](../SOC-Automation-Project-to-Azure-Port.md).)*

This branch implements the same end-to-end SOC pipeline as `main` (Splunk + n8n + DFIR-Iris on private VMware NAT) but on Azure-native tooling. The two branches together form a comparison narrative: *"Same end-to-end SOC pipeline in two stacks — what translated and what didn't."*

**Living architecture diagram:** [architecture/current-state.md](architecture/current-state.md) — Mermaid diagram of what's provisioned vs. what's still being built. Updated as components come online.

## Side-by-side architecture (current target)

| Layer | v1 (`main` branch) | v2-Azure (this branch) |
|---|---|---|
| **SIEM** | Splunk Enterprise 10.2.2 | Microsoft Sentinel (Log Analytics workspace) |
| **Endpoint telemetry** | Sysmon 15.20 + SwiftOnSecurity config + Splunk Universal Forwarder on Win10 VMware VM | Sysmon (same config, TBD install path) + Azure Monitor Agent (AMA) on Azure Windows VM |
| **SOAR** | n8n on Ubuntu Server 24.04 (docker-compose) | **Azure Logic App (Consumption)** — Sentinel-triggered, hand-built Claude tool-use `Until` loop |
| **AI triage** | Claude API (Opus 4.7) with tool-use: VirusTotal + AbuseIPDB enrichment + `submit_triage_result` structured-output schema | Same Claude API contract — only the SOAR invocation layer changes |
| **Case management** | DFIR-Iris v2.4.22 (Ubuntu / docker-compose) | **Sentinel-native incidents** — comment + severity + IOC tags on the incident the SIEM raised; no DFIR-Iris |
| **Lab infrastructure** | VMware Workstation Pro, private NAT subnet `192.168.129.0/24` | Azure subscription on `owner@example.com`, **Central US** region |
| **Working comparison detection** | T1059.001 PowerShell Encoded Command — Splunk saved search → n8n webhook → Claude → IRIS alert #4 (validated 2026-05-12) | T1059.001 ported to KQL — first end-to-end alert firing in v2 is the Phase 1 goal |

## Locked design decisions (2026-05-22, with 2026-05-23 reversal noted)

- **Endpoint approach:** Pure Azure (new Azure Windows VM ingesting via AMA). Not hybrid; not forwarding from the existing on-prem Win10. Cleanest parallel-implementation narrative. **(For the Phase 1 endpoint — still valid for `vm-soc-v2-win`.)**
- **2026-05-23 reversal — broader "no v1 migration" stance:** The original framing assumed v1 stayed entirely on local VMware as the comparison baseline. Reversed 2026-05-23: the user is now lift-and-shifting the full v1 stack (Splunk + n8n + DFIR-Iris) to Azure IaaS before the Microsoft-native rewrite resumes. Primary driver: free up local C: drive space. Secondary driver: broader Azure exposure. The Phase 1 Azure endpoint (`vm-soc-v2-win`) stays as-is; this reversal is about the *other three v1 VMs* the original decision excluded. See [`../SOC-Automation-Project-to-Azure-Port.md`](../SOC-Automation-Project-to-Azure-Port.md) for the new Phase 2 scope.
- **Region:** Central US. Originally East US (cheaper, lower latency from NoVA, general-purpose) — moved 2026-05-22 because the Free Trial subscription had zero vCPU quota in East US across all VM families. Microsoft Q&A confirms Free Trial subs cannot request quota increases — only path was either a region change or upgrading to PAYG. Central US verified to have D-series v7 availability before teardown. Latency from NoVA is ~10ms worse than East US (still imperceptible for lab work); pricing is identical. Not East US 2 — federal-aligned region was the only reason to consider it, and the v2-Azure work is portfolio, not contract-bound.
- **Repo structure:** This branch (`v2-azure`) of the existing `SOC-Automation-Project` repo. Not a separate repo. Comparison narrative is much stronger when both implementations live side-by-side in one repo's branch view.
- **Windows VM size:** `Standard_D4as_v7` (4 vCPU / 16 GiB, AMD EPYC). Originally targeted `Standard_D4s_v5` — substituted to v7-family AMD variant because that's what the Free Trial in Central US made available. Functionally equivalent for the AMA + Sysmon workload, ~15% cheaper than the Intel equivalent. Full spec at [`infrastructure/vm-soc-v2-win.md`](infrastructure/vm-soc-v2-win.md).

## Phase 1 — Foundation (COMPLETE — 2026-05-22)

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

## Phase 1 results (2026-05-22)

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

**Full commentary** in [`detections/t1059-001-powershell-encoded-azure.md#v1--v2-comparison-the-portfolio-value`](detections/t1059-001-powershell-encoded-azure.md#v1--v2-comparison-the-portfolio-value).

## Phase 2 — SOAR layer (SHIPPED 2026-06-02 · "Phase 3" on `v3-microsoft-native`)

- [x] Decision: **Logic Apps** (Consumption) over Azure Functions — keeps the agent loop visible in the designer
- [x] Wire Sentinel incident → Automation Rule → Logic App → Claude API call (same 3-tool A1 contract as v1, verbatim)
- [x] Decided: **Sentinel-native incidents** — no DFIR-Iris; the incident object is the case terminal
- [x] Secrets in Key Vault + managed identity (no keys in workflow JSON), `secureData`-masked
- [x] Self-conducted security review + hardening (secret masking, prompt-injection-resistant tool-arg encoding, analyst-comment sanitization)
- [x] Validated end-to-end, fully automatic, on Sentinel incident #14 (2026-06-02)

**Deliverable:** [`logic-app/DELIVERABLE.md`](logic-app/DELIVERABLE.md) · **Rebuild runbook:** [`logic-app/runbook.md`](logic-app/runbook.md) · **Workflow JSON:** [`logic-app/workflow.json`](logic-app/workflow.json)

### Phase 2 (SOAR) results — incident #14 (2026-06-02)

| Dimension | v1 (Splunk + n8n + IRIS) | v2 (Sentinel + Logic App) | Verdict |
|---|---|---|---|
| Claude tool contract | 3 tools, A1 schema | same 3 tools, **verbatim** | parity (by design) |
| Agent loop | n8n LangChain node | hand-built Logic App `Until` loop | v2 more transparent, more verbose |
| Secrets | n8n creds / plaintext | Key Vault + MI, `secureData`-masked | **v2 win** |
| Trigger | Splunk webhook | RBAC-gated Automation Rule (no public endpoint) | **v2 win** |
| Case write-back | DFIR-Iris API | native Sentinel incident (comment + severity + tags) | **v2 win** (one fewer product) |
| SOAR-layer latency | ~seconds | **30.58s** Logic App run | comparable (Claude-bound) |
| End-to-end (event→triaged) | ~15s | ~12 min | v2 regression — scheduled-rule cadence dominates, not the SOAR engine |

Full commentary, engineering lessons, and the security-review writeup in [`logic-app/DELIVERABLE.md`](logic-app/DELIVERABLE.md).

## Phase 3 — Compare, write up, publish (queued)

- [ ] Comparison post (Medium / dev.to / GitHub Pages)
- [ ] Update LinkedIn Featured + GitHub profile with v2 work
- [ ] Natural SC-200 readiness check at end of phase

## Working notes

Daily/weekly working notes live in `v2-azure/notes/` (created as needed). KQL queries land in `v2-azure/detections/`. Lab diagrams in `v2-azure/architecture/`.

## Reading order for a fresh visitor

1. This README
2. [../README.md](../README.md) — main branch README for the v1 baseline this is being compared against
3. [../vault/detections/t1059-001-powershell-encoded.md](../vault/detections/t1059-001-powershell-encoded.md) — the v1 worked example being ported
4. `detections/t1059-001-powershell-encoded-azure.md` (Phase 1 deliverable) — the v2 KQL port + the comparison commentary
