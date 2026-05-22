# SOC_Automation_Project — v2-Azure (Microsoft Sentinel + Azure-native implementation)

This branch implements the same end-to-end SOC pipeline as `main` (Splunk + n8n + DFIR-Iris on private VMware NAT) but on Azure-native tooling. The two branches together form a comparison narrative: *"Same end-to-end SOC pipeline in two stacks — what translated and what didn't."*

**Living architecture diagram:** [architecture/current-state.md](architecture/current-state.md) — Mermaid diagram of what's provisioned vs. what's still being built. Updated as components come online.

## Side-by-side architecture (current target)

| Layer | v1 (`main` branch) | v2-Azure (this branch) |
|---|---|---|
| **SIEM** | Splunk Enterprise 10.2.2 | Microsoft Sentinel (Log Analytics workspace) |
| **Endpoint telemetry** | Sysmon 15.20 + SwiftOnSecurity config + Splunk Universal Forwarder on Win10 VMware VM | Sysmon (same config, TBD install path) + Azure Monitor Agent (AMA) on Azure Windows VM |
| **SOAR** | n8n on Ubuntu Server 24.04 (docker-compose) | Logic Apps OR Azure Functions (decision in Phase 2) |
| **AI triage** | Claude API (Opus 4.7) with tool-use: VirusTotal + AbuseIPDB enrichment + `submit_triage_result` structured-output schema | Same Claude API contract — only the SOAR invocation layer changes |
| **Case management** | DFIR-Iris v2.4.22 (Ubuntu / docker-compose) | TBD Phase 2 — either keep DFIR-Iris cross-cloud, or replace with Microsoft Defender XDR / Sentinel-native incidents |
| **Lab infrastructure** | VMware Workstation Pro, private NAT subnet `192.168.129.0/24` | Azure subscription on `owner@example.com`, **Central US** region |
| **Working comparison detection** | T1059.001 PowerShell Encoded Command — Splunk saved search → n8n webhook → Claude → IRIS alert #4 (validated 2026-05-12) | T1059.001 ported to KQL — first end-to-end alert firing in v2 is the Phase 1 goal |

## Locked design decisions (2026-05-22)

- **Endpoint approach:** Pure Azure (new Azure Windows VM ingesting via AMA). Not hybrid; not forwarding from the existing on-prem Win10. Cleanest parallel-implementation narrative.
- **Region:** Central US. Originally East US (cheaper, lower latency from NoVA, general-purpose) — moved 2026-05-22 because the Free Trial subscription had zero vCPU quota in East US across all VM families. Microsoft Q&A confirms Free Trial subs cannot request quota increases — only path was either a region change or upgrading to PAYG. Central US verified to have D-series v7 availability before teardown. Latency from NoVA is ~10ms worse than East US (still imperceptible for lab work); pricing is identical. Not East US 2 — federal-aligned region was the only reason to consider it, and the v2-Azure work is portfolio, not contract-bound.
- **Repo structure:** This branch (`v2-azure`) of the existing `SOC-Automation-Project` repo. Not a separate repo. Comparison narrative is much stronger when both implementations live side-by-side in one repo's branch view.
- **Windows VM size:** `Standard_D4as_v7` (4 vCPU / 16 GiB, AMD EPYC). Originally targeted `Standard_D4s_v5` — substituted to v7-family AMD variant because that's what the Free Trial in Central US made available. Functionally equivalent for the AMA + Sysmon workload, ~15% cheaper than the Intel equivalent. Full spec at [`infrastructure/vm-soc-v2-win.md`](infrastructure/vm-soc-v2-win.md).

## Phase 1 — Foundation (active)

- [x] Azure subscription confirmed active (owner@example.com tenant)
- [x] Log Analytics workspace created in Central US
- [x] Microsoft Sentinel onboarded to the Log Analytics workspace
- [x] Azure Windows VM provisioned in Central US (2026-05-22) — see [`infrastructure/vm-soc-v2-win.md`](infrastructure/vm-soc-v2-win.md)
- [ ] Azure Monitor Agent (AMA) installed on the VM
- [ ] Data Collection Rule (DCR) configured to ship Windows Security / System / Application + Sysmon events into the Sentinel workspace
- [ ] Confirm events visible in Sentinel logs (`SecurityEvent` table or `Event` table depending on data source)
- [ ] Port T1059.001 PowerShell Encoded Command detection from Splunk SPL → KQL; save as Analytics Rule in Sentinel
- [ ] Fire the detection end-to-end (Atomic Red Team test on the VM → AMA → Sentinel → analytics rule trigger → Sentinel incident)
- [ ] Document the side-by-side detection in `detections/t1059-001-powershell-encoded-azure.md`
- [ ] Natural AZ-900 readiness check at end of phase

## Phase 2 — SOAR layer (queued)

- [ ] Decision: Logic Apps vs. Azure Functions for the SOAR layer
- [ ] Wire Sentinel incident → SOAR trigger → Claude API call (same tool-use contract as v1)
- [ ] Decide: keep DFIR-Iris cross-cloud, or migrate to Sentinel-native incidents

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
