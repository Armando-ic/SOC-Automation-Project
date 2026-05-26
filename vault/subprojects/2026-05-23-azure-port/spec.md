---
status: complete
updated: 2026-05-26
sub_project: P2 (Azure Port)
approach: Fresh-provision all 3 VMs in Azure (no VHD import); reuse Phase 1 VNet/RG; aggressive same-day archive + delete decommission
related: [[README]], [[runbook]], [[notes]], [[comparison-latency]], [[../../architecture/components/splunk]], [[../../architecture/components/n8n]], [[../../architecture/components/dfir-iris]], [[../../architecture/current-state]]
---

# Spec — Sub-project P2: Azure Port (v1 → Azure IaaS)

## Summary

Port the existing local-VMware SOC automation stack (Splunk + n8n + DFIR-IRIS) to Azure IaaS, then decommission the local VMs. The Phase 1 Windows endpoint (`vm-soc-v2-win`, already in Azure) stays as-is and adds a second log destination — Sysmon UF → the new Splunk-in-Azure — in parallel to its existing AMA → Log Analytics flow.

The Phase 3 Microsoft-native SOAR rewrite (Logic Apps + Sentinel-native incidents) is **deferred until P2 ships**. Its spec + plan exist on the `v3-microsoft-native` branch and are explicitly out of scope here.

## Goal

- **Primary:** Free up local C: drive space by deleting the 4 local VMs (3 Linux services + 1 Win10 endpoint already replaced in Phase 1).
- **Secondary:** Broader Azure IaaS exposure — networking, NSGs, VM provisioning, managed disks — as portfolio surface area beyond Phase 1's PaaS-heavy work (Sentinel + Log Analytics + AMA + DCR).
- **Tertiary:** Establish the cross-stack latency baseline. Capture end-to-end alert-pipeline latency in Azure for comparison against v1 (local VMware) and eventually Phase 3 (Microsoft-native).

## Scope

### In scope

- **Provision 3 new Azure Linux VMs** (Central US, same RG/VNet as Phase 1): `vm-soc-v2-splunk`, `vm-soc-v2-n8n`, `vm-soc-v2-iris`.
- **Splunk migration (fresh install):** Splunk Enterprise 10.2.2 on Ubuntu 24.04 LTS. Re-install 2 add-ons (`Splunk_TA_microsoft_sysmon` v5.0.0, `Splunk_TA_windows` v10.0.1). Create empty `mydfir-project` index. Re-create 2 saved searches (`T1059.001 - PowerShell Encoded Command` enabled; `Test-Brute-Force-External-Spoofed` disabled, matching v1 state). Apply for Splunk Developer License at dev.splunk.com (parallel background task).
- **n8n migration (fresh docker-compose redeploy):** Stand up n8n via the same docker-compose pattern as v1. Re-import `JSON/SOC-Triage-v3.json` workflow. Recreate 4 credentials (Claude API, VirusTotal, AbuseIPDB, IRIS) from the gitignored secrets file.
- **IRIS migration (fresh docker-compose + Postgres dump/restore):** Stand up IRIS 2.4.22 via docker-compose. `pg_dump` from local IRIS, `scp` to Azure VM, restore — preserves cases, alerts, evidence, customer/severity config. Regenerate API keys post-restore if required by IRIS (TBD during plan).
- **Re-point Phase 1's `vm-soc-v2-win` Sysmon UF** to the new Splunk's private IP on port 9997, alongside its existing AMA → Log Analytics output.
- **Network configuration:** NSG rules added to existing Phase 1 subnet (or attached per-NIC); source-IP-restricted public IPs on all 3 new Linux VMs for SSH + per-service web UI; private-IP-only intra-VNet traffic for the alert pipeline.
- **End-to-end verification:** Fire Atomic Red Team T1059.001 Test 15 from `vm-soc-v2-win` → confirm full pipeline lands in IRIS-in-Azure. Capture latency.
- **Decommission of 4 local VMs:** Same-day verify + archive (to external SSD) + delete from VMware library, per-VM, in migration order. C: drive freed at each step.
- **Cherry-pick the handoff doc** (`SOC-Automation-Project-to-Azure-Port.md`) from the `v3-microsoft-native` branch onto `v2-azure` so it's discoverable from the active branch.

### Out of scope (deliberately deferred)

- **Phase 3 — Microsoft-native rewrite** (Logic Apps + Sentinel-native incidents replacing n8n + IRIS). Full spec + plan exist on `v3-microsoft-native` branch at `v2-azure/specs/2026-05-23-phase-2-soar-logic-app-design.md` and `v2-azure/plans/2026-05-23-phase-2-soar-logic-app-plan.md`. Resumes after P2 is stable.
- **A3 Enrichment Expansion** (urlscan.io, URLhaus, IP2Location). Originally planned as a v1 sub-project; remains permanently deferred and likely dropped if Azure work delivers higher portfolio value.
- **Splunk historical data migration.** Course CSVs, BOTSv1, prior training data. Fresh-start Splunk; re-ingest selectively post-P2 only if needed for portfolio demonstrations.
- **n8n pinned webhook test data.** Convenience for development; not load-bearing. Re-pin if/when needed.
- **Azure Bastion or VPN-based access patterns.** Source-IP-restricted public IPs are sufficient for a portfolio lab; Bastion's ~$140/month is unjustifiable on a Trial subscription.
- **Splunk Cloud or paid Enterprise license.** Dev License is the long-term-stable target; trial reinstall is the fallback if Dev License is denied or delayed.
- **Multi-region or HA configuration.** Single-VM-per-service, Central US only.

## Approach

**Fresh-provision over lift-and-shift, across all 3 VMs.** Each option was evaluated separately during brainstorming; fresh-provision won every comparison.

- **Splunk fresh install** chosen because: lift-and-shift carries the same Jun 24, 2026 trial expiry (~32 days from spec date) into Azure, forcing a license switch before the migration even stabilizes. Fresh install resets the 60-day trial clock at install time, decoupling from the Jun 24 deadline.
- **n8n fresh redeploy** chosen because: workflow JSON is already in git (`JSON/SOC-Triage-v3.json`), making re-import trivial. The 4 credentials must be recreated anyway (n8n encrypts credentials with a per-instance key — a VHD-imported install loses the key and breaks them). The OS is throwaway state.
- **IRIS fresh redeploy + Postgres dump/restore** chosen because: the docker-compose pattern is reproducible, IRIS is portable across hosts, and `pg_dump`/restore is a well-defined operation that preserves all meaningful state (cases, alerts, evidence, customer/severity config). VHD import would drag VMware-specific drivers and a heavier blast radius.

**Splunk Developer License application in parallel.** Submit at dev.splunk.com on day 1 of execution. Typical approval ~3–7 business days. If approved before the new install's trial expires (~60 days from install), apply the dev license to the running Azure Splunk — long-term-stable outcome (10 GB/day, full features, no expiry). If denied or delayed, evaluate fallback paths: serial trial reinstalls (acceptable for lab) or Splunk Cloud Free.

**Aggressive decommission:** Verify each Azure VM end-to-end, then archive its local VMDK to external SSD and delete it from the VMware library — same day. No 30-day hold. Primary driver is the user's blocking C: drive constraint; the external-SSD archive provides the rollback floor.

Rejected alternatives:

- **Lift-and-shift VMware disks via VHD import** (any VM). Reasons given per-VM above; common theme is brittle state (Splunk trial expiry, n8n encryption key, VMware drivers) versus the cleanness of standing each stack up from scratch.
- **Mixed approach** (e.g., n8n fresh + IRIS lift-and-shift). Adds complexity for marginal benefit; brainstorming concluded both docker-compose stacks redeploy cleanly enough that the consistency of "all fresh" wins.
- **Azure Bastion / no public IPs.** Cost-disqualified on a Trial subscription.
- **Bastion-host pattern via n8n** (only one Linux VM publicly accessible). Operationally cleaner but adds friction for admin tasks; deferred as a possible post-P2 hardening pass.
- **New resource group / new VNet peered with Phase 1.** Cleaner cost separation but introduces VNet peering complexity for a 4-VM lab; reuse wins on simplicity.
- **30-day archive hold before delete.** Conservative but conflicts with the "C: drive recovery is the primary driver" priority.

## Design

### 1. Per-VM specifications

| VM | Size | OS | Role | Services |
|---|---|---|---|---|
| `vm-soc-v2-splunk` | `Standard_D4s_v3` (4 vCPU, 16 GiB) | Ubuntu Server 24.04 LTS | SIEM | Splunk Enterprise 10.2.2 (fresh install, new 60-day trial clock), Sysmon TA v5.0.0, Windows TA v10.0.1 |
| `vm-soc-v2-n8n` | `Standard_D2s_v3` (2 vCPU, 8 GiB) | Ubuntu Server 24.04 LTS | SOAR | n8n via docker-compose (SOC Triage v3 workflow) |
| `vm-soc-v2-iris` | `Standard_D2s_v3` (2 vCPU, 8 GiB) | Ubuntu Server 24.04 LTS | Case management | DFIR-IRIS 2.4.22 via docker-compose |

**Sizing rationale:** Splunk gets `D4s_v3` per the user's stated VM-sizing preference (non-B-series, 16 GiB headroom). n8n and IRIS get `D2s_v3` because they're lightweight docker-compose workloads that don't justify 16 GiB. Total new vCPUs in Central US = 8 (on top of Phase 1's 4 = 12 in the subscription).

**Auto-shutdown:** All 3 VMs configured with daily auto-shutdown to conserve trial credits. Default schedule: 11 PM local; user-adjustable during provisioning.

**Quota pre-flight:** Central US `Standard DSv3 Family vCPUs` quota must accommodate +8 vCPUs. Phase 1 hit a quota wall in East US that forced the Central US move; same risk applies here. Pre-flight check via Azure portal → Subscription → Usage + quotas. Quota-increase request as needed.

**Fallback sizing if quota blocks D4s_v3:** Splunk drops to `D2s_v3` (8 GiB — Splunk runs but tighter; close monitoring on first ingestion). n8n/IRIS already at minimum acceptable size.

### 2. Network architecture

**Reuse Phase 1's existing resource group + VNet + subnet in Central US.** Exact names need to be read off the Azure portal during plan execution; handoff doc only names the abandoned East US RG (`rg-soc-v2-azure-east-us`) and the unmoved Log Analytics workspace (`law-soc-v2-azure`).

**Per-VM public IP:** Each Linux VM gets a public IP. NSG rules restrict inbound to the user's home IP (discovered at plan time) for SSH + each service's web UI. Intra-VNet traffic uses private IPs only.

**NSG inbound ruleset:**

| Source | Destination | Port | Protocol | Purpose |
|---|---|---|---|---|
| `<user home IP>` | All 3 Linux VMs | 22 | TCP | SSH admin access |
| `<user home IP>` | `vm-soc-v2-splunk` | 8000 | TCP | Splunk Web UI |
| `<user home IP>` | `vm-soc-v2-n8n` | 5678 | TCP | n8n Web UI |
| `<user home IP>` | `vm-soc-v2-iris` | 443 | TCP | IRIS Web UI |
| `vm-soc-v2-win` (private) | `vm-soc-v2-splunk` | 9997 | TCP | Sysmon UF → Splunk receiver |
| `vm-soc-v2-splunk` (private) | `vm-soc-v2-n8n` | 5678 | TCP | Splunk saved-search webhook → n8n |
| `vm-soc-v2-n8n` (private) | `vm-soc-v2-iris` | 443 | TCP | n8n → IRIS REST API |

**NSG outbound:** Default-allow-internet remains for `vm-soc-v2-n8n` (Claude API, VT, AbuseIPDB) and `vm-soc-v2-splunk` (apps, add-ons, Dev License activation). `vm-soc-v2-iris` needs outbound during build (docker image pulls, package updates) and for any future updates; default-allow during build, optionally restrict outbound to package mirrors only post-build if hardening is desired.

**Default deny on everything else.** All rules added via Azure portal.

### 3. State migration

| VM | What state lives in v1 | How it moves to Azure |
|---|---|---|
| Splunk | License (Enterprise Trial, expires Jun 24); 2 saved searches; 2 add-ons; `mydfir-project` index data (skip); admin user `mydfir`; MCP service user `mcpuser`; Sysmon UF outputs config (lives on `vm-soc-v2-win`, not Splunk) | Fresh license (new trial + Dev License application). Saved searches re-created from `vault/architecture/components/splunk.md` definitions. Add-ons re-installed from Splunkbase, version-pinned. Index recreated empty. Users recreated from secrets file. UF outputs reconfigured on `vm-soc-v2-win` (Azure side). |
| n8n | Workflow JSON; 4 credentials; pinned webhook test data | Workflow JSON re-imported from `JSON/SOC-Triage-v3.json` (already in git). Credentials recreated from the gitignored `SOC-Automation-Project.md` secrets file. Test data optionally re-pinned. |
| IRIS | Postgres database (cases, alerts, evidence, customer/severity config); API keys; SSL cert | `pg_dump` → scp → restore. API keys regenerated post-restore (verify during plan whether existing keys survive a Postgres restore or need regen). SSL cert regenerated (Azure VM has a different hostname). |

### 4. Migration sequencing

Strict order — n8n and IRIS depend on a working Splunk source for end-to-end verification.

1. **Pre-flight** (no VM work):
   - Submit Splunk Developer License application at dev.splunk.com.
   - Run vCPU quota check in Azure portal; request increase if needed.
   - Read & record Phase 1's existing resource group name, VNet name, subnet CIDR, and `vm-soc-v2-win`'s private IP.
   - Cherry-pick `SOC-Automation-Project-to-Azure-Port.md` from `v3-microsoft-native` onto `v2-azure`.
   - Source the user's current home IP for NSG rule construction.

2. **VM 1 — `vm-soc-v2-splunk`:**
   - Provision via portal (size, OS, public IP with NSG rules).
   - Install Splunk Enterprise 10.2.2; configure boot-start.
   - Install `Splunk_TA_microsoft_sysmon` v5.0.0 and `Splunk_TA_windows` v10.0.1.
   - Create `mydfir-project` index.
   - Recreate `mydfir` admin user from secrets.
   - Re-create 2 saved searches (T1059.001 enabled with webhook placeholder URL; brute-force disabled).
   - SSH to `vm-soc-v2-win`; update Sysmon UF `outputs.conf` to point at the new Splunk's private IP:9997. Restart UF.
   - **Verify VM 1:** Fire ATH Test 15 from `vm-soc-v2-win` → confirm event lands in `mydfir-project`. Saved-search webhook will fail (n8n doesn't exist yet) — expected.

3. **VM 2 — `vm-soc-v2-n8n`:**
   - Provision via portal.
   - Install docker + docker-compose.
   - Stand up n8n via docker-compose.
   - Import `JSON/SOC-Triage-v3.json` workflow.
   - Recreate 4 credentials from secrets file.
   - Update Splunk's T1059.001 saved-search webhook URL to the n8n endpoint.
   - **Verify VM 2:** Fire ATH Test 15 → confirm Splunk → n8n webhook fires, Claude triage runs. IRIS step will fail (IRIS doesn't exist yet) — expected.

4. **VM 3 — `vm-soc-v2-iris`:**
   - Provision via portal.
   - Install docker + docker-compose.
   - Stand up IRIS via docker-compose (pin Postgres image to v1's major version).
   - `pg_dump` from local IRIS → scp to Azure VM → restore.
   - Regenerate API keys if required; otherwise reuse from secrets.
   - Update n8n's IRIS credential to point at new IRIS URL + (potentially new) API key.
   - **Verify VM 3 (end-to-end):** Fire ATH Test 15 → confirm full pipeline produces an alert in IRIS-in-Azure. Capture end-to-end latency.

5. **Decommission (per-VM, in migration order):**
   - For each local VM (Splunk → n8n → IRIS → Win10), after its Azure equivalent passes the relevant verification gate:
     - Power off VM in VMware.
     - Export VMDK to external SSD (per-VM folder).
     - Verify SSD copy integrity (size match or sha256).
     - Delete VM from VMware library.
     - Confirm C: drive space recovered (record before/after).
   - Win10 endpoint goes last; it was already replaced functionally in Phase 1 but kept as safety net.

### 5. Verification

**Per-VM gate (intermediate verification):**
- VM 1: ATH Test 15 fires → event in Splunk's `mydfir-project` index.
- VM 2: Splunk saved-search webhook fires → n8n workflow execution shows up in Executions tab.
- VM 3: Full pipeline → alert visible in IRIS UI.

**End-to-end success criterion (Phase 2 ships when this passes):**

> From `vm-soc-v2-win`, run Atomic Red Team T1059.001 Test 15. Within the pipeline's normal cadence (Splunk saved search runs every 5 minutes), an alert appears in `vm-soc-v2-iris` with the expected Claude triage output, VirusTotal + AbuseIPDB enrichment results, and a link back to the Splunk search.

**Latency capture:** Time-stamp each pipeline step (ATH fire time, Splunk index time, Splunk saved-search fire time, n8n workflow execution time, IRIS alert creation time). Record in a comparison table alongside v1's local-VMware baseline.

### 6. Rollback

**Per-VM rollback during migration:** Each local VM remains running until its Azure equivalent passes verification. Worst case if an Azure VM fails — abandon the Azure VM, keep using local. No data is lost because the Azure side has no source-of-truth state yet (Splunk index empty in Azure; IRIS Postgres state was copied, not moved).

**Post-decommission rollback (after local VMs deleted):** External-SSD VMDK archive → re-import to VMware (slow but possible). Archive is kept indefinitely (no expiration); space permits since SSD is dedicated.

**Identified risks and mitigations:**

| Risk | Mitigation |
|---|---|
| Central US vCPU quota blocks D4s_v3 | Pre-flight quota check; quota-increase request; fallback to D2s_v3 for Splunk |
| Splunk Dev License denied or delayed | Apply early; if denied, fallback paths: serial Trial reinstalls (lab-acceptable), Splunk Cloud Free |
| `vm-soc-v2-win` outage during Splunk UF re-point | Keep local Splunk running; configure UF to dual-output during cutover; revert if Azure Splunk fails to index |
| IRIS Postgres version mismatch on restore | Pin Postgres docker image to the same major version as v1; verify with `psql --version` before restore |
| Source-IP change (home IP rotates) | Break-glass: update NSG rules from Azure portal; ensure at least one path doesn't lock the user out (portal access always available with Azure account auth) |
| Loss of saved-search webhook config knowledge | Component docs (`vault/architecture/components/splunk.md`) capture the canonical saved-search definitions; re-create from those |
| Sub-project doc lives on different branch | Cherry-pick handoff doc to `v2-azure` as pre-flight step (§4 step 1) |

## Open questions resolved during brainstorming

| Original handoff Q | Resolution |
|---|---|
| Q1: Win10 endpoint status | Still exists locally; in scope for decommission (same treatment as Linux VMs). |
| Q2: Splunk license | Enterprise Trial, 500 MB/day, expires **Jun 24, 2026** (~32 days from spec date). Drives the fresh-install decision. |
| Q3: Branch strategy | Resolved by branch restructure 2026-05-23 (Task 0 before brainstorming): old `v2-azure` → `v3-microsoft-native`; fresh `v2-azure` from `main` for this work. |
| Q4: Naming convention | `vm-soc-v2-splunk` / `vm-soc-v2-n8n` / `vm-soc-v2-iris` (parallel to existing `vm-soc-v2-win`). |
| Q5: vCPU quota check | Folded into pre-flight (§4 step 1). |
| Q6: Splunk index data preservation | Skip historical migration; fresh-start the index. Selective re-ingest deferred to post-P2 if needed. |

## References

- Project-root handoff doc: `SOC-Automation-Project-to-Azure-Port.md` (currently on `v3-microsoft-native`; cherry-pick to `v2-azure` as pre-flight).
- [[../../architecture/components/splunk]] — v1 Splunk configuration (saved searches, add-ons, indexes, MCP user).
- [[../../architecture/components/n8n]] — v1 n8n configuration.
- [[../../architecture/components/dfir-iris]] — v1 IRIS configuration.
- [[../../architecture/current-state]] — v1 architecture diagram.
- Deferred Phase 3 artifacts (on `v3-microsoft-native` branch): `v2-azure/specs/2026-05-23-phase-2-soar-logic-app-design.md`, `v2-azure/plans/2026-05-23-phase-2-soar-logic-app-plan.md`.
