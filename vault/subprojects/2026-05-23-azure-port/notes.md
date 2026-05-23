---
status: active
updated: 2026-05-23
sub_project: P2 (Azure Port)
related: [[spec]], [[README]]
---

# P2 — Working notes

Append entries as work progresses. Newest at the top.

## Phase 1 resource discovery (Task 3) — 2026-05-23

| Resource | Name / Value | Notes |
|---|---|---|
| Resource group | `rg-soc-v2-azure-central-us` | Central US; sibling `NetworkWatcherRG` is the Azure-default Network Watcher RG, not used by us |
| VNet | `vm-soc-v2-win-vnet` | Overall address space TBD — read off VNet Overview blade at Task 6 if needed. Subnet at 10.0.0.0/24; all new P2 VMs reuse the existing `default` subnet so address-space detail is informational only. |
| Subnet | `default` | CIDR: `10.0.0.0/24` (250 available IPs; only 1 used by `vm-soc-v2-win` at .4) |
| Existing NSG | `vm-soc-v2-win-nsg` | **Per-NIC attachment** (subnet shows `Security group: -`). New VMs will follow same pattern → one NSG per new VM, attached to its NIC. Matches plan Task 7 Step 1 Option B. |
| `vm-soc-v2-win` | Private IP: `10.0.0.4` | Size: `Standard D4as v7` (Dasv7 family, 4 vCPU / 16 GiB, Threads/core: 2); OS: Windows; Status: **Stopped (deallocated)** — start before Task 12 Sysmon UF re-point + Task 19 verify; Public IP: `52.242.192.109`; NIC: `vm-soc-v2-win858`; Created: 2026-05-22 10:16 PM UTC |
| Log Analytics workspace | `law-soc-v2-azure` | Workspace ID: `<workspace-id>`; Pricing: Pay-as-you-go; Active; SecurityInsights solution attached; Phase 1 workspace — not touched by P2 |
| Home IP for NSG rules | `x.x.x.x` | Source-IP-restricted access (single /32). Per spec §6, if home IP rotates we update NSG rules from the portal. |

## vCPU quota status (Task 2) — 2026-05-23

| Family | Region | Limit | Current usage | Available | Need +8? |
|---|---|---|---|---|---|
| Total Regional vCPUs | Central US | **20** (raised from 10) | 4 | 16 | yes — covered |
| Standard Dasv7 Family vCPUs | Central US | 10 | 4 (vm-soc-v2-win) | 6 | n/a (new VMs are DSv3) |
| Standard DSv3 Family vCPUs | Central US | TBD | 0 | unknown | likely covered (Trial default ~10); if blocked at Task 6, file family-specific increase. |

**Quota increase 2026-05-23:** filed 3:48 PM (Total Regional vCPUs Central US, 10 → 20); auto-approved 3:50 PM (~2 min). Today's experience: small Trial-tier requests auto-approve fast, so deferring DSv3-family check to Task 6 is low-risk.

## Splunk Dev License application (Task 1) — 2026-05-23

- Submitted: **2026-05-23 3:36 PM** at https://dev.splunk.com/enterprise/
- Splunk response page indicated **3–5 business day** approval window (Splunk's stated SLA, not the plan's 7-day rule of thumb).
- Confirmation email: not yet received at submission — check inbox within 2 hours; if still missing tomorrow morning, may need to re-submit or contact Splunk support.
- Follow-up reminder: **2026-06-03** (7 business days out, conservative ceiling on Splunk's 3–5 day SLA).
- Status: `pending`.

## Things to track during build

- `vm-soc-v2-win` is currently Stopped (deallocated). Auto-shutdown is doing its job. Will need to start it before Task 12 (Sysmon UF re-point) and Task 19 end-to-end verify.
- All new VMs will get per-NIC NSGs named `vm-soc-v2-<role>-nsg` (mirrors Phase 1 pattern).
- VNet `vm-soc-v2-win-vnet` overall address-space value: gather opportunistically if it surfaces in any wizard tab during Task 6; not blocking.
- DSv3 family quota: confirm visibility at Task 6 wizard size-picker; if "Insufficient quota" warning shows, file increase to 12 (current expected limit 10, need 8 — but file 12 with same headroom rationale we used today).
