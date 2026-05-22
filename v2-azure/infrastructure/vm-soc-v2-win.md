# vm-soc-v2-win — Windows endpoint VM spec

The Azure-native Windows endpoint for v2-Azure Phase 1. Runs Sysmon + Azure Monitor Agent (AMA) and is the target for Atomic Red Team test executions that fire the ported T1059.001 KQL detection in Sentinel.

**Equivalent v1 component:** the on-prem VMware Workstation Windows 10 VM that runs Sysmon + Splunk Universal Forwarder.

## Resource details

| Field | Value |
|---|---|
| Subscription | Azure subscription 1 (Free Trial → PAYG on ~2026-06-21) |
| Resource group | `rg-soc-v2-azure-central-us` |
| Region | Central US |
| VM name | `vm-soc-v2-win` |
| Image | Windows Server 2025 Datacenter — x64 Gen2 (NOT Azure Edition) |
| Size | `Standard_D4as_v7` (4 vCPU / 16 GiB RAM, AMD EPYC, Premium SSD support) |
| OS disk | Premium SSD LRS, delete-with-VM enabled |
| Disk controller | NVMe |
| Authentication | Local administrator (password) |
| Username | see [`../secrets.local.md`](../secrets.local.md) (gitignored) |

**Why Standard_D4as_v7:** Direct successor in availability terms for the originally targeted D4s_v5 (which was zero-quota'd in this Free Trial across all candidate regions). AMD EPYC chosen over Intel for ~15–20% cost saving with no measurable difference for Sysmon/AMA event-forwarding workload. Non-`d` variant (no local NVMe temp disk) because event forwarding doesn't benefit from local scratch I/O.

**Why Windows Server 2025 Datacenter (NOT Azure Edition):** Broader VM-size compatibility, hotpatching/SDN features of Azure Edition not needed for this lab. Standard Datacenter avoids the Azure Edition licensing-coupling complications.

## Networking

| Field | Value |
|---|---|
| Virtual network | `vm-soc-v2-win-vnet` (auto-created with VM) |
| Subnet | `default` (10.0.0.0/24) |
| Public IP | `vm-soc-v2-win-ip` (dynamic; recorded in [`../secrets.local.md`](../secrets.local.md)) |
| NSG | `vm-soc-v2-win-nsg` (custom, IP-restricted) |
| Accelerated networking | Off (Microsoft.Network resource provider not registered; non-blocking for AMA) |
| Public IP + NIC cleanup | Delete-with-VM enabled (avoid orphan resource billing) |

### NSG inbound rules

| Priority | Name | Source | Destination | Port | Protocol | Action |
|---|---|---|---|---|---|---|
| 1010 | `Allow-RDP-MyIP` | Single source IP (operator's home public IP, see secrets file) | Any | 3389 | TCP | Allow |
| (implicit) | Default deny-all | * | Any | * | * | Deny |

**Design intent:** RDP is the only inbound path, and it is restricted to a single operator source IP. Public Inbound Ports on the Basics tab was deliberately set to "None" so the only rule on the NSG is the IP-restricted custom rule — no exposed-to-internet RDP window during or after provisioning.

**Operational note:** If the operator's home public IP rotates (ISP renewal, modem reboot), the rule must be re-edited with the current IP before RDP works again.

## Management

| Field | Value |
|---|---|
| Auto-shutdown | Enabled, 23:59 UTC (19:59 EDT), email notification to operator |
| Backup | Disabled (lab VM, no recoverability requirement) |
| Site Recovery | Disabled |
| Microsoft Defender for Cloud | Basic (free tier) |
| Patch orchestration | OS-orchestrated (Hotpatch not available on standard Datacenter image) |
| Entra ID login | Disabled (local admin only) |

**Auto-shutdown is the cost-control mechanism.** Even at D4as_v7 ($267.18/mo if run 24/7), deallocation at the daily shutdown gives ~$89/mo for an 8-hour-per-weekday usage pattern. Well within the remaining Free Trial credit window.

## Monitoring

| Field | Value |
|---|---|
| Boot diagnostics | On (managed storage) |
| OS guest diagnostics | Off (using AMA via DCR instead — see Phase 1 plan) |
| Alerts | Off (will configure incident-level alerts in Sentinel rather than VM-level metrics) |

## Cost (estimated, Central US, May 2026)

| Component | Cost (24/7) | Cost (8h/day weekdays) |
|---|---|---|
| Standard_D4as_v7 compute | $267.18/mo | ~$89/mo |
| Premium SSD LRS (default OS disk size) | ~$10/mo | ~$10/mo (storage bills on allocation, not runtime) |
| Public IP (dynamic) | ~$3.65/mo | ~$3.65/mo |
| **Total** | **~$281/mo** | **~$103/mo** |

Free Trial $200 credit covers ~70 days at the 24/7 rate, ~6 months at the auto-shutdown rate. Trial converts to PAYG on ~2026-06-21; at that point this VM continues billing at the same rates against the PAYG card on file unless deallocated or resized.

## Provisioning history

- **2026-05-22 (East US attempt):** Blocked by Free Trial vCPU quota — every D-series and B-series SKU returned `NotAvailableForSubscription` in East US. Documented in handoff `HANDOFF-2026-05-22.md`.
- **2026-05-22 (Central US success):** Resource Group + LAW + Sentinel + VM provisioned in Central US. Same operator session, ~25 min total elapsed from teardown to VM deployment kick-off.

## Next configuration steps (Phase 1 continues)

1. Reset administrator password via Azure portal (Help → Reset password) — replaces initial provisioning password.
2. RDP login validation from operator IP.
3. Install Sysmon 15.x with SwiftOnSecurity configuration (same config XML as v1 to preserve detection parity).
4. Create Data Collection Rule (DCR) targeting Windows Security/System/Application + Sysmon channels, scoped to this VM.
5. Confirm events visible in the `Event` / `SecurityEvent` tables in the `law-soc-v2-azure` workspace via KQL.
6. Port `vault/detections/t1059-001-powershell-encoded.md` (Splunk SPL) to KQL; save as Analytics Rule in Sentinel.
7. Fire Atomic Red Team T1059.001 atomic on this VM → confirm Sentinel incident lands.

## Credentials & live connection info

**Not in this file.** See [`../secrets.local.md`](../secrets.local.md) — gitignored via the `*.local.md` pattern in repo root `.gitignore`.
