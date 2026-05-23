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
- **Received: 2026-05-23 5:01 PM** (~90 min turnaround — far faster than Splunk's stated 3–5 business day SLA).
- License file: `Splunk.License` (2 KB attachment from `noreply@splunk.com`).
- Product: **Splunk Developer Personal License** (NOT FOR RESALE).
- Size: **10 GB/day** indexing volume.
- Expiration: **2026-11-19** 11:59 PM (6 months).
- Renewal: same form at https://dev.splunk.com/enterprise/, eligible within 10 days before expiry.
- Status: **received** — apply during Task 8 (post fresh install) via Splunk UI → Settings → Licensing → Change license group → Enterprise → install license XML. Trial-clock fallback no longer needed; Developer License is the long-term-stable target as planned.

**Plan impact:** The fresh-install rationale ("reset the trial clock") is now incidental — the install still uses Trial briefly before swapping to Developer. Spec §"Approach" Splunk paragraph is now historical context, not active constraint. Update spec only if it becomes confusing later; not worth a churn commit today.

## VMs provisioned

| VM | Public IP | Private IP | Size | NIC name | Provisioned (Eastern) |
|---|---|---|---|---|---|
| vm-soc-v2-splunk | `20.236.193.253` | `10.0.0.5` | Standard_D4s_v3 | `vm-soc-v2-splunk843` | 2026-05-23 4:29 PM |

**SSH key:** `C:\Users\Owner\.ssh\vm-soc-v2-linux-key.pem` (RSA, generated during Task 6, will be reused for n8n + IRIS VMs).

**OS disk:** `vm-soc-v2-splunk_OsDisk_1_68042d8f0c8841f0ba830dbbb9711cdc` (Premium SSD, 64 GiB, delete-with-VM enabled).

**Image baseline:** Canonical `ubuntu-24_04-lts/server`, Gen2, Trusted launch (Secure boot + vTPM, Integrity monitoring off).

## Task 8 — Splunk install complete (2026-05-23 5:26 PM Eastern)

- **Version installed:** Splunk Enterprise **10.4.0** (build `f798d4d49089`). Plan called for 10.2.2 but the live downloads page only offered 10.4.0 today — acceptable per "any 10.x stable" stance during planning. Pin **10.4.0** as the runbook baseline.
- **Download URL pinned:** `https://download.splunk.com/products/splunk/releases/10.4.0/linux/splunk-10.4.0-f798d4d49089-linux-amd64.deb`
- **Splunk user:** runs as `splunk:splunk` via systemd unit `Splunkd.service`. Use `sudo systemctl restart Splunkd` for service lifecycle. CLI commands (e.g. `splunk add user`) hit the management API on 8089 with `-auth admin:<pw>` and are user-context-agnostic.
- **Boot-start:** enabled via systemd (`/etc/systemd/system/Splunkd.service`).
- **mydfir admin user:** created (password reused from v1 secrets convention).
- **Receiver port 9997:** listening on `0.0.0.0:9997` for forwarder traffic.
- **Splunk Web:** `http://20.236.193.253:8000` (NSG-restricted to home IP).
- **Management API:** `https://10.0.0.5:8089` (internal); not exposed to internet.

### License status
- **Active group:** Enterprise (was Trial during initial start; swapped automatically when the Developer License was added — no manual `splunk edit licenser-groups` needed).
- **Stack:** `enterprise`.
- **License applied:** "Splunk Developer Personal License DO NOT DISTRIBUTE" — quota 10 GB/day, expires 2026-11-19 23:59:59 UTC.
- **Trial license:** auto-deactivated; Embedded/Free/Lite/Forwarder groups inactive (default).

### Gotchas discovered during install (worth carrying forward)
- **Splunk 10.4 hard-deprecates run-as-root.** Running `sudo /opt/splunk/bin/splunk start ...` aborts immediately with "Running Splunk Enterprise as root is deprecated… To run as root, use the --run-as-root option." Use `sudo -u splunk /opt/splunk/bin/splunk ...` for first-start lifecycle commands.
- **dpkg postinst leaves bundled libs root-owned.** After `dpkg -i splunk.deb`, many shared libs under `/opt/splunk/opt/`, `/opt/splunk/lib/` are root-owned even though `/opt/splunk/bin/splunk` itself is splunk-owned. Before first start, run `sudo chown -R splunk:splunk /opt/splunk`. Otherwise the `splunk` user can't write log files at init time.
- **CLI noun rename:** `splunk show licenser-localslave` (Splunk 9.x and earlier) is no longer valid in 10.4. Use `splunk list licenser-groups` for active-group state and `splunk list licenses` for installed licenses.
- **Splunk Web takes ~10–15 sec to bind 0.0.0.0:8000 after splunkd starts.** A quick `ss -tlnp` immediately post-restart may miss it. Sleep before checking, or grep for the actual splunkd process child handle.

### Recovery / break-glass
- Bootstrap admin password (24-char, throwaway): see `SOC-Automation-Project.md` § Azure VMs (P2). Use `mydfir` for everything; `admin` is only for break-glass if `mydfir` is ever locked out.

## Things to track during build

- `vm-soc-v2-win` is currently Stopped (deallocated). Auto-shutdown is doing its job. Will need to start it before Task 12 (Sysmon UF re-point) and Task 19 end-to-end verify.
- All new VMs will get per-NIC NSGs named `vm-soc-v2-<role>-nsg` (mirrors Phase 1 pattern).
- VNet `vm-soc-v2-win-vnet` overall address-space value: gather opportunistically if it surfaces in any wizard tab during Task 6; not blocking.
- DSv3 family quota: confirm visibility at Task 6 wizard size-picker; if "Insufficient quota" warning shows, file increase to 12 (current expected limit 10, need 8 — but file 12 with same headroom rationale we used today).
