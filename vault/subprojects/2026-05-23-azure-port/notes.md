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
| vm-soc-v2-n8n | `52.173.105.92` | `10.0.0.6` | Standard_D2s_v3 | `vm-soc-v2-n8n859` | 2026-05-25 |
| vm-soc-v2-iris | `20.29.76.25` | `10.0.0.7` | Standard_D2s_v3 | `vm-soc-v2-iris706` | 2026-05-25 |

**SSH key:** `C:\Users\Owner\.ssh\vm-soc-v2-linux-key.pem` (RSA, generated during Task 6, reused across all three P2 Linux VMs — splunk, n8n, iris).

**DSv3 quota status:** confirmed adequate. Final usage across all 3 P2 VMs: 8 vCPUs (Splunk D4s_v3 + n8n D2s_v3 + iris D2s_v3) within Trial DSv3 family limit. No quota increases needed for P2.

## Plan re-order 2026-05-25

Task 17 (IRIS VM provision) pulled forward ahead of Task 15 completion because the `n8n-nodes-dfir-iris` community node's credential validation made it cleaner to wire IRIS credentials against a real Azure IRIS host rather than the Option-B placeholder against v1's unreachable `192.168.129.133`. Plan Task 19's `pg_dump`/restore step is being **skipped** — v1 IRIS is itself a 2026-05-12 fresh rebuild with minimal historical alerts (max alert #64 per 2026-05-19 demo log), so the migration cost outweighs the benefit. Azure IRIS becomes a fresh install. Tasks 17 → 18 → resume 15 → 16 → simplified 19 (just e2e verify, no migration).

## Task 14 — n8n install complete (2026-05-25)

- **n8n version installed: 2.21.7** (image digest `sha256:9f1f8e4c093c9924338bd168e3f813f746041d13b337753af0dbdd329e7b50f7`, Docker Hardened Image released 2025-05-06, alpine-3.22 + node 24-dev). Pinned in compose file at the user's request: today's `:latest` becomes the canonical baseline for future rebuilds.
- **Compose file:** `/home/azureuser/docker-compose.yml` on `vm-soc-v2-n8n`. Uses bind-mount `~/.n8n:/home/node/.n8n` for state persistence; container runs as UID 1000 (= azureuser host UID), so no permission gotchas.
- **Auth pattern:** **No basic-auth env vars** — used n8n native user management (owner account at `owner@example.com` / `[REDACTED-LAB-PW]`, matching v1 convention). Deviates from plan Task 14 Step 3's `N8N_BASIC_AUTH_*` prescription, which was incorrect — `N8N_BASIC_AUTH_*` is deprecated since n8n 1.0+ and v1 actually used native user management too.
- **Required env vars set:** `N8N_SECURE_COOKIE=false` (honors 2026-05-12 gotcha for LAN HTTP access), `N8N_HOST=52.173.105.92`, `N8N_PROTOCOL=http`, `WEBHOOK_URL=http://52.173.105.92:5678/`, `GENERIC_TIMEZONE=America/New_York`.

### Gotchas discovered during n8n install (worth carrying forward)

- **n8n 2.21.7 logs a Python 3 missing warning at startup.** "Failed to start Python task runner in internal mode... Python 3 is missing from this system." Non-blocking — the JS Task Runner registers fine and our v3 workflow uses only JavaScript code nodes. Install python3 + restart container only if a future workflow needs Python code nodes.
- **n8n's setup wizard SHOWS as `userManagement.showSetupOnFirstLoad: true` in `/rest/settings` on a fresh install.** Confirmed via REST API query before browser handoff. Once owner account is created, this flips false and the wizard never reappears.
- **The `version: '3.8'` line in docker-compose.yml is obsolete with Compose v5.1.4** — generates a warning but is ignored. Safe to omit entirely in future compose files.
- **n8n's frontend serves at SPA-routed paths (`/setup`, `/workflow`, etc.), not at root `/`.** A `curl http://localhost:5678/` returns 404 — that's expected; browsers follow the SPA's JS routing. Use `/healthz` for liveness probes.

## Task 15 — DFIR IRIS community node integration (2026-05-25)

Used the community package `n8n-nodes-dfir-iris` v2.0.3 by `barn4k` (https://github.com/barn4k/n8n-nodes-dfir-iris). The package is well-designed for v2.4.x IRIS — supports the full alert/case/IOC API surface against IRIS API v2.0.4.

- **Note:** v3 workflow's "Create Iris Alert" was an `n8n-nodes-base.httpRequest` with `nodeCredentialType: dfirIrisApi` — referencing a custom credential type that was hand-registered in v1's n8n install (never an npm package). On the Azure n8n, that custom credential type is absent, so the v3 JSON imports with a broken Iris node ("Install this node to use it").
- **Chosen resolution:** install the community node + replace the broken HTTP request node with the package's purpose-built DFIR IRIS node (Resource=Alert, Operation=Create). Deviates from v3 JSON canonically, but more reproducible (anyone cloning the repo can install one npm package; no need to hunt for custom credential files).
- **Alternative considered + rejected:** switch the node to generic HTTP Header Auth with `Authorization: Bearer <key>`. Functionally identical but loses the structured DFIR-IRIS operation UI.

## Task 18 — IRIS install complete (2026-05-25)

- **IRIS version installed:** dfir-iris/iris-web @ tag `v2.4.22` (commit `f75e56fb` — matches 2026-05-12 v1 rebuild commit exactly).
- **Compose pulled all 4 images successfully:** `iriswebapp_db:v2.4.22`, `iriswebapp_app:v2.4.22`, `iriswebapp_nginx:v2.4.22`, `rabbitmq:3-management-alpine`.
- **5 containers running healthy:** db, rabbitmq, app, nginx (with health check), worker. Worker connects to rabbitmq + celery ready in ~15 sec post-start.
- **Total startup time: ~30 sec** from `docker compose up -d` to "IRIS IS READY on port 443" log line.
- **HTTPS on 443 bound** via docker-proxy on host. Web UI at `https://20.29.76.25` (self-signed cert). API at `https://10.0.0.7/api/*` for n8n.
- **Admin login:** `administrator` / `[REDACTED-LAB-PW]` (via `IRIS_ADM_PASSWORD` in .env).
- **API key:** captured in secrets file (set via `IRIS_ADM_API_KEY` in .env — no log-scraping needed).
- **`/api/ping` returns `{"status":"success","message":"pong"}` with Bearer token auth — confirmed end-to-end.**

### Gotchas discovered + updates to v1-era guidance (worth carrying forward)

- **`depends_on:` commenting workaround from 2026-04-29 / 2026-05-12 is NO LONGER NEEDED with modern `docker compose v5.1.4` (plugin).** v1 used legacy `docker-compose 1.29.2` which had ordering / KeyError issues; the modern plugin handles short-form `depends_on` cleanly. Skipped the awk pass and confirmed all 5 containers came up in correct order on first try. Update the runbook to note: workaround only required if falling back to legacy docker-compose.
- **`IRIS_ADM_API_KEY` can be set explicitly in `.env`** — no need to bring IRIS up, scrape logs, and regenerate via UI. The .env.model documents this as optional (commented out by default); uncommenting and setting it gives a known API key from first start. Much cleaner for automation / reproducible rebuilds than the v1 pattern of log-scraping.
- **`.env.model → .env` step is still required** (v1 gotcha persists in v2.4.22) — the repo doesn't ship a `.env`, only `.env.model`. Postgres won't start without the file existing.
- **Benign db log warning during first start:** `"duplicate key value violates unique constraint groups_group_name_key" Key (group_name)=(Analysts) already exists`. IRIS's init script tries to insert default groups and catches the conflict downstream. Harmless. Don't chase it.
- **All 4 IRIS images pulled in parallel in <2 minutes** on Azure D2s_v3 — significantly faster than v1's local VMware experience (15-20 min on USB HDD storage per 2026-05-08 notes). Premium SSD + Azure container registry caching pays off.

### IRIS credential update for n8n (next user step)

The DFIR-IRIS credential created earlier with v1 placeholder host needs updating:
- **Host:** `192.168.129.133` → `10.0.0.7` (vm-soc-v2-iris private IP — n8n reaches IRIS over VNet)
- **Token:** v1's `<redacted-key-prefix>...` → new `***REMOVED-IRIS-ADMIN-API-KEY (rotate on next IRIS start)***` (set via IRIS_ADM_API_KEY)
- **Use HTTP:** OFF (still HTTPS)
- **Ignore SSL Issues:** ON (still self-signed)
- **API Version:** 2.0.4 (unchanged)

## Task 15 complete — workflow live (2026-05-25)

- Workflow **SOC Triage v3** activated on `vm-soc-v2-n8n`.
- **Production webhook URL:** `http://52.173.105.92:5678/webhook/db7245f7-8451-4bea-b47d-f6ad35b818cd` (public IP form)
- **Production webhook URL (private IP form — preferred for Splunk→n8n VNet traffic):** `http://10.0.0.6:5678/webhook/db7245f7-8451-4bea-b47d-f6ad35b818cd`
- **GUID `db7245f7-8451-4bea-b47d-f6ad35b818cd` survived JSON import unchanged** — matches the v3-era GUID preserved during 2026-05-12 v1 rebuild specifically so Splunk needed no change.
- 4 credentials wired:
  - **Anthropic account** → Anthropic API node
  - **VirusTotal account** → lookup_file_hash_virustotal HTTP Request Tool
  - **Header Auth account** → enrich_ip_abuseipdb HTTP Request Tool (Name=`Key`)
  - **DFIR IRIS account** → Add new Alert node (community node `n8n-nodes-dfir-iris.dfirIris` v2)
- Updated workflow JSON exported back to `JSON/SOC-Triage-v3.json` and committed.

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

## Task 9 / 10 / 11 — Splunk add-ons, index, saved searches (2026-05-23)

### Task 9 — add-ons installed via Splunk Web "Find More Apps"
- `Splunk_TA_microsoft_sysmon` **5.0.0** (matches plan's pinned version exactly)
- `Splunk_TA_windows` **10.0.1** (matches plan's pinned version exactly)
- Both required Splunk.com credential entry in the UI install flow + a Splunk restart per add-on.

### Task 10 — index `mydfir-project` created
- `splunk add index mydfir-project` (defaults: datatype=event, paths under `/opt/splunk/var/lib/splunk/mydfir-project/`).
- No bucket/retention tuning — Dev License's 10 GB/day cap is the natural ceiling for this lab.

### Task 11 — saved searches via REST API (Splunk mgmt API on https://localhost:8089)
- **`T1059.001 - PowerShell Encoded Command`** — enabled, cron `*/5 * * * *`, owner mydfir/search, SPL identical to vault canonical at [[../../detections/t1059-001-powershell-encoded]] (the regex `(?i)\s-e[ncodedommand]*\s` survived URL-encoding intact). Webhook URL is `http://placeholder-update-in-task-16.invalid:5678/webhook/db7245f7-8451-4bea-b47d-f6ad35b818cd` — `.invalid` TLD ensures fast DNS failure rather than misroute. **Update at Task 16.**
- **`Test-Brute-Force-External-Spoofed`** — disabled, cron `* * * * *`. **SPL is a reconstruction:** the canonical original SPL was not captured in any vault doc; reconstructed approximation is `index=mydfir-project EventCode=4625 | stats count by user, src_ip, host | where count >= 5 | eval src_ip="185.220.101.42"`. Behavior at runtime is unverified (search is disabled). If A1/A2 verification is ever re-run from this Azure Splunk, the SPL may need re-derivation against actual 4625 event structure under `Splunk_TA_windows` 10.0.1's field extractions.

### Splunk REST API gotchas discovered during Task 11
- **`actions = webhook` is the master switch, not `action.webhook = 1`.** A POST with only `action.webhook=1 action.webhook.param.url=...` creates the search but webhook stays inactive. Splunk's REST returns `action.webhook = 0` and the search never fires the action. Fix: POST `actions=webhook` (singular field, value is the action name; multi-action would be comma-separated). Once `actions` includes "webhook", `action.webhook=1` is auto-derived.
- **curl's `-d` does NOT URL-encode; semicolons in field values silently split fields.** A description with text like `"context A; context B"` causes Splunk to reject the second half as an "unsupported argument" (HTTP 400). Fix: use `--data-urlencode 'description=...'` for any free-text field. Already-known pattern for the `search` field; same rule applies to `description`, `alert_subject`, etc. The leading-`search`-keyword REST-API trap captured at [[../../detections/t1059-001-powershell-encoded#saved-search-rest-api-trap]] is a separate but related class — same lesson: be deliberate about what crosses the REST boundary verbatim.
- **The Splunk 10.2.2 `realtime_schedule=False` gotcha still applies in 10.4.** Explicitly setting `realtime_schedule=0` keeps `is_scheduled=1` stable across edits. Without it, the UI's "Real-Time Schedule" radio flips `is_scheduled=0` silently after the next edit.

## Task 12 — Sysmon UF on vm-soc-v2-win → Splunk (2026-05-23)

### Plan gap discovered + handled
Phase 1's spec said Sentinel + AMA + DCR + KQL on vm-soc-v2-win — but **never installed the Splunk Universal Forwarder.** Plan Task 12's "Re-point UF" implicitly assumed UF was there. Added an undocumented pre-step: install Splunk UF 10.4.0 (.msi, `splunkforwarder-10.4.0-f798d4d49089-windows-x64.msi`, same build hash as Splunk Enterprise — Splunk ships them from the same release).

### Final verified state
- **Sysmon 15.20** running, Automatic. Source-of-truth Sysmon channel: `Microsoft-Windows-Sysmon/Operational`.
- **Splunk UF 10.4.0** running, Automatic, **as LocalSystem** (StartName changed via CIM `Invoke-CimMethod`).
- **inputs.conf** at `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf` — single Sysmon stanza with `source=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` and `renderXml=true`. (No Security/Application/System channels — minimal scope for this lab. Add later if needed.)
- **outputs.conf** in same dir, autogenerated by MSI's `RECEIVING_INDEXER=10.0.0.5:9997` parameter.
- **End-to-end verified:** 3,337 events from `vm-soc-v2-win` indexed into `mydfir-project` within ~7 minutes of UF service start. Synthetic `powershell.exe -NoProfile -EncodedCommand <UTF16-base64>` fired at 22:32:43 UTC, indexed in Splunk at 22:32:43.226 UTC (sub-second lag). Saved search `T1059.001 - PowerShell Encoded Command` next cron tick (22:35 UTC) picked it up — resultCount went from 4 → 5. Saved search now firing every 5 min on schedule. Webhook attempts fail against `.invalid` URL by design (Task 16 will swap to the real n8n URL).

### Gotchas captured (carry forward)
- **Splunk UF MSI requires `SPLUNKPASSWORD=` in 10.x silent install.** Without it, install fails. Used `[REDACTED-LAB-PW]` matching the project's `mydfir` convention — UF admin auth is rarely needed (manage via files) but available for break-glass via `splunk` CLI on the Windows side.
- **Splunk UF MSI parameters** that actually mattered: `AGREETOLICENSE=Yes RECEIVING_INDEXER=<ip>:<port> LAUNCHSPLUNK=0 SPLUNKPASSWORD=<pw>`. With `LAUNCHSPLUNK=0`, the service is created but not started — gives you a chance to drop inputs.conf in place before first launch.
- **Default UF service account `NT SERVICE\SplunkForwarder` cannot subscribe to the Sysmon channel** — `errorCode=5` (ERROR_ACCESS_DENIED) in `splunkd.log`. This is the same gotcha captured in the 2026-05-08 D1 rebuild log. **Fix: change service account to `LocalSystem`.**
- **`sc.exe config <svc> obj= LocalSystem password= ""` is fragile under PowerShell argument parsing.** The `=` signs and empty string `""` get interpreted weirdly by PowerShell and `sc.exe` prints its USAGE help instead of executing. **Use CIM instead:**
  ```powershell
  $svc = Get-CimInstance Win32_Service -Filter "Name='SplunkForwarder'"
  Invoke-CimMethod -InputObject $svc -MethodName Change -Arguments @{
    StartName     = "LocalSystem"
    StartPassword = ""
  }
  ```
  PowerShell-native, no shell parsing surprises. `ReturnValue: 0` = success.
- **Run Command in Azure runs scripts as SYSTEM in Session 0 (no desktop).** **Never spawn GUI apps** — `notepad.exe`, `mspaint.exe`, etc. will hang forever waiting for a window that can't exist. They block any subsequent `Out-Null` / `-Wait` clause. If you need a process to fire a Sysmon EventCode=1, use console-only apps (e.g., `Start-Process powershell.exe -ArgumentList ...,-Wait`). Notepad hang requires a VM restart to clear; no portal-side cancel for Run Command.
- **PowerShell `@"..."@` here-strings in Run Command's textbox can break** if even trailing whitespace appears after the opening `@"`. The parser then treats subsequent `[...]` lines as type literals. **Safer pattern: string arrays piped to `Set-Content`:**
  ```powershell
  @('[Stanza]', 'key1 = value', 'key2 = value') | Set-Content -Path $p -Encoding ascii
  ```
- **Splunk UF's own internal helpers (`splunk-regmon`, `splunk-powershell`, `splunk-netmon`, `splunk-admon`) generate Sysmon EventCode=1 events that the UF then forwards to itself (via the indexer).** Not a loop because Splunk filters/dedups, but expect to see UF helpers as the bulk of the index in the first few minutes after service start.

### Anomaly worth follow-up (NOT blocking)
- `Get-Service AzureMonitorAgent` returned NOT INSTALLED on vm-soc-v2-win. Handoff doc + Phase 1 spec say AMA was installed and Sentinel KQL detection was working. Possibilities: (a) AMA installed under a different service name (extension-based AMA shows up as something like `AMAExtHandler`), (b) AMA was uninstalled/orphaned, (c) my service-name guess was wrong. The Sentinel-side data flow may or may not currently be working. **Splunk-side path is independent and works.** Investigate at start of next session if Sentinel/KQL state matters for downstream Phase 3 work.

## Things to track during build

- `vm-soc-v2-win` is currently Stopped (deallocated). Auto-shutdown is doing its job. Will need to start it before Task 12 (Sysmon UF re-point) and Task 19 end-to-end verify.
- All new VMs will get per-NIC NSGs named `vm-soc-v2-<role>-nsg` (mirrors Phase 1 pattern).
- VNet `vm-soc-v2-win-vnet` overall address-space value: gather opportunistically if it surfaces in any wizard tab during Task 6; not blocking.
- DSv3 family quota: ~~confirm visibility at Task 6 wizard size-picker~~ resolved at Task 13 (D2s_v3 accepted without warning; usage now 6 vCPUs).
