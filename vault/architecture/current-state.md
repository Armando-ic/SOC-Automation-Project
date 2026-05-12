---
status: active
updated: 2026-05-12
related: [[architecture/target-state]], [[workflows/soc-triage-pipeline]], [[decisions/0007-remove-slack-iris-native-gate]]
---

# Current System State

The lab as it exists today, **post-rebuild (2026-05-08 Win10-v2, 2026-05-12 n8n-v2 + IRIS-v2)** and **post-D1 (Detection Foundations shipped 2026-04-30, re-validated 2026-05-12)**.

## Hosts

| Host | IP | VM location | Role |
|---|---|---|---|
| MyDfir-Windows10-v2 | 192.168.129.130 | `C:\VMs\MyDfir-Windows10-v2\` (NVMe) | Endpoint generating telemetry. Sysmon 15.20 + SwiftOnSecurity config, Splunk Universal Forwarder, Atomic Red Team. RDP target. **Hostname inside Windows: `DESKTOP-VNEF7PC`.** |
| MyDFIR-Splunk | 192.168.129.131 | `F:\VMs\MyDFIR-Splunk\` (USB HDD, intentional — see [[../decisions/]] / VM-storage memory) | Splunk Enterprise 10.2.2 (Trial license). Web UI :8000, management API :8089, receiver :9997. Indexes: `mydfir-project`. |
| MyDFIR-n8n-VM-v2 | 192.168.129.132 | `C:\VMs\MyDFIR-n8n-VM-v2\` (NVMe) | n8n via docker-compose on Ubuntu Server 24.04. Web UI :5678. **Static IP pinned via netplan** (cloud-init network config disabled to prevent overwrites). |
| MyDFIR-DFIR-IRIS-VM-v2 | 192.168.129.133 | `C:\VMs\MyDFIR-DFIR-IRIS-VM-v2\` (NVMe) | DFIR-Iris v2.4.22 via docker-compose on Ubuntu Server 24.04. Web UI :443 (HTTPS, self-signed). Containers: db (postgres), app, nginx, rabbitmq, worker. **Static IP pinned via netplan.** |

Old VMs (`MyDfir-Windows10`, `MyDFIR-n8n-VM`, `MyDIFR-DFIR-IRIS0VM`) are still listed in VMware's `inventory.vmls` pointing at OneDrive paths — those entries are stale, the underlying files are quarantined post-incident. Removable via VMware UI right-click → Remove from Library. Not load-bearing for current operations.

## Snapshots (canonical revert points)

| VM | Snapshot name | Captured |
|---|---|---|
| MyDfir-Windows10-v2 | `D1-fully-installed-2026-05-08` | After D1 install on the rebuilt Win10 |
| MyDFIR-Splunk | `D1-baseline-restored-2026-05-08` | After OneDrive-incident recovery + `Splunk_TA_microsoft_sysmon` reinstall |
| MyDFIR-n8n-VM-v2 | `n8n-installed-2026-05-12` *(pending)* | After fresh install + v3 workflow imported + 4 credentials wired |
| MyDFIR-DFIR-IRIS-VM-v2 | `IRIS-installed-2026-05-12` *(pending)* | After fresh install + first-boot admin password captured + API key generated |

## Data flow (current — post-ADR 0007)

```
Win10-v2 (DESKTOP-VNEF7PC)
    Sysmon EventCode=1 events (process create)
    + Windows Security/Application/System channels
    ↓ Universal Forwarder (TCP :9997)
Splunk indexer (mydfir-project)
    ↓ Saved search "T1059.001 - PowerShell Encoded Command"
    ↓   cron */5 * * * *, Time Range -24h@h, alert.digest_mode=0
    ↓   trigger: webhook
    ↓ HTTP POST
n8n SOAR (MyDFIR-n8n-VM-v2 :5678)
    Webhook → Message a model (Claude Opus 4.7, agentic)
        ├── ai_tool: AbuseIPDB enrichment
        ├── ai_tool: VirusTotal hash lookup
        └── ai_tool: submit_triage_result (structured outputs, A1)
    ↓ Extract Triage Result (Code node, A1)
    ↓ Create Iris Alert (HTTP POST /alerts/add)
DFIR-Iris (MyDFIR-DFIR-IRIS-VM-v2 :443)
    Alert lands with status_id=1, severity_id from Claude's mapping,
    iocs[] from enrichment.
    [Human approval gate is HERE — analyst reviews in IRIS and clicks
     "Escalate to Case" manually if escalation warranted. ADR 0007.]
```

Slack is **no longer in the workflow** as of 2026-05-12 (ADR 0007). The v2 gate-fired branch (Slack approval → auto-escalate) was retired; A2's Wait-resume URL pattern, signed-Slack-button design, and Iris escalate handler null-check workarounds are preserved in the vault as historical documentation, not in the runtime workflow.

## Interactive investigation path

Independent of the alert pipeline:
- Claude Desktop and Claude Code both have a `splunk` MCP server connected to Splunk at `:8089` as `mcpuser`. Used for ad-hoc queries, validating detections, hunting. See [[architecture/components/splunk-mcp]].
- mydfir admin REST access at `:8089` via `mydfir/<password from secrets file>` works for saved-search creation, dispatching, log inspection, etc.

## Detection inventory

| Technique | Status | Worked example? |
|---|---|---|
| T1059.001 PowerShell Encoded Command | ✅ Active saved search, validated end-to-end | Yes — see [[../detections/t1059-001-powershell-encoded]] |

D1 deliberately scoped to a single vertical-slice technique. Additional detections are future sub-project scope (D-series).

## Sub-projects shipped

| Sub-project | Date shipped | Summary |
|---|---|---|
| A1 — Structured Outputs | 2026-04-28 | `submit_triage_result` tool + `Extract Triage Result` Code node; programmatic IOC + severity routing |
| A2 — Iris Escalation Gate | 2026-04-30 | Slack-interactive Wait-resume gate, additive `ioc_type` schema (ADR 0005); **retired by ADR 0007** but design preserved in vault |
| D1 — Detection Foundations | 2026-04-30 | Sysmon + ART + observation lab; T1059.001 worked example. Re-validated 2026-05-12 on rebuilt lab. |

Active sub-project: **none** — D1 frozen as of 2026-05-12.

Next planned: **A3 Enrichment Expansion** (stub at [[../subprojects/2026-05-12-enrichment-expansion/README]]) — awaiting brainstorm; comes after Microsoft Sentinel / Azure pivot work begins.

## Known issues in the current workflow

Inherited / re-confirmed during the 2026-05-12 rebuild:

1. **Webhook is unauthenticated** — security-through-obscurity GUID path only; anyone reachable on the n8n network can POST fake alerts. Deferred since v0; ADR 0007 doesn't change this.
2. **`alert_status_id=1` maps to "Unspecified"** on IRIS v2.4.22, not "New" as historically documented in [[components/dfir-iris]]. Cosmetic for portfolio use; workflow's hardcoded value should be re-derived from `/manage/alert-status/list`. Verified 2026-05-12.
3. **Severity-stamping inconsistency** persists in v3. Claude's structured `severity` field occasionally diverges from technique-class risk (e.g., alert #4 came back as "Low" for an encoded-PowerShell event that should be Medium-or-higher). Hypothesis: Claude is severity-rating based on decoded-payload benignness rather than technique class. System-prompt tuning issue, not wiring. Deferred to a future tuning pass.
4. **`Splunk_TA_windows` lookup CSVs missing** on the rebuilt Splunk install. Three `Could not load lookup=LOOKUP-*_for_windows` warnings appear on most searches. Cosmetic — these apply to `wineventlog` sourcetype, not Sysmon (which D1 uses). Fix during a future Splunk-add-on hygiene pass.
5. **AtomicTestHarnesses module install missed** on Win10-v2 rebuild. Needs TLS 1.2 explicit enable before `Install-Module` succeeds. Workaround for D1 freeze: synthetic `powershell.exe -EncodedCommand` invocation substituted for ATH Test 15 — same SPL match. Fix when next running ATH-based tests.

Issues 1–7 from the original v0/v1 era are all closed: 1–4 and 6 by A1, 7 by Slack removal (no longer relevant since there's no Slack-interactive gate to protect).

## Operational entry points

- **Start the lab:** [[../runbooks/starting-the-vms]]
- **Re-deploy / re-import the workflow:** [[../runbooks/n8n-workflow-deployment]]
- **Splunk MCP setup (fresh instance):** [[../runbooks/splunk-mcp-setup]]
- **Run a MITRE technique through the lab:** [[../subprojects/2026-04-30-detection-foundations/runbook]] §"The run-a-technique loop"
- **Where secrets live:** [[../runbooks/secrets-management]]
