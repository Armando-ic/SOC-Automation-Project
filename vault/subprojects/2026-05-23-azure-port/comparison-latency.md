---
status: active
updated: 2026-05-26
sub_project: P2 (Azure Port)
related: [[README]], [[spec]], [[notes]], [[runbook]]
---

# P2 Latency comparison — v1 (local VMware) vs P2 (Azure IaaS)

## Headline

> **Active-processing latency on Azure D2s_v3 = ~16–23 seconds end-to-end** (saved-search dispatch → IRIS alert visible). Cron-tick wait of up to 5 minutes is the dominant factor in total ATH-to-IRIS time and is identical to v1 by design (`*/5 * * * *` schedule).

## How this was captured

Two fires on the Azure stack with full pipeline trace, both gathered during P2 verification:

- **Single-IOC-free fire** (Task 19 verification, 2026-05-25): synthetic `powershell.exe -EncodedCommand` matching the existing `T1059.001 - PowerShell Encoded Command` saved search. Empty `alert_iocs`. Used to verify the e2e schema/transport.
- **IOC-rich fire** (Task 24 prep, 2026-05-26): the 2026-05-19-demo `cmd.exe` synthetic with `IOC_IP=185.220.101.42`, `IOC_HASH=<EICAR SHA-256>`, and an `.invalid` URL. Matched the back-ported `T1059.003 - Suspicious cmd.exe IOC References` saved search and naturally exercised both enrichment tools.

Timestamps were sourced from:
- Win VM fire time: `Get-Date` captured in Run Command stdout
- Splunk indexed time: prior baseline (~150 ms from UF → indexer per Task 12 verification — not re-measured for these specific fires; UF behavior unchanged)
- Saved-search dispatch time: cron tick wall-clock (`*/5`)
- n8n exec start/end: `execution_entity` table in `~/.n8n/database.sqlite` on `vm-soc-v2-n8n`
- IRIS alert creation time: `alert_creation_time` field returned by `GET /alerts/<id>` against the IRIS API

## Latency table

| Step | v1 (local VMware) | P2 (Azure IaaS, D2s_v3) | Delta | Notes |
|---|---|---|---|---|
| Endpoint fire → Splunk indexed | not measured in v1 era | **~150 ms** | n/a | UF behavior unchanged across platforms; ~150 ms ballpark from Task 12 verification on Azure |
| Splunk indexed → saved-search dispatch | up to 5 min (cron `*/5`) | up to 5 min (cron `*/5`) | **0** | Identical schedule; pure scheduling latency |
| Saved-search dispatch → n8n exec start | not measured in v1 era | **< 1 sec** | n/a | Intra-VNet `10.0.0.5 → 10.0.0.6:5678`; sanity-tested at 260 ms in Task 16 |
| n8n exec start → IRIS alert (no-IOC path, T1059.001) | not measured in v1 era | **~16 sec** | n/a | Task 19 fire; Claude triage + empty-IOC short-circuit + IRIS write |
| n8n exec start → IRIS alert (IOC-rich path, T1059.003) | not measured in v1 era | **~22 sec** | n/a | Task 24 prep fire; Claude triage + AbuseIPDB tool call + VirusTotal tool call + IRIS write |
| **End-to-end (fire → IRIS alert)** | not measured in v1 era | **1 min 42 sec (single fire, IOC-rich)** | n/a | Cron wait dominates; active processing is 22 sec |

## Honest-data note on v1 baseline

**v1 timestamps were never captured during the local-VMware era.** The original tutorial and the A1–D1 sub-project work focused on functional verification, not latency profiling. The v1 column is left as "not measured" rather than fabricated.

If a baseline becomes useful for a future phase comparison, it could be reconstructed by replaying the VMware-archived VMs from `F:\VMs\` (post-decommission archive location), re-firing the same synthetic, and timing it the same way. Cost-benefit isn't there today — the Azure numbers stand on their own and the Phase 3 (Microsoft-native) comparison will be against the Azure numbers, not v1.

## Observations

- **Cron wait dominates total latency.** Tightening cadence (e.g., `*/2` or `*/1`) would shave 1–4 minutes off worst-case total at the cost of more search dispatches per hour. Real-time scheduling would eliminate the wait entirely but trips the `realtime_schedule=False` gotcha (loses `is_scheduled=True` stability across edits per [[../../detections/t1059-001-powershell-encoded]]).
- **IOC-rich paths cost ~6 seconds more than empty-IOC paths.** Two extra HTTP tool calls (AbuseIPDB + VirusTotal) over public internet from `vm-soc-v2-n8n`. Both APIs are well behaved (free-tier rate limits not approached during testing).
- **D2s_v3 is right-sized for the n8n + IRIS workloads at this volume.** Active processing fits well under any plausible alert-rate constraint (current rate: 2 alerts per cron tick × 12 ticks/hour = 24/hour theoretical peak; observed: ~1 alert per 5 min = 12/hour).
- **Sub-second indexing latency** (~150 ms from Sysmon EventCode=1 emit → searchable in `mydfir-project`) is unchanged from local-VMware era and not a tuning lever.

## Future comparison row (Phase 3 / Microsoft-native)

When Phase 3 ships on the `v3-microsoft-native` branch, capture an additional row: ATH → Sentinel Incident → Logic App → Sentinel Update Incident. Compare against the P2 (Azure IaaS) row above — same Win VM source telemetry, same physical infrastructure region, different SOAR plane.

Specifically worth measuring:
- Sentinel ingestion lag (AMA → Log Analytics → analytic-rule fire) vs. Splunk indexing + saved-search cron
- Logic App invocation overhead vs. n8n webhook + exec start
- Sentinel incident creation latency vs. IRIS `/alerts/add`

These three legs should swap cleanly with the corresponding P2 hops, so the delta will isolate "SOAR plane choice" from "endpoint telemetry latency."
