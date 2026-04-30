---
status: untested
technique_id: T<id>
tactic: <Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact>
last_run: YYYY-MM-DD
related: [[../subprojects/2026-04-30-detection-foundations/runbook]], [[../architecture/components/sysmon]]
---

# T<id> — <name>

## Description

<one paragraph: what the technique is, what it looks like in practice, why it matters in a SOC context>

## ART command

```powershell
Import-Module C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1
Invoke-AtomicTest T<id> -ShowDetailsBrief                 # preview the test catalog
Invoke-AtomicTest T<id> -TestNumbers <N> -GetPrereqs      # install any required modules
Invoke-AtomicTest T<id> -TestNumbers <N>                  # execute test N
Invoke-AtomicTest T<id> -TestNumbers <N> -Cleanup         # cleanup after
```

## Observations

<Sysmon EventCodes seen, fields populated, surprises. Update on each run.
Lifecycle: status moves `untested` → `observed` → `spl-drafted` → `saved-search-active` as work progresses.>

## SPL

```spl
(none yet)
```

## Saved search

(none yet) — when one is created, list name, cron, webhook target.

## Notes

<false positives, parent-process patterns, tuning observations, references to ATT&CK and Sigma rules.>
