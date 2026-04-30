"""D1 Phase 2 — UF backup + restart + smoke-test trigger.

Phase 2 was reduced to verify-only after Phase 0 found the Sysmon stanza
already exists. Steps:
  1. Backup inputs.conf (defensive, no edit happens).
  2. Restart SplunkForwarder so the dormant Sysmon stanza binds to the
     freshly-installed Sysmon channel from Phase 1.
  3. Tail splunkd.log to confirm the bind succeeded.
  4. Spawn notepad.exe to seed the Tier-1 smoke test #1.

Splunk-side verification (smoke-test query) is run from the host via REST,
not from this script.
"""

from d1_lib import connect, run_ps_script


PS = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

Write-Output '--- Step 1: Backup inputs.conf (defensive) ---'
$src = 'C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf'
$bak = "$src.pre-D1.bak"
Copy-Item -Path $src -Destination $bak -Force
$bakInfo = Get-Item $bak
Write-Output ('backup path:  ' + $bakInfo.FullName)
Write-Output ('backup bytes: ' + $bakInfo.Length)
Write-Output ('backup time:  ' + $bakInfo.LastWriteTime)

Write-Output ''
Write-Output '--- Step 2: Confirm SplunkForwarder service state pre-restart ---'
Get-Service SplunkForwarder | Format-Table Name, Status, StartType -AutoSize | Out-String

Write-Output '--- Step 3: Restart SplunkForwarder ---'
Restart-Service SplunkForwarder
Start-Sleep -Seconds 3
Get-Service SplunkForwarder | Format-Table Name, Status, StartType -AutoSize | Out-String

Write-Output '--- Step 4: Tail splunkd.log for Sysmon binding evidence ---'
$log = 'C:\Program Files\SplunkUniversalForwarder\var\log\splunk\splunkd.log'
Get-Content $log -Tail 200 |
  Select-String -Pattern 'Sysmon|inputs\.conf|WinEventLog|EventLogStartReadingFromCheckpoint' |
  Select-Object -Last 25 |
  ForEach-Object { Write-Output ('  ' + $_.Line) }

Write-Output ''
Write-Output '--- Step 5: Spawn notepad.exe to seed smoke test #1 ---'
$ts = Get-Date -Format 'yyyy-MM-ddTHH:mm:ss'
Write-Output ('spawn timestamp (local): ' + $ts)
$proc = Start-Process notepad.exe -PassThru
Write-Output ('notepad PID:             ' + $proc.Id)
Start-Sleep -Seconds 2
Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
Write-Output 'notepad killed; smoke event should appear in Splunk within ~60s'

Write-Output ''
Write-Output '--- Capture summary ---'
@{
    backup_path        = $bakInfo.FullName
    backup_bytes       = $bakInfo.Length
    forwarder_restart  = 'Running'
    notepad_spawn_time = $ts
    notepad_pid        = $proc.Id
} | ConvertTo-Json
""".strip()


def main():
    c = connect()
    run_ps_script(c, PS, remote_path=r"C:\Tools\d1-phase2.ps1",
                  timeout=120, label="Phase 2 — UF backup + restart + smoke seed")
    c.close()


if __name__ == "__main__":
    main()
