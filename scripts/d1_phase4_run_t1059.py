"""D1 Phase 4 - run T1059.001-15 once to seed SPL development.

ATH (Atomic Test Harness) test #15 exercises -EncodedCommand parameter
variations. Generates one or more EventCode=1 events with powershell.exe
+ -EncodedCommand <base64>. Used as the development data for hand-crafting
the T1059.001 detection SPL.
"""

from d1_lib import connect, run_ps_script


PS = r"""
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

$psd1 = 'C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1'
Import-Module $psd1 -Force

Write-Output '--- T1059.001-15 details (read-only preview) ---'
Invoke-AtomicTest T1059.001 -TestNumbers 15 -ShowDetailsBrief

Write-Output ''
Write-Output '--- Check + install prereqs (AtomicTestHarnesses module) ---'
Invoke-AtomicTest T1059.001 -TestNumbers 15 -GetPrereqs

Write-Output ''
Write-Output '--- Run T1059.001-15 ---'
$ts = Get-Date
Write-Output ('exec start (local): ' + $ts.ToString('yyyy-MM-ddTHH:mm:ss'))
Invoke-AtomicTest T1059.001 -TestNumbers 15
$ts2 = Get-Date
Write-Output ('exec end   (local): ' + $ts2.ToString('yyyy-MM-ddTHH:mm:ss'))
Write-Output ('exec duration:      ' + ($ts2 - $ts).TotalSeconds + 's')
""".strip()


def main():
    c = connect()
    run_ps_script(c, PS, remote_path=r"C:\Tools\d1-phase4.ps1",
                  timeout=180, label="Phase 4 - Run T1059.001-15 (dev seed)")
    c.close()


if __name__ == "__main__":
    main()
