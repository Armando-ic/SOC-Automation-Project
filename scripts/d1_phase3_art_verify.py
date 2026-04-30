"""Verify ART module loads via explicit psd1 path; capture T1059.001 catalog."""

from d1_lib import connect, run_ps_script


PS = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$psd1 = 'C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1'
if (-not (Test-Path $psd1)) { throw "module not at $psd1" }

Write-Output '--- Step C: Import module by full path ---'
Import-Module $psd1 -Force
Get-Module Invoke-AtomicRedTeam | Format-Table Name, Version, ModuleType, Path -AutoSize | Out-String

Write-Output '--- Step D: Atomics library inventory ---'
$atomicsRoot = 'C:\AtomicRedTeam\atomics'
$techniqueDirs = Get-ChildItem $atomicsRoot -Directory
Write-Output ('atomics root:    ' + $atomicsRoot)
Write-Output ('technique dirs:  ' + $techniqueDirs.Count)

$t1059 = Join-Path $atomicsRoot 'T1059.001'
Write-Output ('T1059.001 dir:   ' + $t1059)
Get-ChildItem $t1059 | Format-Table Name, Length, LastWriteTime -AutoSize | Out-String

Write-Output '--- Step E: T1059.001 -ShowDetailsBrief catalog ---'
$prevPref = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
Invoke-AtomicTest T1059.001 -ShowDetailsBrief
$ErrorActionPreference = $prevPref

Write-Output ''
Write-Output '--- Capture summary ---'
@{
    art_module_version  = (Get-Module Invoke-AtomicRedTeam).Version.ToString()
    art_module_path     = (Get-Module Invoke-AtomicRedTeam).Path
    atomics_root        = $atomicsRoot
    technique_count     = $techniqueDirs.Count
    t1059_001_dir       = $t1059
} | ConvertTo-Json
""".strip()


def main():
    c = connect()
    run_ps_script(c, PS, remote_path=r"C:\Tools\d1-phase3-verify.ps1",
                  timeout=120, label="Phase 3 ART verify + T1059.001 catalog")
    c.close()


if __name__ == "__main__":
    main()
