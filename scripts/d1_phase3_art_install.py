"""D1 Phase 3 - Atomic Red Team install + T1059.001 catalog inspection.

Bootstraps Invoke-AtomicRedTeam from Red Canary's installer, downloads the
atomics library to C:\\AtomicRedTeam\\atomics\\, and captures the T1059.001
test catalog so we can pick the right test number for D1's worked example.
"""

from d1_lib import connect, run_ps_script


PS = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

Write-Output '--- Step A: Set ExecutionPolicy + bootstrap installer ---'
Set-ExecutionPolicy Bypass -Scope CurrentUser -Force

# Ensure modern TLS so GitHub raw download negotiates correctly on Windows 10
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$installerUrl = 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1'
Invoke-Expression (Invoke-WebRequest -Uri $installerUrl -UseBasicParsing -TimeoutSec 30).Content
Write-Output 'installer source loaded'

Write-Output ''
Write-Output '--- Step B: Install the module + download atomics library (large download) ---'
Install-AtomicRedTeam -getAtomics -Force
Write-Output 'Install-AtomicRedTeam completed'

Write-Output ''
Write-Output '--- Step C: Verify module is importable ---'
Import-Module Invoke-AtomicRedTeam -Force
Get-Module Invoke-AtomicRedTeam | Format-Table Name, Version, ModuleType, Path -AutoSize | Out-String

Write-Output '--- Step D: Confirm atomics library landed ---'
$atomicsRoot = 'C:\AtomicRedTeam\atomics'
if (-not (Test-Path $atomicsRoot)) { throw "atomics directory missing at $atomicsRoot" }
$techniqueDirs = Get-ChildItem $atomicsRoot -Directory
Write-Output ('atomics root:    ' + $atomicsRoot)
Write-Output ('technique dirs:  ' + $techniqueDirs.Count)

$t1059 = 'C:\AtomicRedTeam\atomics\T1059.001'
if (-not (Test-Path $t1059)) { throw "T1059.001 directory missing at $t1059" }
Write-Output ('T1059.001 dir:   ' + $t1059)
Get-ChildItem $t1059 | Format-Table Name, Length, LastWriteTime -AutoSize | Out-String

Write-Output '--- Step E: Show T1059.001 test catalog (-ShowDetailsBrief) ---'
$prevPref = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
Invoke-AtomicTest T1059.001 -ShowDetailsBrief
$ErrorActionPreference = $prevPref

Write-Output ''
Write-Output '--- Step F: Capture summary ---'
@{
    art_module_version = (Get-Module Invoke-AtomicRedTeam).Version.ToString()
    atomics_root       = $atomicsRoot
    technique_count    = $techniqueDirs.Count
    t1059_001_dir      = $t1059
} | ConvertTo-Json
""".strip()


def main():
    c = connect()
    run_ps_script(c, PS, remote_path=r"C:\Tools\d1-phase3.ps1",
                  timeout=420, label="Phase 3 - ART install")
    c.close()


if __name__ == "__main__":
    main()
