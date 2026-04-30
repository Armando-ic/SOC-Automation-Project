"""D1 Phase 1 — Sysmon install via paramiko.

Downloads SwiftOnSecurity config (no git on the VM, so via raw URL + GitHub API
for commit SHA), downloads Sysmon binary from Sysinternals, installs Sysmon as
a service, verifies. Captures all values D1 needs to record in notes.md / sysmon.md.
"""

from d1_lib import connect, run_ps_script


PS_INSTALL = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

Write-Output '--- Step A: Create working directories ---'
New-Item -ItemType Directory -Path C:\Tools -Force | Out-Null
New-Item -ItemType Directory -Path C:\Tools\sysmon-config -Force | Out-Null
New-Item -ItemType Directory -Path C:\Tools\Sysmon -Force | Out-Null
Write-Output 'OK'

Write-Output ''
Write-Output '--- Step B: Capture latest SwiftOnSecurity master commit SHA via GitHub API ---'
$apiResp = Invoke-WebRequest -Uri 'https://api.github.com/repos/SwiftOnSecurity/sysmon-config/branches/master' -UseBasicParsing -TimeoutSec 15
$branch = $apiResp.Content | ConvertFrom-Json
$sha = $branch.commit.sha
$msg = $branch.commit.commit.message -split "`n" | Select-Object -First 1
Write-Output ('commit SHA:    ' + $sha)
Write-Output ('commit msg:    ' + $msg)

Write-Output ''
Write-Output '--- Step C: Download sysmonconfig-export.xml from master ---'
$rawUrl = 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/' + $sha + '/sysmonconfig-export.xml'
$cfgPath = 'C:\Tools\sysmon-config\sysmonconfig-export.xml'
Invoke-WebRequest -Uri $rawUrl -OutFile $cfgPath -UseBasicParsing -TimeoutSec 30
$cfgInfo = Get-Item $cfgPath
$cfgHash = (Get-FileHash $cfgPath -Algorithm SHA256).Hash
Write-Output ('config path:   ' + $cfgPath)
Write-Output ('config bytes:  ' + $cfgInfo.Length)
Write-Output ('config SHA256: ' + $cfgHash)

Write-Output ''
Write-Output '--- Step D: Download Sysmon.zip from Sysinternals ---'
$zipPath = 'C:\Tools\Sysmon\Sysmon.zip'
Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile $zipPath -UseBasicParsing -TimeoutSec 60
$zipInfo = Get-Item $zipPath
Write-Output ('zip path:      ' + $zipPath)
Write-Output ('zip bytes:     ' + $zipInfo.Length)

Write-Output ''
Write-Output '--- Step E: Extract Sysmon binaries ---'
Expand-Archive -Path $zipPath -DestinationPath C:\Tools\Sysmon -Force
$exe = 'C:\Tools\Sysmon\Sysmon64.exe'
if (-not (Test-Path $exe)) { throw 'Sysmon64.exe missing after extract' }
Write-Output ('exe path:      ' + $exe)

Write-Output ''
Write-Output '--- Step F: Capture Sysmon binary version (from file metadata) ---'
$verInfo = (Get-Item $exe).VersionInfo
$versionLine = ($verInfo.ProductName + ' ' + $verInfo.ProductVersion + ' (FileVersion ' + $verInfo.FileVersion + ')')
Write-Output $versionLine

Write-Output ''
Write-Output '--- Step G: Install Sysmon as a service with the SwiftOnSecurity config ---'
# Native commands (Sysmon64.exe) write to stderr even on success; relax error
# preference for this block and gate on $LASTEXITCODE explicitly.
$prevPref = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
$installOutput = & $exe -accepteula -i $cfgPath 2>&1
$installExit = $LASTEXITCODE
$ErrorActionPreference = $prevPref
Write-Output ('Sysmon install exit code: ' + $installExit)
Write-Output ('Sysmon install stdout/stderr (combined):')
$installOutput | ForEach-Object { Write-Output ('  ' + $_) }
if ($installExit -ne 0) { throw ('Sysmon install failed with exit code ' + $installExit) }

Write-Output ''
Write-Output '--- Step H: Verify service is running ---'
Get-Service Sysmon64 | Format-Table Name, Status, StartType -AutoSize | Out-String

Write-Output '--- Step I: Verify Event Log channel registered + receiving events ---'
$ch = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue
if ($null -eq $ch) {
    Write-Output 'Channel NOT registered yet'
} else {
    Write-Output ('Channel:       ' + $ch.LogName)
    Write-Output ('IsEnabled:     ' + $ch.IsEnabled)
    Write-Output ('RecordCount:   ' + $ch.RecordCount)
}

Write-Output ''
Write-Output '--- Step J: Confirm running config matches the file (Sysmon64 -c head) ---'
$prevPref = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
(& $exe -c 2>&1) | Select-Object -First 12 | ForEach-Object { Write-Output ('  ' + $_) }
$ErrorActionPreference = $prevPref

Write-Output ''
Write-Output '--- Capture summary (for notes.md) ---'
@{
    SwiftOnSec_commit_SHA = $sha
    SwiftOnSec_commit_msg = $msg
    config_file_SHA256    = $cfgHash
    config_file_bytes     = $cfgInfo.Length
    sysmon_exe_path       = $exe
    sysmon_version_line   = ($versionLine -split "`n" | Select-Object -First 1)
    install_exit_code     = $installExit
    service_status        = (Get-Service Sysmon64).Status.ToString()
    channel_RecordCount   = if ($ch) { $ch.RecordCount } else { 'unknown' }
} | ConvertTo-Json
""".strip()


def main():
    c = connect()
    run_ps_script(c, PS_INSTALL, remote_path=r"C:\Tools\d1-phase1.ps1",
                  timeout=240, label="Phase 1 — Sysmon install")
    c.close()


if __name__ == "__main__":
    main()
