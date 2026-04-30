"""D1 Phase 2 Smoke test #2 seed - exercises multiple Sysmon EventCodes.

After running this, query Splunk for EventCode distribution to confirm the
SwiftOnSecurity config is emitting a non-trivial spread (EventCodes 1, 3,
11, 12-14, 22, 23 expected based on what we trigger here).
"""

from d1_lib import connect, run_ps_script


PS = r"""
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

Write-Output '--- Seeding varied activity for EventCode coverage check ---'

# EventCode 1 (Process Create) + 5 (Process Terminate) - notepad
Start-Process notepad.exe; Start-Sleep 2
Stop-Process -Name notepad -ErrorAction SilentlyContinue

# EventCode 1 + 5 - calc (ms-paint substitute if calc isn't responsive)
Start-Process calc.exe; Start-Sleep 2
Stop-Process -Name *calc* -ErrorAction SilentlyContinue

# EventCode 22 (DNS Query) + 3 (Network Connect) - simple HTTP request
try { Invoke-WebRequest -Uri 'https://www.google.com' -UseBasicParsing -TimeoutSec 5 | Out-Null } catch { }

# EventCode 11 (File Create)
'd1 coverage seed' | Out-File C:\Tools\d1-coverage-seed.txt -Encoding utf8

# EventCode 12/13 (Registry events) - touch HKCU current user run-key check
$rk = 'HKCU:\Software\D1Test'
if (-not (Test-Path $rk)) { New-Item -Path $rk -Force | Out-Null }
Set-ItemProperty -Path $rk -Name 'D1CoverageSeed' -Value 'hello' -Type String

# EventCode 23 (File Delete)
Remove-Item C:\Tools\d1-coverage-seed.txt -Force

# Cleanup the registry test key so we don't leave artifacts
Remove-Item -Path $rk -Recurse -Force

Write-Output 'seed activities completed'
Get-Date -Format 'yyyy-MM-ddTHH:mm:ss' | ForEach-Object { Write-Output ('seed end (local): ' + $_) }
""".strip()


def main():
    c = connect()
    run_ps_script(c, PS, remote_path=r"C:\Tools\d1-phase2-seed.ps1",
                  timeout=60, label="Phase 2 Smoke #2 seed activity")
    c.close()


if __name__ == "__main__":
    main()
