"""Probe where the ART installer landed Invoke-AtomicRedTeam."""

from d1_lib import connect, run_ps_script


PS = r"""
$ErrorActionPreference = 'Continue'
Write-Output '--- $env:PSModulePath ---'
$env:PSModulePath -split ';' | ForEach-Object { Write-Output ('  ' + $_) }

Write-Output ''
Write-Output '--- Hunting for Invoke-AtomicRedTeam.psd1 across common roots ---'
$roots = @(
    'C:\AtomicRedTeam',
    "$env:ProgramFiles\WindowsPowerShell\Modules",
    "$env:USERPROFILE\Documents\WindowsPowerShell\Modules",
    'C:\Program Files\WindowsPowerShell\Modules',
    'C:\Users\mydfir\Documents\WindowsPowerShell\Modules'
)
foreach ($r in $roots) {
    if (Test-Path $r) {
        $hits = Get-ChildItem -Path $r -Recurse -Filter 'Invoke-AtomicRedTeam.psd1' -ErrorAction SilentlyContinue -Depth 4
        foreach ($h in $hits) { Write-Output ('  ' + $h.FullName) }
    }
}

Write-Output ''
Write-Output '--- AtomicRedTeam folder contents (top level) ---'
if (Test-Path 'C:\AtomicRedTeam') {
    Get-ChildItem 'C:\AtomicRedTeam' | Format-Table Name, Length, LastWriteTime -AutoSize | Out-String
}
""".strip()


def main():
    c = connect()
    run_ps_script(c, PS, remote_path=r"C:\Tools\d1-phase3-locate.ps1",
                  timeout=60, label="ART install location probe")
    c.close()


if __name__ == "__main__":
    main()
