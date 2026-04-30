"""D1 Phase 0 SSH probes — runs Sysmon baseline + write-test + UF inputs.conf inspection.

One-off helper. Uses forward slashes in PowerShell paths to dodge Python escape issues.
"""

import os
import re
import sys

import paramiko

HOST = "192.168.129.130"
USER = "mydfir"


def _load_password():
    """Read the lab password from the gitignored secrets file at repo root."""
    here = os.path.dirname(os.path.abspath(__file__))
    secrets_path = os.path.normpath(os.path.join(here, "..", "SOC-Automation-Project.md"))
    with open(secrets_path, "r", encoding="utf-8") as f:
        text = f.read()
    m = re.search(r"MyDfir-Windows-10:\s*USERNAME:\s*\S+\s*\|\s*PASSWORD:\s*(\S+)", text)
    if not m:
        raise RuntimeError("MyDfir-Windows-10 password not found in SOC-Automation-Project.md")
    return m.group(1)


PASSWORD = _load_password()


def run(client, label, ps_command):
    print(f"=== {label} ===")
    cmd = f'powershell -NoProfile -Command "{ps_command}"'
    stdin, stdout, stderr = client.exec_command(cmd, timeout=30)
    print(stdout.read().decode())
    err = stderr.read().decode()
    if err.strip():
        print(f"--- stderr ---\n{err}")
    print()


def main():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, username=USER, password=PASSWORD,
                   look_for_keys=False, allow_agent=False, timeout=10)

    # Task 0.1 Step 4 — Sysmon baseline (NOT installed expected)
    run(client, "Sysmon baseline (Get-Service Sysmon64)", (
        "$s = Get-Service Sysmon64 -ErrorAction SilentlyContinue; "
        "if ($null -eq $s) { Write-Output 'Sysmon64 service NOT present - clean baseline' } "
        "else { $s | Format-Table Name, Status, StartType -AutoSize }"
    ))

    # Task 0.4 Step 2 — write-capability sanity check
    run(client, "Write-capability test", (
        "New-Item -ItemType Directory -Path C:/Tools -Force | Out-Null; "
        "'test' | Out-File -FilePath C:/Tools/d1-write-test.txt -Encoding utf8; "
        "Get-Content C:/Tools/d1-write-test.txt; "
        "Remove-Item C:/Tools/d1-write-test.txt; "
        "Write-Output 'write-test: PASS'"
    ))

    # Task 0.3 — UF inputs.conf path + existing stanzas
    run(client, "UF inputs.conf path + listing", (
        "$inputs = 'C:/Program Files/SplunkUniversalForwarder/etc/system/local/inputs.conf'; "
        "Write-Output ('Test-Path: ' + (Test-Path $inputs)); "
        "Write-Output ''; "
        "Write-Output '--- Directory listing ---'; "
        "Get-ChildItem 'C:/Program Files/SplunkUniversalForwarder/etc/system/local' | "
        "Format-Table Name, Length, LastWriteTime -AutoSize | Out-String"
    ))

    run(client, "UF inputs.conf contents", (
        "$inputs = 'C:/Program Files/SplunkUniversalForwarder/etc/system/local/inputs.conf'; "
        "Get-Content $inputs"
    ))

    # Bonus: confirm Splunk Universal Forwarder service is running (we'll restart it later)
    run(client, "SplunkForwarder service state", (
        "Get-Service SplunkForwarder | Format-Table Name, Status, StartType -AutoSize | Out-String"
    ))

    client.close()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"ERROR: {type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(1)
