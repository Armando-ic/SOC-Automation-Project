"""Shared paramiko helper for D1 Windows-VM SSH probes.

Reusable across Phase 0/1/2/3 helpers - reads creds from the gitignored
SOC-Automation-Project.md (no plaintext secrets in any committed script).
"""

import os
import re

import paramiko

HOST = "192.168.129.130"
USER = "mydfir"


def _load_password():
    here = os.path.dirname(os.path.abspath(__file__))
    secrets_path = os.path.normpath(os.path.join(here, "..", "SOC-Automation-Project.md"))
    with open(secrets_path, "r", encoding="utf-8") as f:
        text = f.read()
    m = re.search(r"MyDfir-Windows-10:\s*USERNAME:\s*\S+\s*\|\s*PASSWORD:\s*(\S+)", text)
    if not m:
        raise RuntimeError("MyDfir-Windows-10 password not found in SOC-Automation-Project.md")
    return m.group(1)


def connect():
    """Return a connected paramiko SSH client to the Windows 10 VM."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, username=USER, password=_load_password(),
                   look_for_keys=False, allow_agent=False, timeout=10)
    return client


def run_ps(client, ps_command, timeout=60, label=None):
    """Run a short PowerShell command via -EncodedCommand (UTF-16LE base64).

    Use this for one-liners. cmd.exe (the default OpenSSH shell wrapper on
    Windows) caps the command line at ~8KB; encoded scripts ~3KB original
    text fit comfortably. For longer scripts, use run_ps_script().
    """
    import base64
    if label:
        print(f"=== {label} ===")
    encoded = base64.b64encode(ps_command.encode("utf-16-le")).decode("ascii")
    cmd = f"powershell -NoProfile -EncodedCommand {encoded}"
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace")
    if out:
        print(out.rstrip())
    if err.strip():
        print(f"--- stderr ---\n{err.rstrip()}")
    if label:
        print()
    return out, err


def run_ps_script(client, ps_script, remote_path=r"C:\Tools\d1-tmp.ps1",
                  timeout=300, label=None):
    """SFTP a PowerShell script to the Windows VM and execute it via -File.

    Bypasses cmd.exe's ~8KB command-line limit so arbitrarily long scripts
    work. The remote .ps1 is left in place (safe to overwrite next call).
    """
    if label:
        print(f"=== {label} ===")
    sftp = client.open_sftp()
    # Ensure the parent directory exists.
    parent = remote_path.rsplit("\\", 1)[0]
    try:
        client.exec_command(f'cmd /c "if not exist \\"{parent}\\" mkdir \\"{parent}\\""')
    except Exception:
        pass
    # Write with BOM so PowerShell parses it as Unicode without surprises.
    body = ("﻿" + ps_script).encode("utf-8")
    with sftp.file(remote_path, "wb") as f:
        f.write(body)
    sftp.close()
    cmd = (f'powershell -NoProfile -ExecutionPolicy Bypass '
           f'-File "{remote_path}"')
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace")
    if out:
        print(out.rstrip())
    if err.strip():
        print(f"--- stderr ---\n{err.rstrip()}")
    if label:
        print()
    return out, err
