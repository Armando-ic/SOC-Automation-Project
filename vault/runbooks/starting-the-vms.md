---
status: active
updated: 2026-04-27
related: [[architecture/current-state]]
---

# Starting the VMs

Boot sequence for the SOC automation lab.

## Prerequisites

- VMware Workstation installed on host
- VMs imported into the `Soc_Automation_Project` folder in VMware

## VM start order (matters)

1. **MyDFIR-Splunk** — start first; SIEM must be up before forwarders/agents can ship logs
2. **MyDFIR-n8n-VM** — workflow engine
3. **MyDFIR-DFIR-IRIS-VM** — case management
4. **MyDfir-Windows-10** — endpoint generating telemetry
5. **kali-linux-2026** — optional, for adversary simulation

## After boot — getting things running

### Splunk

Splunk is configured to start at boot via `splunk enable boot-start --user splunk`. No manual start needed.

### n8n

Not configured to auto-start. After SSHing in:

```bash
ssh mydfir@192.168.129.132
cd n8n-compose
sudo docker-compose up -d
```

Web UI then available at http://192.168.129.132:5678.

### DFIR-Iris

Same pattern:

```bash
ssh mydfir@192.168.129.133
cd iris-web
sudo docker-compose up
```

Web UI at https://192.168.129.133 (accept the self-signed cert warning).

## Verification

Open all four web pages and confirm reachability:

| Service | URL |
|---|---|
| Splunk | http://192.168.129.131:8000 |
| n8n | http://192.168.129.132:5678 |
| DFIR-Iris | https://192.168.129.133 |
| Windows 10 (RDP) | RDP to 192.168.129.130 |

Credentials: see [[runbooks/secrets-management]].
