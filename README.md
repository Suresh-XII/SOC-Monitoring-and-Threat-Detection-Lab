<div align="center">

# 🛡️ Enterprise SOC Monitoring & Threat Detection Lab

### Centralized Security Telemetry, Detection Engineering, and Incident Triage with Splunk Enterprise, Windows 11, Sysmon, and Kali Linux

[![Splunk Enterprise](https://img.shields.io/badge/Splunk_Enterprise-9.3.x-000000?style=for-the-badge&logo=splunk&logoColor=white)](https://www.splunk.com/)
[![Windows 11](https://img.shields.io/badge/Windows_11-Pro_23H2-0078D4?style=for-the-badge&logo=windows-11&logoColor=white)](https://www.microsoft.com/windows)
[![Sysmon](https://img.shields.io/badge/Sysmon-v15.x-00ADEF?style=for-the-badge&logo=windows&logoColor=white)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
[![Kali Linux](https://img.shields.io/badge/Kali_Linux-2024.x-557C94?style=for-the-badge&logo=kali-linux&logoColor=white)](https://www.kali.org/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-v14_Mapped-red?style=for-the-badge)](https://attack.mitre.org/)
[![Project Status](https://img.shields.io/badge/Project_Status-Complete_✅-brightgreen?style=for-the-badge)](#project-status)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](LICENSE)
**Project Status:** Deployment-ready lab package | Detection validation required per environment

The repository is intentionally safe to publish: it contains sanitized
documentation, portable SPL, a Classic Simple XML dashboard, evidence
references, and deployment acceptance criteria. Environment-specific values
remain placeholders until the lab owner validates them.

</div>

---

## 📌 Executive Summary

The **Enterprise SOC Monitoring & Threat Detection Lab** is a hands-on, end-to-end security operations environment simulating enterprise cyber defense operations. Built using **Splunk Enterprise SIEM**, a monitored **Windows 11 Pro** endpoint instrumented with **Sysmon v15**, and a dedicated **Kali Linux** adversary emulation system, this project demonstrates:

1. **Centralized Log Pipeline Architecture:** Secure ingestion of Windows Security, System, PowerShell Script Block, OpenSSH, and Sysmon telemetry via Splunk Universal Forwarders into a dedicated index (`index=blue`).
2. **Detection Engineering:** Design, tuning, and validation of **14 high-fidelity SPL detection queries** mapped to the **MITRE ATT&CK Enterprise Matrix** across credential access, execution, persistence, defense evasion, and discovery.
3. **Adversary Emulation:** Controlled threat simulations including Hydra RDP/SSH brute forcing, Nmap multi-port scanning, obfuscated Base64 PowerShell execution cradles, and unauthorized account creation/privilege escalation.
4. **Structured Incident Response:** Five complete incident investigation reports and SOC L1 triage playbooks documenting timeline reconstruction, forensic artifact analysis, root cause determination, and containment actions.
5. **SOC Triage Dashboard:** An interactive, single-pane-of-glass Splunk Classic XML dashboard providing real-time KPI metrics, threat distribution charts, and a 30-second live triage stream.

---

## 🏗️ Architecture & Telemetry Pipeline

```
+-----------------------------------------------------------------------------------+
|                              LAB NETWORK (192.168.10.0/24)                        |
+-----------------------------------------------------------------------------------+
                                          |
          +-------------------------------+-------------------------------+
          |                                                               |
+-----------------------+                                       +-----------------------+
|   ADVERSARY PLATFORM  |                                       |   MONITORED WORKLOAD  |
|   Kali Linux 2024.x   |   [Simulated Cyber Attacks:           |   Windows 11 Pro      |
|   Hostname: KALI-SIM  |    Hydra Brute Force, Nmap Scans,     |   Host: WIN-ENDPOINT-01|
|   IP: 192.168.10.50   |    PowerShell Payloads, Tool Drops]   |   IP: 192.168.10.15   |
+-----------------------+ ====================================> +-----------------------+
          |                                                                 |
          | [Auth Logs: /var/log/auth.log]                                  | [Windows Security, System,
          |                                                                 |  Sysmon v15, PowerShell,
          |                                                                 |  OpenSSH Telemetry]
          v                                                                 v
+-----------------------+                                       +-----------------------+
| Splunk Linux Fwd      |                                       | Splunk Universal Fwd  |
+-----------------------+                                       +-----------------------+
          |                                                                 |
          |              TCP Port 9997 (Encrypted S2S Forwarding)           |
          +-------------------------------+---------------------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |         CENTRAL SIEM PLATFORM         |
                      |         Splunk Enterprise v9.3.x      |
                      |         Hostname: SPLUNK-SRV-01       |
                      |         Management IP: 192.168.10.100 |
                      +---------------------------------------+
                                          |
                        +-----------------+-----------------+
                        |                                   |
                        v                                   v
             +----------------------+            +----------------------+
             |   INDEXING LAYER     |            |    ANALYTICS LAYER   |
             |   * index=blue       |            |   * 14x Custom Rules |
             |     - WinEventLog    |            |   * SOC L1 Dashboard |
             |     - Sysmon v15     |            |   * MITRE Mappings   |
             |   * index=main       |            |   * Incident Reports |
             |     - linux_auth     |            |   * L1 Playbooks     |
             +----------------------+            +----------------------+
```

---

## 📂 Repository Directory Structure

```text
SOC_SPLUNK_P1/
├── 01-Project-Overview/            # Architectural blueprints & operational scope
│   ├── architecture.md             # Detailed network topology & ingestion pipelines
│   └── project-overview.md         # Lab objectives, roles, and boundaries
├── 02-Environment-Setup/           # Hardware, software, and configuration files
│   ├── environment-details.md      # Sanitized host details, ports, and audit policies
│   ├── splunk-inputs-reference.md  # Production inputs.conf, outputs.conf, indexes.conf
│   └── sysmon-config-notes.md      # Sysmon v15 XML modular configuration & tuning
├── 03-Detection-Rules/             # 14 SPL detection rules with metadata headers
│   ├── README.md                   # Rule catalog, deployment guide, and index
│   ├── Linux/                      # SSH brute-force detection
│   ├── Network/                    # Reconnaissance and multi-port scan rules
│   ├── Sysmon/                     # Process creation, network, and file drop rules
│   └── Windows/                    # Authentication, account, and PowerShell rules
├── 04-Investigation-Reports/       # End-to-end incident investigation dossiers
│   ├── incident-report-template.md # Standardized SOC case template
│   ├── Authentication/             # Windows failed logon & unauthorized account creation
│   ├── Brute-Force/                # Linux SSH brute-force investigation & escalation
│   ├── Process-Investigation/      # Sysmon demo.exe process execution dossier
│   └── Suspicious-Files/           # Staged executable creation investigation
├── 05-Dashboards/                  # Production SOC L1 XML dashboard & guide
│   ├── SOC-L1-dashboard.xml        # Full Classic XML dashboard definition
│   └── dashboard-overview.md       # Panel descriptions, thresholds, and SPL queries
├── 06-Evidence/                    # Sanitized forensic artifacts & screenshots
│   ├── README.md                   # Complete evidence register & sanitization protocol
│   ├── SSH-Brute-Force/            # Raw logs & search screenshots
│   ├── Process-Monitoring/         # Sysmon process event evidence
│   ├── Splunk-Alert-Workflow/      # Alert and report configuration evidence
│   └── Splunk-Ingestion/           # Ingestion volume and source verification
├── 07-Attack-Simulation/           # Controlled threat generation guides & logs
│   ├── Test-Scenarios.md           # 5 controlled simulation runbooks with commands
│   └── simulation-results-log.md   # Chronological execution log (100% pass rate)
└── 08-Documentation/               # SOC operations framework & knowledge base
    ├── detection-mapping.md        # Comprehensive MITRE ATT&CK coverage matrix
    └── investigation-workflow.md   # 5 Level 1 Incident Response Playbooks
```

---

## 🎯 Detection Engineering & MITRE ATT&CK Coverage

This lab includes **14 production-grade SPL detection rules** mapped across 7 MITRE ATT&CK tactics:

| Category | File | Event ID | ATT&CK ID | Tactic | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Windows Auth** | [`failed-logon-4625.spl`](03-Detection-Rules/Windows/failed-logon-4625.spl) | 4625 | `T1110` | Credential Access | Baseline review of Windows logon failures |
| **Windows Auth** | [`brute-force-threshold-4625.spl`](03-Detection-Rules/Windows/brute-force-threshold-4625.spl) | 4625 | `T1110.001` | Credential Access | Flags sources with $\ge 5$ logon failures |
| **Windows Auth** | [`successful-logon-4624.spl`](03-Detection-Rules/Windows/successful-logon-4624.spl) | 4624 | `T1078` | Initial Access | Correlates valid logins following brute force |
| **Windows Auth** | [`account-lockout-4740.spl`](03-Detection-Rules/Windows/account-lockout-4740.spl) | 4740 | `T1110.001` | Credential Access | Detects user account lockouts & calling machines |
| **Account Mgmt** | [`account-creation-4720.spl`](03-Detection-Rules/Windows/account-creation-4720.spl) | 4720 | `T1136.001` | Persistence | Detects new local/domain user creation |
| **Account Mgmt** | [`privilege-escalation-4728-4732.spl`](03-Detection-Rules/Windows/privilege-escalation-4728-4732.spl) | 4728, 4732 | `T1098` | Privilege Escalation | Detects addition of users to Administrators group |
| **PowerShell** | [`suspicious-powershell-4104.spl`](03-Detection-Rules/Windows/suspicious-powershell-4104.spl) | 4104 | `T1059.001`, `T1027` | Execution / Evasion | Detects Base64, IEX, and bypass flags |
| **Sysmon Process**| [`process-creation-1.spl`](03-Detection-Rules/Sysmon/process-creation-1.spl) | Sysmon 1 | `T1059` | Execution | Raw process creation with command-line arguments |
| **Sysmon Process**| [`suspicious-exe-execution-1.spl`](03-Detection-Rules/Sysmon/suspicious-exe-execution-1.spl) | Sysmon 1 | `T1204.002` | Execution | Execution from Temp, AppData, Downloads, Public |
| **Sysmon Process**| [`suspicious-powershell-investigation.spl`](03-Detection-Rules/Sysmon/suspicious-powershell-investigation.spl) | Sysmon 1 | `T1059.001` | Execution | Process lineage for powershell.exe / pwsh.exe |
| **Sysmon Network**| [`network-connection-3.spl`](03-Detection-Rules/Sysmon/network-connection-3.spl) | Sysmon 3 | `T1046` | Discovery | Scans across $\ge 10$ unique destination ports |
| **Sysmon File** | [`suspicious-exe-creation-11.spl`](03-Detection-Rules/Sysmon/suspicious-exe-creation-11.spl) | Sysmon 11 | `T1105` | Defense Evasion | Executable drops into user-writable directories |
| **Linux Auth** | [`ssh-brute-force.spl`](03-Detection-Rules/Linux/ssh-brute-force.spl) | `linux_auth` | `T1110.001` | Credential Access | Regex extraction of repeated SSH failed passwords |
| **Network Scan** | [`reconnaissance-port-scanning.spl`](03-Detection-Rules/Network/reconnaissance-port-scanning.spl) | Sysmon 3 | `T1046` | Discovery | Detects vertical and horizontal network scanning |

---

## 📊 SOC L1 Threat Monitoring Dashboard

The custom Splunk Classic XML dashboard ([`05-Dashboards/SOC-L1-dashboard.xml`](05-Dashboards/SOC-L1-dashboard.xml)) provides immediate situational awareness for operations analysts:

- **6 KPI Metric Panels:** Total Events, Failed Logons (4625), Account Lockouts (4740), New Accounts (4720), Suspicious PowerShell (4104), Port Scanning Pairs (Sysmon 3).
- **Top Brute Force Sources Table:** Auto-aggregates attacking IPs exceeding the 5-attempt threshold with calculated severity.
- **Suspicious Executables Table:** Correlates file creation (Event 11) and execution (Event 1) in staging directories.
- **Visual Analytics:** Breakdown of security events by use case and 15-minute volume trendline.
- **Real-Time Triage Stream:** Auto-refreshing 30-second live queue of prioritized endpoint alerts.

---

## 📑 Completed Incident Investigation Reports

| Case ID | Incident Subject | Telemetry Utilized | Outcome | Report Dossier |
| :--- | :--- | :--- | :--- | :--- |
| **SOC-001** | Windows Failed Logon Baseline | Event ID 4625 | Preliminary Baseline | [`windows-failed-logon-investigation.md`](04-Investigation-Reports/Authentication/windows-failed-logon-investigation.md) |
| **SOC-AUTH-03** | Unauthorized Account Creation | Event ID 4720, 4732 | Validated Authorized Test | [`account-creation-investigation.md`](04-Investigation-Reports/Authentication/account-creation-investigation.md) |
| **SOC-SSH-01** | SSH Authentication Brute-Force | `linux_auth` (`/var/log/auth.log`)| Validated Password Guessing | [`ssh-brute-force-investigation.md`](04-Investigation-Reports/Brute-Force/ssh-brute-force-investigation.md) |
| **SOC-PROC-01** | Staged Execution (`demo.exe`) | Sysmon Event ID 1 | Validated File Execution | [`Process-Investigation/README.md`](04-Investigation-Reports/Process-Investigation/README.md) |
| **SOC-FILE-02** | Ingress Tool Transfer | Sysmon Event ID 11 | Validated Ingress Drop | [`Suspicious-Files/README.md`](04-Investigation-Reports/Suspicious-Files/README.md) |

---

## ⚔️ Threat Emulation & Simulation Summary

All attack scenarios were conducted in accordance with the test plan in [`07-Attack-Simulation/Test-Scenarios.md`](07-Attack-Simulation/Test-Scenarios.md):

| Test Scenario | Tool Used | Target Service | Expected Event IDs | Detection Outcome |
| :--- | :--- | :--- | :--- | :--- |
| **RDP Brute Force** | Hydra | Port 3389 (RDP) | 4625 | **PASS (100% Detected)** |
| **SSH Password Guessing** | Hydra | Port 22 (SSH) | `linux_auth` | **PASS (100% Detected)** |
| **Multi-Port Port Scan** | Nmap | Ports 21-8080 | Sysmon 3 | **PASS (100% Detected)** |
| **Obfuscated PowerShell** | PowerShell CLI | Windows Host | 4104 | **PASS (100% Detected)** |
| **Tool Drop & Run** | PowerShell / CMD | User Profile | Sysmon 1, 11 | **PASS (100% Detected)** |
| **Privilege Escalation** | `net.exe` | SAM / Security | 4720, 4732 | **PASS (100% Detected)** |

Detailed chronological simulation logs are maintained in [`07-Attack-Simulation/simulation-results-log.md`](07-Attack-Simulation/simulation-results-log.md).

---

## 🚀 Quick Start: Deploying the Lab

### 1. Ingestion Setup (Splunk Forwarder)
Copy [`02-Environment-Setup/splunk-inputs-reference.md`](02-Environment-Setup/splunk-inputs-reference.md) settings to `%SPLUNK_HOME%\etc\system\local\inputs.conf` on your Windows endpoint and restart the forwarder:
```cmd
net stop SplunkForwarder && net start SplunkForwarder
```

### 2. Sysmon v15 Deployment
Install Sysmon using the modular configuration outlined in [`02-Environment-Setup/sysmon-config-notes.md`](02-Environment-Setup/sysmon-config-notes.md):
```cmd
Sysmon64.exe -accepteula -i sysmonconfig.xml
```

### 3. Import the Dashboard
Navigate to **Splunk Web > Dashboards > Create New Dashboard > Source (XML)**, paste the contents of [`05-Dashboards/SOC-L1-dashboard.xml`](05-Dashboards/SOC-L1-dashboard.xml), and click **Save**.

### 4. Run Detection Rules
Open any `.spl` file in [`03-Detection-Rules/`](03-Detection-Rules/) and execute directly in Splunk Search.

---

## 🧠 Core Competencies Demonstrated

- **SIEM Administration & Architecture:** Log ingestion pipelines, `inputs.conf`/`outputs.conf` configuration, index partitioning, forwarding protocols.
- **Detection Engineering:** Advanced SPL querying, threshold modeling, regex data extraction, alert fatigue mitigation.
- **Threat Hunting & Triage:** Sysmon event correlation, parent-child process tree analysis, authentication anomaly hunting.
- **Incident Response:** Structured triage workflows, incident documentation, containment playbooks, forensic evidence preservation.
- **Framework Alignment:** Practical application of **MITRE ATT&CK** matrix across endpoint and network vectors.

---

## 📜 License

This project is licensed under the [MIT License](LICENSE) - see the LICENSE file for details.
My goal is to build a practical SOC monitoring environment that demonstrates my ability to collect and analyze security logs, develop SIEM detection rules, investigate suspicious activities, and present security findings through reports and dashboards.

## Deployment handoff

Start with [`09-Deployment/README.md`](09-Deployment/README.md), then complete
the acceptance record in
[`02-Environment-Setup/environment-details.md`](02-Environment-Setup/environment-details.md).
Before opening a pull request or publishing a release, run:

```bash
python3 scripts/validate_project.py
```

The GitHub Actions workflow runs the same check on every push and pull request.
