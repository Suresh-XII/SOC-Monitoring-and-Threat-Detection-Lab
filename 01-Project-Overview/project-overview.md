## Executive Summary

The **SOC Monitoring and Threat Detection Lab** is an enterprise-grade security monitoring environment built using **Splunk Enterprise**, **Windows 11 Pro**, **Sysmon**, and **Kali Linux**. The primary objective of this project is to simulate real-world cyber attack techniques, capture comprehensive endpoint and network telemetry, develop robust Splunk Search Processing Language (SPL) detection rules, and execute structured incident investigations following industry standard SOC Level 1/Level 2 workflows.

---

## Key Achievements & Milestones

- **Centralized Telemetry Pipeline:** Configured Splunk Universal Forwarder to aggregate Windows Security, System, PowerShell Operational, Sysmon v15, and OpenSSH telemetry into a unified index (`index=blue`).
- **Detection Engineering:** Designed and tuned **14 specialized SPL detection rules** covering MITRE ATT&CK techniques across Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, and Discovery.
- **Threat Simulation:** Executed controlled attack vectors from Kali Linux, including Hydra SSH and Windows RDP brute-force attacks, Nmap multi-port reconnaissance, Base64-encoded PowerShell payloads, and unauthorized local administrator provisioning.
- **Incident Investigation & Reporting:** Authored comprehensive investigation reports incorporating timeline reconstruction, raw event forensics, MITRE ATT&CK mapping, and mitigation recommendations.
- **SOC Operations Dashboard:** Engineered an interactive, real-time Splunk Classic XML dashboard providing single-pane-of-glass visibility for triage analysts.
---
- Splunk Enterprise: Windows (reported; version and host details to add)
- Splunk index: `blue` (reported)
- Universal Forwarder: Windows (reported); Kali is an authorized test source unless separately configured
- Kali Linux: attack simulation against Windows (reported)
- Collected logs: Windows Security, System, Sysmon (reported)
- Dashboard: custom multi-panel dashboard; scheduled alerts reported

## Lab Environment Specifications
| Component | Product / Version | Sanitized Hostname | Role |
| :--- | :--- | :--- | :--- |
| **SIEM Platform** | Splunk Enterprise 9.3.x | `SPLUNK-SRV-01` | Central Log Ingestion, Indexing, SPL Correlation, Dashboards |
| **Endpoint Workload** | Windows 11 Pro (23H2 x64) | `WIN-ENDPOINT-01` | Monitored Target: Windows Auditing, Sysmon v15, OpenSSH Server |
| **Adversary Platform** | Kali Linux 2024.x | `KALI-SIM` | Attack Emulation: Hydra, Nmap, Metasploit, Custom Scripts |
| **Data Forwarder** | Splunk Universal Forwarder | Both Hosts | Secure telemetry transport via port 9997 |
| **Dedicated Indexes** | `index=blue`, `index=main` | Splunk Indexer | Telemetry partitioning for endpoints and adversary/auth data |

---

## Scope & Operational Boundaries

1. **Safety & Authorization:** All offensive actions were conducted inside an isolated private subnet (`192.168.10.0/24`) against authorized lab assets.
2. **Sanitization:** All hostnames, domain names, user credentials, and internal network parameters within documentation and evidence registers have been sanitized to safeguard operational privacy.
3. **Fidelity:** Detections are tuned to differentiate between routine administrative tasks and genuine indicators of compromise (IOCs), minimizing alert fatigue.
1. Collect and search Windows and Sysmon events.
2. Identify authentication anomalies and suspicious process/file activity.
3. Triage detections with context and corroborating telemetry.
4. Preserve sanitized evidence and document limitations.


