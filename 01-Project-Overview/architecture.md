# SOC Monitoring Lab Architecture

## Overview

This document details the architectural design, network topology, log pipelines, and telemetry flow for the Security Operations Center (SOC) monitoring lab. The environment is designed to simulate a real-world enterprise endpoint and attack scenario, enabling centralized log aggregation, custom detection engineering, threat hunting, and incident investigation.

---

## Architecture Diagram

```
+-----------------------------------------------------------------------------------+
|                              LAB NETWORK (192.168.10.0/24)                        |
+-----------------------------------------------------------------------------------+
                                          |
          +-------------------------------+-------------------------------+
          |                                                               |
+-----------------------+                                       +-----------------------+
|   ATTACK PLATFORM     |                                       |   MONITORED ENDPOINT  |
|   Kali Linux Rolling  |   [Attack Traffic: Port Scans,        |   Windows 11 Pro      |
|   Hostname: KALI-SIM  |    SSH / RDP Brute Force, Payloads]   |   Host: WIN-ENDPOINT-01|
|   IP: 192.168.10.50   | ====================================> |   IP: 192.168.10.15   |
+-----------------------+                                       +-----------------------+
          |                                                                 |
          | [Auth & Command Logs]                                           | [Windows Events,
          |                                                                 |  Sysmon v15,
          |                                                                 |  OpenSSH Logs]
          |                                                                 |
          v                                                                 v
+-----------------------+                                       +-----------------------+
|  Splunk Forwarder     |                                       | Splunk Universal Fwd  |
|  (Linux Forwarder)    |                                       | (v9.3.x on Windows)   |
+-----------------------+                                       +-----------------------+
          |                                                                 |
          |               Port 9997 (Encrypted S2S Forwarding)              |
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
             |   * index=blue       |            |   * 14x SPL Rules    |
             |     - WinEventLog    |            |   * SOC L1 Dashboard |
             |     - Sysmon         |            |   * MITRE Mappings   |
             |   * index=main       |            |   * Alert Workflows  |
             |     - linux_auth     |            |   * Investigation    |
             |     - openssh        |            |     Reports          |
             +----------------------+            +----------------------+
```

---

## Network & Host Specifications

| Role | Hostname (Sanitized) | OS / Platform | Network Address | Primary Function |
| :--- | :--- | :--- | :--- | :--- |
| **SIEM Server** | `SPLUNK-SRV-01` | Windows Server / 11 Pro | `192.168.10.100` | Ingestion, Indexing, SPL Evaluation, Dashboarding |
| **Monitored Endpoint** | `WIN-ENDPOINT-01` | Windows 11 Pro (x64) | `192.168.10.15` | Target workload generating Windows Security & Sysmon telemetry |
| **Adversary Emulation** | `KALI-SIM` | Kali Linux 2024.x | `192.168.10.50` | Controlled attack simulation (Hydra, Nmap, PowerShell payloads) |

---

## Telemetry Pipelines & Ingestion Flow

### 1. Windows Endpoint Telemetry (`WIN-ENDPOINT-01`)
* **Collector:** Splunk Universal Forwarder (v9.3.x)
* **Configuration:** `%SPLUNK_HOME%\etc\apps\Splunk_TA_windows\local\inputs.conf`
* **Channels Ingested:**
  - `WinEventLog://Security`: Event IDs 4624 (Successful Logon), 4625 (Failed Logon), 4720 (User Created), 4728/4732 (Group Membership Changes), 4740 (Account Lockout).
  - `WinEventLog://System`: System lifecycle events, service installations (7045).
  - `WinEventLog://Microsoft-Windows-Sysmon/Operational`: Sysmon v15.x telemetry covering Event ID 1 (Process Creation with Command Line), Event ID 3 (Network Connection), and Event ID 11 (File Creation).
  - `WinEventLog://Microsoft-Windows-PowerShell/Operational`: Event ID 4104 (Script Block Logging).
  - `WinEventLog://OpenSSH/Operational`: Windows OpenSSH authentication and session events.
* **Target Index:** `index=blue` (sourcetypes: `WinEventLog:Security`, `WinEventLog:System`, `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`).

### 2. Linux Adversary & SSH Telemetry (`KALI-SIM`)
* **Collector:** Splunk Universal Forwarder for Linux
* **Channels Ingested:**
  - `/var/log/auth.log`: SSH connection attempts, sudo executions, authentication anomalies.
* **Target Index:** `index=main` (sourcetype: `linux_auth`).

---

## Ingestion & Storage Architecture

* **Receiving Port:** TCP `9997` configured on `SPLUNK-SRV-01` via `inputs.conf`.
* **Splunk Web Interface:** TCP `8000` accessible for SOC analysts.
* **Index Configuration (`indexes.conf`):**
  - **`index=blue`**: Endpoint detection telemetry (Windows Security, Sysmon, PowerShell). Sized for 10 GB hot/warm retention with a 90-day search window.
  - **`index=main`**: Linux host authentication telemetry and supplementary operational logs.

---

## Detection & Investigation Layer

1. **Scheduled Alerts & Saved Searches:** SPL queries monitor for threshold deviations (e.g., $\ge 5$ failed logons within 5 minutes, suspicious execution paths, port scanning heuristics).
2. **SOC L1 Triage Dashboard:** Real-time visibility into authentication failures, account modifications, script block executions, and network reconnaissance.
3. **Investigation Workflow:** Systematic alert validation, evidence preservation, lateral movement correlation, and incident report generation aligned with the MITRE ATT&CK framework.
