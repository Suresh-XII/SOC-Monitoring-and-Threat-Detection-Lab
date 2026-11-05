# Environment Setup & Configuration Details

## 1. Splunk Enterprise (Central SIEM)
Use this file as the environment acceptance record. Replace bracketed values with
sanitized values before publishing. Never commit passwords, tokens, private keys,
real public IP addresses, or unredacted internal hostnames.

This file is a checklist, not a claim that every step is already configured. Record actual versions and sanitized configuration snippets.


- **Version / Build:** Splunk Enterprise 9.3.1 (Build e0b7931c8d)
- **Host OS:** Windows 11 Pro 64-bit / Windows Server
- **Sanitized Hostname:** `SPLUNK-SRV-01`
- **Management Web Port:** `8000` (`http://192.168.10.100:8000`)
- **Receiving Port:** TCP `9997` (Configured via `Settings > Forwarding and receiving > Receive data`)
- **Indexes Configured:**
  - `blue`: Endpoint Windows Security, Sysmon, PowerShell, Application, System. Max size: 10 GB.
  - `main`: Default index; Linux authentication logs (`/var/log/auth.log`).
- **Search Time Zone:** UTC / Local (System Timezone synchronized via NTP)

---

## 2. Universal Forwarder (Windows Endpoint)

- **Version / Build:** Splunk Universal Forwarder 9.3.1
- **Target Host:** `WIN-ENDPOINT-01` (`192.168.10.15`)
- **Service Status:** Running (`SplunkForwarder` service configured for Automatic start)
- **Inputs Configuration Path:** `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`
- **Outputs Configuration Path:** `C:\Program Files\SplunkUniversalForwarder\etc\system\local\outputs.conf`
- **Forwarding Destination:** `192.168.10.100:9997`
- **Monitored Event Channels:**
  - `WinEventLog://Security` -> `index = blue`
  - `WinEventLog://System` -> `index = blue`
  - `WinEventLog://Application` -> `index = blue`
  - `WinEventLog://Microsoft-Windows-Sysmon/Operational` -> `index = blue`
  - `WinEventLog://Microsoft-Windows-PowerShell/Operational` -> `index = blue`
  - `WinEventLog://OpenSSH/Operational` -> `index = blue`

---

## 3. Windows Endpoint Auditing Policies

Configured via Local Security Policy (`secpol.msc`) and PowerShell:

| Audit Category / Subcategory | Setting | Monitored Event IDs |
| :--- | :--- | :--- |
| **Logon/Logoff:** Audit Logon | Success and Failure | 4624 (Logon), 4625 (Failed Logon) |
| **Logon/Logoff:** Audit Account Lockout | Success | 4740 (Account Locked Out) |
| **Account Management:** Audit User Account Management | Success and Failure | 4720 (User Created), 4722 (Enabled), 4726 (Deleted) |
| **Account Management:** Audit Security Group Management | Success and Failure | 4728 (Member Added to Global Group), 4732 (Local Group) |
| **Privilege Use:** Audit Sensitive Privilege Use | Success and Failure | 4672 (Special Privileges Assigned) |
| **Detailed Tracking:** Audit Process Creation | Success | 4688 (Process Creation with CommandLine) |

### PowerShell Script Block Logging:
- **Registry Key:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`
- **Value:** `EnableScriptBlockLogging = 1`
- **Event Captured:** Event ID 4104 (`Microsoft-Windows-PowerShell/Operational`)

---

## 4. Sysmon (System Monitor) v15.x

- **Sysmon Binary:** Sysmon64.exe v15.11
- **Configuration Schema:** Schema version 4.90 (Modular XML)
- **Deployment Command:**
  ```cmd
  Sysmon64.exe -accepteula -i C:\Tools\sysmonconfig.xml
  ```
- **Monitored Telemetry:**
  - **Event ID 1:** Process Creation (Captures hashes SHA256/MD5, ParentImage, CommandLine).
  - **Event ID 3:** Network Connection (Captures SourceIp, DestinationIp, DestinationPort, Protocol, Image).
  - **Event ID 11:** File Creation (Targets executable drop paths: `\AppData\`, `\Temp\`, `\Downloads\`, `\ProgramData\`).

---

## 5. Linux Adversary Machine (Kali Linux)

- **OS / Distribution:** Kali Linux Rolling 2024.x
- **Sanitized Hostname:** `KALI-SIM` (`192.168.10.50`)
- **Telemetry Collected:** `/var/log/auth.log` forwarded to `SPLUNK-SRV-01:9997` into `index=main` sourcetype `linux_auth`.
- **Simulation Tooling:**
  - `hydra`: Automated network and SSH brute-force testing.
  - `nmap`: Host discovery and multi-port scanning.
  - `metasploit-framework` / `powershell-empire`: Simulated post-exploitation commands.

---

## 6. Verification & Validation Checklist

| Telemetry Source | Expected Event ID | Verified in Splunk | Extracted Key Fields |
| :--- | :--- | :--- | :--- |
| Windows Security | Event ID 4625 (Failed Logon) | **VERIFIED** | `TargetUserName`, `IpAddress`, `Status`, `SubStatus` |
| Windows Security | Event ID 4624 (Success Logon) | **VERIFIED** | `TargetUserName`, `IpAddress`, `LogonType` |
| Windows Security | Event ID 4720 (User Created) | **VERIFIED** | `TargetUserName`, `SubjectUserName` |
| Windows Security | Event ID 4740 (Account Lockout) | **VERIFIED** | `TargetUserName`, `CallerComputerName` |
| Windows PowerShell | Event ID 4104 (Script Block) | **VERIFIED** | `ScriptBlockText`, `user`, `Path` |
| Sysmon Operational | Event ID 1 (Process Create) | **VERIFIED** | `Image`, `ParentImage`, `CommandLine`, `User` |
| Sysmon Operational | Event ID 3 (Network Connect) | **VERIFIED** | `SourceIp`, `DestinationIp`, `DestinationPort` |
| Sysmon Operational | Event ID 11 (File Create) | **VERIFIED** | `TargetFilename`, `Image`, `User` |
| Linux Auth | SSH Failed Password | **VERIFIED** | `user`, `src_ip`, `host` |

For each source, record one known test event and confirm its raw event, timestamp, host, index, sourcetype, and extracted fields in Splunk.

| Source | Test event/time (UTC) | Index | Sourcetype | Expected fields | Result |
| --- | --- | --- | --- | --- | --- |
| Windows Security | `[record]` | `blue` | `[record]` | `EventCode`, `host`, `_time` | `[Pass/Fail]` |
| Sysmon | `[record]` | `blue` | `[record]` | `EventCode`, `Image`, `_time` | `[Pass/Fail]` |
| OpenSSH (optional) | `[record]` | `blue` | `linux_auth` | `user`, `src_ip`, `_time` | `[Pass/Fail]` |

## Deployment acceptance criteria

- [ ] Splunk receives events continuously for the agreed test window.
- [ ] All dashboard panels return either data or an explained zero-event result.
- [ ] Each enabled detection has a saved-search owner, schedule, threshold, and response action.
- [ ] Test evidence is sanitized and linked from the relevant investigation report.
