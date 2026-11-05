# MITRE ATT&CK Detection Coverage & Mapping

This document maps all detection rules developed in this project to the **MITRE ATT&CK Enterprise Matrix (v14)**. Each mapping connects adversary tactics and techniques to specific telemetry sources, event identifiers, and detection logic.

---

## MITRE ATT&CK Detection Matrix

| Tactic | Technique Name | Technique ID | Sub-technique | Detection Rule | Telemetry Source | Event ID | Confidence | Severity |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Credential Access** | Brute Force | `T1110` | `T1110.001` Password Guessing | [`brute-force-threshold-4625.spl`](../03-Detection-Rules/Windows/brute-force-threshold-4625.spl) | WinEventLog:Security | 4625 | High | High |
| **Credential Access** | Brute Force | `T1110` | `T1110.001` Password Guessing | [`ssh-brute-force.spl`](../03-Detection-Rules/Linux/ssh-brute-force.spl) | linux_auth | Auth.log | High | High |
| **Credential Access** | Brute Force | `T1110` | `T1110.001` Password Guessing | [`account-lockout-4740.spl`](../03-Detection-Rules/Windows/account-lockout-4740.spl) | WinEventLog:Security | 4740 | High | Medium |
| **Execution** | Command & Scripting Interpreter | `T1059` | `T1059.001` PowerShell | [`suspicious-powershell-4104.spl`](../03-Detection-Rules/Windows/suspicious-powershell-4104.spl) | WinEventLog:PowerShell | 4104 | High | High |
| **Execution** | Command & Scripting Interpreter | `T1059` | `T1059.001` PowerShell | [`suspicious-powershell-investigation.spl`](../03-Detection-Rules/Sysmon/suspicious-powershell-investigation.spl) | Sysmon Operational | 1 | Medium | Medium |
| **Execution** | User Execution | `T1204` | `T1204.002` Malicious File | [`suspicious-exe-execution-1.spl`](../03-Detection-Rules/Sysmon/suspicious-exe-execution-1.spl) | Sysmon Operational | 1 | High | High |
| **Persistence** | Create Account | `T1136` | `T1136.001` Local Account | [`account-creation-4720.spl`](../03-Detection-Rules/Windows/account-creation-4720.spl) | WinEventLog:Security | 4720 | High | Medium |
| **Privilege Escalation** | Account Manipulation | `T1098` | - | [`privilege-escalation-4728-4732.spl`](../03-Detection-Rules/Windows/privilege-escalation-4728-4732.spl) | WinEventLog:Security | 4728, 4732 | High | High |
| **Defense Evasion** | Obfuscated Files or Info | `T1027` | - | [`suspicious-powershell-4104.spl`](../03-Detection-Rules/Windows/suspicious-powershell-4104.spl) | WinEventLog:PowerShell | 4104 | High | High |
| **Defense Evasion** | Deobfuscate/Decode Files | `T1140` | - | [`suspicious-powershell-4104.spl`](../03-Detection-Rules/Windows/suspicious-powershell-4104.spl) | WinEventLog:PowerShell | 4104 | High | High |
| **Command and Control** | Ingress Tool Transfer | `T1105` | - | [`suspicious-exe-creation-11.spl`](../03-Detection-Rules/Sysmon/suspicious-exe-creation-11.spl) | Sysmon Operational | 11 | High | High |
| **Discovery** | Network Service Discovery | `T1046` | - | [`network-connection-3.spl`](../03-Detection-Rules/Sysmon/network-connection-3.spl) | Sysmon Operational | 3 | Medium | Medium/High |
| **Discovery** | Network Service Discovery | `T1046` | - | [`reconnaissance-port-scanning.spl`](../03-Detection-Rules/Network/reconnaissance-port-scanning.spl) | Sysmon Operational | 3 | Medium | Medium/High |
| **Initial Access / Lateral** | Valid Accounts | `T1078` | - | [`successful-logon-4624.spl`](../03-Detection-Rules/Windows/successful-logon-4624.spl) | WinEventLog:Security | 4624 | High | Contextual |

---

## ATT&CK Coverage Summary

```
+---------------------------------------------------------------------------------------------------------+
| Initial Access | Execution     | Persistence   | Priv Escalation | Defense Evasion | Discovery  | C2    |
|----------------+---------------+---------------+-----------------+-----------------+------------+-------|
| T1078          | T1059.001     | T1136.001     | T1098           | T1027           | T1046      | T1105 |
| (Valid Accts)  | (PowerShell)  | (Local Acct)  | (Acct Tamper)   | (Obfuscation)   | (Net Scan) | (Tool |
|                | T1204.002     |               |                 | T1140           |            | Trans)|
|                | (User Exec)   |               |                 | (Deobfuscate)   |            |       |
+---------------------------------------------------------------------------------------------------------+
```

---

## Mapping Conditions & Analyst Guidance

1. **Evidence-Based Mapping:** Detections are mapped to ATT&CK techniques only when supporting event artifacts corroborate the behavior (e.g., repeatedly failed authentications from a single host for `T1110`).
2. **Contextual Distinction:** Single events (e.g. an isolated Event 4625 or PowerShell launch) do not warrant a threat technique verdict without contextual aggregation.
