# Attack Simulation Execution Log

This log chronicles all controlled attack simulations executed within the lab environment, recording execution dates, target assets, triggered detection rules, and validation outcomes.

---

## Chronological Simulation Log

| Simulation ID | Date & Time (UTC) | Adversary Host | Target Host | Attack Scenario | Triggered Rule / Event ID | Outcome | Evidence Reference |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **SIM-2026-001** | 2026-10-28 14:22:10 | `KALI-SIM` (`192.168.10.50`) | `WIN-ENDPOINT-01` | SSH Password Guessing | `ssh-brute-force.spl` (`linux_auth`) | **PASS** | `06-Evidence/SSH-Brute-Force/` |
| **SIM-2026-002** | 2026-10-30 18:14:05 | `KALI-SIM` (`192.168.10.50`) | `WIN-ENDPOINT-01` | RDP Password Brute-Force | `brute-force-threshold-4625.spl` (Event 4625) | **PASS** | `06-Evidence/Windows-Authentication/` |
| **SIM-2026-003** | 2026-10-30 19:39:04 | `WIN-ENDPOINT-01` | `WIN-ENDPOINT-01` | Ingress Executable Drop | `suspicious-exe-creation-11.spl` (Sysmon 11) | **PASS** | `04-Investigation-Reports/Suspicious-Files/` |
| **SIM-2026-004** | 2026-10-30 19:42:15 | `WIN-ENDPOINT-01` | `WIN-ENDPOINT-01` | Execution from Downloads (`demo.exe`) | `suspicious-exe-execution-1.spl` (Sysmon 1) | **PASS** | `06-Evidence/Process-Monitoring/sysmon-process-event-demo-exe.png` |
| **SIM-2026-005** | 2026-10-30 19:55:40 | `KALI-SIM` (`192.168.10.50`) | `WIN-ENDPOINT-01` | Multi-Port Reconnaissance (Nmap) | `network-connection-3.spl` (Sysmon 3) | **PASS** | `03-Detection-Rules/Sysmon/network-connection-3.spl` |
| **SIM-2026-006** | 2026-10-30 20:05:12 | `WIN-ENDPOINT-01` | `WIN-ENDPOINT-01` | Encoded PowerShell Cradle | `suspicious-powershell-4104.spl` (PowerShell 4104) | **PASS** | `03-Detection-Rules/Windows/suspicious-powershell-4104.spl` |
| **SIM-2026-007** | 2026-10-30 20:15:22 | `WIN-ENDPOINT-01` | `WIN-ENDPOINT-01` | Local Account Creation (`backdoor_user`) | `account-creation-4720.spl` (Event 4720) | **PASS** | `04-Investigation-Reports/Authentication/` |
| **SIM-2026-008** | 2026-10-30 20:16:07 | `WIN-ENDPOINT-01` | `WIN-ENDPOINT-01` | Privilege Escalation to Administrators | `privilege-escalation-4728-4732.spl` (Event 4732) | **PASS** | `04-Investigation-Reports/Authentication/` |

---

## Summary of Results

- **Total Simulations Run:** 8
- **Detections Triggered:** 8 (100% detection coverage of executed TTPs)
- **False Negative Rate:** 0%
- **All test artifacts cleaned up following testing:** Yes
