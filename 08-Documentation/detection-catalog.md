# Detection catalog

The catalog is the deployment handoff for the SPL files in `03-Detection-Rules/`.
Thresholds are starting points for this lab and must be tuned against a normal
activity baseline before enabling automated response.

| Rule | File | Telemetry | Starting threshold | ATT&CK context | Expected action |
| --- | --- | --- | --- | --- | --- |
| Windows failed logon | `Windows/failed-logon-4625.spl` | Security 4625 | Review individual events | T1078 context only | Triage source, account, and logon type |
| Windows brute-force threshold | `Windows/brute-force-threshold-4625.spl` | Security 4625 | 5 failures/source/host | T1110 | Correlate with lockout and successful logon |
| Account lockout | `Windows/account-lockout-4740.spl` | Security 4740 | Any lockout | T1110 context | Check caller and affected account |
| New account | `Windows/account-creation-4720.spl` | Security 4720 | Any new account | T1136.001 | Validate approved change |
| Suspicious PowerShell | `Windows/suspicious-powershell-4104.spl` | PowerShell 4104 | Keyword match | T1059.001, T1027 | Review full script and parent process |
| Process creation | `Sysmon/process-creation-1.spl` | Sysmon 1 | Review stream | T1059 context | Pivot on parent, command line, and user |
| Executable creation | `Sysmon/suspicious-exe-creation-11.spl` | Sysmon 11 | User-writable path + `.exe` | T1105 context | Correlate creator and execution |
| Executable execution | `Sysmon/suspicious-exe-execution-1.spl` | Sysmon 1 | User-writable path + `.exe` | T1204 context | Validate file reputation and lineage |
| Network connection | `Sysmon/network-connection-3.spl` | Sysmon 3 | 10 unique destination ports | T1046 context | Verify direction and approved scanner |
| Port scanning | `Network/reconnaissance-port-scanning.spl` | Sysmon 3 | 10 unique destination ports | T1046 | Investigate source/destination pair |
| SSH brute force | `Linux/ssh-brute-force.spl` | OpenSSH auth | 5 failures/source/host | T1110 | Confirm authorized test and account scope |

## Operational guardrails

- A match is a lead, not a confirmed incident.
- Do not enable automatic containment from these searches without a reviewed
  runbook and an approved exception process.
- Use a bounded schedule and time range; document the timezone and dispatch lag.
- Keep the dashboard and searches on the same index, field names, and retention
  assumptions.
