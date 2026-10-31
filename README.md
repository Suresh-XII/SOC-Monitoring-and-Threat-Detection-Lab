# SOC Monitoring and Threat Detection Lab

A hands-on SOC monitoring portfolio project using Splunk, Windows security telemetry, Sysmon, and controlled Kali Linux simulations. It documents detection logic, analyst investigation steps, and evidence for a small home lab.

> **Status:** Starter repository based on the lab details shared so far. Queries and dashboard searches are examples that must be validated against your actual sourcetypes, field extractions, and events. The available screenshot showed one Windows Event ID 4625 on host `Suresh` on 30 October 2026; that single failure does not establish brute force. Screenshots and other evidence have not been supplied in this package.

## Project goals

- Centralize Windows logs in Splunk (index: `blue`, as stated in the shared chat).
- Monitor failed logons, account changes, suspicious PowerShell, executable creation/execution, and network connections.
- Investigate alerts with timestamps, hosts, users, process context, and supporting events.
- Present a compact SOC L1 dashboard and reproducible SPL examples.

## Repository map

| Path | Contents |
| --- | --- |
| `01-Project-Overview/` | Scope, objectives, and architecture template |
| `02-Environment-Setup/` | Setup notes with fields to complete from the real environment |
| `03-Detection-Rules/` | SPL searches grouped by Windows, Sysmon, and network use case |
| `04-Investigation-Reports/` | Incident report and investigation templates |
| `05-Dashboards/` | Splunk Simple XML dashboard |
| `06-Evidence/` | Directories for genuine screenshots and sanitized artifacts |
| `07-Attack-Simulation/` | Controlled lab test plan |
| `08-Documentation/` | Investigation workflow, MITRE notes, and limitations |

## Lab architecture (reported)

The shared chat describes Splunk Enterprise on Windows, a Universal Forwarder on Windows and Kali, Kali used to simulate attacks against Windows, and Windows Security, System, and Sysmon logs collected. Confirm each role and data flow before treating this as the final architecture. See [architecture](01-Project-Overview/architecture.md).

## Detection use cases

- Windows failed logon (4625) and threshold-based brute-force triage
- Account creation (4720), lockout (4740), and selected privilege/group changes
- PowerShell Script Block Logging (4104)
- Sysmon process creation (1), network connection (3), and file creation (11)
- Potential network reconnaissance based on unique destination ports

## Getting started

1. Confirm Splunk, forwarder, Sysmon, and Windows audit policy settings in `02-Environment-Setup/`.
2. Inspect raw events and verify field names before using the searches in `03-Detection-Rules/`.
3. Import `05-Dashboards/SOC-L1-dashboard.xml` as a Classic Simple XML dashboard and validate each panel.
4. Run controlled tests only on systems you own or are authorized to assess; record the test and matching telemetry.
5. Write one report per validated detection using the template in `04-Investigation-Reports/`.
6. Add genuine, sanitized screenshots under `06-Evidence/` and link them from the relevant report.

## Evidence and accuracy

The initial failed-logon screenshot identified EventCode 4625, Windows Security, host `Suresh`, and a failed authentication. It did not show a username, source IP, or process. Those values are intentionally not guessed. The incident report is marked preliminary pending corroborating events.

## Safety and privacy

Use only authorized lab systems. Sanitize public screenshots and configurations; remove credentials, tokens, private keys, personal data, and real network details that should not be disclosed. Never publish raw logs without reviewing them for sensitive information.

## License

MIT; see [LICENSE](LICENSE).
