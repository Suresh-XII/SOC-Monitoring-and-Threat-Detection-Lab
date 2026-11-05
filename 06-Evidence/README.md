# SOC Lab Evidence Register

This register indexes all raw forensic evidence, screenshots, and telemetry exports captured during the lab exercises. All artifacts have been sanitized to remove private network parameters, real user names, and proprietary configurations.

---

## Evidence Index & Mapping

| Directory | Evidence Filename | Telemetry Type | Captured Event IDs | Sanitization Status | Associated Investigation / Scenario |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `SSH-Brute-Force/` | `soc-dashboard-ssh-summary.png` | Splunk Dashboard Panel | `linux_auth` | Sanitized | SSH Brute-Force Investigation |
| `SSH-Brute-Force/` | `ssh-failed-password-search.png` | Splunk Search Query View | `linux_auth` | Sanitized | SSH Brute-Force Investigation |
| `SSH-Brute-Force/` | `ssh-auth-event-details.png` | Raw Event Ingestion Log | `linux_auth` | Sanitized | SSH Brute-Force Investigation |
| `Process-Monitoring/`| `sysmon-process-event-demo-exe.png`| Sysmon Operational Log | Sysmon Event ID 1 | Sanitized | Process Investigation (`demo.exe`) |
| `Linux-Telemetry/` | `linux-systemd-events.png` | Linux Syslog / Systemd | `systemd`, `auth` | Sanitized | Linux Host Health Telemetry |
| `Windows-Authentication/` | `windows-system-events-review.png` | Windows Event Log | Event ID 4625 | Sanitized | Windows Failed Logon Investigation |
| `Splunk-Ingestion/` | `ingestion-summary-2026-10-30.png` | Splunk Source/Sourcetype | All Ingested Sources | Sanitized | Ingestion Verification |
| `Splunk-Ingestion/` | `daily-event-summary-2026-10-30.png` | Daily Event Ingestion Stats| All Indexes | Sanitized | Capacity & Retention Triage |
| `Splunk-Alert-Workflow/` | `dashboard-inventory.png` | Splunk Dashboard Catalog | Classic XML Views | Sanitized | Dashboard Setup Reference |
| `Splunk-Alert-Workflow/` | `save-alert-settings.png` | Alert Trigger Setup Modal | Scheduled Searches | Sanitized | Alerting Workflow Documentation |
| `Splunk-Alert-Workflow/` | `save-report-dialog.png` | Splunk Report Configuration | Saved SPL Reports | Sanitized | Reporting Workflow Reference |
| `Environment-Context/` | `file-in-use-dialog.png` | OS Operational Context | System Notification | Sanitized | Lab Troubleshooting Documentation |

---

## Sanitization Protocol

1. **IP Addresses:** Internal addresses replaced with standardized RFC 1918 blocks (`192.168.10.0/24`).
2. **User Accounts:** Administrative identities mapped to generic labels (`labadmin`, `WIN-ENDPOINT-01`).
3. **Domain & Hostnames:** Internal systems sanitized to structured names (`SPLUNK-SRV-01`, `WIN-ENDPOINT-01`, `KALI-SIM`).
4. **Binary & Malware Safety:** No live or compiled malicious binaries are committed. Benign binaries (e.g. `whoami.exe` renamed to `demo.exe`) are used exclusively.
