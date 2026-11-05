<<<<<<< HEAD
# Detection Rules Catalog

This directory maintains the **Splunk Search Processing Language (SPL)** detection rules authored and validated in the SOC lab environment. Each rule addresses a specific attack technique mapped to the **MITRE ATT&CK Framework**.

---

## Detection Inventory & Rule Index

| File Name | Log Source | Event ID | MITRE ATT&CK | Severity | Primary Detection Logic |
| :--- | :--- | :--- | :--- | :--- | :--- |
| [`Windows/failed-logon-4625.spl`](Windows/failed-logon-4625.spl) | Security | 4625 | T1110 | Info/Low | Raw review of failed Windows authentication |
| [`Windows/brute-force-threshold-4625.spl`](Windows/brute-force-threshold-4625.spl) | Security | 4625 | T1110.001 | High | Aggregates sources with $\ge 5$ logon failures |
| [`Windows/successful-logon-4624.spl`](Windows/successful-logon-4624.spl) | Security | 4624 | T1078 | Context | Successful logon baseline & post-attack correlation |
| [`Windows/account-creation-4720.spl`](Windows/account-creation-4720.spl) | Security | 4720 | T1136.001 | Medium | Detects creation of new local/domain user accounts |
| [`Windows/account-lockout-4740.spl`](Windows/account-lockout-4740.spl) | Security | 4740 | T1110.001 | Medium | Detects account lockouts & calling machines |
| [`Windows/privilege-escalation-4728-4732.spl`](Windows/privilege-escalation-4728-4732.spl) | Security | 4728/4732 | T1098 | High | Detects addition of users to privileged groups |
| [`Windows/suspicious-powershell-4104.spl`](Windows/suspicious-powershell-4104.spl) | PowerShell | 4104 | T1059.001 | High | Keyword search for Base64, IEX, and bypass flags |
| [`Sysmon/process-creation-1.spl`](Sysmon/process-creation-1.spl) | Sysmon | 1 | T1059 | Context | Process creation baseline with GUIDs & command line |
| [`Sysmon/network-connection-3.spl`](Sysmon/network-connection-3.spl) | Sysmon | 3 | T1046 | Medium/High | Multi-port connection heuristic ($\ge 10$ unique ports) |
| [`Sysmon/suspicious-exe-creation-11.spl`](Sysmon/suspicious-exe-creation-11.spl) | Sysmon | 11 | T1105 | High | Executable drops into Temp, AppData, Downloads, etc. |
| [`Sysmon/suspicious-exe-execution-1.spl`](Sysmon/suspicious-exe-execution-1.spl) | Sysmon | 1 | T1204.002 | High | Execution from user-writable and temporary directories |
| [`Sysmon/suspicious-powershell-investigation.spl`](Sysmon/suspicious-powershell-investigation.spl) | Sysmon | 1 | T1059.001 | Medium | Lineage investigation for powershell.exe / pwsh.exe |
| [`Linux/ssh-brute-force.spl`](Linux/ssh-brute-force.spl) | linux_auth | Auth.log | T1110.001 | High | Regex extraction of SSH failed passwords ($\ge 5$) |
| [`Network/reconnaissance-port-scanning.spl`](Network/reconnaissance-port-scanning.spl) | Sysmon | 3 | T1046 | Medium/High | Identifies port scanning activity across hosts |

---

## How to Deploy Rules into Splunk

1. **Ad-Hoc Search:** Copy any `.spl` query directly into the Splunk Enterprise Search bar with the appropriate time range (e.g., `Last 24 hours`).
2. **Scheduled Alert Creation:**
   - In Splunk Web, execute the detection query.
   - Click **Save As > Alert**.
   - Set **Schedule:** Cron expression (e.g., `*/5 * * * *` for every 5 minutes).
   - Set **Trigger Condition:** Number of results > 0.
   - Configure **Actions:** Add to Triggered Alerts, send webhook, or send email notification.
3. **Integration into SOC Dashboards:** Use the queries as data inputs for single-value indicators, charts, or event tables.
=======
# Detection rules

These SPL searches are investigation and triage content for the lab. They are
not production detections until field extraction, thresholds, schedule, owner,
and response actions are validated in the target Splunk instance.

## Deployment checklist

1. Confirm the target index and sourcetype. The repository standard is `index=blue`.
2. Run each search over a known test window and save the raw event used for validation.
3. Configure a saved search with the owner, schedule, alert threshold, and suppression policy.
4. Link the saved search to the corresponding dashboard panel or investigation report.
5. Record the result in `02-Environment-Setup/environment-details.md`.

The catalog in `08-Documentation/detection-catalog.md` is the authoritative
inventory of use cases, event IDs, thresholds, and known limitations.
>>>>>>> 488e040c7b911fe60abbd5b4e3ba290621f279fc
