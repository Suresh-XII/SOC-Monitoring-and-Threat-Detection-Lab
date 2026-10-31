# Evidence Register

These screenshots were supplied for the SOC lab documentation. Keep them in the private repository while they contain internal host/user labels and a private LAN address. Review and sanitize them before any public release. Repeated identical attachments were deduplicated: the overview screenshot appeared three times and the SSH search-results screenshot appeared twice.

| Folder | Evidence |
| --- | --- |
| `SSH-Brute-Force/` | SOC dashboard, SSH failed-password search, raw auth event details |
| `Splunk-Ingestion/` | Index/sourcetype summary and separate daily event summary |
| `Splunk-Alert-Workflow/` | Dashboard inventory, alert setup dialog, report dialog |
| `Linux-Telemetry/` | Linux systemd/syslog events |
| `Windows-Authentication/` | Windows System event review |
| `Process-Monitoring/` | Sysmon process event showing a demo executable path |
| `Environment-Context/` | File-in-use dialog; contextual only, not incident evidence |

The screenshots show different searches and time ranges. Do not combine event counts unless the query, time window, and aggregation match.
