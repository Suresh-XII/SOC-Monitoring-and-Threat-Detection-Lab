# SOC L1 Threat Monitoring & Triage Dashboard Overview

## Purpose & Scope

The **SOC L1 Threat Monitoring & Triage Dashboard** (`SOC-L1-dashboard.xml`) provides Tier 1 SOC analysts with an operational, single-pane-of-glass overview of endpoint and network security posture. It ingests telemetry from `index=blue` (Windows Security, Sysmon, and PowerShell Operational logs), presenting key performance indicators (KPIs), categorized event distributions, threat tables, and a real-time event triage stream.

---

## Dashboard Architecture & Layout

```
+---------------------------------------------------------------------------------------------------+
|  FILTERS: [ Time Range Picker ]                                     [ Host Filter: * ]            |
+---------------------------------------------------------------------------------------------------+
|  [ Total Events ]  [ Failed Logons ]  [ Lockouts ]  [ New Accounts ]  [ PowerShell ]  [ Port Scan]|
+---------------------------------------------------------------------------------------------------+
|  [ Top Brute Force Sources Table (>= 5 Failures) ]  | [ Suspicious Executable Paths (Sysmon 1/11)]|
+---------------------------------------------------------------------------------------------------+
|  [ Security Events by Use Case (Bar Chart) ]        | [ Security Event Volume Timeline (Line)]    |
+---------------------------------------------------------------------------------------------------+
|  [ Recent SOC L1 Triage Stream (Real-Time 30s Auto-Refresh Table)                                ] |
+---------------------------------------------------------------------------------------------------+
```

---

## Detailed Panel Breakdown & Triage Guidance

### 1. KPI Single-Value Panels
- **Total Security Events:** Total count of ingested endpoint events in the selected interval.
  - *Triage Action:* Establishes baseline log volume. Drops to zero indicate forwarder outages.
- **Failed Logons (4625):** Aggregated count of Windows Event ID 4625.
  - *Thresholds:* Green (< 5), Orange (5-19), Red ($\ge 20$).
  - *Triage Action:* Spikes indicate potential password spraying or dictionary attacks.
- **Account Lockouts (4740):** Total count of locked accounts.
  - *Thresholds:* Green (0), Orange (1-4), Red ($\ge 5$).
  - *Triage Action:* Cross-reference with Caller Computer Name to locate the source machine.
- **New Account Created (4720):** Total user accounts provisioned.
  - *Thresholds:* Green (0), Orange ($\ge 1$).
  - *Triage Action:* Must be verified against approved administrative change tickets.
- **Suspicious PowerShell (4104):** Counts script blocks matching high-risk signatures (e.g. `FromBase64String`, `DownloadString`, `IEX`, `ExecutionPolicy Bypass`).
  - *Thresholds:* Green (0), Red ($\ge 1$).
  - *Triage Action:* Immediate inspection of de-obfuscated script block text.
- **Port Scanning Pairs:** Count of source-destination pairs exhibiting connections to $\ge 10$ unique ports.
  - *Thresholds:* Green (0), Orange (1-2), Red ($\ge 3$).

### 2. Threat Analysis Tables
- **Top Brute Force Sources:** Displays Source IP, targeted accounts, failure counts, and assigned severity (`High`, `Medium`, `Low`).
  - *Analyst Response:* Check if source IP is external or internal. Determine if failures were followed by an Event ID 4624 (successful logon).
- **Suspicious Executables in User-Writable Paths:** Highlights files created (`EventCode=11`) or executed (`EventCode=1`) inside `\Temp\`, `\AppData\`, `\Downloads\`, `\Public\`, or `\ProgramData\`.
  - *Analyst Response:* Inspect `CommandLine` and `ParentImage`. Calculate cryptographic file hash and check against threat intelligence (VirusTotal).

### 3. Visual Trend Analytics
- **Security Events by Tactic / Use Case (Bar Chart):** Visualizes the proportion of events belonging to Authentication Failures, Account Modifications, PowerShell Activity, Process/File Activity, and Network Connections.
- **Security Event Volume Timeline (Line Chart):** 15-minute bucketed timechart displaying anomaly spikes in telemetry volume.

### 4. Recent SOC L1 Triage Stream
- Live stream displaying the most recent 100 triage events, refreshing automatically every 30 seconds.
- Enables analysts to observe ongoing activity in real time without manually reloading searches.

---

## How to Import into Splunk Enterprise

1. Navigate to **Splunk Enterprise > Search & Reporting**.
2. Click **Dashboards** in the top navigation bar.
3. Click **Create New Dashboard**.
4. Enter Dashboard Title: `SOC L1 Threat Monitoring & Triage Dashboard`.
5. Switch to **Source** mode (XML editor).
6. Replace all existing XML with the contents of [`SOC-L1-dashboard.xml`](SOC-L1-dashboard.xml).
7. Click **Save** and verify data renders from `index=blue`.
