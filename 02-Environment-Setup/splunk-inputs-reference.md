# Splunk Forwarder Configuration Reference

This reference documents the configuration files utilized by the **Splunk Universal Forwarder** on `WIN-ENDPOINT-01` and `KALI-SIM` to ingest telemetry into Splunk Enterprise (`SPLUNK-SRV-01`).

---

## 1. Universal Forwarder: `inputs.conf` (Windows Endpoint)

Path: `C:\Program Files\SplunkUniversalForwarder\etc\apps\Splunk_TA_windows\local\inputs.conf`

```ini
[default]
host = WIN-ENDPOINT-01

# --- Windows Security Event Log ---
[WinEventLog://Security]
disabled = 0
start_from = oldest
current_only = 0
checkpointInterval = 5
index = blue
renderXml = false

# --- Windows System Event Log ---
[WinEventLog://System]
disabled = 0
start_from = oldest
current_only = 0
checkpointInterval = 5
index = blue
renderXml = false

# --- Windows Application Event Log ---
[WinEventLog://Application]
disabled = 0
start_from = oldest
current_only = 0
checkpointInterval = 5
index = blue
renderXml = false

# --- Sysmon Operational Telemetry ---
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
start_from = oldest
current_only = 0
checkpointInterval = 5
index = blue
renderXml = true
sourcetype = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

# --- PowerShell Script Block Logging ---
[WinEventLog://Microsoft-Windows-PowerShell/Operational]
disabled = 0
start_from = oldest
current_only = 0
checkpointInterval = 5
index = blue
renderXml = false

# --- Windows OpenSSH Server Operational ---
[WinEventLog://OpenSSH/Operational]
disabled = 0
start_from = oldest
current_only = 0
checkpointInterval = 5
index = blue
renderXml = false
```

---

## 2. Universal Forwarder: `outputs.conf` (Windows Endpoint & Kali)

Path: `C:\Program Files\SplunkUniversalForwarder\etc\system\local\outputs.conf`

```ini
[tcpout]
defaultGroup = default-autolb-group

[tcpout:default-autolb-group]
server = 192.168.10.100:9997

[tcpout-server://192.168.10.100:9997]
```

---

## 3. Kali Linux Forwarder: `inputs.conf`

Path: `/opt/splunkforwarder/etc/system/local/inputs.conf`

```ini
[default]
host = KALI-SIM

[monitor:///var/log/auth.log]
disabled = 0
sourcetype = linux_auth
index = main
```

---

## 4. Splunk Indexer Configuration: `indexes.conf`

Path: `C:\Program Files\Splunk\etc\system\local\indexes.conf` on `SPLUNK-SRV-01`

```ini
[blue]
homePath   = $SPLUNK_DB/blue/db
coldPath   = $SPLUNK_DB/blue/colddb
thawedPath = $SPLUNK_DB/blue/thaweddb
maxTotalDataSizeMB = 10240
frozenTimePeriodInSecs = 7776000
```

---

## 5. Verification Commands

### Forwarder Status Check:
```powershell
& "C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe" status
& "C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe" list forward-server
```

### Ingestion Validation Search in Splunk:
```spl
| tstats count where index=blue by sourcetype host
```
