# SOC Investigation Report: Suspicious Process Execution (`demo.exe`)

**Incident ID:** SOC-PROC-2026-1030-01  
**Status:** Closed (Validated Authorized Lab Test)  
**Severity:** High (Execution of unverified binary from staging path)  
**Detection Source:** Sysmon Event ID 1 (`XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`)  
**First Seen / Last Seen:** 2026-10-30 19:42:15 UTC  
**Affected Host:** `WIN-ENDPOINT-01` (Sanitized hostname)  
**User / Account:** `WIN-ENDPOINT-01\labadmin`  
**Associated Evidence:** [`06-Evidence/Process-Monitoring/sysmon-process-event-demo-exe.png`](../../06-Evidence/Process-Monitoring/sysmon-process-event-demo-exe.png)

---

## Executive Summary

During endpoint monitoring on `WIN-ENDPOINT-01`, a high-severity alert triggered indicating execution of an untrusted binary named `demo.exe` located within a user-writable directory (`C:\Users\labadmin\Downloads\demo.exe`). Sysmon Event ID 1 captured the full execution telemetry, identifying `cmd.exe` as the parent process. An investigation was conducted to determine execution lineage, file origin, and post-execution network or persistence behavior.

---

## Event Evidence

| Timestamp | Host | Event ID | Image | Parent Process | Command Line | Evidence Reference |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `2026-10-30 19:42:15` | `WIN-ENDPOINT-01` | Sysmon 1 | `C:\Users\labadmin\Downloads\demo.exe` | `C:\Windows\System32\cmd.exe` | `"C:\Users\labadmin\Downloads\demo.exe" -run` | `sysmon-process-event-demo-exe.png` |

---

## Detection Logic

```spl
index=blue EventCode=1
| eval Process_Path=coalesce(Image,image)
| where match(Process_Path,"(?i)\\(temp|appdata|downloads|public|desktop|programdata)\\") AND match(Process_Path,"(?i)\.exe$")
| table _time host User Process_Path ParentImage CommandLine ProcessId ParentProcessId
| sort - _time
```

---

## Investigation Methodology

1. **Process Lineage Verification:**
   - Identified Parent Image as `cmd.exe` (PID 4812) executed by `labadmin`.
   - Determined that `cmd.exe` was spawned interactively via `explorer.exe`, indicating manual operator execution rather than automated lateral movement.
2. **File Creation Telemetry Correlation:**
   - Queried Sysmon Event ID 11 (`TargetFilename="*demo.exe"`) to inspect file drop time and origin.
   - Confirmed file was saved 3 minutes prior from browser process `chrome.exe`.
3. **Network Activity Correlation:**
   - Queried Sysmon Event ID 3 filtered on `ProcessId` of `demo.exe`.
   - No outbound network connections or beaconing activity observed.
4. **Persistence & Child Process Inspection:**
   - Queried for child processes spawned by `demo.exe` (`ParentProcessId=...`).
   - Process terminated cleanly without generating persistence mechanisms (no scheduled tasks or registry run keys created).

---

## Findings & Assessment

- **Observed Facts:** The binary `demo.exe` was executed with `-run` flag from the Downloads directory by an interactive administrator.
- **Assessment:** Activity matches Scenario 2 in the controlled test plan (`07-Attack-Simulation/Test-Scenarios.md`). Non-malicious test binary used to validate detection rules.
- **MITRE ATT&CK Mapping:**
  - **T1204.002:** User Execution: Malicious File
  - **T1059.003:** Command and Scripting Interpreter: Windows Command Shell

---

## Response & Remediation Actions

- Verified binary hash against lab baseline.
- Validated alerting fidelity of Sysmon Event ID 1 rule.
- File removed during post-test cleanup routine.
- Ticket closed as **Authorized Simulation**.
