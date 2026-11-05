# SOC L1 Investigation Workflows & Incident Response Playbooks

## Core Tier 1 Investigation Lifecycle

```
+-------------------+      +-------------------+      +-------------------+      +-------------------+
| 1. ALERT TRIAGE   | ---> | 2. TELEMETRY      | ---> | 3. CORRELATION    | ---> | 4. ASSESSMENT &   |
| - Verify Index    |      |    EXTRACTION     |      | - Process Lineage |      |    CONTAINMENT    |
| - Validate Event  |      | - Identify Host   |      | - Network Conns   |      | - True/False Pos  |
| - Check Threshold |      | - Extract Users   |      | - Auth Baseline   |      | - Isolate/Escalate|
+-------------------+      +-------------------+      +-------------------+      +-------------------+
```

---

## Playbook 1: Windows Authentication Failure / Brute Force (Event 4625 / 4740)

### Phase 1: Alert Validation
1. Verify timestamp, source IP (`IpAddress`), workstation name, and targeted account (`TargetUserName`).
2. Run `brute-force-threshold-4625.spl` over a $\pm 1$ hour window to count total failures.
3. Check SubStatus failure code:
   - `0xC000006A`: Bad password (user name is valid).
   - `0xC0000064`: User name does not exist.
   - `0xC0000234`: Account locked out.

### Phase 2: Correlation & Impact Check
1. Execute `successful-logon-4624.spl` for the same `Source_IP` to determine if brute force was successful:
   ```spl
   index=blue EventCode=4624 IpAddress="<SOURCE_IP>"
   ```
2. If successful logon is observed after consecutive failures -> **Escalate to Tier 2 / Incident Response immediately (P1 Incident)**.

### Phase 3: Containment & Remediation
- If internal source: Isolate originating machine for malware triage.
- If external source: Add IP to perimeter firewall blocklist.
- Unlock affected account and enforce credential reset.

---

## Playbook 2: Suspicious PowerShell Execution (Event 4104 / Sysmon 1)

### Phase 1: Script De-obfuscation
1. Locate Event ID 4104 in `Microsoft-Windows-PowerShell/Operational`.
2. Extract full `ScriptBlockText`. If Base64 encoded, decode using CyberChef or PowerShell:
   ```powershell
   [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("<BASE64_STRING>"))
   ```
3. Identify download URLs, dropped paths, or memory injection techniques.

### Phase 2: Process Tree Reconstruction (Sysmon 1)
1. Query Sysmon Event ID 1 using `ProcessGuid` or `ProcessId`:
   ```spl
   index=blue EventCode=1 (ProcessGuid="<GUID>" OR ParentProcessGuid="<GUID>")
   | table _time ParentImage Image CommandLine User
   ```
2. Determine if spawned by Office binaries (`winword.exe`), script hosts (`wscript.exe`), or web services.

### Phase 3: Remediation
- Terminate malicious process tree.
- Delete dropped payload from disk.
- Block any identified C2 domains or IP addresses at DNS/Proxy layer.

---

## Playbook 3: Suspicious Executable Drops & Execution (Sysmon 11 & 1)

### Phase 1: File Verification
1. Inspect file path (`TargetFilename`). Staging paths like `\Temp\`, `\AppData\`, or `\Public\` require heightened scrutiny.
2. Check file hash (SHA256 from Sysmon 1) against threat intelligence databases (VirusTotal).

### Phase 2: Network & Persistence Correlation
1. Query Sysmon Event ID 3 for network connections initiated by the process.
2. Check for persistence creation:
   - Registry Run Keys (Event ID 13).
   - Scheduled Tasks created (Event ID 4698).

### Phase 3: Remediation
- Quarantine endpoint from network.
- Collect memory image and disk forensic triage package.
- Remove binary and associated persistence mechanisms.

---

## Playbook 4: Linux / OpenSSH Brute Force

### Phase 1: Source & Rate Analysis
1. Query `ssh-brute-force.spl` in `index=main sourcetype=linux_auth`.
2. Assess attempt volume: $\ge 20$ attempts classified as automated password guessing.
3. Check for successful logins from the same `src_ip`:
   ```spl
   index=main sourcetype=linux_auth "Accepted password" src_ip="<SOURCE_IP>"
   ```

### Phase 2: Remediation
- Block attacker IP on `iptables` or host firewall:
  ```bash
  sudo iptables -A INPUT -s <ATTACKER_IP> -j DROP
  ```
- Enforce public-key authentication only; disable SSH password authentication in `/etc/ssh/sshd_config`.

---

## Playbook 5: Unauthorized Account Privilege Escalation (Event 4720 & 4732)

### Phase 1: Authorization Check
1. Extract `Actor` (SubjectUserName) and `TargetUserName`.
2. Verify against internal change management and ticketing systems (e.g. Jira/ServiceNow).
3. If no ticket exists -> **Confirmed Unauthorized Activity**.

### Phase 2: Containment
1. Disable newly created account immediately:
   ```cmd
   net user <SUSPICIOUS_ACCOUNT> /active:no
   ```
2. Remove account from local Administrators group:
   ```cmd
   net localgroup administrators <SUSPICIOUS_ACCOUNT> /delete
   ```
3. Audit `Actor` credentials for possible compromise.
