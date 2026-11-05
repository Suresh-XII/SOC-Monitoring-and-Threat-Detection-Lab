# Controlled Attack Simulation Scenarios & Testing Guide

## Scope & Pre-Simulation Checklist

All attack simulations must strictly occur inside the isolated private test lab (`192.168.10.0/24`) between authorized endpoints (`KALI-SIM` at `192.168.10.50` and `WIN-ENDPOINT-01` at `192.168.10.15`).

### Pre-Attack Checklist:
- [x] Splunk Universal Forwarder running on both target and adversary machines.
- [x] Splunk Enterprise receiving port 9997 confirmed listening.
- [x] Target audit policies and Sysmon v15 service active.
- [x] Baseline search confirms events are indexing into `index=blue`.
- [x] Isolated virtual network / host-only adapter verified.

---

## Scenario 1: Windows Authentication Brute-Force Simulation

- **Objective:** Trigger and validate Windows Event ID 4625 ingestion, field extractions, and the 5-failure threshold detection rule.
- **MITRE ATT&CK:** T1110.001 (Password Guessing)
- **Execution Command (from Kali):**
  ```bash
  # Using hydra against target RDP / SMB service with wordlist
  hydra -l Administrator -P /usr/share/wordlists/fasttrack.txt 192.168.10.15 rdp -t 4
  ```
- **Expected Telemetry:** Windows Security Event ID 4625 generated with `TargetUserName="Administrator"`, `IpAddress="192.168.10.50"`, and `Status="0xC000006D"`.
- **Observed Result:** **PASS - VALIDATED**
  - Splunk detection rule `brute-force-threshold-4625.spl` captured 25 consecutive failed logon attempts within 2 minutes.
  - Severity dynamically assigned as `High`.
  - Evidence preserved in `06-Evidence/Windows-Authentication/`.

---

## Scenario 2: Executable File Drop and Execution in Staging Directory

- **Objective:** Validate Sysmon Event ID 11 (File Creation) and Event ID 1 (Process Creation) for binaries staged in user-writable paths.
- **MITRE ATT&CK:** T1105 (Ingress Tool Transfer), T1204.002 (User Execution: Malicious File)
- **Execution Commands (on Windows Endpoint):**
  ```powershell
  # Step 1: Simulate tool drop into Downloads
  Copy-Item -Path "C:\Windows\System32\whoami.exe" -Destination "$env:USERPROFILE\Downloads\demo.exe"

  # Step 2: Execute the staged binary
  cmd.exe /c "C:\Users\labadmin\Downloads\demo.exe"
  ```
- **Expected Telemetry:**
  - Sysmon Event ID 11 logging creation of `demo.exe` in `\Downloads\`.
  - Sysmon Event ID 1 logging execution of `demo.exe` with parent `cmd.exe`.
- **Observed Result:** **PASS - VALIDATED**
  - Splunk rules `suspicious-exe-creation-11.spl` and `suspicious-exe-execution-1.spl` flagged both events immediately.
  - Evidence preserved in `06-Evidence/Process-Monitoring/sysmon-process-event-demo-exe.png`.

---

## Scenario 3: Network Reconnaissance & Port Scanning

- **Objective:** Validate network telemetry collection and multi-port scanning detection via Sysmon Event ID 3.
- **MITRE ATT&CK:** T1046 (Network Service Discovery)
- **Execution Command (from Kali):**
  ```bash
  nmap -sS -p 21,22,23,25,80,135,139,443,445,1433,3389,8080 192.168.10.15
  ```
- **Expected Telemetry:** Sysmon Event ID 3 events recording incoming connections across destination ports from `192.168.10.50`.
- **Observed Result:** **PASS - VALIDATED**
  - Splunk detection rule `network-connection-3.spl` aggregated connections, identifying 12 unique ports scanned by `192.168.10.50`.
  - Severity evaluated as `Medium`.
  - Evidence logged in network triage register.

---

## Scenario 4: Suspicious Obfuscated PowerShell Execution

- **Objective:** Trigger and validate PowerShell Script Block Logging (Event ID 4104) for Base64-encoded download cradles.
- **MITRE ATT&CK:** T1059.001 (PowerShell), T1027 (Obfuscated Files or Information)
- **Execution Command (on Windows Endpoint):**
  ```powershell
  # Base64 encoded payload: Write-Host 'Simulated Obfuscated Payload Executed'
  powershell.exe -NoP -NonI -W Hidden -Enc VwByAGkAdABlAC0ASABvAHMAdAAgACcAUwBpAG0AdQBsAGEAdABlAGQAIABPAGIAZgB1AHMAYwBhAHQAZQBkACAAUABhAHkAbABvAGEAZAAgAEUAeABlAGMAdQB0AGUAZAAnAA==
  ```
- **Expected Telemetry:** Microsoft-Windows-PowerShell Event ID 4104 capturing both the encoded string and the de-obfuscated script block text.
- **Observed Result:** **PASS - VALIDATED**
  - Splunk detection rule `suspicious-powershell-4104.spl` triggered with `Detection_Indicator="Encoded PowerShell Command"`.
  - Script block text extracted and displayed in SOC dashboard.

---

## Scenario 5: Unauthorized Local Account Creation & Privilege Escalation

- **Objective:** Validate Windows Security Event IDs 4720 (User Created) and 4732 (Added to Local Group).
- **MITRE ATT&CK:** T1136.001 (Local Account), T1098 (Account Manipulation)
- **Execution Commands (on Windows Endpoint):**
  ```cmd
  net user backdoor_user P@ssword123! /add
  net localgroup administrators backdoor_user /add
  ```
- **Expected Telemetry:**
  - Event ID 4720 recording `TargetUserName="backdoor_user"` by actor `labadmin`.
  - Event ID 4732 recording member added to `TargetUserName="Administrators"`.
- **Observed Result:** **PASS - VALIDATED**
  - Both detection rules (`account-creation-4720.spl` and `privilege-escalation-4728-4732.spl`) alerted in Splunk within 15 seconds.
  - Incident documented in `04-Investigation-Reports/Authentication/account-creation-investigation.md`.

---

## Post-Simulation Cleanup Procedures

After completing each simulation run:
1. Delete any dropped artifacts:
   ```powershell
   Remove-Item -Path "$env:USERPROFILE\Downloads\demo.exe" -Force -ErrorAction SilentlyContinue
   Remove-Item -Path "$env:TEMP\payload_test.exe" -Force -ErrorAction SilentlyContinue
   ```
2. Remove any provisioned test accounts:
   ```cmd
   net user backdoor_user /delete
   ```
3. Verify test accounts are removed from local groups:
   ```cmd
   net localgroup administrators
   ```
4. Archive relevant raw Splunk search results into the project evidence directory.
