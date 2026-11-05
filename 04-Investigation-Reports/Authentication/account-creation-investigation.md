# SOC Investigation Report: Unauthorized Account Creation

**Incident ID:** SOC-AUTH-2026-1030-03  
**Status:** Closed (Authorized Simulation)  
**Severity:** High (Local administrator account provisioned)  
**Detection Source:** Windows Security Event ID 4720 (`WinEventLog:Security`)  
**First Seen / Last Seen:** 2026-10-30 20:15:22 UTC  
**Affected Host:** `WIN-ENDPOINT-01`  
**Creator Account (Actor):** `labadmin`  
**Target Account Created:** `backdoor_user`  
**Associated Evidence:** Windows Security Event Log Register

---

## Executive Summary

A security alert was generated in Splunk detecting the provisioning of a new local user account (`backdoor_user`) on endpoint `WIN-ENDPOINT-01`. Corroborating telemetry confirmed that within 45 seconds of creation, the account was subsequently added to the local `Administrators` security group (Event ID 4732), indicating privilege escalation and persistence behavior.

---

## Event Evidence

| Timestamp | Host | Event ID | Actor (SubjectUserName) | Target Account | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `2026-10-30 20:15:22` | `WIN-ENDPOINT-01` | 4720 | `labadmin` | `backdoor_user` | A user account was created |
| `2026-10-30 20:15:48` | `WIN-ENDPOINT-01` | 4738 | `labadmin` | `backdoor_user` | A user account was modified |
| `2026-10-30 20:16:07` | `WIN-ENDPOINT-01` | 4732 | `labadmin` | `backdoor_user` | Added to local Administrators group |

---

## Detection Logic

```spl
index=blue EventCode=4720
| eval Created_Account=coalesce(TargetUserName,Target_Account_Name)
| eval Actor=coalesce(SubjectUserName,Subject_Account_Name,user)
| table _time host Actor Created_Account SubjectDomainName Message
| sort - _time
```

---

## Investigation Methodology

1. **Verify Creator Context:**
   - Evaluated Event ID 4720; subject user identified as `labadmin`.
   - Checked session ID and logon type: Logon Type 2 (Interactive console logon).
2. **Examine Group Modifications (Event ID 4732):**
   - Queried `index=blue EventCode=4732 MemberName="*backdoor_user*"`.
   - Identified that `TargetUserName="Administrators"`, confirming elevation to administrative privileges.
3. **Inspect Process Lineage (Sysmon Event ID 1):**
   - Correlated timestamp `20:15:22` with Sysmon Event ID 1.
   - Identified command line: `net user backdoor_user P@ssword123! /add` followed by `net localgroup administrators backdoor_user /add`.
   - Spawning parent: `cmd.exe` running under an elevated command prompt.
4. **Account Activity Inspection:**
   - Searched for any logon attempts (Event ID 4624/4625) with `TargetUserName="backdoor_user"`.
   - No logons observed; account was quarantined immediately.

---

## Findings & Assessment

- **Observed Facts:** An unauthorized local account was created and added to the local Administrators group via `net.exe` command-line utilities.
- **Assessment:** Consistent with adversary persistence mechanisms (MITRE ATT&CK T1136.001 & T1098). Matched Scenario 4 of the authorized attack simulation plan.
- **MITRE ATT&CK Mapping:**
  - **T1136.001:** Create Account: Local Account
  - **T1098:** Account Manipulation

---

## Response & Remediation

- Disabled and removed the `backdoor_user` account:
  ```cmd
  net user backdoor_user /delete
  ```
- Validated that no residual scheduled tasks, services, or registry run keys were installed.
- Documented detection efficacy in simulation results log.
