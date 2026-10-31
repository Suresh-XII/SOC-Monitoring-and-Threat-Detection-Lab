# SOC Investigation Report: Windows Failed Logon

**Status:** Preliminary; one event observed, broader activity not established.  
**Incident ID:** SOC-001 (portfolio example)  
**Category:** Authentication failure  
**Source:** Windows Security Event Log, Event ID 4625  
**Splunk index:** `blue` (reported)

## Executive summary

A Windows Security Event ID 4625 was visible in the supplied screenshot. It records an unsuccessful authentication on the computer shown as `Suresh`, dated 30 October 2026 at 07:50:09.510 PM (as displayed). A single failed logon is not sufficient to classify the activity as a brute-force attack. The screenshot did not expose a username, source IP, or process name; these are left unknown rather than inferred.

## Observed evidence

| Field | Observed value |
| --- | --- |
| Event ID | 4625 |
| Log | Windows Security |
| Computer | Suresh (as displayed; consider sanitizing) |
| Event time | 30 Oct 2026, 07:50:09.510 PM (displayed local time) |
| Result | Failed logon / Audit Failure |
| Target user | Not visible in supplied screenshot |
| Source IP / workstation | Not visible in supplied screenshot |
| Process | Not established by this event/screenshot |

## Event review SPL

```spl
index=blue EventCode=4625
| table _time host ComputerName TargetUserName IpAddress WorkstationName LogonType Status SubStatus Message
| sort - _time
```

## Brute-force triage SPL

This query counts failures by source and host across the selected time range. The threshold is a lab starting point and should be tuned to the environment.

```spl
index=blue EventCode=4625
| eval Source_IP=coalesce(IpAddress,Source_Network_Address)
| eval Target_User=coalesce(TargetUserName,Account_Name,user)
| where isnotnull(Source_IP) AND Source_IP!="-"
| stats count AS Failed_Attempts values(Target_User) AS Targeted_Accounts earliest(_time) AS First_Seen latest(_time) AS Last_Seen by Source_IP host
| where Failed_Attempts>=5
| eval Severity=case(Failed_Attempts>=20,"High",Failed_Attempts>=10,"Medium",true(),"Low")
| convert ctime(First_Seen) ctime(Last_Seen)
| table First_Seen Last_Seen Source_IP host Targeted_Accounts Failed_Attempts Severity
| sort - Failed_Attempts
```

## Investigation steps

1. Review the raw 4625 event and verify extracted account, source, logon type, status, and substatus fields.
2. Search for repeated failures from the same source and for multiple targeted accounts.
3. Correlate with successful logons (4624), account lockouts (4740), and approved lab test timestamps.
4. Identify whether the source and target are expected lab assets.
5. Review adjacent process/network telemetry where available; do not infer the originating process from 4625 alone.
6. Record findings, false-positive rationale, and escalation decision.

## Assessment and next steps

**Current assessment:** One authentication failure observed; malicious intent and brute-force behavior are unconfirmed.  
**Recommended action:** Continue monitoring and correlate with related events. Escalate only if repeated or otherwise suspicious activity is supported by evidence.

## MITRE ATT&CK

T1110 (Brute Force) is relevant only if a pattern of password guessing is established. A single 4625 event alone is not enough to make that mapping as a finding.
