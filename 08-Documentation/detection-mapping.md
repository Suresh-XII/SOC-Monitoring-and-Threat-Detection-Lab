# Detection Mapping and Coverage

| Use case | Telemetry | ATT&CK reference | Mapping condition |
| --- | --- | --- | --- |
| Password guessing | Windows 4625 | T1110 Brute Force | Assign only when repeated failures support password guessing |
| PowerShell execution | PowerShell 4104 / Sysmon 1 | T1059.001 PowerShell | Execution evidence supports PowerShell use; sub-technique does not itself imply maliciousness |
| Encoded/obfuscated script | 4104 | T1027 / T1140 | Add only when event content supports obfuscation or decoding behavior |
| Network service discovery | Sysmon 3 | T1046 Network Service Discovery | Add when activity supports service discovery, not merely because many ports appear |

Mappings are analyst context and should be backed by event evidence. This lab does not claim comprehensive ATT&CK coverage.
