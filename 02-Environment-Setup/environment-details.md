# Environment Setup Notes

This file is a checklist, not a claim that every step is already configured. Record actual versions and sanitized configuration snippets.

## Splunk Enterprise

- Version/build:
- Host OS:
- Receiving port:
- Index: `blue` (reported; verify it exists and retention settings)
- Search time zone:

## Universal Forwarder

- Installed endpoints:
- Service status:
- `inputs.conf` location and monitored channels:
- `outputs.conf` destination (redact host/IP if needed):
- Forwarder-to-index mapping:

## Windows and Sysmon

- Audit policy enabled for logon events:
- PowerShell Script Block Logging enabled (4104):
- Sysmon version/configuration:
- Events verified in Splunk: 1, 3, 11 (confirm individually)

## Validation

For each source, record one known test event and confirm its raw event, timestamp, host, index, sourcetype, and extracted fields in Splunk.
