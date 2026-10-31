# SOC Lab Architecture

## Current understanding (confirm before publication)

The shared project notes indicate Splunk Enterprise runs on Windows. A Universal Forwarder is reported on Windows and Kali, while Kali is described as generating controlled attacks against Windows. Windows Security, System, and Sysmon data are reported as collected in Splunk index `blue`.

```text
Kali Linux (authorized test source) ── test traffic ──> Windows endpoint
Windows Security + Sysmon ── Universal Forwarder ──> Splunk Enterprise (index=blue)
Kali logs ── Universal Forwarder? ──> Splunk Enterprise (confirm whether configured)
```

## Complete these details

- Splunk version and host OS:
- Windows endpoint name (use a sanitized label in public docs):
- Kali role and whether its logs are forwarded:
- Forwarder receiver address/port (replace real values with placeholders):
- Enabled Windows channels and Sysmon configuration:
- Splunk sourcetype(s), source(s), and input configuration:
- Network mode/topology (NAT, host-only, bridged):

Do not commit real credentials, private network diagrams, or exposed host details.
