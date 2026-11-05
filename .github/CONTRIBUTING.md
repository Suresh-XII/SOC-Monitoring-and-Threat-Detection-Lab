# Contributing to the SOC Monitoring & Threat Detection Lab

Thank you for your interest in contributing! This project is maintained as a professional portfolio and educational reference for SIEM implementation, threat hunting, and SOC operations.

---

## Contribution Guidelines

### 1. New Detection Rules (`03-Detection-Rules/`)
- Every detection rule must be saved as a `.spl` file in the appropriate directory (`Windows/`, `Sysmon/`, `Linux/`, or `Network/`).
- Rules must include a header comment block specifying:
  - Rule Name
  - Event Code(s)
  - MITRE ATT&CK Mapping (Tactic, Technique ID)
  - Severity & Confidence Level
  - Data Source / Sourcetype
  - Description and detection logic
- All field names should use `coalesce()` where applicable to handle varied sourcetypes.

### 2. Investigation Reports (`04-Investigation-Reports/`)
- Use the standard template located at `04-Investigation-Reports/incident-report-template.md`.
- Include exact SPL queries, observed evidence tables, timeline reconstruction, and MITRE mappings.

### 3. Attack Simulations (`07-Attack-Simulation/`)
- Document attack commands and parameters clearly.
- Include pre-attack safety checks, expected telemetry, and mandatory cleanup commands.

### 4. Sanitization Policy (Strict Requirement)
- **NEVER commit sensitive, private, or identifying information.**
- Sanitize all public IP addresses, real corporate domain names, employee names, and passwords.
- Use RFC 1918 placeholder addresses (e.g. `192.168.10.X`).
- Do not commit malicious executables or dangerous payload scripts. Use harmless mock binaries.
