# Controlled Test Scenarios

Run these scenarios only in an isolated lab you own or are authorized to assess. Record the exact time window, source and target labels, expected event IDs, observed events, and cleanup. The notes below define validation goals; they are not instructions to target third-party systems.

## Repeated failed logons

- **Goal:** Confirm Windows Security Event ID 4625 ingestion and threshold triage.
- **Pre-check:** Use a dedicated test account and controlled Windows target.
- **Expected evidence:** Raw 4625 events in `blue`; source/account fields verified; alert threshold outcome recorded.
- **Result:** [Not run / Pass / Fail; attach evidence]

## Executable file creation and execution

- **Goal:** Confirm Sysmon Event ID 11 and Event ID 1 collection for a benign test executable.
- **Pre-check:** Use a harmless test file; do not commit binaries to this repository.
- **Expected evidence:** File path and creating process (11), process image/parent/command line (1), matching timestamps.
- **Result:** [Not run / Pass / Fail; attach evidence]

## Network reconnaissance telemetry

- **Goal:** Validate network event visibility for a controlled scan of a lab-owned target.
- **Pre-check:** Isolated test network, approved target, and logging enabled.
- **Expected evidence:** Event source and direction validated; do not assume Sysmon Event ID 3 records every attempted or blocked port.
- **Result:** [Not run / Pass / Fail; attach evidence]
