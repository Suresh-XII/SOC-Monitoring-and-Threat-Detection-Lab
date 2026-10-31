# SOC L1 Investigation Workflow

1. **Validate the alert:** Confirm the time range, index, source, sourcetype, event ID, and raw event.
2. **Collect context:** Identify host, account, source/destination, process, and nearby events when present.
3. **Check expected activity:** Compare with approved lab tests, administrator actions, and known baselines.
4. **Correlate:** Use relevant adjacent Windows/Sysmon events; account for ingestion delay and time zones.
5. **Assess:** Record facts separately from hypotheses; explain severity and confidence.
6. **Respond or escalate:** Follow the lab's authorized response plan; document the decision and next owner.
7. **Close the record:** Save sanitized screenshots and the exact SPL, time range, and outcome.

## Limitations to remember

- One failed logon does not prove brute force.
- A process name in a search result is not proof it caused an authentication event.
- A binary in a user-writable directory is suspicious context, not proof of malware.
- Sysmon Event ID 3 reports observed network connections, not every attempted or blocked scan. Confirm source/destination field semantics before describing a scanner.
- Keyword-based PowerShell searches can miss obfuscation and generate benign matches.
