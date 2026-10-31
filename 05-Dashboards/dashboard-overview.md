# SOC L1 Dashboard

Import `SOC-L1-dashboard.xml` in Splunk as a Classic Simple XML dashboard. It provides top-level event counts, a recent-event triage table, event categories, and a timeline.

The XML uses `index=blue`, matching the index stated in the shared project chat. Validate index, EventCode extraction, source fields, and data availability in the target Splunk instance. A panel that returns zero events may indicate no activity, a field mismatch, or a time-range issue. The dashboard is a review aid; its rows are not findings without investigation.
