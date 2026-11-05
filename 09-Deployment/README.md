# Deployment handoff

This package is designed for a small, authorized Splunk lab. It does not
replace a production change process, CIM onboarding, or an incident-response
runbook.

## Install

1. Import `05-Dashboards/SOC-L1-dashboard.xml` as a Classic Simple XML dashboard.
2. Copy the SPL files from `03-Detection-Rules/` into saved searches or use them
   as analyst searches. Keep the `index=blue` convention unless the target
   environment intentionally changes it.
3. Use `08-Documentation/detection-catalog.md` to assign an owner, schedule,
   threshold, and response action to each enabled search.
4. Complete the acceptance table in `02-Environment-Setup/environment-details.md`.
5. Run the controlled scenarios in `07-Attack-Simulation/Test-Scenarios.md`.
6. Store sanitized screenshots and investigation reports under `06-Evidence/`
   and `04-Investigation-Reports/`.

## Rollback

Disable the saved search or remove the dashboard through Splunk's UI. Repository
changes are versioned in Git; do not delete evidence or overwrite incident
reports to roll back a configuration.

## Release gate

The repository is ready to publish when the validator passes, all environment
placeholders are either completed or explicitly marked not applicable, and each
enabled detection has a documented validation result.
