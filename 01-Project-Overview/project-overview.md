# Project Overview

## Purpose

Build and document a small SOC monitoring lab that collects endpoint telemetry in Splunk, detects selected security events, and records an analyst's investigation.

## Scope

This repository covers Windows Security events, Sysmon telemetry, Splunk SPL examples, a dashboard, controlled attack simulations, and investigation reports. It is an educational lab, not a production SOC or proof that any event is malicious.

## Reported environment

- Splunk Enterprise: Windows (reported; version and host details to add)
- Splunk index: `blue` (reported)
- Universal Forwarder: Windows and Kali (reported; validate Kali's role)
- Kali Linux: attack simulation against Windows (reported)
- Collected logs: Windows Security, System, Sysmon (reported)
- Dashboard: custom multi-panel dashboard; scheduled alerts reported

## Objectives

1. Collect and search Windows and Sysmon events.
2. Identify authentication anomalies and suspicious process/file activity.
3. Triage detections with context and corroborating telemetry.
4. Preserve sanitized evidence and document limitations.
