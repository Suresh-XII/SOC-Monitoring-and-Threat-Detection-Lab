# SSH Brute Force Investigation and Escalation

**Incident:** SOC-SSH-2026-1028-01  
**Priority:** High, provisional  
**Status:** Open for detection validation  
**Observed date:** 28 October 2026 evidence window  
**Data source:** Splunk `index=main`, `sourcetype=linux_auth` in the detailed SSH search screenshot

## Executive assessment

The Splunk dashboard shows 671 failed SSH authentication events and one potential brute-force source, rated HIGH. A separate detailed search shows 271 events over its own visible time range, with `host=kali`, `user=kali`, and `src_ip=192.168.1.5`. Raw event details show repeated SSH `Failed password` lines. This pattern is consistent with password guessing.

The project owner previously described running a brute-force simulation in this lab. Confirm these screenshots match that authorized test and verify the target host. The dashboard count and detailed-search count use different visible windows or search logic; do not combine them or report a reconciled total yet. Keep the case open until the count and index differences are explained.

## Incident details

| Field | Observed value |
| --- | --- |
| Alert | Possible SSH Brute Force |
| Dashboard priority | HIGH |
| Dashboard count | 671 failed SSH authentication events |
| Detailed search count | 271 events in separate search view |
| Search index / sourcetype | `main` / `linux_auth` |
| Host shown | `kali` |
| Source field | `192.168.1.5` (`src_ip`, private LAN address) |
| Targeted user values | `admin`, `kali` (dashboard); `kali` in the detailed search table |
| Disposition | Suspected brute-force pattern; reported lab simulation, authorization-to-evidence match pending |

## Evidence and time window

- The dashboard screenshot is set to **Last 24 hours**, reports 671 failed SSH authentication events, and lists one source at `192.168.1.5` with 671 attempts against `admin` and `kali`.
- The separate search shows `index=main sourcetype=linux_auth "Failed password"` and 271 matching events between 27 October 2026 18:30 and 28 October 2026 19:26:46 as displayed in Splunk.
- A raw event sample shows repeated `Failed password` lines from `192.168.1.5`. One raw timestamp uses `-04:00`, while Splunk's `_time` display appears in another local time zone. Preserve raw and normalized timestamps when exporting.
- Index-wide ingestion screenshots separately show `index=blue` with Linux and Windows sourcetypes. Keep this distinct from the SSH search on `index=main` until the routing/configuration is checked.

Evidence files are indexed in [`../../06-Evidence/README.md`](../../06-Evidence/README.md). Primary incident exhibits:

1. [`soc-dashboard-ssh-summary.png`](../../06-Evidence/SSH-Brute-Force/soc-dashboard-ssh-summary.png)
2. [`ssh-failed-password-search.png`](../../06-Evidence/SSH-Brute-Force/ssh-failed-password-search.png)
3. [`ssh-auth-event-details.png`](../../06-Evidence/SSH-Brute-Force/ssh-auth-event-details.png)

## Detection SPL

```spl
index=main sourcetype=linux_auth "Failed password"
| rex "Failed password for (?:(?:invalid user )?)(?<user>\S+) from (?<src_ip>\S+)"
| stats count AS failed_attempts values(user) AS targeted_users earliest(_time) AS first_seen latest(_time) AS last_seen by host src_ip
| where failed_attempts >= 5
| eval severity=case(failed_attempts>=100,"HIGH",failed_attempts>=20,"MEDIUM",true(),"LOW")
| convert ctime(first_seen) ctime(last_seen)
| sort 0 - failed_attempts
```

The threshold shown is a lab baseline. Validate extraction for valid and invalid users, the index, sourcetype, time range, and alert schedule before using it operationally.

## Analysis and limitations

- Repeated failed SSH passwords from a single displayed source are consistent with password guessing.
- The supplied screenshots do not show a successful SSH authentication. Search for accepted logins and subsequent sessions before assessing compromise.
- The dashboard total (671) and detailed search total (271) are separate observations. Compare the underlying SPL, time bounds, deduplication, and index before treating either as the final total.
- `192.168.1.5` is a private address. Its role as the attacker/test source and the identity of the target must be confirmed from the lab topology.
- The `main` versus `blue` index discrepancy means telemetry routing/completeness is not yet established.
- Confidence: medium that repeated authentication failures occurred; authorization and incident impact remain to be confirmed.

## Escalation and response

| Stage | Escalation trigger | Action |
| --- | --- | --- |
| L1 triage, now | Case open | Preserve exact SPL and absolute time bounds; verify test authorization, source/target roles, and the count discrepancy; search for successful SSH logins. |
| L2 / Detection Engineering | Counts do not reconcile, parsing is uncertain, or activity falls outside the test window | Review Linux auth parsing, invalid-user handling, duplicate ingestion, `main`/`blue` routing, time zones, and alert threshold/schedule. |
| Incident Response / Security lead | Unauthorized activity, production target, or a successful login after failures | Follow the organization's incident procedure; preserve logs, assess account and host activity, and use containment or credential changes only through the authorized owner and response process. |
| Close as authorized test | Lab owner confirms this matches the controlled simulation | Attach test record and time window, document detection success/count variance, tune if needed, and close as an authorized simulation with no production compromise asserted. |

### Recommended next actions

1. Match the screenshots to the reported lab exercise; confirm source role, target host, and exact test time.
2. Run both dashboard and detailed searches over the same fixed absolute interval; compare event counts and filters.
3. Verify if Linux auth data is in `main`, `blue`, or both, and whether duplicates exist.
4. Search for successful SSH authentication and new sessions for the same source and accounts.
5. Escalate to L2 or IR using the triggers above if the activity is not authorized or if successful access/production impact is found.

## Closure criteria

Close only after the lab owner or incident owner confirms the disposition, the 671/271 difference and `main`/`blue` discrepancy are explained, and successful-login checks are recorded. Otherwise retain as open and escalate as appropriate.
