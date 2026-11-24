# ATT&CK coverage

This document describes how MxTac calculates the numbers on the ATT&CK Coverage page and the Overview page. The code is in `app/backend/app/repositories/rule_repo.py`, `app/backend/app/repositories/detection_repo.py` and `app/backend/app/api/v1/endpoints/coverage.py`.

## What "covered" means

A technique is covered when at least one **enabled** rule in the `rules` table has a tag for it (`attack.tNNNN` or `attack.tNNNN.NNN`).

Coverage is a statement about rules, not about data. It does not check that a source delivers the events a rule needs, and it does not check that the rule matches real attacks.

The bundled rules from `app/backend/sigma_rules/` are imported into the `rules` table at startup and count like any other rule. A new installation with the 20 bundled rules enabled reports 21 covered technique IDs, which is 20.0 %. Disabling or deleting rules lowers the number. See [sigma-engine.md](sigma-engine.md).

All numbers come from the `rules` and `detections` tables. Nothing is estimated or filled in.

## Coverage percentage

```
covered_count = number of distinct technique IDs tagged on enabled rules, capped at 105
coverage_pct  = covered_count / 105 * 100, rounded to one decimal
```

The total of 105 is a fixed number in the code. It is the sum of per-tactic totals for the nine tactics the UI tracks:

| Tactic | Label | Total |
|--------|-------|-------|
| Reconnaissance | RECON | 9 |
| Resource Development | RES | 6 |
| Initial Access | INIT | 9 |
| Execution | EXEC | 14 |
| Persistence | PERS | 12 |
| Privilege Escalation | PRIV | 11 |
| Defense Evasion | DEF-E | 17 |
| Credential Access | CRED | 14 |
| Discovery | DISC | 13 |

Limits of this method:

- The scope is nine tactics. Lateral Movement, Collection, Command and Control, Exfiltration and Impact are not part of the total.
- Technique IDs are counted as tagged. `T1003` and `T1003.001` count as two. A technique from a tactic outside the nine still counts towards `covered_count`.
- The totals are constants and do not follow new ATT&CK releases.

Treat the percentage as a progress indicator for your rule set, not as a measurement against the full ATT&CK matrix.

## Routes

All routes require the `detections:read` permission, except setting the target, which requires `detections:write`.

| Route | Result |
|-------|--------|
| `GET /api/v1/coverage` | `coverage_pct`, `covered_count`, `total_count` |
| `GET /api/v1/coverage/gaps` | `gap_count` (105 minus `covered_count`) and `uncovered_techniques`: technique IDs that appear on some rule but on no enabled rule. These are techniques you could cover by enabling a rule you already have |
| `GET /api/v1/coverage/by-datasource` | Covered techniques and rule counts per source type, derived from each rule's `logsource` (table below) |
| `GET /api/v1/coverage/trend?days=30` | One point per day. The route stores today's value each time it is called, so days on which nobody opened the page have no point. Nothing is stored while coverage is zero. There is no history from before the first call |
| `GET /api/v1/coverage/navigator` | An ATT&CK Navigator layer. The score of a technique is the number of enabled rules tagged with it |
| `GET /api/v1/coverage/target` | The configured target and whether current coverage is below it. Defaults to 80 %, disabled |
| `PUT /api/v1/coverage/target` | Set the target percentage, label and whether it is enabled |

### Source classification

| Source | Rule `logsource` |
|--------|------------------|
| Wazuh | `product` is `windows`, `linux`, `macos`, `unix` or `endpoint` |
| Zeek | `product` is `zeek`, or `category` is `network_connection`, `network_flow`, `dns`, `proxy`, `http`, `ssl` or `network` |
| Suricata | `product` is `suricata`, or `service` contains `suricata` |

Rules that match none of these are not assigned to a source.

This classification is used for the coverage breakdown only, and it is coarser than the engine:

- There is no entry for syslog or webhook sources. Rules with the product `linux` or `windows` are listed under Wazuh, although the engine also evaluates them for syslog and webhook events.
- A rule with only `category: dns_query`, like the two bundled DNS rules, is not assigned to a source. The Zeek list contains `dns`, not `dns_query`.

Which events a rule is actually evaluated against is described in [sigma-engine.md](sigma-engine.md).

## Overview page

| Element | Source |
|---------|--------|
| Coverage KPI card | Same calculation as `GET /api/v1/coverage`. The change value compares with a stored trend snapshot |
| Heatmap (`GET /api/v1/overview/coverage/heatmap`) | Built from detections, not rules. A grid of four technique families (`T1059`, `T1003`, `T1021`, `T1078`) by the nine tactics. A cell counts the distinct technique IDs of that family that were detected under that tactic |

The heatmap reads the `tactic` column of a detection as a tactic name, for example `Credential Access`. The pipeline stores that name; a row of an earlier version that holds the tactic ID, for example `TA0006`, is counted under the tactic it names.

Limitation of the heatmap: it only has the four technique families and nine tactics listed above. A detection of another technique family, or under a tactic outside the nine (Lateral Movement, Collection, Command and Control, Exfiltration, Impact), is not shown in it. The "Top ATT&CK tactics" list on the Overview page counts every detection.
