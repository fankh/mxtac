# Sigma engine

MxTac evaluates Sigma rules with its own small engine in `app/backend/app/engine/sigma_engine.py`. It does not use pySigma. The engine supports a subset of the Sigma specification. This document lists what works and what does not.

## Where rules come from

| Source | Loaded | Visible in the UI | Counted in coverage |
|--------|--------|-------------------|---------------------|
| YAML files in `app/backend/sigma_rules/` (five example rules) | At backend startup | No | No |
| Rules in the `rules` database table, created in the UI or through `POST /api/v1/rules` and `POST /api/v1/rules/import` | At startup and after every change | Yes | Yes |

Notes:

- A database rule replaces a file rule with the same `id`.
- File rules are active in the engine but are not listed on the Sigma Rules page and cannot be disabled there. To manage one of them in the UI, import its YAML.
- `POST /api/v1/rules/reload` clears the engine and loads the database rules only. File rules are loaded again at the next backend start.
- With several backend replicas, a rule change is announced over Valkey so that every replica reloads.

## Rule fields

| Field | Use |
|-------|-----|
| `id` | Rule identifier. A random UUID is assigned when it is missing |
| `title`, `description`, `status`, `references` | Stored and displayed |
| `level` | `critical`, `high`, `medium`, `low` or `informational`. Sets the severity of the detection. Default `medium` |
| `logsource` | Decides which events the rule is evaluated against (see below) |
| `detection` | Selections and `condition` |
| `tags` | `attack.tNNNN` and `attack.tNNNN.NNN` become technique IDs. `attack.taNNNN` becomes a tactic ID |

Tactic tags written as names, for example `attack.credential-access`, are not recognised. A rule without a `attack.taNNNN` tag produces detections without a tactic, and those detections are not grouped into incidents automatically.

## Which rules are evaluated for an event

Rules are indexed by `logsource`. For each normalized event the engine evaluates a rule when one of these is true:

| Rule `logsource` | Event |
|------------------|-------|
| `product` equals the event product in lower case | Product is `wazuh`, `zeek` or `suricata`, set by the normalizer |
| `category: process_creation` | OCSF class 1007 (Process Activity) |
| `category: network_connection` | OCSF class 4001 (Network Activity) |
| `category: dns_query` | OCSF class 4003 (DNS Activity) |
| `category: authentication` | OCSF class 3002 (Authentication) |
| No `product`, `category` or `service` | Every event |

Consequences:

- A rule with only `product: windows` or `product: linux` is never evaluated, because no normalizer sets that product. Add one of the four categories above.
- Other categories and the `service` field are not used to select events.

## Field names

Before evaluation the event is flattened to a dictionary (`app/backend/app/engine/field_mapper.py`). A rule can reference:

- OCSF paths, for example `process.cmd_line`, `src_endpoint.ip`, `dst_endpoint.port`;
- short names of process and endpoint fields, for example `name`, `cmd_line`, `path`, `hostname`, `ip`;
- Sigma field names for the rule's `logsource.category`:

| Category | Sigma fields |
|----------|--------------|
| `process_creation` | `CommandLine`, `Image`, `OriginalFileName`, `ProcessId`, `ParentImage`, `ParentProcessId`, `User`, `Hashes` |
| `network_connection` | `SourceIp`, `SourcePort`, `SourceHostname`, `DestinationIp`, `DestinationPort`, `DestinationHostname`, `Image`, `User` |
| `dns_query` | `QueryName`, `QueryType`, `QueryResults`, `Image`, `User` |
| `authentication` | `TargetUserName`, `TargetUserSid`, `TargetDomainName`, `IpAddress`, `WorkstationName` |
| `file_access`, `file_change`, `file_delete`, `file_event` | `TargetFilename`, `FileName`, `Image`, `CommandLine`, `User` |

A Sigma field is only present when the normalized event contains the underlying OCSF value.

## Detection

### Selections

| Form | Meaning |
|------|---------|
| Map of fields | All fields must match (AND). A list of values for one field matches when any value matches (OR) |
| List of strings | Keyword search. Matches when any keyword is a substring of any value in the event |

A selection that is a list of maps is not supported.

### Modifiers

| Modifier | Behaviour |
|----------|-----------|
| none | Exact match, case-insensitive |
| `contains` | Substring, case-insensitive |
| `startswith` | Prefix, case-insensitive |
| `endswith` | Suffix, case-insensitive |
| `re` | Regular expression (Python `re`, case-insensitive search) |
| `cidr` | The field value is an IP address inside the given network |
| `base64` | The rule value is base64-encoded before comparison. Combine with `contains`, `startswith` or `endswith`. Case-sensitive |
| `all` | Every value in the list must match, instead of any |

Wildcards (`*`, `?`) inside values are compared literally. Use `contains`, `startswith`, `endswith` or `re` instead.

### Conditions

| Expression | Supported |
|------------|-----------|
| `selection` | Yes |
| `a and b`, `a or b` | Yes. `and` binds tighter than `or` |
| `a and not b` | Yes |
| `1 of them`, `1 of selection_*` | Yes |
| `all of them`, `all of selection_*` | Yes |
| Parentheses | Only around the whole expression. Nested groups such as `(a or b) and c` are not parsed correctly |
| `not` at the start of an expression | Negates everything that follows it. Write `a and not b`, not `not b and a` |
| Aggregations (`count()`, `near`), `timeframe`, correlation rules | No |

## Output

A match produces an alert with the rule ID and title, level, technique and tactic IDs, the host (destination hostname or IP of the event), the event time and a snapshot of the flattened event. The alert manager then deduplicates, scores and stores it as a detection. See [architecture.md](architecture.md).

## Testing a rule

| Route | Use |
|-------|-----|
| `POST /api/v1/rules/test` | Validate YAML and evaluate it against a sample event without saving |
| `POST /api/v1/rules/{rule_id}/test` | Evaluate a stored rule against a sample event |

The sample event is matched as given. It is not normalized or mapped first, so use the flattened field names the rule expects.

## Example

```yaml
title: LSASS Memory Access via Process Injection
id: 0d894093-71bc-43c3-b7e0-01eb5adf38cd
status: stable
level: critical
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    path|endswith: '\lsass.exe'
  filter:
    name:
      - 'csrss.exe'
      - 'wininit.exe'
      - 'wmiprvse.exe'
  condition: selection and not filter
tags:
  - attack.T1003.001
  - attack.TA0006
```

This rule is one of the files in `app/backend/sigma_rules/`.
