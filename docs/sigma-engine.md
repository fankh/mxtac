# Sigma engine

MxTac evaluates Sigma rules with its own small engine in `app/backend/app/engine/sigma_engine.py`. It does not use pySigma. The engine supports a subset of the Sigma specification. This document lists what works and what does not.

A rule that uses syntax outside this subset is rejected with an error message when it is created, imported or tested. It is not stored.

## Where rules come from

The `rules` database table is the only source. The engine, the Sigma Rules page and the coverage numbers all read it.

| Origin | `source` | How it gets into the table |
|--------|----------|----------------------------|
| YAML files in `app/backend/sigma_rules/` (20 rules) | `bundled` | Imported at every backend start (`app/backend/app/services/bundled_rules.py`) |
| The UI, `POST /api/v1/rules` and `POST /api/v1/rules/import` | `custom` | Stored when the request is accepted |

Import of the bundled rules:

- A file is matched to a row by its Sigma `id`. A rule that is not in the table yet is inserted, enabled.
- A row that exists is never changed. Edits to a bundled rule and its enabled flag are kept across restarts and upgrades. A new version of a bundled file therefore does not replace a rule that is already in the table.
- A bundled rule that was deleted is inserted again at the next start, because its `id` is missing from the table. To switch a bundled rule off, disable it instead of deleting it.
- A file without an `id`, or one the engine cannot load, is skipped with a warning in the log.

Changes:

- Creating, editing, enabling, disabling and deleting a rule updates the engine at once. The change is committed before the other replicas are told to reload.
- A rule whose `id` already exists is not stored a second time. `POST /api/v1/rules` answers `422` with the reason, and an import lists it in `errors`.
- The YAML of a new rule is stored with its keys in the order they were written. Comments are not kept.
- `POST /api/v1/rules/reload` clears the engine and loads all rules from the table again.
- With several backend replicas, a rule change is announced over Valkey so that every replica reloads.

The `source` value is returned by `GET /api/v1/rules/{rule_id}`. The Sigma Rules page does not display it.

## Bundled rules

This table is generated from the YAML files with `python scripts/gen_rule_table.py --write`.

<!-- bundled-rules:start -->
| File | Title | Level | Technique | Tactic | Applies to |
|------|-------|-------|-----------|--------|------------|
| `dns_public_ip_lookup_service.yml` | DNS Query for a Public IP Lookup Service | low | T1016.001 | Discovery | DNS events from any source |
| `dns_tunneling_long_query.yml` | DNS Tunneling - Suspicious Long Query | medium | T1071.004 | Command and Control | DNS events from any source |
| `lateral_movement_smb.yml` | SMB Lateral Movement via PsExec | high | T1021.002 | Lateral Movement | Network connection events from Windows hosts (Wazuh, syslog, webhook) |
| `linux_audit_logging_stopped.yml` | Linux Audit Logging Stopped or Rules Deleted | high | T1562.012 | Defense Evasion | Process events from Linux hosts (Wazuh, syslog, webhook) |
| `linux_cron_download_and_execute.yml` | Cron Job Downloads and Executes Remote Content | high | T1053.003, T1105 | Execution, Persistence | Events from Linux hosts (Wazuh, syslog, webhook), service `cron` |
| `linux_download_piped_to_shell.yml` | Download Piped to Shell | medium | T1105, T1059.004 | Command and Control, Execution | Process events from Linux hosts (Wazuh, syslog, webhook) |
| `linux_local_account_created.yml` | Local User Account Created | medium | T1136.001 | Persistence | Events from Linux hosts (Wazuh, syslog, webhook) |
| `linux_reverse_shell_command.yml` | Reverse Shell Command Line | high | T1059.004 | Execution | Process events from Linux hosts (Wazuh, syslog, webhook) |
| `linux_shell_history_cleared.yml` | Shell Command History Cleared | medium | T1070.003 | Defense Evasion | Process events from Linux hosts (Wazuh, syslog, webhook) |
| `linux_ssh_authorized_keys_modified.yml` | SSH Authorized Keys File Modified via Command Line | medium | T1098.004 | Persistence | Process events from Linux hosts (Wazuh, syslog, webhook) |
| `linux_ssh_failed_password_root.yml` | SSH Failed Password for Root | medium | T1110.001 | Credential Access | Events from Linux hosts (Wazuh, syslog, webhook), service `sshd` |
| `linux_ssh_root_login_accepted.yml` | SSH Login as Root Accepted | medium | T1078.003, T1021.004 | Initial Access, Lateral Movement | Events from Linux hosts (Wazuh, syslog, webhook), service `sshd` |
| `linux_sudo_authentication_failure.yml` | Sudo Authentication Failure or Denied Command | medium | T1548.003 | Privilege Escalation | Events from Linux hosts (Wazuh, syslog, webhook), service `sudo` |
| `linux_sudo_shadow_file_access.yml` | Password Hash File Accessed via Command Line | high | T1003.008 | Credential Access | Process events from Linux hosts (Wazuh, syslog, webhook) |
| `linux_user_added_to_privileged_group.yml` | User Added to Privileged Group | high | T1098 | Persistence, Privilege Escalation | Events from Linux hosts (Wazuh, syslog, webhook) |
| `lsass_memory_access.yml` | LSASS Memory Access via Process Injection | critical | T1003.001 | Credential Access | Process events from Windows hosts (Wazuh, syslog, webhook) |
| `new_service_creation.yml` | New Service Creation via sc.exe | medium | T1543.003 | Persistence | Process events from Windows hosts (Wazuh, syslog, webhook) |
| `powershell_encoded_command.yml` | PowerShell Encoded Command Execution | high | T1059.001 | Execution | Process events from Windows hosts (Wazuh, syslog, webhook) |
| `suricata_c2_framework_signature.yml` | Suricata Signature Names a C2 Framework | high | T1071 | Command and Control | Suricata events |
| `zeek_http_scripting_tool_user_agent.yml` | HTTP Request from a Scripting Tool User Agent | low | T1071.001 | Command and Control | Zeek events |
<!-- bundled-rules:end -->

How to read "Applies to":

- "Linux hosts" and "Windows hosts" stand for the rule's `product`. A host-based event (Wazuh, syslog, webhook) satisfies it when the event names that operating system, or names none. Zeek and Suricata events never satisfy an operating-system product.
- "Process events", "network connection events" and "DNS events" stand for the rule's `category`.
- A `service` is checked against the services the event names. Syslog events name the program (for example `sshd`), and `auth` or `cron` for those facilities.

The exact logic is described in the next sections. The Linux rules without a category match on the `message` and `app_name` fields of syslog events.

## Rule fields

| Field | Use |
|-------|-----|
| `id` | Rule identifier. A random UUID is assigned when it is missing |
| `title`, `description`, `status`, `references` | Stored and displayed |
| `level` | `critical`, `high`, `medium`, `low` or `informational`. Sets the severity of the detection. Default `medium` |
| `logsource` | Decides which events the rule is evaluated against (see below) |
| `detection` | Selections and `condition` |
| `tags` | ATT&CK techniques and tactics (see below) |

### ATT&CK tags

| Tag | Result |
|-----|--------|
| `attack.t1059`, `attack.t1059.001` | Technique ID `T1059`, `T1059.001` |
| `attack.ta0006` | Tactic ID `TA0006` |
| `attack.credential-access`, `attack.credential_access` | Tactic ID `TA0006`. All 14 enterprise tactic names are recognised |

Tags are not case-sensitive. Other tags are ignored. A rule without a tactic tag produces detections without a tactic, and those detections are not grouped into incidents automatically.

## Which rules are evaluated for an event

A rule's `logsource` may contain `product`, `category` and `service`. Each one that is present must be satisfied by the event. A rule without any of them is evaluated for every event.

### `product`

| Event source | Products the event satisfies |
|--------------|------------------------------|
| Zeek | `zeek` |
| Suricata | `suricata` |
| Wazuh, syslog, webhook, when the event names the operating system of the host | The source (`wazuh`, `syslog`, `webhook`) and that operating system (`windows`, `linux` or `macos`) |
| Wazuh, syslog, webhook, when the event does not name the operating system | The source and all of `windows`, `linux`, `macos`. The field conditions of the rule decide |

The operating system comes from the Wazuh agent information, or from the `os` or `os_name` field of a webhook event. Syslog events do not name it.

### `category`

The category is derived from the OCSF class of the event.

| Rule `category` | Event class |
|-----------------|-------------|
| `process_creation` | Process Activity (1007) |
| `network_connection`, `firewall` | Network Activity (4001) |
| `dns_query`, `dns` | DNS Activity (4003) |
| `authentication` | Authentication (3002) |
| `webserver`, `proxy` | HTTP Activity (4002) |
| `file_event`, `file_access`, `file_change`, `file_delete` | File Activity (1001) |

A rule with any other category is never evaluated.

### `service`

Some normalizers name services in the event. Syslog events name `syslog`, the program name in lower case (for example `sshd`, `sudo`), and `auth` or `cron` for the `auth`, `authpriv` and `cron` facilities. A webhook event can set a `service` field. Wazuh, Zeek and Suricata events name no service.

A rule with a `service` is evaluated when the event names that service, and also when the event names no service at all.

## Field names

Before evaluation the event is flattened to a dictionary (`app/backend/app/engine/field_mapper.py`). A rule can reference:

- OCSF paths, for example `process.cmd_line`, `src_endpoint.ip`, `dst_endpoint.port`, `actor_user.name`, `network_traffic.<key>`, `file.<key>`;
- short names of process and source endpoint fields, for example `name`, `cmd_line`, `path`, `hostname`, `ip`;
- `finding_info.title` and `finding_info.analytic.uid`, the name and ID of the Wazuh rule or Suricata signature behind the event;
- source-specific fields. Every key the normalizer keeps in `unmapped` is available as `unmapped.<key>` and, when the name is free, as `<key>`. Examples: `message`, `app_name` and `facility_name` of a syslog event, and every extra field of a webhook event;
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
| List of maps | Matches when any of the maps matches (OR) |
| List of strings, or one string | Keyword search. Matches when any keyword is a substring of any value in the event |

A field value that is itself a list in the event matches when any of its items matches. A `null` value in the rule matches when the field is missing.

### Modifiers

| Modifier | Behaviour |
|----------|-----------|
| none | Whole value, case-insensitive |
| `contains` | Substring, case-insensitive |
| `startswith` | Prefix, case-insensitive |
| `endswith` | Suffix, case-insensitive |
| `re` | Regular expression (Python `re`, case-insensitive search) |
| `cidr` | The field value is an IP address inside the given network |
| `base64` | The rule value is base64-encoded before comparison. Combine with `contains`, `startswith` or `endswith`. Case-sensitive |
| `all` | Every value in the list must match, instead of any |

These eight are the complete list. Any other modifier, for example `base64offset`, `windash`, `utf16le`, `lt` or `gte`, is rejected.

### Wildcards

In plain string values `*` matches any number of characters and `?` matches one character. This also works together with `contains`, `startswith` and `endswith`. Write `\*` and `\?` for the literal characters and `\\` for a backslash. Wildcards have no special meaning in `re`, `cidr` and `base64` values.

### Conditions

| Expression | Supported |
|------------|-----------|
| `selection` | Yes |
| `a and b`, `a or b`, `not a` | Yes. `not` binds tighter than `and`, and `and` binds tighter than `or` |
| Parentheses, also nested: `(a or b) and not (c or d)` | Yes |
| `1 of them`, `1 of selection_*` | Yes |
| `all of them`, `all of selection_*` | Yes |
| `2 of them`, `3 of selection_*` (any number) | Yes. At least that many selections match |
| A list of conditions | Yes. The rule matches when any of them matches |
| Aggregations (`... | count() > 5`, `... | near ...`) | No, rejected |
| `timeframe` | No, rejected |
| Correlation rules | No, rejected |

Without a `condition`, the selection named `selection` is used. A condition that names an unknown selection, or a pattern that matches no selection, is rejected.

## Unsupported syntax

| Route | Result for an invalid or unsupported rule |
|-------|--------------------------------------------|
| `POST /api/v1/rules` | `422` with the reason |
| `PATCH /api/v1/rules/{rule_id}` with new content | `422` with the reason |
| `POST /api/v1/rules/import` | The rule is skipped. The response lists the reason for each skipped rule in `errors` |
| `POST /api/v1/rules/test`, `POST /api/v1/rules/{rule_id}/test` | `matched: false` and the reason in `errors` |

The UI shows these messages in the rule editor, the import dialog and the test panel.

## Output

A match produces an alert with the rule ID and title, level, technique and tactic IDs, the host (destination hostname or IP of the event), the event time and a snapshot of the flattened event. The alert manager then deduplicates, scores and stores it as a detection. See [architecture.md](architecture.md).

## Testing a rule

| Route | Use |
|-------|-----|
| `POST /api/v1/rules/test` | Validate YAML and evaluate it against a sample event without saving |
| `POST /api/v1/rules/{rule_id}/test` | Evaluate a stored rule against a sample event |

The sample event is matched as given. It is not normalized or mapped first, and the `logsource` is not checked, so use the flattened field names the rule expects.

## Examples

A Windows rule with a filter:

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

A Linux rule for syslog events, with a service and a tactic tag by name:

```yaml
title: SSH Failed Password for Root
id: b67d5827-73fd-46a2-a8fd-d15594ac491e
status: test
level: medium
logsource:
  product: linux
  service: sshd
detection:
  selection:
    message|startswith: 'Failed password for root from '
  condition: selection
tags:
  - attack.credential-access
  - attack.t1110.001
```

Both rules are files in `app/backend/sigma_rules/`.

## Current limitations

- No aggregations, no `timeframe`, no correlation rules. Each rule is evaluated against one event at a time, so "more than five failed logins in a minute" cannot be expressed.
- Only the eight modifiers listed above.
- Field names are not translated beyond the tables above. A rule from a public Sigma repository only matches when the fields it uses exist in the flattened event. Check with the test function and a sample event taken from Hunt.
- Rules for an operating-system product are also evaluated for host events that do not name their operating system. This avoids missing events, and it can match an event from a different operating system when the field conditions are loose.
- A bundled rule that was changed in a new release is not updated in an existing installation, because existing rows are never overwritten. Delete the rule and restart the backend to get the new version.
