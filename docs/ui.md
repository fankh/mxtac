# User interface

The frontend is a single-page application in `app/frontend/`: React 18, TypeScript, Vite, Tailwind CSS, React Router, TanStack Query and Zustand. Charts use Recharts. The Sigma rule editor uses Monaco.

The UI shows data from the API only. On a new installation every page shows zeros and empty states with a hint on what to do next.

## Pages

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

Unknown paths redirect to `/`. All pages except Login require a signed-in user and redirect to `/login` otherwise.

The sidebar links to every page in three groups: Monitor, Investigate and Configure. Its footer shows the account, opens the MFA dialog, switches the theme, opens the shortcut list, signs out and collapses the sidebar.

The backend enforces what a role may do. The UI also hides or disables controls a role cannot use, as noted per page below. See [security.md](security.md).

### Login

| Step | When | Content |
|------|------|---------|
| Sign in | Always | Email and password |
| Set a new password | The account must change its password: a new account, the first account `admin@mxtac.local`, or an expired password | New password and confirmation, with the password rules. The UI checks that both entries match and that the new password differs from the one just typed. "Back to sign in" cancels |
| Two-factor authentication | The account has MFA | A 6-digit code from the authenticator app, sent as soon as six characters are typed. "Use a backup code" switches to an 8-character backup code. "Back to sign in" cancels |

The steps follow each other: after a forced password change, an account with MFA is asked for its code. The password-change token is kept in memory only.

### Overview

A time range (24 hours, 7, 30 or 90 days; default 7 days) applies to the page. The data refreshes every 60 seconds.

| Element | Content | Empty state |
|---------|---------|-------------|
| KPI cards | Detections with the change against the previous period, critical alerts, open incidents, ATT&CK coverage, mean time to detect, active Sigma rules | Zeros |
| Detections over time | Stacked bars by severity | "No detections in this period" |
| Top ATT&CK tactics | Detections by tactic | "No tactics observed yet" |
| Recent critical and high detections | Table with a link to Detections | "No critical or high detections" |
| Data sources | Status of each connector, with a link to Sources | "No data sources connected" and an "Add a source" button |
| ATT&CK coverage heatmap | Technique families by tactic, see [attack-coverage.md](attack-coverage.md#overview-page) | A grid of zeros |

### Detections

| Element | Content |
|---------|---------|
| Filters | Search text, tactic, host, severity chips, status chips, "Clear filters" |
| Table | Sortable by score, severity, tactic, host and time. 25, 50 or 100 rows per page |
| Export CSV | Up to 10,000 rows with the current filters and sort order |
| Live banner | Counts detections that arrived over the WebSocket since the list was loaded, with a "Show" button |
| Bulk actions | Select up to 500 rows: investigate, resolve, mark as false positive, reopen, or create an incident from the selection |
| Side panel | All fields of one detection, an "Assign to" form and status buttons |

Empty states: "No detections yet" on a new installation, "No detections match the filters" with filters set. The viewer role sees no checkboxes, bulk actions, assign form or status buttons.

### Incidents

| Element | Content |
|---------|---------|
| Metric cards | Open incidents, new this week, mean time to resolve, mean time to detect |
| Filters | Search text, assignee, "Assigned to me", sort order, severity and status chips |
| Table | 20 rows per page |
| New incident | Title, severity, description, assignee, and detection IDs when it is not opened from a selection on the Detections page |
| Side panel | Status (it only moves forward: new, investigating, contained, resolved, closed), severity, assignee. Tabs for details, timeline with notes, and linked detections |

Empty states: "No incidents yet", "No incidents match the filters". The viewer role cannot create or change incidents or add notes.

### Hunt

Hunt is open to the hunter, engineer and admin roles. Other roles see a notice instead of the page.

| Element | Content |
|---------|---------|
| Search form | Query text, time range (1 hour to 30 days; default 24 hours), and up to 50 filters on host, user, source IP, destination IP, source, event class, class UID, severity ID and process hash |
| Event volume | Chart of events over time |
| Top values | Most frequent values of a selectable field. Clicking a value adds a filter |
| Results | Table with 50 rows per page. Shows the query and a copy button |
| Event detail sheet | The full event, copy buttons, and for each entity (host, user, IP, hash) a filter action and a timeline of that entity's events |
| Saved queries | Save the current search, run, edit and delete saved ones |
| Export CSV | Up to 10,000 rows |

Empty states: "No events match this search", "No events in this time range", "No saved queries". The search text is matched as one case-insensitive substring of the summary, event class, host, user, addresses and process command line; see [architecture.md](architecture.md#event-document).

### ATT&CK Coverage

| Element | Content |
|---------|---------|
| Stat cards | Technique coverage with the target marker, target status with "Edit target", techniques without a rule, techniques covered only by disabled rules |
| Coverage trend | 7, 30 or 90 days, with the target line. Empty state: "No snapshots yet" |
| Coverage by data source | Covered techniques and rule counts per source type |
| Tactic and technique matrix | Coverage per tactic |
| Techniques | Tabs "Covered" and "Gaps", with a search for a technique ID |
| Download Navigator layer | An ATT&CK Navigator layer as a JSON file |

The viewer role does not see "Edit target". With the 20 bundled rules enabled, a new installation already shows coverage. The numbers are explained in [attack-coverage.md](attack-coverage.md).

### Sigma Rules

| Element | Content |
|---------|---------|
| Stat cards | Rules, enabled, critical, high |
| Filters | Search by title, ID or technique; level; enabled or disabled. 50 rows per page |
| Table | Title and ID, level, techniques, log source, status, hits, false positives, an enable switch and actions |
| Rule editor | Monaco YAML editor with a syntax marker and a "Format" button. Checks for `title`, `detection` and `condition` before sending |
| Import | Sigma YAML with one or more documents, up to 10 MB. Invalid documents are skipped and reported |
| Test | Evaluate a rule against a sample event. The result is "Matched", "No match" or "Rule error" with the messages |
| Reload engine | Loads all rules from the database into the engine again |

A new installation lists the 20 bundled rules. The page does not show whether a rule is bundled or custom. Errors from the backend, including the message for unsupported Sigma syntax, are shown under the editor, in the import dialog and in the test panel.

Only the engineer and admin roles see "New rule", "Import", "Reload engine" and "Delete", and can use the enable switch. The hunter role can open a rule read-only, test it and mark a false positive.

### Sources

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

Stored settings are not shown when a source is edited; only the fields that are filled in are changed. The empty state reads "No data sources yet". The page shows its controls to every role; the backend only accepts them from the engineer and admin roles.

### Settings

| Tab | Content |
|-----|---------|
| Profile and security | Email, name and role (read-only). MFA status with "Set up MFA". A form to change the password: current password, new password and confirmation. The new password cannot be one of the last two |
| Users (admin only) | User table with role, status, a "Password pending" mark for accounts that still have to change their password, and MFA state. Add user, edit name and role, deactivate, reactivate, reset MFA |
| Appearance | Light or dark theme, saved in the browser |

Add user asks for email, full name, role and a temporary password. The user must change the temporary password at the first sign-in. An administrator cannot change the own role or deactivate the own account.

MFA setup shows a QR code and a key for manual entry, asks for one code, and then shows the backup codes with "Copy all" and "Download .txt". A user cannot switch MFA off; an administrator resets it on the Users tab.

## Live updates

New detections arrive over a WebSocket (`/api/v1/ws/alerts`) and are shown without reloading the page. The top bar shows the state of the connection.

| Indicator | Meaning |
|-----------|---------|
| Live | Connected |
| Reconnecting | The connection dropped. The UI tries again every 5 seconds, each time with the current access token |
| Offline | Not connected and not retrying: there is no access token, or the server refused the token. Sign in again |

The hook is `src/hooks/useAlertStream.ts`. It stops retrying when the server closes the connection with code 1008. The server refuses a bad token before it accepts the connection, which a browser reports like a network failure. For a connection that closes without having opened, the hook therefore also asks `GET /api/v1/auth/me` and stops when the answer is `401`. Opening another page starts a new attempt.

## Keyboard shortcuts

| Keys | Action |
|------|--------|
| `g` then `d` | Overview |
| `g` then `e` | Detections |
| `g` then `i` | Incidents |
| `g` then `h` | Hunt |
| `g` then `c` | ATT&CK Coverage |
| `g` then `r` | Sigma Rules |
| `g` then `s` | Sources |
| `?` | Show the shortcut list |
| `Esc` | Close the shortcut list or the open panel |

The second key of a `g` shortcut must follow within 1.5 seconds. Shortcuts are ignored while typing in a field and while Ctrl, Alt or the Meta key is held. The shortcut list also names `/` for focusing a search field; no page reacts to it yet.

## Design tokens

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

### Themes

There are two themes, light and dark. The first visit follows the operating system setting. The choice is saved in the browser. The theme is applied by setting the `dark` class and a `data-theme` attribute on the `<html>` element (`src/stores/uiStore.ts`).

### Rules for new UI code

- Use the base components instead of raw `<button>`, `<input>` or `<select>` elements.
- Use token classes (`bg-card`, `text-muted-foreground`, `border-border`) instead of fixed colors, so that both themes work.
- Use the `sev-*` and `status-*` classes for severity and status colors.
- Show an empty state when there is no data. Do not fill a page with placeholder values.
