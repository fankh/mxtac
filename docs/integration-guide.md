# Source integration guide

MxTac has five source types. Three of them feed the detection pipeline.

| Type | Input | Normalized and evaluated by Sigma rules |
|------|-------|------------------------------------------|
| `wazuh` | Polls the Wazuh manager REST API | Yes |
| `zeek` | Reads Zeek log files from a directory | Yes |
| `suricata` | Reads the Suricata EVE JSON file | Yes |
| `syslog` | Listens for syslog messages | No. Messages are accepted and then not processed |
| `generic` | Receives JSON over HTTP (webhook) | No. Events are accepted and then not processed |

Syslog and webhook events are published to the internal queue, but no normalizer consumes them yet. They are not stored, do not appear in Hunt and do not produce detections.

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

`config` holds the settings from the sections below. Enabled connectors start with the backend. Connector settings are stored in the database without encryption.

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

There are two ways to receive syslog. Both parse RFC 3164 and RFC 5424 messages. Neither feeds the detection pipeline yet.

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

The Compose files do not publish a syslog port. Add a port mapping to the `backend` service, for example `"514:1514/udp"`.

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
     -d '[{"timestamp": "2026-01-01T12:00:00Z", "message": "Suspicious login", "src_ip": "203.0.113.5"}]'
   ```

   The response reports how many events were accepted: `{"accepted": 1, "rejected": 0}`.

| Limit | Value |
|-------|-------|
| Body size | 5 MB |
| Requests per source | 100 per minute |
| Requests per client IP | 60 per minute (general write limit) |

`POST /api/v1/ingest/test` checks the source name and token without sending events.

Accepted events are published to the topic `mxtac.raw.<source name>`. Nothing consumes that topic yet.

## Checking that events arrive

1. Open the **Sources** page. A running connector shows its status, event count and the time of the last event.
2. Open **Hunt** and search for recent events (Wazuh, Zeek and Suricata only).
3. Check the backend log: `docker compose logs -f backend`.
4. Check the metrics at `/metrics`, for example the counters for ingested events and dead-letter events.
