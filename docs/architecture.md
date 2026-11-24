# Architecture

This document describes the components that exist in the repository and how an event moves through them. File paths are relative to `app/backend/app/` unless stated otherwise.

## Components

| Component | Technology | Role |
|-----------|------------|------|
| Frontend | React 18, TypeScript, Vite, Tailwind CSS, TanStack Query, Zustand | Single-page web UI. Calls the backend under `/api/v1` and listens on a WebSocket for new detections |
| Backend | Python 3.12, FastAPI, SQLAlchemy 2 (async), Alembic | REST API, connectors, normalizers, Sigma engine, alert manager |
| PostgreSQL 16 | | Users, rules, detections, incidents, connectors, saved queries, coverage snapshots and targets, normalized events |
| Valkey 8 | Redis-compatible | Rate-limit counters, login lockout, revoked tokens, alert deduplication, GeoIP cache, WebSocket fan-out between replicas, rule-reload notifications, optional queue backend |
| OpenSearch 2.17 | | Index of normalized events for Hunt search, alert index, audit log index |

Optional services in `app/docker-compose.yml`, each behind a Compose profile: OpenSearch Dashboards (`dashboards`), Prometheus and Grafana (`monitoring`).

## Backend layout

| Directory | Content |
|-----------|---------|
| `api/v1/endpoints/` | Route handlers: `auth`, `overview`, `coverage`, `detections`, `incidents`, `rules`, `connectors`, `users`, `events`, `saved_queries`, `websocket`, `webhook_ingest` |
| `core/` | Settings, JWT and password helpers, RBAC, rate limiting, security headers, access log, metrics, validators |
| `connectors/` | `wazuh`, `zeek`, `suricata`, `syslog`, `syslog_receiver`, and the registry that starts connectors from the database |
| `services/normalizers/` | Wazuh, Zeek, Suricata, syslog and webhook events to OCSF |
| `engine/` | Sigma engine and the OCSF-to-Sigma field mapper |
| `services/` | Bundled-rule import, Sigma consumer, alert manager, event persister, WebSocket broadcaster, dead-letter consumer, OpenSearch client, audit logger |
| `pipeline/queue.py` | Queue abstraction with in-memory and Valkey Streams backends |
| `repositories/` | Database queries, one module per model |
| `models/` | SQLAlchemy models |
| `db/` | First-run seeder and the SQLite auto-migration helper |

## Event pipeline

Components exchange messages through queue topics (`pipeline/queue.py`).

| Topic | Published by | Consumed by |
|-------|--------------|-------------|
| `mxtac.raw.wazuh` | Wazuh connector | Normalizer |
| `mxtac.raw.zeek` | Zeek connector | Normalizer |
| `mxtac.raw.suricata` | Suricata connector | Normalizer |
| `mxtac.raw.syslog` | Syslog connector and syslog receiver | Normalizer |
| `mxtac.raw.webhook` | Webhook endpoint `POST /api/v1/ingest`. Each event carries the connector name in `_webhook_source` | Normalizer |
| `mxtac.normalized` | Normalizer | Event persister, Sigma consumer |
| `mxtac.alerts` | Sigma consumer | Alert manager |
| `mxtac.enriched` | Alert manager | WebSocket broadcaster |
| `mxtac.dlq` | Normalizer, when an event fails | Dead-letter consumer (logs and counts the event) |

All five source types feed the same pipeline.

Steps:

1. **Collect.** A connector reads events from its source and publishes each raw event to its topic. Connectors are rows in the `connectors` table and start with the backend. They can be started and stopped at runtime through the API. The syslog receiver and the webhook endpoint publish in the same way.
2. **Normalize.** `NormalizerPipeline` converts the raw event to an `OCSFEvent` and publishes it to `mxtac.normalized`. Events that fail are sent to `mxtac.dlq`.

   | Source | OCSF classes produced |
   |--------|-----------------------|
   | Wazuh | Process Activity, Network Activity, Authentication, File Activity, Security Finding |
   | Zeek | Network Activity, DNS Activity, HTTP Activity |
   | Suricata | Security Finding, DNS Activity, Network Activity |
   | Syslog | Authentication for SSH and PAM login results, Process Activity for sudo command logs, Base Event for every other message |
   | Webhook | Process Activity when the event has a process or command line, Network Activity when it has a source and a destination address, otherwise Base Event |

3. **Persist.** The event persister writes the event to the PostgreSQL `events` table and indexes it in OpenSearch (`mxtac-events-YYYY.MM.DD`) with the same ID. A failure in either store is logged and does not stop the pipeline.
4. **Detect.** The Sigma consumer evaluates the enabled rules that apply to the event. Each match is published to `mxtac.alerts` and increments the rule's hit counter. See [sigma-engine.md](sigma-engine.md).
5. **Triage.** The alert manager:
   - drops the alert if the same rule fired on the same host in the last 5 minutes (a Valkey key with a 300-second lifetime);
   - adds a GeoIP lookup for public IP addresses when `GEOIP_DB_PATH` points to a MaxMind database;
   - computes a score from 0 to 10 from the rule level and how often the alert recurs;
   - stores the alert as a row in `detections`. The `tactic` column holds the first ATT&CK tactic ID of the rule, for example `TA0006`;
   - if `AUTO_CREATE_INCIDENT_ENABLED` is true, adds the detection to an open incident with the same host and tactic inside `CORRELATION_WINDOW_SECONDS`, or creates an incident when the severity is at least `AUTO_CREATE_INCIDENT_MIN_SEVERITY`;
   - publishes the result to `mxtac.enriched`.
6. **Notify.** The WebSocket broadcaster sends the enriched alert to every browser connected to `/api/v1/ws/alerts`. A connection needs a valid access token. With several backend replicas, the message is relayed through a Valkey pub/sub channel.

### Queue backends

`QUEUE_BACKEND` selects the implementation. Any other value stops the backend at startup.

| Value | Implementation | Notes |
|-------|----------------|-------|
| `memory` (default) | `asyncio` queues inside the process | Messages are lost on restart. One backend process only |
| `redis` | Valkey Streams with consumer groups | Streams are capped at about 10,000 entries per topic |

## Rules

The `rules` table is the only source of rules for the engine, the Sigma Rules page and the coverage numbers. At startup the YAML files in `app/backend/sigma_rules/` are imported into the table (`services/bundled_rules.py`): a file whose Sigma `id` is not in the table yet is inserted with the source `bundled`, enabled. Existing rows are never updated, so edits and the enabled flag of a bundled rule are kept. The engine is then loaded from the table.

## Storage

| Store | Data | Notes |
|-------|------|-------|
| PostgreSQL | All application state and a copy of every normalized event | Schema managed by Alembic (`app/backend/alembic/`) |
| OpenSearch | `mxtac-events-*`, `mxtac-alerts-*`, `mxtac-audit-*`, `mxtac-rules` | Index templates and retention policies are created at startup. Retention is set by the `OPENSEARCH_*_RETENTION_DAYS` settings. `OPENSEARCH_USERNAME` and `OPENSEARCH_PASSWORD` are sent as HTTP basic authentication when the user name is set |
| Valkey | Short-lived keys only | No data that must survive a flush |

Event search (`POST /api/v1/events/search`, `/aggregate`, `/export`) queries OpenSearch and falls back to PostgreSQL when OpenSearch is not reachable. Reading one event or an entity timeline always uses PostgreSQL.

With `SQLITE_MODE=true` the backend uses a local SQLite file instead of PostgreSQL and applies migrations at startup. In this mode `/ready` only requires the database.

API responses are built from these stores only. When a table is empty, the routes return zeros and empty lists.

## Startup sequence

`main.py` runs these steps when the backend starts:

1. Apply migrations (SQLite mode only). With PostgreSQL, run `alembic upgrade head` before starting the backend. The Compose files do this in the backend command.
2. Run the seeder. When the `users` table is empty it creates `admin@mxtac.local` with a forced password change, and with `SEED_DEMO_DATA=true` also the demo accounts and sample rows. Otherwise it does nothing. See [First login](../README.md#first-login).
3. Start the queue.
4. Connect to OpenSearch and create retention policies and index templates.
5. Import the bundled Sigma rules that are missing in the `rules` table, then load the engine from the table.
6. Start the normalizer, dead-letter consumer, event persister, Sigma consumer, alert manager and WebSocket broadcaster.
7. Start the enabled connectors from the database.
8. Start background tasks: rule-reload subscriber, daily OpenSearch snapshot, storage metrics.
9. Start the syslog receiver when `SYSLOG_ENABLED=true`.

## Operational endpoints

| Path | Purpose |
|------|---------|
| `/health` | Liveness. Returns the version |
| `/ready` | Readiness. Checks the database, Valkey and OpenSearch, each with a 3-second timeout. Returns `503` when a required check fails. Also reports the age of the newest file in `BACKUP_DIR` (informational) |
| `/metrics` | Prometheus metrics: HTTP metrics plus pipeline counters such as processed and deduplicated alerts, rule matches, ingested events, active connectors, WebSocket connections and dead-letter events |

## Current limitations

Each item was checked against the code.

- **Event search on OpenSearch does not match the indexed document.** The event persister indexes the nested OCSF event. The search code (`services/opensearch_client.py`, `api/v1/endpoints/events.py`) expects flat fields:
  - the free-text query searches `summary`, `class_name`, `hostname` and `username`. Only `class_name` exists in the index, as a keyword, so a query only matches an exact class name such as `"Process Activity"`;
  - the hits are returned as nested documents, so the `hostname`, `username`, `src_ip`, `dst_ip`, `source` and `summary` values the Hunt table shows are missing;
  - the `hostname` filter is mapped to `src_endpoint.hostname`, while most host-based events carry the host in `dst_endpoint.hostname` (there is a separate `dst_endpoint.hostname` filter field).

  Exact-match filters on `source`, `class_name`, `class_uid` and `severity_id` work. The PostgreSQL path has none of these problems, because the `events` table has the flat columns. It is used when OpenSearch is not reachable, and always for reading one event and for entity timelines.
- **The Overview heatmap does not count pipeline detections.** It maps the `tactic` column through a table of tactic names (`repositories/detection_repo.py`), and the alert manager stores the tactic ID.
- The in-memory queue is the default. It does not survive a restart and does not work across several backend processes.
- Sigma rules are evaluated one event at a time. There is no state across events apart from the 5-minute deduplication.
- The syslog normalizer recognises SSH, PAM and sudo messages. Every other message becomes a Base Event whose text is only available in the `message` field.
- Every backend replica starts every enabled connector, so with more than one replica each event is collected once per replica.
