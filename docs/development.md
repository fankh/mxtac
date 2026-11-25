# Development

- [Development](#development)
- [Architecture](#architecture)

## Development

### Requirements

| Tool | Version |
|------|---------|
| Docker with Compose v2 | For the full stack |
| Python | 3.12 or newer (backend) |
| Node.js | 20 or newer (frontend). CI uses 22 |

### Option 1: everything in Docker Compose

```bash
cd app
docker compose up -d --build
```

| Service | Host port | Notes |
|---------|-----------|-------|
| backend | 15000 | Source is mounted from `app/backend`. Uvicorn runs with `--reload` |
| frontend | 15001 | Source is mounted from `app/frontend`. Vite dev server with hot reload. Forwards `/api` to `http://backend:8080` (`VITE_PROXY_TARGET`) |
| postgres | 15002 | User `mxtac`, password `mxtac`, database `mxtac` |
| redis (Valkey) | 15003 | |
| opensearch | 15004, 15005 | Security plugin disabled |
| opensearch-dashboards | 15006 | Profile `dashboards` |
| prometheus | 15009 | Profile `monitoring` |
| grafana | 15010 | Profile `monitoring` |

The backend container runs `alembic upgrade head` before it starts. On an empty database it then creates the account `admin@mxtac.local` and imports the bundled Sigma rules. Read the generated password with:

```bash
docker compose logs backend | grep "INITIAL ADMIN PASSWORD"
```

For a fixed password in development, start the stack with `INITIAL_ADMIN_PASSWORD='<password>' docker compose up -d`. For sample content, add `SEED_DEMO_DATA=true`. Both only apply while the `users` table is empty; `docker compose down -v` gives you an empty database again. See [First login](../README.md#first-login).

To run a migration command by hand:

```bash
docker compose exec backend alembic current
docker compose exec backend alembic upgrade head
```

Useful commands:

```bash
docker compose logs -f backend
docker compose down        # keep data
docker compose down -v     # delete data
```

On Windows, check out the repository with LF line endings for shell scripts. `.gitattributes` enforces this for `*.sh`. A `docker-entrypoint.sh` with CRLF line endings stops the backend container at startup.

### Option 2: backend on the host

The backend image does not contain the test tools. Run tests and linters from a virtual environment on the host.

```bash
cd app/backend
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

The backend needs a database. Two ways:

| Way | Command | Notes |
|-----|---------|-------|
| SQLite | `SQLITE_MODE=true uvicorn app.main:app --reload --port 8080` | Creates `./mxtac.db` and applies migrations at startup. Valkey and OpenSearch are optional in this mode; without them, lockout and token revocation are not active and event search uses the database |
| PostgreSQL from Compose | `docker compose -f ../docker-compose.yml up -d postgres redis opensearch`, then set `DATABASE_URL`, `VALKEY_URL`, `OPENSEARCH_PORT` to the published ports and run `alembic upgrade head` and `uvicorn app.main:app --reload --port 8080` | See the example below |

Example `.env` in `app/backend/` for the Compose services:

```bash
DATABASE_URL=postgresql+asyncpg://mxtac:mxtac@localhost:15002/mxtac
VALKEY_URL=redis://localhost:15003/0
OPENSEARCH_HOST=localhost
OPENSEARCH_PORT=15004
```

Settings are documented in [configuration.md](configuration.md). The backend does not start when `.env` contains a setting that does not exist in `app/core/config.py`.

The generated password of `admin@mxtac.local` is written to the output of `uvicorn` at the first start.

### Option 3: frontend on the host

```bash
cd app/frontend
npm ci
npm run dev
```

The frontend calls the API with relative URLs (`/api/v1/...`). In development, the Vite server forwards `/api` to a backend, including the alert WebSocket at `/api/v1/ws/alerts` (`vite.config.ts`). The target is the environment variable `VITE_PROXY_TARGET`.

| Backend | `VITE_PROXY_TARGET` |
|---------|---------------------|
| Compose backend, published on port 15000 | Not needed. The default is `http://localhost:15000` |
| Backend on the host on port 8080 (Option 2) | `http://localhost:8080` |
| Inside the Compose network | `http://backend:8080`. `app/docker-compose.yml` sets this for the frontend service |

```bash
VITE_PROXY_TARGET=http://localhost:8080 npm run dev
```

Open <http://localhost:5173>. The built frontend has no environment variables.

### Tests and checks

Backend, from `app/backend`:

| Command | Purpose |
|---------|---------|
| `pytest` | All tests with coverage (configured in `pyproject.toml`). Tests use an in-memory SQLite database |
| `pytest tests/engine -q` | One test directory |
| `ruff check .` | Lint |
| `mypy app/` | Type check (strict) |

Frontend, from `app/frontend`:

| Command | Purpose |
|---------|---------|
| `npm test` | Vitest, single run |
| `npm run test:watch` | Vitest in watch mode |
| `npm run test:coverage` | Vitest with coverage |
| `npm run lint` | ESLint |
| `npx tsc --noEmit` | Type check |
| `npm run build` | Type check and production build into `dist/` |

The frontend build (`npm run build`) type-checks with `tsc -b`.

CI runs the same commands (`.github/workflows/backend-ci.yml`, `frontend-ci.yml`). After both succeed on `main`, `docker-build.yml` builds and pushes the images to GitHub Container Registry and scans them with Trivy.

### Database migrations

Migrations live in `app/backend/alembic/versions/`. Alembic reads the database URL from the application settings.

```bash
cd app/backend
alembic revision --autogenerate -m "describe the change"
alembic upgrade head
alembic downgrade -1
```

CI checks that there is one migration head, that an empty database upgrades to head and that downgrade to `0027` and upgrade again succeed on PostgreSQL 16 (`0027` is one-way), and that `alembic check` finds no difference between models and migrations.

`alembic upgrade head` works on an empty PostgreSQL database. In SQLite mode the backend applies the migrations itself at startup.

### Adding things

| Task | Where |
|------|-------|
| New API route | Add a module in `app/api/v1/endpoints/`, register it in `app/api/v1/router.py`, protect it with `require_permission`, then run `python scripts/gen_api_docs.py` |
| New permission | `PERMISSIONS` in `app/core/rbac.py`, then `docs/security.md` |
| New setting | `Settings` in `app/core/config.py`, then `docs/configuration.md` and `app/backend/.env.example`. When you remove a setting, remove it from every `.env` example and deployment file as well |
| New connector | Subclass `BaseConnector` in `app/connectors/`, add it to `CONNECTOR_TYPES` in `app/connectors/registry.py` and in `app/api/v1/endpoints/connectors.py`, add a topic in `app/pipeline/queue.py`, add a normalizer in `app/services/normalizers/` and subscribe it in `NormalizerPipeline`. The normalizer must set `metadata_product`, which Sigma rules match as `logsource.product` |
| New Sigma rule shipped with the code | A YAML file with an `id` in `app/backend/sigma_rules/`, then `python scripts/gen_rule_table.py --write`. It is imported into the database at the next backend start. Use only the syntax listed in [sigma-rules.md](sigma-rules.md) |
| New field for Sigma rules | `app/engine/field_mapper.py`, then [sigma-rules.md](sigma-rules.md) |
| New page | A component under `src/components/features/`, a route in `src/App.tsx`, a link in `src/components/layout/Sidebar.tsx` |

### Scripts

| Script | Purpose |
|--------|---------|
| `scripts/gen_api_docs.py` | Regenerate `docs/api.md` from the routes the backend registers. Run it after adding or changing a route |
| `scripts/gen_rule_table.py` | Print the table of bundled Sigma rules, or with `--write` replace it in `docs/sigma-rules.md` |
| `scripts/audit-deps.sh` | `pip-audit` and `npm audit`. `--ci` exits non-zero on findings |
| `scripts/scan-images.sh` | Scan the backend and frontend images with Grype or Trivy. `--build` builds them first |
| `scripts/backup-db.sh` | PostgreSQL dump with retention |
| `scripts/restore-db.sh` | Restore a dump |
| `scripts/deploy.sh` | Pull images and restart a Compose or k3s deployment |

## Architecture

This document describes the components that exist in the repository and how an event moves through them. File paths are relative to `app/backend/app/` unless stated otherwise.

### Components

| Component | Technology | Role |
|-----------|------------|------|
| Frontend | React 18, TypeScript, Vite, Tailwind CSS, TanStack Query, Zustand | Single-page web UI. Calls the backend under `/api/v1` and listens on a WebSocket for new detections |
| Backend | Python 3.12, FastAPI, SQLAlchemy 2 (async), Alembic | REST API, connectors, normalizers, Sigma engine, alert manager |
| PostgreSQL 16 | | Users, rules, detections, incidents, connectors, saved queries, coverage snapshots and targets, normalized events |
| Valkey 8 | Redis-compatible | Rate-limit counters, login lockout, revoked tokens, alert deduplication, GeoIP cache, WebSocket fan-out between replicas, rule-reload notifications, optional queue backend |
| OpenSearch 2.17 | | Index of normalized events for Hunt search, alert index, audit log index |

Optional services in `app/docker-compose.yml`, each behind a Compose profile: OpenSearch Dashboards (`dashboards`), Prometheus and Grafana (`monitoring`).

### Backend layout

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

### Event pipeline

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
2. **Normalize.** `NormalizerPipeline` converts the raw event to an `OCSFEvent`, assigns the event its ID (a UUID that travels next to the event as `mxtac_event_id`) and publishes it to `mxtac.normalized`. The event persister stores the event under that ID, and a detection raised from the event records it as `event_id`, which is how the UI links a detection to its event. Events that fail are sent to `mxtac.dlq`.

   | Source | OCSF classes produced |
   |--------|-----------------------|
   | Wazuh | Process Activity, Network Activity, Authentication, File Activity, Security Finding |
   | Zeek | Network Activity, DNS Activity, HTTP Activity |
   | Suricata | Security Finding, DNS Activity, Network Activity |
   | Syslog | Authentication for SSH and PAM login results, Process Activity for sudo command logs, Base Event for every other message |
   | Webhook | Process Activity when the event has a process or command line, Network Activity when it has a source and a destination address, otherwise Base Event |

3. **Persist.** The event persister writes the event to the PostgreSQL `events` table and indexes the same event document in OpenSearch (`mxtac-events-v2-YYYY.MM.DD`) with the same ID. A failure in either store is logged and does not stop the pipeline.
4. **Detect.** The Sigma consumer evaluates the enabled rules that apply to the event. Each match is published to `mxtac.alerts` and increments the rule's hit counter. See [sigma-rules.md](sigma-rules.md).
5. **Triage.** The alert manager:
   - drops the alert if the same rule fired on the same host in the last 5 minutes (a Valkey key with a 300-second lifetime);
   - adds a GeoIP lookup for public IP addresses when `GEOIP_DB_PATH` points to a MaxMind database;
   - computes a score from 0 to 10 from the rule level and how often the alert recurs;
   - stores the alert as a row in `detections`. The `tactic` column holds the name of the first ATT&CK tactic of the rule, for example `Credential Access`, and `tactic_id` its ID, for example `TA0006`. Rows written by earlier versions hold the ID in `tactic`; they are read as the tactic they name;
   - if `AUTO_CREATE_INCIDENT_ENABLED` is true, adds the detection to an open incident with the same host and tactic inside `CORRELATION_WINDOW_SECONDS`, or creates an incident when the severity is at least `AUTO_CREATE_INCIDENT_MIN_SEVERITY`;
   - publishes the result to `mxtac.enriched`.
6. **Notify.** The WebSocket broadcaster sends the enriched alert to every browser connected to `/api/v1/ws/alerts`. A connection needs a valid access token. With several backend replicas, the message is relayed through a Valkey pub/sub channel.

#### Queue backends

`QUEUE_BACKEND` selects the implementation. Any other value stops the backend at startup.

| Value | Implementation | Notes |
|-------|----------------|-------|
| `memory` (default) | `asyncio` queues inside the process | Messages are lost on restart. One backend process only |
| `redis` | Valkey Streams with consumer groups | Streams are capped at about 10,000 entries per topic |

### Rules

The `rules` table is the only source of rules for the engine, the Sigma Rules page and the coverage numbers. At startup the YAML files in `app/backend/sigma_rules/` are imported into the table (`services/bundled_rules.py`): a file whose Sigma `id` is not in the table yet is inserted with the source `bundled`, enabled. Existing rows are never updated, so edits and the enabled flag of a bundled rule are kept. The engine is then loaded from the table.

### Storage

| Store | Data | Notes |
|-------|------|-------|
| PostgreSQL | All application state and a copy of every normalized event | Schema managed by Alembic (`app/backend/alembic/`) |
| OpenSearch | `mxtac-events-v2-*`, `mxtac-alerts-*`, `mxtac-audit-*`, `mxtac-rules` | Index templates and retention policies are created at startup. Retention is set by the `OPENSEARCH_*_RETENTION_DAYS` settings. `OPENSEARCH_USERNAME` and `OPENSEARCH_PASSWORD` are sent as HTTP basic authentication when the user name is set |
| Valkey | Short-lived keys only | No data that must survive a flush |

Event search (`POST /api/v1/events/search`, `/aggregate`, `/export`) queries OpenSearch and falls back to PostgreSQL when OpenSearch is not reachable or a query fails. After a query that could not reach OpenSearch, it is skipped for 30 seconds. Reading one event or an entity timeline always uses PostgreSQL.

#### Event document

Both stores hold the same document for an event, and the event endpoints return it (`services/event_document.py`):

- the flat fields `id`, `event_uid`, `time`, `class_name`, `class_uid`, `severity_id`, `src_ip`, `dst_ip`, `hostname`, `username`, `process_hash`, `source` and `summary`. These are the columns of the `events` table. `hostname` is the host of the source endpoint or, if that is empty, of the destination endpoint;
- on top of them the full normalized event (`src_endpoint`, `dst_endpoint`, `actor_user`, `process`, `unmapped`, `raw` and so on).

A search gives the same rows, in the same order, from either store:

| Part of the request | Match |
|---------------------|-------|
| Free text (`query`) | The text as one case-insensitive substring of `summary`, `class_name`, `hostname`, `username`, `src_ip`, `dst_ip` or the process command line. No query syntax is interpreted |
| Filter `eq`, `ne` | Exact value, case-sensitive. `ne` only matches events that have a value in the field |
| Filter `contains` | Case-insensitive substring |
| Filter `gt`, `gte`, `lt`, `lte` | Numeric comparison for `severity_id` and `class_uid`, string comparison for the other fields |
| Filter fields | The flat fields. The nested names `src_endpoint.ip`, `dst_endpoint.ip`, `dst_endpoint.hostname`, `actor_user.name` and `process.hash_sha256` are accepted as aliases of `src_ip`, `dst_ip`, `hostname`, `username` and `process_hash` |
| Order | Newest first, then by ID |
| Terms aggregation | Buckets by count. Events without a value are counted under an empty key |

The index template `mxtac-events-template` maps the flat fields as keywords (numbers as integers) and does not index fields it does not list (`dynamic: false`), so a free-form field of a source cannot cause a mapping conflict. `POST /api/v1/events/query-dsl` returns a Lucene query on the flat fields that can be used in OpenSearch Dashboards on `mxtac-events-v2-*`.

Indices named `mxtac-events-YYYY.MM.DD` were written by earlier versions. They hold the nested event without the flat fields and are not searched. When the backend finds such an index at startup, it copies the events of the last 90 days from PostgreSQL into the current indices and marks the old index as done. The old indices are deleted by the retention policy.

With `SQLITE_MODE=true` the backend uses a local SQLite file instead of PostgreSQL and applies migrations at startup. In this mode `/ready` only requires the database.

API responses are built from these stores only. When a table is empty, the routes return zeros and empty lists.

### Startup sequence

`main.py` runs these steps when the backend starts:

1. Apply migrations (SQLite mode only). With PostgreSQL, run `alembic upgrade head` before starting the backend. The Compose files do this in the backend command.
2. Run the seeder. When the `users` table is empty it creates `admin@mxtac.local` with a forced password change, and with `SEED_DEMO_DATA=true` also the demo accounts and sample rows. Otherwise it does nothing. See [First login](../README.md#first-login).
3. Start the queue.
4. Connect to OpenSearch and create retention policies and index templates. If event indices of an earlier version exist, start re-indexing the events from PostgreSQL in the background (see [Event document](#event-document)).
5. Import the bundled Sigma rules that are missing in the `rules` table, then load the engine from the table.
6. Start the normalizer, dead-letter consumer, event persister, Sigma consumer, alert manager and WebSocket broadcaster.
7. Start the enabled connectors from the database.
8. Start background tasks: rule-reload subscriber, daily OpenSearch snapshot, storage metrics.
9. Start the syslog receiver when `SYSLOG_ENABLED=true`.

### Operational endpoints

| Path | Purpose |
|------|---------|
| `/health` | Liveness. Returns the version |
| `/ready` | Readiness. Checks the database, Valkey and OpenSearch, each with a 3-second timeout. Returns `503` when a required check fails. Also reports the age of the newest file in `BACKUP_DIR` (informational) |
| `/metrics` | Prometheus metrics: HTTP metrics plus pipeline counters such as processed and deduplicated alerts, rule matches, ingested events, active connectors, WebSocket connections and dead-letter events |

### Current limitations

Each item was checked against the code.

- **Events ingested while OpenSearch is not reachable are not indexed later.** They are stored in PostgreSQL only. Event search answers from PostgreSQL during the outage and shows them; once OpenSearch is reachable again, search answers from OpenSearch and those events are missing from the results. Reading one event and entity timelines are not affected. The backend connects to OpenSearch at startup only: if OpenSearch is down at that moment, search stays on PostgreSQL and nothing is indexed until the backend is restarted.
- Free-text search and `contains` filters match a substring with a leading wildcard, on both stores. On large event volumes these searches are slow; exact-match filters and a short time range keep them fast. In OpenSearch, a summary or command line longer than 8191 characters is not searchable.
- The in-memory queue is the default. It does not survive a restart and does not work across several backend processes.
- Sigma rules are evaluated one event at a time. There is no state across events apart from the 5-minute deduplication.
- The syslog normalizer recognises SSH, PAM and sudo messages. Every other message becomes a Base Event whose text is only available in the `message` field.
- Every backend replica starts every enabled connector, so with more than one replica each event is collected once per replica.
