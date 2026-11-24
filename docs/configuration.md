# Environment variable reference

The backend reads its settings from environment variables and from a `.env` file in the working directory (`app/backend/.env`). Variable names are not case-sensitive. The source of truth is `app/backend/app/core/config.py`. This file lists every setting defined there.

`app/backend/.env.example` is a template.

Unknown settings are handled differently depending on where they come from:

| Source | Unknown setting |
|--------|-----------------|
| `.env` file read by the backend | The backend does not start (`Extra inputs are not permitted`). This applies to settings that were removed, such as `KAFKA_BOOTSTRAP_SERVERS` and `SMTP_HOST` |
| Environment variable | Ignored |

## Application

| Variable | Default | Description |
|----------|---------|-------------|
| `DEBUG` | `true` | Development mode. Set to `false` for any shared deployment. With `false`, the backend adds the HSTS header, writes its log in a JSON-style line format and refuses to start with the default `SECRET_KEY` |
| `APP_NAME` | `MxTac API` | Title shown in the API documentation |
| `VERSION` | `2.0.0` | Version reported by `/health` |
| `API_PREFIX` | `/api/v1` | Path prefix of the REST API. The frontend expects the default |
| `CORS_ORIGINS` | `["http://localhost:5173","http://localhost:3000"]` | JSON array of origins that may call the API from a browser. Must be valid JSON; a comma-separated list is rejected |
| `RATE_LIMIT_PER_MINUTE` | `300` | Read requests (`GET`, `HEAD`, and the event queries of the Hunt page) allowed per client IP and minute. Login and MFA routes (10), export routes (5) and other write requests (60) have fixed limits in `app/core/rate_limit.py` |

## Authentication

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | `dev-secret-change-in-production` | Signs JWTs and derives the key that encrypts MFA secrets. Generate with `openssl rand -hex 32`. Required when `DEBUG=false` |
| `JWT_KEY_VERSION` | `1` | Increase to invalidate every issued token |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `60` | Access token lifetime |
| `REFRESH_TOKEN_EXPIRE_DAYS` | `7` | Refresh token lifetime |
| `ACCOUNT_INACTIVITY_DAYS` | `90` | Deactivate an account at login when its last login is older than this. `0` disables the check |
| `PASSWORD_EXPIRY_DAYS` | `90` | Require a new password at login when the password is older than this. `0` disables expiry |

## First start

These two settings are only read while the `users` table is empty. See [First login](../README.md#first-login).

| Variable | Default | Description |
|----------|---------|-------------|
| `INITIAL_ADMIN_PASSWORD` | not set | Password of the first account, `admin@mxtac.local`. Must meet the password policy (8 to 128 characters, three of: upper case, lower case, digit, symbol, no character more than three times in a row); a weaker value stops the startup. When it is not set or empty, a random password is generated and written once to the startup log in a `WARNING` line that starts with `INITIAL ADMIN PASSWORD (generated, shown only once)`. A value set here is never logged. Either way the account must set a new password at the first sign-in |
| `SEED_DEMO_DATA` | `false` | `true` also creates the accounts `analyst@mxtac.local`, `hunter@mxtac.local` and `engineer@mxtac.local` (same first password, also changed at first sign-in) and invented sample detections, incidents, connectors and rules. For demonstrations only. Must be `true` or `false`; an empty value stops the startup |

## Database

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgresql+asyncpg://mxtac:mxtac@localhost:5432/mxtac` | SQLAlchemy async URL of the PostgreSQL database |
| `SQLITE_MODE` | `false` | Use a local SQLite file instead of PostgreSQL. Migrations are applied at startup, and `/ready` only requires the database |
| `SQLITE_PATH` | `./mxtac.db` | SQLite file used when `SQLITE_MODE=true` |

## Valkey and queue

| Variable | Default | Description |
|----------|---------|-------------|
| `VALKEY_URL` | `redis://localhost:6379/0` | Valkey (or Redis) URL. Used for rate limits, login lockout, token revocation, alert deduplication, the GeoIP cache, WebSocket fan-out and rule-reload notifications |
| `QUEUE_BACKEND` | `memory` | Pipeline queue: `memory` (inside the backend process) or `redis` (Valkey Streams). Any other value stops the startup |

## OpenSearch

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENSEARCH_HOST` | `localhost` | Host name |
| `OPENSEARCH_PORT` | `9200` | Port |
| `OPENSEARCH_USERNAME` | empty | User name for HTTP basic authentication. When empty, the backend connects without credentials |
| `OPENSEARCH_PASSWORD` | empty | Password for `OPENSEARCH_USERNAME`. An empty password with a host other than `localhost` or `127.0.0.1` causes a startup warning |
| `OPENSEARCH_USE_SSL` | `false` | Connect with HTTPS. Certificates are not verified |
| `OPENSEARCH_EVENTS_RETENTION_DAYS` | `90` | Delete event indices after this many days |
| `OPENSEARCH_ALERTS_RETENTION_DAYS` | `365` | Delete alert indices after this many days |
| `OPENSEARCH_AUDIT_RETENTION_DAYS` | `1095` | Delete audit indices after this many days |
| `OPENSEARCH_SNAPSHOT_REPO` | `/backups/opensearch` | File system path of the snapshot repository for the daily snapshot. The path must be allowed in OpenSearch (`path.repo`) |
| `OPENSEARCH_SNAPSHOT_RETENTION_DAYS` | `30` | Delete snapshots older than this |

## Syslog receiver

| Variable | Default | Description |
|----------|---------|-------------|
| `SYSLOG_ENABLED` | `false` | Start the syslog receiver with the backend |
| `SYSLOG_HOST` | `0.0.0.0` | Bind address |
| `SYSLOG_PORT` | `1514` | Port |
| `SYSLOG_PROTOCOL` | `udp` | `udp`, `tcp` or `both` |
| `SYSLOG_MAX_MESSAGE_SIZE` | `65535` | Maximum message size in bytes |

Received messages are normalized, stored and evaluated by Sigma rules. See [docs/integration-guide.md](integration-guide.md#syslog).

## Detection pipeline

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTO_CREATE_INCIDENT_ENABLED` | `true` | Group detections into incidents automatically |
| `AUTO_CREATE_INCIDENT_MIN_SEVERITY` | `high` | Lowest severity that opens a new incident: `low`, `medium`, `high` or `critical` |
| `CORRELATION_WINDOW_SECONDS` | `3600` | A detection joins an open incident with the same host and tactic that is at most this old |
| `GEOIP_DB_PATH` | not set | Path to a MaxMind GeoLite2-City or GeoIP2-City `.mmdb` file. Without it, GeoIP enrichment is off |
| `GEOIP_CACHE_TTL` | `86400` | Seconds a GeoIP result is cached in Valkey |

## Backup check

| Variable | Default | Description |
|----------|---------|-------------|
| `BACKUP_DIR` | `./backups` | Directory in which `/ready` looks for `mxtac_backup_*.sql.gz` files |
| `BACKUP_STALE_HOURS` | `48` | `/ready` reports a warning when the newest backup is older than this. The warning does not change the ready status |

## Read directly from the environment

This variable is not a setting in `config.py` and cannot be set in `.env`.

| Variable | Default | Description |
|----------|---------|-------------|
| `MXTAC_STATE_DIR` | `/var/lib/mxtac` | Directory for the read positions of Zeek and Suricata connectors |

## Frontend

The built frontend has no environment variables. It calls the API with relative URLs on its own origin.

| Variable | Used by | Default | Description |
|----------|---------|---------|-------------|
| `VITE_PROXY_TARGET` | `app/frontend/vite.config.ts` (dev server only) | `http://localhost:15000` | Backend address the Vite dev server forwards `/api` to, including the alert WebSocket. `app/docker-compose.yml` sets it to `http://backend:8080` |

## Variables used by deployment files

These are not backend settings. They are read by Compose files, scripts or the container entrypoint.

| Variable | Used by | Description |
|----------|---------|-------------|
| `INITIAL_ADMIN_PASSWORD`, `SEED_DEMO_DATA` | `app/docker-compose.yml`, `app/docker-compose.prod.yml`, both stack files, `app/setup.sh` | Passed from the host environment (or the `.env` file next to the Compose file) to the backend. Optional |
| `SECRET_KEY` | `app/docker-compose.prod.yml` | Required. Passed to the backend |
| `POSTGRES_PASSWORD` | `app/docker-compose.prod.yml`, `app/setup.sh` | Database password. It is placed in `DATABASE_URL`, so use letters and digits |
| `DOMAIN` | `app/docker-compose.prod.yml`, `app/docker-stack.yml` | Public host name, used for `CORS_ORIGINS` |
| `HTTP_PORT`, `HTTPS_PORT` | `app/docker-compose.prod.yml` | Host ports of Nginx. Default `80` and `443` |
| `BACKEND_IMAGE`, `FRONTEND_IMAGE` | `app/docker-compose.prod.yml` | Image names, default `mxtac-backend:latest` and `mxtac-frontend:latest` |
| `IMAGE_PREFIX`, `VERSION` | `app/docker-stack.yml` | Image prefix and tag |
| `SECRET_KEY_FILE` | `app/backend/docker-entrypoint.sh` | File that contains the secret key. Default `/run/secrets/mxtac_secret_key` |
| `POSTGRES_PASSWORD_FILE` | `app/backend/docker-entrypoint.sh` | File that contains the database password. It is inserted into `DATABASE_URL`. Default `/run/secrets/mxtac_postgres_password` |
| `MXTAC_HOST` | `app/setup.sh` | Host name or IP address of the server |

## Example for a production `.env`

```bash
DEBUG=false
SECRET_KEY=<output of: openssl rand -hex 32>
DATABASE_URL=postgresql+asyncpg://mxtac:<password>@postgres:5432/mxtac
VALKEY_URL=redis://valkey:6379/0
QUEUE_BACKEND=redis
OPENSEARCH_HOST=opensearch
OPENSEARCH_PORT=9200
CORS_ORIGINS=["https://mxtac.example.com"]
```
