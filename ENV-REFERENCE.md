# Environment variable reference

The backend reads its settings from environment variables and from a `.env` file in the working directory (`app/backend/.env`). Variable names are not case-sensitive. The source of truth is `app/backend/app/core/config.py`.

`app/backend/.env.example` is a template. The frontend has no environment variables.

## Application

| Variable | Default | Description |
|----------|---------|-------------|
| `DEBUG` | `true` | Development mode. Set to `false` for any shared deployment. With `false`, the backend adds the HSTS header and refuses to start with the default `SECRET_KEY` |
| `APP_NAME` | `MxTac API` | Title shown in the API documentation |
| `VERSION` | `2.0.0` | Version reported by `/health` |
| `API_PREFIX` | `/api/v1` | Path prefix of the REST API. The frontend expects the default |
| `CORS_ORIGINS` | `["http://localhost:5173","http://localhost:3000"]` | JSON array of origins that may call the API from a browser. Must be valid JSON; a comma-separated list is rejected. The first entry is also used as the base URL in invite emails |

## Authentication

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | `dev-secret-change-in-production` | Signs JWTs and derives the key that encrypts MFA secrets. Generate with `openssl rand -hex 32`. Required when `DEBUG=false` |
| `JWT_KEY_VERSION` | `1` | Increase to invalidate every issued token |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `60` | Access token lifetime |
| `REFRESH_TOKEN_EXPIRE_DAYS` | `7` | Refresh token lifetime |
| `ACCOUNT_INACTIVITY_DAYS` | `90` | Deactivate an account at login when its last login is older than this. `0` disables the check |
| `PASSWORD_EXPIRY_DAYS` | `90` | Require a new password at login when the password is older than this. `0` disables expiry |

## Database

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgresql+asyncpg://mxtac:mxtac@localhost:5432/mxtac` | SQLAlchemy async URL of the PostgreSQL database |
| `SQLITE_MODE` | `false` | Use a local SQLite file instead of PostgreSQL. Migrations are applied at startup, and `/ready` only requires the database |
| `SQLITE_PATH` | `./mxtac.db` | SQLite file used when `SQLITE_MODE=true` |

## Valkey and queue

| Variable | Default | Description |
|----------|---------|-------------|
| `VALKEY_URL` | `redis://localhost:6379/0` | Valkey (or Redis) URL. Used for rate limits, login lockout, token revocation, alert deduplication, the GeoIP cache and WebSocket fan-out |
| `QUEUE_BACKEND` | `memory` | Pipeline queue: `memory`, `redis` (Valkey Streams) or `kafka` |
| `KAFKA_BOOTSTRAP_SERVERS` | `localhost:9092` | Kafka brokers, used when `QUEUE_BACKEND=kafka` |

`QUEUE_BACKEND=kafka` needs the `aiokafka` Python package, which is not in `requirements.txt` and not in the Docker image. Install it yourself (`pip install aiokafka==0.12.0`).

## OpenSearch

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENSEARCH_HOST` | `localhost` | Host name |
| `OPENSEARCH_PORT` | `9200` | Port |
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

Received messages are not processed further yet. See [docs/integration-guide.md](docs/integration-guide.md).

## Detection pipeline

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTO_CREATE_INCIDENT_ENABLED` | `true` | Group detections into incidents automatically |
| `AUTO_CREATE_INCIDENT_MIN_SEVERITY` | `high` | Lowest severity that opens a new incident: `low`, `medium`, `high` or `critical` |
| `CORRELATION_WINDOW_SECONDS` | `3600` | A detection joins an open incident with the same host and tactic that is at most this old |
| `GEOIP_DB_PATH` | not set | Path to a MaxMind GeoLite2-City or GeoIP2-City `.mmdb` file. Without it, GeoIP enrichment is off |
| `GEOIP_CACHE_TTL` | `86400` | Seconds a GeoIP result is cached in Valkey |

## Email

Used only by `POST /api/v1/users/invite`.

| Variable | Default | Description |
|----------|---------|-------------|
| `SMTP_HOST` | `localhost` | SMTP server |
| `SMTP_PORT` | `587` | Port. `465` uses implicit TLS, other ports use STARTTLS |
| `SMTP_USERNAME` | empty | Login, optional |
| `SMTP_PASSWORD` | empty | Password, optional |
| `SMTP_FROM_ADDRESS` | `mxtac-alerts@localhost` | Sender address |

## Backup check

| Variable | Default | Description |
|----------|---------|-------------|
| `BACKUP_DIR` | `./backups` | Directory in which `/ready` looks for `mxtac_backup_*.sql.gz` files |
| `BACKUP_STALE_HOURS` | `48` | `/ready` reports a warning when the newest backup is older than this. The warning does not change the ready status |

## Other

| Variable | Default | Description |
|----------|---------|-------------|
| `MXTAC_STATE_DIR` | `/var/lib/mxtac` | Directory for the read positions of Zeek and Suricata connectors. Read directly from the environment, not from `.env` |

## Settings without effect

These settings exist in `config.py` but the code does not use them.

| Variable | Note |
|----------|------|
| `RATE_LIMIT_PER_MINUTE` | The rate limits are fixed in `app/core/rate_limit.py` |
| `OPENSEARCH_USERNAME`, `OPENSEARCH_PASSWORD` | The OpenSearch client connects without credentials. An empty password only triggers a startup warning when the host is not local |
| `KAFKA_CONSUMER_GROUP` | Not read by the Kafka queue |

## Variables used by deployment files

These are not backend settings. They are read by Compose files, scripts or the container entrypoint.

| Variable | Used by | Description |
|----------|---------|-------------|
| `POSTGRES_PASSWORD` | `app/docker-compose.prod.yml`, `app/setup.sh` | Database password |
| `DOMAIN` | `app/docker-compose.prod.yml`, `app/docker-stack.yml` | Public host name, used for `CORS_ORIGINS` |
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
