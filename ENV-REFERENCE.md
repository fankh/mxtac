# ENV-REFERENCE — MxTac Environment Variable Reference

This document summarizes backend environment variables based on:
- `app/backend/.env.example`
- `app/backend/app/core/config.py`
- `app/docker-compose.yml`

All values below are example values only (no real secrets).

## Database

| Variable | Default | Description | Required |
|---|---|---|---|
| `DATABASE_URL` | `postgresql+asyncpg://mxtac:mxtac@localhost:5432/mxtac` | Primary metadata database DSN. In Docker Compose backend uses `postgresql+asyncpg://mxtac:mxtac@postgres:5432/mxtac`. | Yes |
| `VALKEY_URL` | `redis://localhost:6379/0` | Valkey/Redis URL for cache, coordination, and some background features. In Docker Compose backend uses `redis://redis:6379/0`. | No |
| `SQLITE_MODE` | `false` | If `true`, app can run with local SQLite (single-binary mode) when `DATABASE_URL` is not explicitly sqlite. | No |
| `SQLITE_PATH` | `./mxtac.db` | SQLite file path used when `SQLITE_MODE=true`. | No |
| `DUCKDB_ENABLED` | `false` | Enables DuckDB event analytics fallback/mirroring features. | No |
| `DUCKDB_PATH` | `./mxtac-events.duckdb` | DuckDB file path when DuckDB mode is enabled. | No |

## API Keys

| Variable | Default | Description | Required |
|---|---|---|---|
| `SECRET_KEY` | `dev-secret-change-in-production` (example/dev only) | JWT signing key. Must be changed for production; startup fails in prod mode if left as dev default. Example secure value: `a3f9...` (64 hex chars). | Yes (production) |
| `OPENSEARCH_USERNAME` | *(empty)* | OpenSearch username when cluster security/auth is enabled. Example: `mxtac_reader`. | No |
| `OPENSEARCH_PASSWORD` | *(empty)* | OpenSearch password for `OPENSEARCH_USERNAME`. Example: `change-me-opensearch-password`. | No |
| `SMTP_USERNAME` | *(empty)* | Default SMTP auth username for notification dispatcher. Example: `smtp_user`. | No |
| `SMTP_PASSWORD` | *(empty)* | Default SMTP auth password for notification dispatcher. Example: `change-me-smtp-password`. | No |
| `ALERT_EMAIL_SMTP_USERNAME` | *(empty)* | SMTP username for alert email output integration. | No |
| `ALERT_EMAIL_SMTP_PASSWORD` | *(empty)* | SMTP password for alert email output integration. | No |
| `OPENCTI_TOKEN` | *(empty)* | Token for OpenCTI enrichment API (if used). | No |
| `THREAT_INTEL_FEEDS` | `[]` | JSON array of STIX/TAXII feed objects, can include per-feed `api_key`. Example: `[{"name":"AlienVault","taxii_url":"https://taxii.example/api","collection_id":"abcd","api_key":"demo-key"}]`. | No |

## Server

| Variable | Default | Description | Required |
|---|---|---|---|
| `APP_NAME` | `MxTac API` | API service display name. | No |
| `VERSION` | `2.0.0` | Application version string. | No |
| `DEBUG` | `false` in `.env.example` (`true` in `config.py` default, `true` in compose dev) | Enables debug/development behavior. Example production value: `false`. | No |
| `API_PREFIX` | `/api/v1` | Base path prefix for backend API routes. | No |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `60` | Access token lifetime in minutes. | No |
| `REFRESH_TOKEN_EXPIRE_DAYS` | `7` | Refresh token lifetime in days. | No |
| `JWT_KEY_VERSION` | `1` | JWT key version claim value for mass token invalidation on rotation. | No |
| `CORS_ORIGINS` | `["http://localhost:5173","https://mxtac.example.com"]` (`.env.example`) | JSON array of allowed frontend origins. Compose dev example uses localhost origins. | No |
| `RATE_LIMIT_PER_MINUTE` | `300` | Per-client API request rate limit. | No |
| `QUEUE_BACKEND` | `memory` | Queue backend: `memory`, `redis`, or `kafka`. Compose sets `memory` for dev. | No |
| `KAFKA_BOOTSTRAP_SERVERS` | `localhost:9092` | Kafka bootstrap servers when Kafka queue backend is used. Compose dev example: `redpanda:9092`. | No |
| `KAFKA_CONSUMER_GROUP` | `mxtac` | Kafka consumer group id. | No |
| `OPENSEARCH_HOST` | `localhost` | OpenSearch hostname. Compose dev example: `opensearch`. | No |
| `OPENSEARCH_PORT` | `9200` | OpenSearch API port. | No |
| `OPENSEARCH_USE_SSL` | `false` | Enables HTTPS connection to OpenSearch. | No |
| `SMTP_HOST` | `localhost` | Default SMTP host for notifications. Example: `smtp.example.com`. | No |
| `SMTP_PORT` | `587` | Default SMTP port. | No |
| `SMTP_FROM_ADDRESS` | `mxtac-alerts@localhost` | Default sender address for notification emails. Example: `alerts@mxtac.example.com`. | No |

## Feature Flags

| Variable | Default | Description | Required |
|---|---|---|---|
| `ALERT_FILE_OUTPUT_ENABLED` | `false` | Enable writing alerts to local JSONL files. | No |
| `ALERT_WEBHOOK_OUTPUT_ENABLED` | `false` | Enable alert delivery via HTTP webhooks. | No |
| `SYSLOG_ENABLED` | `false` | Enable inbound syslog receiver. | No |
| `ALERT_SYSLOG_OUTPUT_ENABLED` | `false` | Enable outbound alert syslog forwarding. | No |
| `ALERT_EMAIL_OUTPUT_ENABLED` | `false` | Enable outbound alert email notifications. | No |
| `DUCKDB_ENABLED` | `false` | Enable DuckDB analytics support. | No |
| `SQLITE_MODE` | `false` | Enable SQLite single-node mode. | No |
| `AUTO_CREATE_INCIDENT_ENABLED` | `true` | Auto-create incidents from correlated alerts. | No |
| `ASSET_AUTO_DISCOVERY` | `true` | Auto-upsert assets from normalized events. | No |
| `ALERT_AUTO_CLOSE_ENABLED` | `true` | Auto-close alerts after no recurrence window. | No |

## Notes

- **Required vs optional**: Most variables have safe defaults for local development. For production, at minimum set a strong `SECRET_KEY` and a valid `DATABASE_URL`.
- **Compose overrides**: `app/docker-compose.yml` passes dev-friendly values for backend (`DEBUG=true`, local service hostnames, etc.).
- **Secret handling**: Never commit real credentials in `.env` files; use secret managers or deployment-time environment injection.
