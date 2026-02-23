# ENV-REFERENCE — MxTac Environment Variable Reference

All environment variables used across MxTac components, grouped by component.
Copy each component's `.env.example` to `.env` and fill in the required values.

---

## App Backend (`app/backend/.env.example`)

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `APP_NAME` | Application display name | `MxTac API` | No |
| `VERSION` | Application version string | `2.0.0` | No |
| `DEBUG` | Enable debug mode (never set `true` in production) | `false` | No |
| `SECRET_KEY` | JWT signing secret — generate with `openssl rand -hex 32` | *(none)* | **Yes** |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | JWT access token lifetime in minutes | `60` | No |
| `REFRESH_TOKEN_EXPIRE_DAYS` | JWT refresh token lifetime in days | `7` | No |
| `DATABASE_URL` | PostgreSQL async DSN (`postgresql+asyncpg://...`) | `postgresql+asyncpg://mxtac:mxtac@localhost:5432/mxtac` | **Yes** |
| `VALKEY_URL` | Valkey / Redis connection URL | `redis://localhost:6379/0` | **Yes** |
| `QUEUE_BACKEND` | Event queue backend: `memory`, `redis`, or `kafka` | `memory` | No |
| `KAFKA_BOOTSTRAP_SERVERS` | Kafka broker list (used when `QUEUE_BACKEND=kafka`) | `localhost:9092` | No |
| `KAFKA_CONSUMER_GROUP` | Kafka consumer group id | `mxtac` | No |
| `OPENSEARCH_HOST` | OpenSearch hostname | `localhost` | No |
| `OPENSEARCH_PORT` | OpenSearch HTTP port | `9200` | No |
| `OPENSEARCH_USERNAME` | OpenSearch username (leave empty if auth disabled) | *(empty)* | No |
| `OPENSEARCH_PASSWORD` | OpenSearch password | *(empty)* | No |
| `OPENSEARCH_USE_SSL` | Enable TLS for OpenSearch connection | `false` | No |
| `RATE_LIMIT_PER_MINUTE` | Max API requests per IP per minute | `300` | No |
| `CORS_ORIGINS` | JSON array of allowed CORS origins | `["http://localhost:5173","https://mxtac.example.com"]` | No |
| `SMTP_HOST` | SMTP server hostname for email notifications | `localhost` | No |
| `SMTP_PORT` | SMTP server port (587 = STARTTLS) | `587` | No |
| `SMTP_USERNAME` | SMTP authentication username | *(empty)* | No |
| `SMTP_PASSWORD` | SMTP authentication password | *(empty)* | No |
| `SMTP_FROM_ADDRESS` | Sender address for outgoing alert emails | `mxtac-alerts@localhost` | No |

---

## App Frontend (`app/frontend/.env.example`)

Copy to `.env.local`. In development, the Vite proxy handles routing automatically.

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `VITE_API_BASE_URL` | Backend API base URL (used in production builds) | `http://localhost:8080` | No |

---

## Agent Scheduler — Root (`agent-scheduler/.env.example`)

Consumed by the top-level Docker Compose for the scheduler service.

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `AUTH_PASSWORD` | HTTP Basic Auth password for the scheduler API. Leave empty to disable auth. | *(none)* | **Yes (prod)** |

---

## Agent Scheduler — Backend (`agent-scheduler/backend/.env.example`)

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `SCHEDULER_DB_URL` | SQLite async DSN for task persistence | `sqlite+aiosqlite:///./data/scheduler.db` | No |
| `SCHEDULER_HOST` | Host address the scheduler API binds to | `0.0.0.0` | No |
| `SCHEDULER_PORT` | Port the scheduler API listens on | `13002` | No |
| `SCHEDULER_MAX_CONCURRENT` | Maximum number of agent tasks running concurrently | `2` | No |
| `SCHEDULER_SPAWN_DELAY` | Seconds to wait between spawning consecutive tasks | `30` | No |
| `SCHEDULER_TASK_TIMEOUT` | Maximum runtime per task in seconds | `1800` | No |
| `SCHEDULER_RETRY_MAX` | Maximum retry attempts for a failed task | `3` | No |
| `SCHEDULER_RETRY_BACKOFF` | Seconds to wait before retrying a failed task | `60` | No |
| `SCHEDULER_AUTO_START` | Automatically start the scheduler on server startup | `false` | No |
| `CLAUDE_MODEL` | Claude model alias passed to the CLI (`sonnet`, `opus`, `haiku`) | `sonnet` | No |
| `CLAUDE_CLI_PATH` | Path or command name of the Claude CLI binary | `claude` | No |
| `MXTAC_PROJECT_ROOT` | Absolute path to the MxTac repository root | *(none)* | **Yes** |
| `AUTH_PASSWORD` | HTTP Basic Auth password (mirrors root `AUTH_PASSWORD`) | *(none)* | **Yes (prod)** |

---

## Notes

- **Never commit `.env` files.** Each component's `.env.example` is safe to commit; the actual `.env` is in `.gitignore`.
- `AUTH_PASSWORD` appears in both the root and backend `agent-scheduler` examples. When using Docker Compose, set it once in `agent-scheduler/.env`; when running the backend directly, set it in `agent-scheduler/backend/.env`.
- `SECRET_KEY` must be unique per deployment. Reusing the same key across environments is a security risk.
- `QUEUE_BACKEND=memory` is suitable for development only. Use `redis` or `kafka` in production.
