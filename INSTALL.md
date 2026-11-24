# Installation

MxTac consists of a FastAPI backend, a React frontend, PostgreSQL, Valkey and OpenSearch. This guide covers the two supported ways to install it. Other deployment files in the repository are described in [docs/deployment.md](docs/deployment.md).

## Requirements

| Component | Version |
|-----------|---------|
| Docker | With the Compose v2 plugin (`docker compose`) |
| Git | Any recent version |
| Python | 3.12 or newer, for running the backend without Docker |
| Node.js | 20 or newer, for running the frontend without Docker |

OpenSearch is started with a 512 MB Java heap in the development Compose file. On Linux it needs `vm.max_map_count` of at least 262144:

```bash
sudo sysctl -w vm.max_map_count=262144
```

## Option A: local evaluation with Docker Compose

1. Clone the repository.

   ```bash
   git clone https://github.com/fankh/mxtac.git
   cd mxtac/app
   ```

2. Start the stack.

   ```bash
   docker compose up -d --build
   ```

   The backend applies the database migrations and then starts.

3. Check that the backend is ready.

   ```bash
   curl http://localhost:15000/ready
   ```

4. Open <http://localhost:15001> and sign in. The default accounts and how to replace them are described in the [README](README.md#first-login).

| Service | Address |
|---------|---------|
| Web UI | <http://localhost:15001> |
| Backend API | <http://localhost:15000> |
| Swagger UI | <http://localhost:15000/docs> |
| PostgreSQL | `localhost:15002` (user `mxtac`, password `mxtac`) |
| Valkey | `localhost:15003` |
| OpenSearch | <http://localhost:15004> |
| OpenSearch Dashboards | <http://localhost:15006> with `--profile dashboards` |
| Redpanda (Kafka API) | `localhost:15007` with `--profile kafka` |
| Prometheus | <http://localhost:15009> with `--profile monitoring` |
| Grafana | <http://localhost:15010> with `--profile monitoring` |

This setup is for a trusted machine. It uses fixed development credentials and publishes every port.

## Option B: single Ubuntu server

`app/setup.sh` installs Docker, generates secrets, starts the stack behind an Nginx reverse proxy with TLS, and runs the migrations. It targets Ubuntu 22.04 and 24.04 and must run as root. It resets the UFW firewall rules of the host.

```bash
git clone https://github.com/fankh/mxtac.git
cd mxtac/app
sudo MXTAC_HOST=mxtac.example.com bash setup.sh
```

The installation is placed in `/opt/mxtac`. Read [docs/deployment.md](docs/deployment.md#automated-single-host-setup) for what the script does, the steps after it finishes, and its known gaps.

## Running without Docker

See [docs/development.md](docs/development.md). In short:

```bash
# Backend with a local SQLite database
cd app/backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
SQLITE_MODE=true uvicorn app.main:app --port 8080
```

The frontend dev server expects the backend under the host name `backend`; see [docs/development.md](docs/development.md#option-3-frontend-on-the-host).

## Configuration

Settings are environment variables. [ENV-REFERENCE.md](ENV-REFERENCE.md) lists all of them. The ones to set for any shared deployment:

| Variable | Value |
|----------|-------|
| `DEBUG` | `false` |
| `SECRET_KEY` | Output of `openssl rand -hex 32` |
| `DATABASE_URL` | Your PostgreSQL URL with a strong password |
| `CORS_ORIGINS` | JSON array with the URL of the UI, for example `["https://mxtac.example.com"]` |

## Verifying the installation

| Check | Command | Expected |
|-------|---------|----------|
| Backend is running | `curl http://localhost:15000/health` | `{"status":"ok","version":"..."}` |
| Dependencies are reachable | `curl http://localhost:15000/ready` | `"status":"ready"` and `ok` for `db`, `valkey` and `opensearch`. The `backup` entry is informational |
| Containers | `docker compose ps` | All services up |
| Login | Sign in at <http://localhost:15001> | The Overview page opens |

With the single-server setup, replace `http://localhost:15000` with `http://localhost:8080` on the server.

## Upgrading

Development Compose setup:

```bash
cd mxtac
git pull
cd app
docker compose up -d --build
```

Migrations are applied when the backend container starts.

Single-server setup:

```bash
cd mxtac
git pull
sudo bash app/update.sh
```

## Troubleshooting

| Problem | What to check |
|---------|---------------|
| OpenSearch exits at startup on Linux | `sudo sysctl -w vm.max_map_count=262144` |
| `/ready` returns `503` | The `checks` object in the response names the dependency that failed. OpenSearch can take a minute to start |
| Backend exits with `FATAL: SECRET_KEY is set to the development default` | Set `SECRET_KEY` or, for local use only, `DEBUG=true` |
| Backend exits with `error parsing value for field "cors_origins"` | `CORS_ORIGINS` must be a JSON array |
| Backend container exits with `docker-entrypoint.sh: ... not found` on Windows | `app/backend/docker-entrypoint.sh` has CRLF line endings. Convert it to LF. `.gitattributes` keeps `*.sh` files in LF on a new clone |
| Login returns `500` and the backend log shows `relation "users" does not exist` | The migrations did not run. Run `docker compose exec backend alembic upgrade head` and restart the backend |
| Login returns `429` | Five failed logins lock the email address for 30 minutes. The login route also allows 10 requests per minute per IP |
| UI loads but API calls fail | The frontend calls `/api/v1` on its own origin. Check that the proxy forwards `/api/` to the backend |
| A port is already in use | Change the host port in `app/docker-compose.yml` |

Logs:

```bash
docker compose logs -f backend
docker compose logs -f frontend
```

## Further reading

- [docs/deployment.md](docs/deployment.md): deployment files and production notes
- [docs/integration-guide.md](docs/integration-guide.md): connecting data sources
- [docs/security.md](docs/security.md): security model and limitations
