# Installation

MxTac consists of a FastAPI backend, a React frontend, PostgreSQL, Valkey and OpenSearch. This guide covers three ways to install it. Other deployment files in the repository are described in [docs/deployment.md](docs/deployment.md).

## Requirements

| Component | Version |
|-----------|---------|
| Docker | With the Compose v2 plugin (`docker compose`) |
| Git | Any recent version |
| Python | 3.12 or newer, for running the backend without Docker |
| Node.js | 20 or newer, for running the frontend without Docker |

OpenSearch is started with a 512 MB Java heap in the Compose files. On Linux it needs `vm.max_map_count` of at least 262144:

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

   The backend applies the database migrations and then starts. On an empty database it creates the account `admin@mxtac.local` and imports the 20 bundled Sigma rules.

3. Check that the backend is ready.

   ```bash
   curl http://localhost:15000/ready
   ```

4. Read the generated password of `admin@mxtac.local`, open <http://localhost:15001> and sign in. The UI asks for a new password.

   ```bash
   docker compose logs backend | grep "INITIAL ADMIN PASSWORD"
   ```

   The details, and how to choose the password yourself with `INITIAL_ADMIN_PASSWORD`, are in the [README](README.md#first-login).

| Service | Address |
|---------|---------|
| Web UI | <http://localhost:15001> |
| Backend API | <http://localhost:15000> |
| Swagger UI | <http://localhost:15000/docs> |
| PostgreSQL | `localhost:15002` (user `mxtac`, password `mxtac`) |
| Valkey | `localhost:15003` |
| OpenSearch | <http://localhost:15004> |
| OpenSearch Dashboards | <http://localhost:15006> with `--profile dashboards` |
| Prometheus | <http://localhost:15009> with `--profile monitoring` |
| Grafana | <http://localhost:15010> with `--profile monitoring` |

This setup is for a trusted machine. It uses fixed development credentials for the database and the signing key and publishes every port.

## Option B: single host with the production Compose file

`app/docker-compose.prod.yml` runs the backend, the built frontend, PostgreSQL, Valkey and OpenSearch behind an Nginx reverse proxy with TLS. Only Nginx publishes ports.

1. Create `app/.env`.

   ```bash
   cd mxtac/app
   cat > .env <<EOF
   SECRET_KEY=$(openssl rand -hex 32)
   POSTGRES_PASSWORD=$(openssl rand -hex 16)
   DOMAIN=mxtac.example.com
   EOF
   chmod 600 .env
   ```

2. Put the TLS certificate and key in `app/nginx/ssl/` as `server.crt` and `server.key`. For a test, a self-signed pair is enough:

   ```bash
   mkdir -p nginx/ssl
   openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
     -keyout nginx/ssl/server.key -out nginx/ssl/server.crt \
     -subj "/CN=mxtac.example.com" -addext "subjectAltName=DNS:mxtac.example.com"
   ```

3. Start the stack and read the first password.

   ```bash
   docker compose -f docker-compose.prod.yml up -d --build
   docker compose -f docker-compose.prod.yml logs backend | grep "INITIAL ADMIN PASSWORD"
   ```

4. Open `https://mxtac.example.com` and sign in as `admin@mxtac.local`.

[docs/deployment.md](docs/deployment.md#production-compose-file) describes the file, its optional variables and what it does not cover.

## Option C: single Ubuntu server with the setup script

`app/setup.sh` installs Docker, generates secrets, starts the stack behind an Nginx reverse proxy with TLS, and prints how to sign in. It targets Ubuntu 22.04 and 24.04 and must run as root. It resets the UFW firewall rules of the host.

```bash
git clone https://github.com/fankh/mxtac.git
cd mxtac/app
sudo MXTAC_HOST=mxtac.example.com bash setup.sh
```

The installation is placed in `/opt/mxtac`. Read [docs/deployment.md](docs/deployment.md#automated-single-host-setup) for what the script does and the steps after it finishes.

## Running without Docker

See [docs/development.md](docs/development.md). In short:

```bash
# Backend with a local SQLite database
cd app/backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
SQLITE_MODE=true uvicorn app.main:app --port 8080
```

```bash
# Frontend dev server, forwarding /api to that backend
cd app/frontend
npm ci
VITE_PROXY_TARGET=http://localhost:8080 npm run dev
```

The generated password of `admin@mxtac.local` is written to the output of the backend process.

## Configuration

Settings are environment variables. [ENV-REFERENCE.md](ENV-REFERENCE.md) lists all of them. The ones to set for any shared deployment:

| Variable | Value |
|----------|-------|
| `DEBUG` | `false` |
| `SECRET_KEY` | Output of `openssl rand -hex 32` |
| `DATABASE_URL` | Your PostgreSQL URL with a strong password |
| `CORS_ORIGINS` | JSON array with the URL of the UI, for example `["https://mxtac.example.com"]` |
| `QUEUE_BACKEND` | `redis`, so that queued events survive a backend restart |
| `INITIAL_ADMIN_PASSWORD` | Optional. Password of `admin@mxtac.local` for the first start. Without it a random one is written to the log |

## Verifying the installation

| Check | Command | Expected |
|-------|---------|----------|
| Backend is running | `curl http://localhost:15000/health` | `{"status":"ok","version":"..."}` |
| Dependencies are reachable | `curl http://localhost:15000/ready` | `"status":"ready"` and `ok` for `db`, `valkey` and `opensearch`. The `backup` entry is informational |
| Containers | `docker compose ps` | All services up |
| Login | Sign in at <http://localhost:15001> | After the password change, the Overview page opens with zeros and empty states |
| Rules | Open **Sigma Rules** | 20 rules, all enabled |
| Pipeline | Open **Sources**, add a generic webhook source and use **Send test event** | The answer is `202` with `accepted: 1`. A search in **Hunt** without query text lists the event |

With the production Compose file, the backend port is not published. Use `https://<host>/health`, or run the probe in the container: `docker compose -f docker-compose.prod.yml exec backend python -c "import urllib.request; print(urllib.request.urlopen('http://localhost:8080/ready').read().decode())"`. With the setup script, the backend is reachable on the server at `http://localhost:8080`.

## Upgrading

Development Compose setup:

```bash
cd mxtac
git pull
cd app
docker compose up -d --build
```

Production Compose file: the same with `-f docker-compose.prod.yml`. In both cases migrations are applied when the backend container starts.

Setup-script installation:

```bash
cd mxtac
git pull
sudo bash app/update.sh
```

### Upgrade notes

Read these when you upgrade an installation that was created before the changes listed under `[Unreleased]` in [CHANGELOG.md](CHANGELOG.md).

| Change | What to do |
|--------|------------|
| The Kafka queue backend and the `KAFKA_*` settings were removed | Remove `KAFKA_BOOTSTRAP_SERVERS` and `KAFKA_CONSUMER_GROUP` from `app/backend/.env`. The backend does not start while a `.env` file contains a setting it does not know. Set `QUEUE_BACKEND` to `memory` or `redis`; `kafka` stops the startup |
| The `SMTP_*` settings and `POST /api/v1/users/invite` were removed | Remove the `SMTP_*` lines from `app/backend/.env` for the same reason. Create users with **Add user** or `POST /api/v1/users` |
| The Redpanda container is no longer part of any Compose file | After `docker compose up -d`, remove the old container with `docker compose up -d --remove-orphans`. The `redpanda_data` volume can be deleted |
| Existing accounts are kept | The seeder only runs on an empty `users` table. Accounts that were created by an older version with the former shared default password keep that password: change it under **Settings**, or deactivate the accounts |
| Bundled Sigma rules are imported into the `rules` table at startup | Nothing. Rules you created or edited are not overwritten. The list on the Sigma Rules page grows by the bundled rules |
| Detections now also come from syslog and webhook events | Review the bundled Linux rules on the Sigma Rules page and disable the ones you do not want |
| The alert WebSocket requires a valid access token | Scripts that read `/api/v1/ws/alerts` must pass `?token=<access token>` |
| `RATE_LIMIT_PER_MINUTE` now limits read requests | Check the value if you had set it. The default is 300 |
| A setup-script installation keeps its generated `/opt/mxtac/docker-compose.yml` | `update.sh` does not rewrite that file. The Redpanda service in it keeps running unused. Run `setup.sh` again from the updated checkout to regenerate the Compose file and the Nginx configuration; `.env`, the certificate and the data volumes are kept. Note that `setup.sh` resets the UFW rules each time. Afterwards remove the old Redpanda container with `docker compose -f /opt/mxtac/docker-compose.yml up -d --remove-orphans` |

Variables that are passed to the backend as real environment variables (Compose `environment`, systemd `EnvironmentFile`) are ignored when the backend does not know them. Only a `.env` file read by the backend itself (`app/backend/.env`) is strict.

## Troubleshooting

| Problem | What to check |
|---------|---------------|
| OpenSearch exits at startup on Linux | `sudo sysctl -w vm.max_map_count=262144` |
| `/ready` returns `503` | The `checks` object in the response names the dependency that failed. OpenSearch can take a minute to start |
| Backend exits with `FATAL: SECRET_KEY is set to the development default` | Set `SECRET_KEY` or, for local use only, `DEBUG=true` |
| Backend exits with `FATAL: INITIAL_ADMIN_PASSWORD does not meet the password policy` | Use 8 to 128 characters with three of: upper case, lower case, digit, symbol, or remove the variable |
| Backend exits with `Extra inputs are not permitted` and names a setting such as `kafka_bootstrap_servers` or `smtp_host` | `app/backend/.env` contains a setting that no longer exists. Remove the line. See [Upgrade notes](#upgrade-notes) |
| Backend exits with `Unsupported QUEUE_BACKEND` | Use `memory` or `redis` |
| Backend exits with `error parsing value for field "cors_origins"` | `CORS_ORIGINS` must be a JSON array |
| Backend exits with `Input should be a valid boolean` for `seed_demo_data` | `SEED_DEMO_DATA` is set to an empty value. Use `true` or `false`, or remove it |
| Backend container exits with `docker-entrypoint.sh: ... not found` on Windows | `app/backend/docker-entrypoint.sh` has CRLF line endings. Convert it to LF. `.gitattributes` keeps `*.sh` files in LF on a new clone |
| The log has no `INITIAL ADMIN PASSWORD` line | The line is written once, by the start that created the account. It is missing when `INITIAL_ADMIN_PASSWORD` was set, when the `users` table was not empty, or when the container that wrote it was removed. See [First login](README.md#first-login) |
| Login returns `500` and the backend log shows `relation "users" does not exist` | The migrations did not run. Run `docker compose exec backend alembic upgrade head` and restart the backend |
| Login returns `429` | Five failed logins lock the email address for 30 minutes. The login route also allows 10 requests per minute per IP |
| UI loads but API calls fail | The frontend calls `/api/v1` on its own origin. Check that the proxy forwards `/api/` to the backend. For the Vite dev server, check `VITE_PROXY_TARGET` |
| The top bar shows "Offline" or "Reconnecting" | The proxy must forward the WebSocket upgrade for `/api/v1/ws/`. "Offline" also appears when the session is no longer valid; sign in again |
| A port is already in use | Change the host port in `app/docker-compose.yml`, or set `HTTP_PORT` and `HTTPS_PORT` for `app/docker-compose.prod.yml` |

Logs:

```bash
docker compose logs -f backend
docker compose logs -f frontend
```

## Further reading

- [docs/deployment.md](docs/deployment.md): deployment files and production notes
- [docs/integration-guide.md](docs/integration-guide.md): connecting data sources
- [docs/security.md](docs/security.md): security model and limitations
