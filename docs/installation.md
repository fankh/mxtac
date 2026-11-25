# Installation and deployment

- [Installation](#installation)
- [Deployment](#deployment)

## Installation

MxTac consists of a FastAPI backend, a React frontend, PostgreSQL, Valkey and OpenSearch. This guide covers three ways to install it. Other deployment files in the repository are described in [Deployment](#deployment).

### Requirements

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

### Option A: local evaluation with Docker Compose

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

   The details, and how to choose the password yourself with `INITIAL_ADMIN_PASSWORD`, are in the [README](../README.md#first-login).

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

### Option B: single host with the production Compose file

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

[Production Compose file](#production-compose-file) describes the file, its optional variables and what it does not cover.

### Option C: single Ubuntu server with the setup script

`app/setup.sh` installs Docker, generates secrets, starts the stack behind an Nginx reverse proxy with TLS, and prints how to sign in. It targets Ubuntu 22.04 and 24.04 and must run as root. It resets the UFW firewall rules of the host.

```bash
git clone https://github.com/fankh/mxtac.git
cd mxtac/app
sudo MXTAC_HOST=mxtac.example.com bash setup.sh
```

The installation is placed in `/opt/mxtac`. Read [Automated single-host setup](#automated-single-host-setup) for what the script does and the steps after it finishes.

### Running without Docker

See [docs/development.md](development.md). In short:

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

### Configuration

Settings are environment variables. [configuration.md](configuration.md) lists all of them. The ones to set for any shared deployment:

| Variable | Value |
|----------|-------|
| `DEBUG` | `false` |
| `SECRET_KEY` | Output of `openssl rand -hex 32` |
| `DATABASE_URL` | Your PostgreSQL URL with a strong password |
| `CORS_ORIGINS` | JSON array with the URL of the UI, for example `["https://mxtac.example.com"]` |
| `QUEUE_BACKEND` | `redis`, so that queued events survive a backend restart |
| `INITIAL_ADMIN_PASSWORD` | Optional. Password of `admin@mxtac.local` for the first start. Without it a random one is written to the log |

### Verifying the installation

| Check | Command | Expected |
|-------|---------|----------|
| Backend is running | `curl http://localhost:15000/health` | `{"status":"ok","version":"..."}` |
| Dependencies are reachable | `curl http://localhost:15000/ready` | `"status":"ready"` and `ok` for `db`, `valkey` and `opensearch`. The `backup` entry is informational |
| Containers | `docker compose ps` | All services up |
| Login | Sign in at <http://localhost:15001> | After the password change, the Overview page opens with zeros and empty states |
| Rules | Open **Sigma Rules** | 20 rules, all enabled |
| Pipeline | Open **Sources**, add a generic webhook source and use **Send test event** | The answer is `202` with `accepted: 1`. A search in **Hunt** without query text lists the event |

With the production Compose file, the backend port is not published. Use `https://<host>/health`, or run the probe in the container: `docker compose -f docker-compose.prod.yml exec backend python -c "import urllib.request; print(urllib.request.urlopen('http://localhost:8080/ready').read().decode())"`. With the setup script, the backend is reachable on the server at `http://localhost:8080`.

### Upgrading

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

#### Upgrade notes

Read these when you upgrade an installation that was created before the changes listed under `[Unreleased]` in [CHANGELOG.md](../CHANGELOG.md).

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
| Events are indexed in new OpenSearch indices, `mxtac-events-v2-*`, with the fields Hunt searches | Nothing. At the first start the backend copies the events of the last 90 days from PostgreSQL into the new indices; the backend log reports `Re-indexed <n> events from PostgreSQL`. Until that is done, Hunt shows only part of the older events. The old `mxtac-events-YYYY.MM.DD` indices are not searched any more and are deleted by the retention policy; you can delete them earlier. Saved OpenSearch Dashboards queries must use the new index pattern and the flat field names (`hostname`, `username`, `src_ip`, `dst_ip`, `source`) |
| Detections store the tactic name (`Credential Access`) in `tactic` and the ID in `tactic_id` | Nothing. Detections of earlier versions that hold the ID in `tactic` are shown, filtered and counted under the tactic name |
| A setup-script installation keeps its generated `/opt/mxtac/docker-compose.yml` | `update.sh` does not rewrite that file. The Redpanda service in it keeps running unused. Run `setup.sh` again from the updated checkout to regenerate the Compose file and the Nginx configuration; `.env`, the certificate and the data volumes are kept. Note that `setup.sh` resets the UFW rules each time. Afterwards remove the old Redpanda container with `docker compose -f /opt/mxtac/docker-compose.yml up -d --remove-orphans` |

Variables that are passed to the backend as real environment variables (Compose `environment`, systemd `EnvironmentFile`) are ignored when the backend does not know them. Only a `.env` file read by the backend itself (`app/backend/.env`) is strict.

### Troubleshooting

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
| The log has no `INITIAL ADMIN PASSWORD` line | The line is written once, by the start that created the account. It is missing when `INITIAL_ADMIN_PASSWORD` was set, when the `users` table was not empty, or when the container that wrote it was removed. See [First login](../README.md#first-login) |
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

### Further reading

- [Deployment](#deployment): deployment files and production notes
- [docs/user-guide.md](user-guide.md#source-integration-guide): connecting data sources
- [docs/security.md](security.md): security model and limitations

## Deployment

This document describes the deployment files in the repository and how far each one has been checked against the current code. Read the status column before you rely on a file.

### Deployment files

| File | Target | Status |
|------|--------|--------|
| `app/docker-compose.yml` | Development and evaluation on one machine | Tested. Used for the quick start in the [README](../README.md) |
| `app/docker-compose.prod.yml`, `app/nginx/nginx.conf`, `app/frontend/nginx.conf` | One host, behind Nginx with TLS | Tested, see [Production Compose file](#production-compose-file) |
| `app/setup.sh`, `app/update.sh`, `app/enable-https.sh` | One Ubuntu 22.04 or 24.04 host with Docker, Nginx and TLS | `setup.sh` generates its own Compose file and Nginx configuration. Reviewed against the code; the scripts were not run end to end after their last change. See [Automated single-host setup](#automated-single-host-setup) |
| `app/docker-stack.yml`, `app/nginx/nginx.swarm.conf`, `app/.env.swarm.example` | Docker Swarm | Not tested with the current code. Has no OpenSearch service and no migration step |
| `app/deploy/docker-swarm/docker-stack.yml` | Docker Swarm, with OpenSearch | Not tested with the current code. Has no migration step |
| `app/deploy/k3s/` | k3s or Kubernetes (Kustomize manifests and `deploy.sh`) | Not tested with the current code |
| `app/deploy/systemd/` | Backend as a systemd service on a host | Not tested with the current code. Covers the backend only |
| `app/deploy/haproxy/haproxy.cfg` | HAProxy in front of three backend and two frontend instances | Example configuration |
| `app/deploy/monitoring/` | Prometheus and Grafana configuration | Used by the `monitoring` profile of `app/docker-compose.yml` |

"Tested" means the stack was started from an empty state and these points were checked: `/ready` reports all dependencies, the migrations are at the head revision, the generated password line appears once in the backend log, the UI and a deep link such as `/detections` load, the first sign-in forces a password change, 20 rules are listed, a webhook test event is stored and creates a detection, and the alert WebSocket refuses a connection without a token and accepts one with a token.

"Not tested" means the file was kept from an earlier version of the project and has not been run since the code was reduced to the current core. Its settings were checked for references to removed features, and none remain.

### What every deployment needs

| Requirement | Detail |
|-------------|--------|
| Database schema | Run `alembic upgrade head` in the backend before the first start and after every upgrade. The backend applies migrations by itself only in SQLite mode. The Compose files and `setup.sh` run the command when the backend container starts |
| `SECRET_KEY` | A random value, for example `openssl rand -hex 32`. With `DEBUG=false` the backend does not start with the development default |
| `DEBUG=false` | Enables the HSTS header and the secret-key check |
| `CORS_ORIGINS` | JSON array with the URL the UI is served from, for example `["https://mxtac.example.com"]` |
| PostgreSQL, Valkey, OpenSearch | `/ready` returns `503` when one of them is not reachable. Container health checks and load balancers that probe `/ready` then mark the backend as unhealthy |
| Same origin | The frontend calls `/api/v1/...` on its own origin. A reverse proxy must route `/api/` to the backend and everything else to the frontend. The production frontend image can do the `/api` part itself |
| Client-side routes | Paths such as `/detections` must return `index.html`. The production frontend image does this (`app/frontend/nginx.conf`) |
| WebSocket | The proxy must pass the `Upgrade` and `Connection` headers for `/api/v1/ws/`. The request carries the access token in the query string; do not log it |
| Client address | The backend takes the client address for its rate limits from the `X-Forwarded-For` header. The edge proxy must set it to the address of the client |
| First login | The first start on an empty database creates `admin@mxtac.local`. Read the generated password from the backend log, or set `INITIAL_ADMIN_PASSWORD` for the first start. See [First login](../README.md#first-login) |
| No stale settings | A `.env` file read by the backend must not contain removed settings such as `KAFKA_*` or `SMTP_*`. See the [upgrade notes](#upgrade-notes) |
| Network exposure | Publish the reverse proxy only. Do not publish the backend, PostgreSQL, Valkey or OpenSearch ports. See the limitations in [security.md](security.md) |

All settings are listed in [configuration.md](configuration.md).

### Development Compose file

`app/docker-compose.yml` starts the backend, the frontend dev server, PostgreSQL, Valkey and OpenSearch. See the [README](../README.md#quick-start) and [development.md](development.md).

It is not a production setup: `DEBUG=true`, a fixed `SECRET_KEY`, the database password `mxtac`, OpenSearch without authentication, source code mounted into the containers, and all ports published on every interface.

`INITIAL_ADMIN_PASSWORD` and `SEED_DEMO_DATA` are passed from the host environment, or from a file `app/.env`, to the backend.

### Production Compose file

`app/docker-compose.prod.yml` runs everything on one host.

| Service | Image | Published |
|---------|-------|-----------|
| `nginx` | `nginx:1.27-alpine` with `app/nginx/nginx.conf` | `HTTP_PORT` (default 80) and `HTTPS_PORT` (default 443) |
| `backend` | Built from `app/backend/Dockerfile` | No |
| `frontend` | Built from `app/frontend/Dockerfile.prod`: the static build served by Nginx | No |
| `postgres` | `postgres:16-alpine` | No |
| `redis` | `valkey/valkey:8-alpine` | No |
| `opensearch` | `opensearchproject/opensearch:2.17.0`, single node, security plugin disabled | No |

#### Variables

Put them in `app/.env` or export them.

| Variable | Required | Description |
|----------|----------|-------------|
| `SECRET_KEY` | Yes | For example `openssl rand -hex 32` |
| `POSTGRES_PASSWORD` | Yes | Database password. It is placed in a URL: use letters and digits. PostgreSQL only reads it when the data volume is created; changing it later does not change the database password |
| `DOMAIN` | Yes | Public host name. Used for `CORS_ORIGINS` |
| `INITIAL_ADMIN_PASSWORD` | No | Password of `admin@mxtac.local` for the first start |
| `SEED_DEMO_DATA` | No | `true` or `false`. Default `false` |
| `HTTP_PORT`, `HTTPS_PORT` | No | Host ports of Nginx |
| `BACKEND_IMAGE`, `FRONTEND_IMAGE` | No | Image names |

Compose stops with a message when a required variable is missing.

#### Steps

1. Create `app/.env` with the required variables.
2. Put the certificate and the key in `app/nginx/ssl/server.crt` and `app/nginx/ssl/server.key`. These are the names `app/setup.sh` and `app/enable-https.sh` use. The directory is in `.gitignore`.
3. Start the stack.

   ```bash
   cd app
   docker compose -f docker-compose.prod.yml up -d --build
   ```

4. Read the first password and sign in at `https://<DOMAIN>`.

   ```bash
   docker compose -f docker-compose.prod.yml logs backend | grep "INITIAL ADMIN PASSWORD"
   ```

The commands are also in [Option B: single host with the production Compose file](#option-b-single-host-with-the-production-compose-file).

#### How it works

- The backend command runs `alembic upgrade head` and then starts the API. The stack has one backend container, so two migrations cannot run at the same time.
- The backend waits for PostgreSQL, Valkey and OpenSearch to be healthy. Nginx waits for the backend and the frontend.
- The queue backend is Valkey Streams (`QUEUE_BACKEND=redis`).
- Nginx redirects port 80 to HTTPS and routes:

  | Path | Target |
  |------|--------|
  | `/api/v1/ws/` | Backend, with the WebSocket upgrade. Not written to the access log |
  | `/api/` | Backend. At most 600 requests per minute per client address with a burst of 100; more get `429`. The backend applies its own limits per route group |
  | `/health` | Backend |
  | Everything else | Frontend container, which serves the build and falls back to `index.html` |

- `/ready`, `/metrics`, `/docs`, `/redoc` and `/openapi.json` of the backend are not reachable from outside. Probe `/ready` inside the container:

  ```bash
  docker compose -f docker-compose.prod.yml exec backend \
    python -c "import urllib.request; print(urllib.request.urlopen('http://localhost:8080/ready').read().decode())"
  ```

- Nginx sets `X-Forwarded-For` to the address of the client.

#### What it does not cover

| Topic | State |
|-------|-------|
| Certificate | You provide the files and renew them. `enable-https.sh` is written for the `setup.sh` installation |
| HTTP redirect with a changed `HTTPS_PORT` | The redirect from port 80 points to the default HTTPS port |
| OpenSearch | No authentication and one node. It is only reachable inside the Compose network |
| Valkey | No password. It is only reachable inside the Compose network |
| Backups | Not scheduled. See [Backup and restore](#backup-and-restore) |
| Syslog | No syslog port is published. Add a port mapping to the backend service |
| Zeek and Suricata files | Not mounted. Add volumes to the backend service, see [user-guide.md](user-guide.md#source-integration-guide) |
| More than one backend | Not supported by this file. See [Scaling notes](#scaling-notes) |

### Automated single-host setup

`app/setup.sh` prepares one Ubuntu server.

```bash
git clone https://github.com/fankh/mxtac.git
cd mxtac/app
sudo MXTAC_HOST=mxtac.example.com bash setup.sh
```

`MXTAC_HOST` is the host name or IP address users open in the browser. Without it the script uses the first address from `hostname -I`. Add `INITIAL_ADMIN_PASSWORD=<password>` to choose the first password; it is written to `/opt/mxtac/.env`. That file is also read by the shell, so avoid spaces, quotes and `$` in the value.

The script performs these steps and can be run again:

1. Installs packages and configures UFW to allow ports 22, 80 and 443 only. **It resets existing UFW rules.**
2. Installs Docker Engine and the Compose plugin when they are missing.
3. Sets `vm.max_map_count=262144` for OpenSearch.
4. Writes `/opt/mxtac/.env` with a generated `SECRET_KEY` and database password. An existing `.env` is kept.
5. Copies the `app/` directory to `/opt/mxtac` and writes `/opt/mxtac/docker-compose.yml`. That file defines PostgreSQL, Valkey, OpenSearch, the backend, the frontend (static build served by Nginx) and an Nginx reverse proxy. Internal ports are bound to `127.0.0.1`. It is a different file from `app/docker-compose.prod.yml`.
6. Writes `/opt/mxtac/nginx/nginx.conf` and creates a self-signed certificate for `MXTAC_HOST`.
7. Builds and starts the containers and waits for their health checks. The backend applies the migrations when it starts, creates `admin@mxtac.local` and imports the bundled rules.
8. Shows the migration state, the service status, the URL and how to sign in for the first time.

After the script finishes:

1. Sign in. On the server, read the generated password:

   ```bash
   docker compose -f /opt/mxtac/docker-compose.yml logs backend | grep "INITIAL ADMIN PASSWORD"
   ```

   See [First login](../README.md#first-login). On the server the API is reachable at `http://localhost:8080`.
2. Replace the self-signed certificate: `sudo bash /opt/mxtac/enable-https.sh mxtac.example.com`. The script obtains a Let's Encrypt certificate with certbot, installs it for Nginx and adds a renewal cron job. The domain must resolve to the server and port 80 must be reachable.

Upgrade with `sudo bash app/update.sh` from an updated checkout. It copies the source to `/opt/mxtac`, rebuilds the images, runs the migrations with the new backend image, restarts the backend and the frontend, and reloads Nginx. It keeps `.env`, the generated `docker-compose.yml` and the `nginx/` directory. To get a new version of the generated Compose file and Nginx configuration, run `setup.sh` again.

Things to know about this setup:

- The generated Nginx configuration proxies `/api/` to the backend and everything else to the frontend container. `/docs`, `/health` and `/metrics` of the backend are reachable on the server at `http://localhost:8080` only.
- The frontend container falls back to `index.html`, so reloading a page such as `/detections` works.
- The backend uses the Valkey Streams queue (`QUEUE_BACKEND=redis`).
- An installation created by an older version of the script still has a Redpanda service in its Compose file. See the [upgrade notes](#upgrade-notes).

### Other targets

For the Swarm stacks, the k3s manifests and the systemd unit:

- Set `INITIAL_ADMIN_PASSWORD` on the backend for the first start, or read the generated password from the log of the backend instance that created the account. The two stack files pass `INITIAL_ADMIN_PASSWORD` and `SEED_DEMO_DATA` from the environment of the `docker stack deploy` command. `app/deploy/systemd/mxtac.env.example` lists both. The k3s manifests do not set them.
- The Swarm stacks have no migration step. Run `alembic upgrade head` once in a backend container against the database before the backend replicas start. The systemd unit and the k3s deployment run it themselves.
- `app/nginx/nginx.swarm.conf` expects the certificate as `cert.pem` and `key.pem` in `/etc/mxtac/ssl` on the proxy node.

### Backup and restore

| Script | Use |
|--------|-----|
| `scripts/backup-db.sh` | Writes `mxtac_backup_<timestamp>.sql.gz` to `BACKUP_DIR` with `pg_dump` and removes old backups. Connection settings come from `PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD`, `PGDATABASE` or the matching options |
| `scripts/restore-db.sh <file>` | Drops and recreates the database and restores the dump. Asks for confirmation unless `--yes` is given |

Run each script with `--help` for all options.

`/ready` reports the age of the newest backup file in the backend's `BACKUP_DIR` as information. It does not affect the ready status.

The backend also tries to take a daily OpenSearch snapshot into `OPENSEARCH_SNAPSHOT_REPO`. This needs a snapshot path configured in OpenSearch (`path.repo`), which none of the Compose files set.

### Monitoring

```bash
cd app
docker compose --profile monitoring up -d
```

| Service | URL | Notes |
|---------|-----|-------|
| Prometheus | <http://localhost:15009> | Scrapes `backend:8080/metrics`. `deploy/monitoring/prometheus.yml` also lists node, OpenSearch and PostgreSQL exporters that the Compose file does not start; those targets show as down |
| Grafana | <http://localhost:15010> | Login `admin` / `admin` as set in the Compose file. Loads the dashboard `deploy/monitoring/grafana/dashboards/mxtac-overview.json` |

### Scaling notes

- The default queue (`QUEUE_BACKEND=memory`) works with one backend process only. Use `redis` for more than one replica.
- Alert deduplication, rate limits, WebSocket fan-out and rule reloads are shared through Valkey, so replicas need the same `VALKEY_URL`.
- Every backend replica starts every enabled connector. With more than one replica, each event is collected once per replica. Zeek and Suricata connectors also keep their read position in a local state directory.
- Replicas must not run `alembic upgrade head` at the same time. Run the migration as a separate step before the replicas start.
- When several replicas start on an empty database, one of them creates the first account and logs the generated password. Look for the line in the logs of all replicas, or set `INITIAL_ADMIN_PASSWORD`.
