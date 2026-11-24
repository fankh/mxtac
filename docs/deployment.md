# Deployment

This document describes the deployment files in the repository and how far each one has been checked against the current code. Read the status column before you rely on a file.

## Deployment files

| File | Target | Status |
|------|--------|--------|
| `app/docker-compose.yml` | Development and evaluation on one machine | Used for the quick start in the [README](../README.md). The maintained path |
| `app/setup.sh` | One Ubuntu 22.04 or 24.04 host with Docker, Nginx and TLS | Generates its own Compose file and Nginx configuration. Reviewed against the code, see [Automated single-host setup](#automated-single-host-setup) |
| `app/docker-compose.prod.yml`, `app/nginx/nginx.conf` | One host, production-style | Incomplete, see [Known gaps](#known-gaps) |
| `app/docker-stack.yml`, `app/nginx/nginx.swarm.conf`, `app/.env.swarm.example` | Docker Swarm | Not tested with the current code. Has no OpenSearch service |
| `app/deploy/docker-swarm/docker-stack.yml` | Docker Swarm, with OpenSearch | Not tested with the current code |
| `app/deploy/k3s/` | k3s or Kubernetes (Kustomize manifests and `deploy.sh`) | Not tested with the current code |
| `app/deploy/systemd/` | Backend as a systemd service on a host | Not tested with the current code. Covers the backend only |
| `app/deploy/haproxy/haproxy.cfg` | HAProxy in front of three backend and two frontend instances | Example configuration |
| `app/deploy/monitoring/` | Prometheus and Grafana configuration | Used by the `monitoring` profile of `app/docker-compose.yml` |

"Not tested" means the file was kept from an earlier version of the project and has not been run since the code was reduced to the current core. Its settings were checked for references to removed features, and none were found.

## What every deployment needs

| Requirement | Detail |
|-------------|--------|
| Database schema | Run `alembic upgrade head` in the backend before the first start and after every upgrade. The backend applies migrations by itself only in SQLite mode |
| `SECRET_KEY` | A random value, for example `openssl rand -hex 32`. With `DEBUG=false` the backend does not start with the development default |
| `DEBUG=false` | Enables the HSTS header and the secret-key check |
| `CORS_ORIGINS` | JSON array with the URL the UI is served from, for example `["https://mxtac.example.com"]` |
| PostgreSQL, Valkey, OpenSearch | `/ready` returns `503` when one of them is not reachable. Container health checks and load balancers that probe `/ready` then mark the backend as unhealthy |
| Same origin | The frontend calls `/api/v1/...` on its own origin. A reverse proxy must route `/api/` to the backend and everything else to the frontend |
| WebSocket | The proxy must pass the `Upgrade` and `Connection` headers for `/api/v1/ws/` |
| Default accounts | Replace them before the instance is reachable by others. See [First login](../README.md#first-login) |
| Network exposure | Publish the reverse proxy only. Do not publish the backend, PostgreSQL, Valkey or OpenSearch ports. See the limitations in [security.md](security.md) |

All settings are listed in [ENV-REFERENCE.md](../ENV-REFERENCE.md).

## Development Compose file

`app/docker-compose.yml` starts the backend, the frontend dev server, PostgreSQL, Valkey and OpenSearch. See the [README](../README.md#quick-start) and [development.md](development.md).

It is not a production setup: `DEBUG=true`, a fixed `SECRET_KEY`, the database password `mxtac`, OpenSearch without authentication, source code mounted into the containers, and all ports published on every interface.

## Automated single-host setup

`app/setup.sh` prepares one Ubuntu server.

```bash
git clone https://github.com/fankh/mxtac.git
cd mxtac/app
sudo MXTAC_HOST=mxtac.example.com bash setup.sh
```

`MXTAC_HOST` is the host name or IP address users open in the browser. Without it the script uses the first address from `hostname -I`.

The script performs these steps and can be run again:

1. Installs packages and configures UFW to allow ports 22, 80 and 443 only. **It resets existing UFW rules.**
2. Installs Docker Engine and the Compose plugin when they are missing.
3. Sets `vm.max_map_count=262144` for OpenSearch.
4. Writes `/opt/mxtac/.env` with a generated `SECRET_KEY` and database password. An existing `.env` is kept.
5. Copies the `app/` directory to `/opt/mxtac` and writes `/opt/mxtac/docker-compose.yml`. That file defines PostgreSQL, Valkey, OpenSearch, Redpanda, the backend, the frontend (static build served by Nginx) and an Nginx reverse proxy. Internal ports are bound to `127.0.0.1`.
6. Writes `/opt/mxtac/nginx/nginx.conf` and creates a self-signed certificate for `MXTAC_HOST`.
7. Builds and starts the containers and waits for their health checks.
8. Runs `alembic upgrade head` in the backend container and restarts the backend, which then creates the default accounts.
9. Prints the service status and the URL.

After the script finishes:

1. Replace the default accounts. See [First login](../README.md#first-login). On the server the API is reachable at `http://localhost:8080`.
2. Replace the self-signed certificate: `sudo bash /opt/mxtac/enable-https.sh mxtac.example.com`. The script obtains a Let's Encrypt certificate with certbot, installs it for Nginx and adds a renewal cron job. The domain must resolve to the server and port 80 must be reachable.

Upgrade with `sudo bash app/update.sh` from an updated checkout. It copies the source to `/opt/mxtac` (keeping `.env`), rebuilds the images, restarts the backend and the frontend, runs the migrations and reloads Nginx.

Things to know about this setup:

- The generated Nginx configuration proxies `/api/` to the backend and everything else to the frontend container. `/docs`, `/health` and `/metrics` of the backend are reachable on the server at `http://localhost:8080` only.
- The frontend container serves static files with the default Nginx configuration, which has no fallback to `index.html`. Reloading the browser on a path such as `/detections` returns `404`. Open the root URL instead.
- The backend uses the Valkey Streams queue (`QUEUE_BACKEND=redis`). The Redpanda container is started but not used.

## Known gaps

`app/docker-compose.prod.yml` with `app/nginx/nginx.conf` does not work as it is:

| Gap | Effect |
|-----|--------|
| No OpenSearch service and no `OPENSEARCH_HOST` | `/ready` returns `503`, so the backend container is reported unhealthy. Hunt search falls back to PostgreSQL |
| The `frontend_static` volume is mounted into Nginx but nothing copies the built frontend into it | Nginx does not serve the UI |
| No migration step | Run `docker compose -f docker-compose.prod.yml exec backend alembic upgrade head`, then restart the backend |
| `nginx.conf` expects `nginx/ssl/cert.pem` and `nginx/ssl/key.pem` | Provide these files before starting Nginx |
| `nginx.conf` has no WebSocket location | Live updates do not arrive |

Required variables for this file: `SECRET_KEY`, `POSTGRES_PASSWORD`, `DOMAIN`.

Use `app/setup.sh`, or treat this file as a starting point and close the gaps.

## Backup and restore

| Script | Use |
|--------|-----|
| `scripts/backup-db.sh` | Writes `mxtac_backup_<timestamp>.sql.gz` to `BACKUP_DIR` with `pg_dump` and removes old backups. Connection settings come from `PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD`, `PGDATABASE` or the matching options |
| `scripts/restore-db.sh <file>` | Drops and recreates the database and restores the dump. Asks for confirmation unless `--yes` is given |

Run each script with `--help` for all options.

`/ready` reports the age of the newest backup file in the backend's `BACKUP_DIR` as information. It does not affect the ready status.

The backend also tries to take a daily OpenSearch snapshot into `OPENSEARCH_SNAPSHOT_REPO`. This needs a snapshot path configured in OpenSearch (`path.repo`), which none of the Compose files set.

## Monitoring

```bash
cd app
docker compose --profile monitoring up -d
```

| Service | URL | Notes |
|---------|-----|-------|
| Prometheus | <http://localhost:15009> | Scrapes `backend:8080/metrics`. `deploy/monitoring/prometheus.yml` also lists node, OpenSearch and PostgreSQL exporters that the Compose file does not start; those targets show as down |
| Grafana | <http://localhost:15010> | Login `admin` / `admin` as set in the Compose file. Loads the dashboard `deploy/monitoring/grafana/dashboards/mxtac-overview.json` |

## Scaling notes

- The default queue (`QUEUE_BACKEND=memory`) works with one backend process only. Use `redis` for more than one replica.
- Alert deduplication, rate limits, WebSocket fan-out and rule reloads are shared through Valkey, so replicas need the same `VALKEY_URL`.
- Every backend replica starts every enabled connector. With more than one replica, each event is collected once per replica. Zeek and Suricata connectors also keep their read position in a local state directory.
