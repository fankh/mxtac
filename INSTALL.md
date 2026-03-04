# MxTac Installation Guide

MxTac is a MITRE ATT&CK-powered threat detection platform (FastAPI backend + React frontend) with PostgreSQL, Valkey, and OpenSearch.

## Prerequisites

### Hardware

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 2 cores | 4 cores |
| Memory | 4 GB | 8 GB |
| Disk | 20 GB SSD | 50 GB SSD |

### Software

| Component | Version |
|-----------|---------|
| OS | Ubuntu 22.04 / 24.04 LTS |
| Docker | 24.x + Compose V2 |
| Python | 3.12+ (manual install only) |
| Node.js | 20+ (manual install only) |
| Git | 2.x |
| OpenSSL | 3.x |

> **Note:** OpenSearch requires `vm.max_map_count=262144`. The setup script configures this automatically; for manual installs run `sudo sysctl -w vm.max_map_count=262144`.

---

## Quick Start (Development)

### Option A — Docker Compose (Recommended)

```bash
git clone https://github.com/fankh/mxtac.git
cd mxtac/app

# Copy environment files
cp backend/.env.example backend/.env
cp frontend/.env.example frontend/.env

# Start all services (backend, frontend, PostgreSQL 16, Valkey 8, OpenSearch 2.17)
docker compose up --build
```

Services available after startup:

| Service | URL |
|---------|-----|
| API / Swagger | http://localhost:8080/docs |
| Frontend (Vite dev) | http://localhost:5173 |
| OpenSearch Dashboards | http://localhost:5601 (optional: `docker compose --profile dashboards up`) |
| Prometheus | http://localhost:9090 (optional: `docker compose --profile monitoring up`) |
| Grafana | http://localhost:3001 (optional: `docker compose --profile monitoring up`) |

### Option B — Manual

**Backend:**

```bash
cd app/backend
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Note: python3-saml requires libxmlsec1-dev (apt install libxmlsec1-dev)

cp .env.example .env
# Edit .env — set DATABASE_URL, SECRET_KEY, etc.

uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload
```

**Frontend:**

```bash
cd app/frontend
cp .env.example .env
# .env contains: VITE_API_BASE_URL=http://localhost:8080

npm install
npm run dev
# → http://localhost:5173
```

You'll still need PostgreSQL 16, Valkey 8, and OpenSearch 2.17 running separately (or via `docker compose up postgres valkey opensearch`).

---

## Production Deployment

MxTac supports five production deployment options. See [21-DEPLOYMENT-GUIDE.md](21-DEPLOYMENT-GUIDE.md) for full procedures.

### Option A — Automated Ubuntu Setup (Recommended)

```bash
sudo bash app/setup.sh
```

This script is idempotent and handles: system packages, UFW firewall, Docker, kernel tuning, secret generation, deployment to `/opt/mxtac/`, database migrations, and health checks.

### Option B — Docker Compose (Single Host)

```bash
cd app
cp backend/.env.example .env
# Edit .env — generate secrets (see Configuration Reference below)
docker compose -f docker-compose.prod.yml up -d
```

### Option C — Docker Swarm (Multi-Host HA)

```bash
docker stack deploy -c app/docker-stack.yml mxtac
```

Requires Docker Swarm initialized and node labels configured. See [21-DEPLOYMENT-GUIDE.md](21-DEPLOYMENT-GUIDE.md) § Docker Swarm.

### Option D — Kubernetes / K3s

```bash
cd app/deploy/k3s
bash deploy.sh
```

Manifests in `app/deploy/k3s/` include namespace, secrets, statefulsets, deployments, ingress, network policies, HPA, and PDB.

### Option E — Systemd (Bare Metal)

```bash
cd app/deploy/systemd
sudo bash install.sh
```

Uses `mxtac.service` with security hardening. Environment via `mxtac.env`.

### TLS / HTTPS

```bash
sudo bash app/enable-https.sh
```

Obtains a Let's Encrypt certificate, configures Nginx for TLS 1.2/1.3, and sets up a daily auto-renewal cron job.

---

## Configuration Reference

### Environment Files

| File | Purpose |
|------|---------|
| `app/backend/.env.example` | Backend config template |
| `app/frontend/.env.example` | Frontend config template |
| `app/.env.swarm.example` | Docker Swarm variables |
| `app/deploy/systemd/mxtac.env.example` | Systemd environment |

See [ENV-REFERENCE.md](ENV-REFERENCE.md) for the complete variable reference.

### Key Variables

```bash
# Security — generate before first deploy
SECRET_KEY=<openssl rand -hex 32>

# Database
DATABASE_URL=postgresql+asyncpg://mxtac:PASSWORD@localhost:5432/mxtac

# Cache
VALKEY_URL=redis://localhost:6379/0

# Search
OPENSEARCH_HOST=localhost
OPENSEARCH_PORT=9200

# Frontend
VITE_API_BASE_URL=http://localhost:8080   # or https://your-domain.com

# Production essentials
DEBUG=false
CORS_ORIGINS=["https://your-domain.com"]
```

### Port Map

| Port | Service |
|------|---------|
| 80 / 443 | Nginx (HTTP / HTTPS) |
| 8080 | Backend API |
| 3000 | Frontend (production) |
| 5173 | Frontend (Vite dev) |
| 5432 | PostgreSQL |
| 6379 | Valkey |
| 9200 | OpenSearch |

---

## Health Checks & Verification

```bash
# API health
curl http://localhost:8080/health

# API readiness (includes DB + cache connectivity)
curl http://localhost:8080/ready

# Frontend
curl -I http://localhost:5173   # dev
curl -I http://localhost:3000   # production

# Database migrations
cd app/backend
alembic upgrade head

# Docker service health
docker compose ps
docker compose logs -f backend
```

---

## Upgrading

### Automated (Recommended)

```bash
sudo bash app/update.sh
```

Performs a zero-downtime rolling update: syncs source (preserves `.env`), rebuilds images, restarts backend → frontend, runs migrations, and reloads Nginx.

### Manual

```bash
cd app
git pull
docker compose -f docker-compose.prod.yml build
docker compose -f docker-compose.prod.yml up -d backend   # restart backend first
docker compose -f docker-compose.prod.yml up -d frontend   # then frontend
docker compose exec backend alembic upgrade head            # run migrations
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| OpenSearch won't start | `sudo sysctl -w vm.max_map_count=262144` and add to `/etc/sysctl.conf` |
| `SECRET_KEY` error on startup | Generate one: `openssl rand -hex 32` and set in `.env` |
| Database connection refused | Ensure PostgreSQL is running and `DATABASE_URL` is correct |
| Frontend can't reach API | Check `VITE_API_BASE_URL` matches the backend address; check `CORS_ORIGINS` includes the frontend origin |
| Permission denied on Docker | Add your user to the `docker` group: `sudo usermod -aG docker $USER` |
| Port already in use | Check with `ss -tlnp | grep <port>` and stop the conflicting process |
| Alembic migration fails | Check DB connectivity; run `alembic history` to see migration state |
| SAML/SSO import error | Install system dependency: `sudo apt install libxmlsec1-dev` |

### Logs

```bash
# Docker
docker compose logs -f backend
docker compose logs -f frontend

# Systemd
journalctl -u mxtac -f

# Nginx
tail -f /var/log/nginx/access.log /var/log/nginx/error.log
```

---

## Further Reading

- [21-DEPLOYMENT-GUIDE.md](21-DEPLOYMENT-GUIDE.md) — Full production deployment procedures
- [ENV-REFERENCE.md](ENV-REFERENCE.md) — Complete environment variable reference
- [14-DEVELOPMENT-GUIDE.md](14-DEVELOPMENT-GUIDE.md) — Development workflow and conventions
- [12-BACKEND-SECURITY-IMPLEMENTATION.md](12-BACKEND-SECURITY-IMPLEMENTATION.md) — Security implementation details
