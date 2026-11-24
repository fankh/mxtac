# MxTac application

This directory contains the application and its deployment files. For an introduction and the quick start, see the [repository README](../README.md).

## Contents

| Path | Content |
|------|---------|
| `backend/` | FastAPI backend (Python 3.12) |
| `frontend/` | React frontend (TypeScript, Vite, Tailwind CSS) |
| `docker-compose.yml` | Development and evaluation stack |
| `docker-compose.prod.yml` | Single-host production stack behind Nginx with TLS. See [docs/deployment.md](../docs/deployment.md#production-compose-file) |
| `docker-stack.yml`, `.env.swarm.example` | Docker Swarm stack |
| `setup.sh`, `update.sh`, `enable-https.sh` | Install, update and TLS scripts for one Ubuntu server |
| `nginx/` | Nginx reverse-proxy configurations for `docker-compose.prod.yml` and the Swarm stack |
| `frontend/nginx.conf` | Nginx configuration inside the production frontend image: static files, fallback to `index.html`, `/api` proxy |
| `deploy/` | Swarm, k3s, systemd, HAProxy and monitoring files |

## Run

```bash
docker compose up -d --build
```

| Service | URL |
|---------|-----|
| Web UI | <http://localhost:15001> |
| Backend API | <http://localhost:15000> |
| Swagger UI | <http://localhost:15000/docs> |

The first start creates one account, `admin@mxtac.local`. Its password is written once to the backend log:

```bash
docker compose logs backend | grep "INITIAL ADMIN PASSWORD"
```

The UI asks for a new password at the first sign-in. See [First login](../README.md#first-login) for `INITIAL_ADMIN_PASSWORD` and `SEED_DEMO_DATA`.

## Backend layout

```
backend/
  app/
    api/v1/endpoints/   route handlers
    core/               settings, security, RBAC, rate limiting
    connectors/         Wazuh, Zeek, Suricata, syslog
    engine/             Sigma engine and field mapper
    services/           pipeline services, bundled-rule import, normalizers
    pipeline/           queue abstraction (in-memory, Valkey Streams)
    repositories/       database queries
    models/             SQLAlchemy models
    schemas/            Pydantic schemas
    db/                 seed and SQLite migration helper
  alembic/              database migrations
  sigma_rules/          bundled rules, imported into the database at startup
  tests/                pytest tests
```

## Frontend layout

```
frontend/
  src/
    components/
      features/         one directory per page
      layout/           sidebar, top bar, page frame
      shared/           badges, route guard, error boundary
      ui/               base components
    hooks/              WebSocket stream, keyboard shortcuts
    lib/                API client and helpers
    stores/             Zustand stores
    types/              API types
    index.css           design tokens
  nginx.conf            Nginx configuration of the production image
  vite.config.ts        dev server; forwards /api to VITE_PROXY_TARGET
```

## More documentation

| Topic | Document |
|-------|----------|
| API routes | [docs/api.md](../docs/api.md) |
| Architecture | [docs/architecture.md](../docs/architecture.md) |
| Sigma rules | [docs/sigma-engine.md](../docs/sigma-engine.md) |
| Development | [docs/development.md](../docs/development.md) |
| Deployment | [docs/deployment.md](../docs/deployment.md) |
| Settings | [configuration.md](../docs/configuration.md) |
