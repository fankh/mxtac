# MxTac application

This directory contains the application and its deployment files. For an introduction and the quick start, see the [repository README](../README.md).

## Contents

| Path | Content |
|------|---------|
| `backend/` | FastAPI backend (Python 3.12) |
| `frontend/` | React frontend (TypeScript, Vite, Tailwind CSS) |
| `docker-compose.yml` | Development and evaluation stack |
| `docker-compose.prod.yml` | Production-style single-host stack. Incomplete, see [docs/deployment.md](../docs/deployment.md#known-gaps) |
| `docker-stack.yml`, `.env.swarm.example` | Docker Swarm stack |
| `setup.sh`, `update.sh`, `enable-https.sh` | Install, update and TLS scripts for one Ubuntu server |
| `nginx/` | Nginx configurations for `docker-compose.prod.yml` and the Swarm stack |
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

Sign-in accounts are described under [First login](../README.md#first-login).

## Backend layout

```
backend/
  app/
    api/v1/endpoints/   route handlers
    core/               settings, security, RBAC, rate limiting
    connectors/         Wazuh, Zeek, Suricata, syslog
    engine/             Sigma engine
    services/           pipeline services and normalizers
    pipeline/           queue abstraction
    repositories/       database queries
    models/             SQLAlchemy models
    schemas/            Pydantic schemas
    db/                 seed and SQLite migration helper
  alembic/              database migrations
  sigma_rules/          rules loaded at startup
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
```

## More documentation

| Topic | Document |
|-------|----------|
| API routes | [docs/api.md](../docs/api.md) |
| Architecture | [docs/architecture.md](../docs/architecture.md) |
| Development | [docs/development.md](../docs/development.md) |
| Deployment | [docs/deployment.md](../docs/deployment.md) |
| Settings | [ENV-REFERENCE.md](../ENV-REFERENCE.md) |
