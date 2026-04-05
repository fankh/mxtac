# MxTac Governance & Contributing Guide

This document defines project-level governance for **MxTac**, a MITRE ATT&CK-native security platform.

> Existing implementation and quick-start details are documented in `app/README.md`.  
> This file focuses on governance, contribution workflow, and project policies.

## Project Overview

MxTac is a security operations platform designed around the MITRE ATT&CK framework. It provides:
- ATT&CK-aligned detection and analysis workflows
- A modern web UI for analyst operations
- A service-oriented backend for detection logic, data access, and integrations
- Endpoint/network agent projects for telemetry and security enforcement

## Architecture Summary

MxTac is organized into three major layers:

### 1) Frontend (`app/frontend`)
- React 18 + TypeScript user interface
- Analyst-facing dashboards, detections, and workflow views
- Uses typed API clients and modern state management patterns

### 2) Backend (`app/backend`)
- FastAPI-based async API and services
- Layered architecture:
  - **API**: HTTP endpoints and request handling
  - **Services**: business logic and orchestration
  - **Repositories**: data access patterns
  - **Models/Schemas**: ORM entities and API contracts
- Integrates with PostgreSQL/OpenSearch/DuckDB/Redis-class systems as needed

### 3) Agents (`agents/`)
- `mxwatch`: Rust NDR agent
- `mxguard`: Rust endpoint agent
- Developed as separate projects, aligned with core platform data flows

## Port Assignments

All MxTac services use the **15000–15010** port range to avoid conflicts with other services on the same host.

| Service | Host Port | Container Port | Description |
|---------|-----------|----------------|-------------|
| **Backend API** | 15000 | 8080 | FastAPI REST API |
| **Frontend** | 15001 | 5173 | React dev server (Vite) |
| **PostgreSQL** | 15002 | 5432 | Primary database |
| **Valkey (Redis)** | 15003 | 6379 | Cache, dedup, queue |
| **OpenSearch** | 15004 | 9200 | Log search & analytics |
| **OpenSearch Perf** | 15005 | 9600 | Performance analyzer |
| **OS Dashboards** | 15006 | 5601 | OpenSearch Dashboards (optional) |
| **Redpanda Kafka** | 15007 | 19092 | Message queue (optional) |
| **Redpanda Admin** | 15008 | 9644 | Redpanda admin API (optional) |
| **Prometheus** | 15009 | 9090 | Metrics (optional) |
| **Grafana** | 15010 | 3000 | Dashboards (optional) |

### Access URLs

| Service | URL | Credentials |
|---------|-----|-------------|
| Frontend UI | http://localhost:15001 | analyst@mxtac.local / mxtac2026 |
| Backend API | http://localhost:15000/docs | (Swagger UI) |
| OpenSearch | http://localhost:15004 | (no auth in dev) |
| Grafana | http://localhost:15010 | admin / admin |

## Getting Started

### Prerequisites
- Docker + Docker Compose v2
- 4 GB+ RAM available for containers
- Optional: Python 3.12+, Node.js 18+, Rust toolchain (for local dev)

### Quick Start

```bash
# Clone
git clone https://github.com/fankh/mxtac.git
cd mxtac/app

# Start core services (backend + frontend + postgres + valkey + opensearch)
docker compose up -d

# Check health
curl http://localhost:15000/health

# Open UI
open http://localhost:15001
```

### With Optional Services

```bash
# Core + OpenSearch Dashboards
docker compose --profile dashboards up -d

# Core + Kafka (Redpanda)
docker compose --profile kafka up -d

# Core + Monitoring (Prometheus + Grafana)
docker compose --profile monitoring up -d

# Everything
docker compose --profile dashboards --profile kafka --profile monitoring up -d
```

### Stop

```bash
docker compose down          # stop containers, keep data
docker compose down -v       # stop and delete all data
```

## Contributing Guidelines

### Branching and Changes
- Create focused branches for each change.
- Keep pull requests small and reviewable.
- Do not bundle unrelated refactors with feature work.

### Architecture and Code Standards
- Follow layered backend architecture: **API → Services → Repositories → Models**.
- Use async-first patterns for backend I/O and database work.
- Avoid hardcoded credentials/secrets; use environment variables.
- Keep interfaces typed (Python type hints, TypeScript strict mode).

### Testing and Quality Gates
Before opening a pull request, run applicable checks:

#### Backend
```bash
cd app/backend
pytest --cov=app --cov-report=term-missing
ruff check app/ tests/
mypy app/
```

#### Frontend
```bash
cd app/frontend
npm test
npm run lint
npm run build
```

### Documentation Expectations
- Update documentation when behavior, APIs, or workflows change.
- Prefer concise, operationally useful docs.
- Do not duplicate content already maintained in another canonical file.

### Security and Responsible Development
- Never commit secrets, tokens, or private keys.
- Validate and sanitize external inputs.
- Follow least-privilege principles for integrations and services.
- Coordinate responsible disclosure for vulnerabilities through project maintainers.

## License

MxTac is licensed under the terms defined in the project license file (see `LICENSE` at repository root, if present).
If no license file is currently included, contact maintainers before assuming redistribution rights.
