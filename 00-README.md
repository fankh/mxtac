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

## Getting Started

For full runtime instructions, see `app/README.md`. At a governance level, contributors should use the following baseline process.

### Prerequisites
- Git
- Docker + Docker Compose (recommended path)
- Python 3.12+
- Node.js 18+ and npm
- Rust toolchain (only if working on agents)

### Setup Steps
1. Clone repository:
   ```bash
   git clone <repository-url>
   cd mxtac
   ```
2. Review implementation setup in:
   - `app/README.md`
   - `docs/` (security and supporting technical docs)
3. Run the platform (recommended):
   ```bash
   cd app
   docker-compose up
   ```
4. For local development, follow backend/frontend manual setup from `app/README.md`.

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
