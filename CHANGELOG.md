# Changelog

All notable changes to MxTac are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [2.0.0-alpha] — 2026-02-23

Initial alpha release of the MxTac platform (Matrix + Tactic). This release
establishes the core backend, frontend, detection engine, and CI/CD foundation.

### Added

#### Backend (FastAPI / Python 3.13)
- FastAPI application with versioned API under `/api/v1/`
- JWT authentication (access + refresh tokens) with key-version invalidation
- Role-based access control (RBAC) — `admin`, `analyst`, `hunter` roles
- Account lockout after 5 failed attempts (30-minute window)
- Inactive account auto-lock after 90 days
- Password history — cannot reuse last 2 passwords; 90-day expiry policy
- First-login forced password change
- SSO via OIDC (Keycloak, Okta, Azure AD) and SAML 2.0
- SQLAlchemy 2.x async ORM with Alembic migrations
- PostgreSQL primary datastore; SQLite single-binary fallback mode
- Pydantic v2 request/response schemas with strict validation
- Repository pattern for all data access (alerts, rules, users, tenants)
- Service layer with clear separation from persistence
- Sigma detection engine — native rule loading, evaluation, ATT&CK tagging
- Event ingestion pipeline with in-memory and Redis/Valkey queue backends
- Kafka queue backend (optional, configurable via `QUEUE_BACKEND`)
- OpenSearch integration for event storage, full-text search, and ILM retention
- DuckDB embedded event store — local analytics without OpenSearch
- Asset auto-discovery from ingested events (CMDB upsert, RFC 1918 only)
- OpenSearch snapshot management with configurable retention
- Alert output sinks: file (JSON Lines, rotating), webhook (POST, retry), syslog, and email (SMTP)
- Alert enrichment — GeoIP (MaxMind), OpenCTI threat intel, IOC matching
- Alert deduplication — MD5(rule_id + host) key with 5-minute Valkey TTL window
- Risk scoring — severity × 0.60 + asset criticality × 0.25 + recurrence × 0.15
- Alert-to-incident auto-correlation — group by (host, tactic) within 1-hour window
- Escalation policy — auto-escalate unacknowledged critical/high alerts after 30 minutes
- Notification senders — email (SMTP + STARTTLS) and Slack (webhook)
- Dead letter queue — failed events routed for inspection and replay
- Back-pressure handling — slow ingest when queue is full
- Connectors: Wazuh, Zeek, Suricata, Prowler, Velociraptor, OpenCTI (base connector ABC + implementations)
- Custom field mapping config per connector
- `POST /connectors/{id}/test` — health check endpoint
- API key management — create keys with scoped access (read / write / admin)
- `POST /users/invite` — send email invitations to new users
- Rate limiting middleware (configurable per-minute threshold)
- CORS middleware with explicit origin allowlist
- `/health` and `/ready` liveness/readiness probes
- Structured logging (JSON-formatted, no sensitive field leakage)

#### Frontend (React 19 / TypeScript / Vite)
- React 19 with TypeScript strict mode
- Tailwind CSS v4 design system
- Zustand state management stores
- `lib/api.ts` typed API client with error handling
- Authentication flow (login, token refresh, session persistence)
- ATT&CK coverage dashboard — technique heatmap, tactic breakdown
- Alert management — list, detail, acknowledge, filter by severity/technique
- Sigma rule management — browse, enable/disable, upload
- Role-aware UI — route guards, permission-based component rendering
- Vitest + Testing Library unit and integration tests

#### Agents (Rust / Tokio)
- **mxguard** — EDR agent for endpoint event collection
- **mxwatch** — NDR agent for network metadata collection
- Async Tokio runtime; structured event emission to backend pipeline

#### Agent Scheduler
- Next.js frontend for scheduling Claude Code agent tasks
- FastAPI backend with SQLite persistence (aiosqlite)
- Configurable concurrency, retry, timeout, and backoff parameters
- Optional HTTP Basic auth (`AUTH_PASSWORD`)

#### Infrastructure & Operations
- Docker Compose stack for development (`app/docker-compose.yml`)
- Production Docker Compose with Nginx reverse proxy (`app/docker-compose.prod.yml`)
- GitHub Actions CI pipelines:
  - Backend: lint (Ruff, mypy) + pytest
  - Frontend: lint (ESLint) + test (Vitest) + build (Vite)
  - Docker: build and push to GitHub Container Registry
- Dependabot configuration for automated dependency updates
- Trivy vulnerability scanning on every push
- Secret rotation procedures and environment hardening guide

#### Detection
- Sigma rule loader — YAML parsing, compile-time validation
- ATT&CK technique tagging from Sigma rule `tags` field
- Coverage calculator — per-tactic and per-technique detection percentage
- Sample Sigma rules for common ATT&CK techniques

#### Governance & Documentation
- `CHANGELOG.md` — this file
- `SECURITY.md` — vulnerability disclosure policy
- `LICENSE` — GNU Affero General Public License v3.0 (AGPL-3.0)
- `.editorconfig` — consistent formatting across editors
- `app/frontend/.prettierrc` — Prettier code style config
- `ENV-REFERENCE.md` — complete environment variable reference
- API versioning strategy documented in `06-API-SPECIFICATION.md`

### Fixed

- Soft-delete users: set `is_active=False` instead of hard delete to preserve audit trail
- Scheduler: corrected GitHub repository URL for agent task runner

### Security

- Passwords hashed with Argon2id (via `passlib`)
- JWT secrets validated at startup; dev default rejected in production
- Sensitive fields (`SECRET_KEY`, DSN passwords) excluded from logs and repr
- CORS restricted to explicit `CORS_ORIGINS` allowlist
- SQL injection prevention via SQLAlchemy parameterised queries
- XSS mitigation via React DOM escaping + strict Content-Security-Policy headers
- Dependabot and Trivy integrated for supply-chain and CVE scanning

---

[Unreleased]: https://github.com/fankh/mxtac/compare/v2.0.0-alpha...HEAD
[2.0.0-alpha]: https://github.com/fankh/mxtac/releases/tag/v2.0.0-alpha
