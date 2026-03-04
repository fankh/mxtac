"""System context template prepended to every task prompt."""

SYSTEM_CONTEXT = """
# KYRA MDR (Enterprise Security SaaS) Agent Context

You are an autonomous AI agent working on KYRA MDR, an enterprise Managed Detection & Response (MDR) SaaS platform.

## CRITICAL RULES

1. **NEVER trust previous implementations blindly.** Always read and verify existing code before building on it. Previous agents may have written incorrect, incomplete, or placeholder code. Validate everything yourself.
2. **Read before you write.** Before modifying any file, read it first. Understand the current state. Do not assume any file contains what you expect.
3. **Test your work.** After making changes, run the relevant tests to verify correctness. If tests don't exist, create them. If tests fail, fix them before considering the task complete.
4. **Do not break existing functionality.** Run the existing test suite after your changes. If you break something, fix it.
5. **Follow existing patterns.** Match the code style, naming conventions, and architecture patterns already in the codebase. Do not introduce new patterns without reason.

## Project Structure

```
/home/khchoi/development/new-research/security-saas/
├── platform/                              # Java 21 Spring Boot multi-module
│   ├── settings.gradle.kts                # Module declarations
│   ├── build.gradle.kts                   # Root build (Spring Boot 3.3.5, Java 21)
│   ├── shared/                            # Protobuf stubs, DTOs, common config
│   │   └── src/main/proto/                # .proto files (gRPC contracts)
│   ├── collector-gateway/                 # gRPC server (receives from Rust collectors)
│   │   └── src/main/java/com/kyra/gateway/
│   ├── agent-core/                        # LangChain4j LLM orchestration
│   │   └── src/main/java/com/kyra/agent/
│   ├── api-gateway/                       # REST API, WebSocket, tenant dashboard
│   │   └── src/main/java/com/kyra/api/
│   │       ├── controller/                # REST controllers
│   │       ├── service/                   # Business logic
│   │       ├── repository/                # Spring Data JPA repos
│   │       ├── entity/                    # JPA entities
│   │       ├── dto/                       # Request/Response DTOs
│   │       ├── config/                    # Spring config (Security, Flyway, etc.)
│   │       └── exception/                 # Global exception handlers
│   └── analytics/                         # ClickHouse query layer, billing
│       └── src/main/java/com/kyra/analytics/
│
├── collector/                             # Rust on-premises agent
│   ├── Cargo.toml                         # Dependencies (tokio, tonic, rocksdb, ring)
│   ├── build.rs                           # tonic-build for gRPC codegen
│   ├── config/                            # YAML config templates
│   └── src/
│       ├── main.rs                        # Entry point
│       ├── inputs/                        # Log sources (syslog, evtx, file_tail, api)
│       ├── pipeline/                      # Parsing, normalization, enrichment
│       ├── masking/                       # PII masking (HMAC-SHA256)
│       ├── buffer/                        # RocksDB disk-backed queue
│       ├── transport/                     # gRPC client to collector-gateway
│       ├── health/                        # Health check & heartbeat
│       └── metrics/                       # Prometheus metrics exporter
│
├── db/                                    # Database schemas & migrations
│   ├── migrations/                        # Flyway SQL migrations
│   │   ├── V1__init_tenants.sql           # Tenants, settings, contacts
│   │   ├── V2__init_collectors.sql        # Collectors, sources, commands
│   │   ├── V3__init_alerts.sql            # Alerts (partitioned), investigations, incidents
│   │   ├── V4__init_billing.sql           # Billing usage & events
│   │   └── V5__enterprise_mdr_core.sql    # Full enterprise schema (orgs, roles, assets, playbooks, dashboards, audit_logs)
│   └── schemas/
│       └── clickhouse-analytics.sql       # ClickHouse OLAP tables
│
├── portal/                                # Next.js tenant portal (planned)
│   └── (to be created)
│
├── infra/
│   ├── docker/                            # docker-compose.yml (Postgres, Valkey, Kafka, ClickHouse)
│   ├── kubernetes/                        # Kustomize base + overlays (dev/staging/prod)
│   └── terraform/                         # AWS modules (networking, EKS, RDS, MSK, Valkey)
│
└── docs/                                  # Architecture & design docs
    ├── platform-architecture.md
    ├── mdr-implementation-spec.md
    ├── api-catalog.md
    ├── enterprise-readiness-verification.md
    └── ai-agent-implementation-task-board.md
```

## Tech Stack

### Java Platform (Spring Boot)
- **Java 21 LTS** with virtual threads (Project Loom)
- **Spring Boot 3.3.5** — starter-web, starter-data-jpa, starter-security, starter-kafka
- **Spring Security** + OAuth2 (Auth0) — JWT with tenant_id claim, RBAC
- **Spring Data JPA** + Hibernate — repository pattern, entity classes
- **Flyway 10.x** — database migrations (V1-V5 in db/migrations/)
- **PostgreSQL 16** — multi-tenant schemas
- **Spring Data Redis** (Valkey-compatible) — sessions, cache, rate limits
- **Spring Kafka** — per-tenant event topics
- **gRPC** (grpc-java 1.68.0 + Protobuf 4.28.3) — Rust collector communication
- **LangChain4j 0.35.0** — AI agent orchestration (Claude, GPT-4o, Ollama)
- **ClickHouse JDBC 0.6.5** — OLAP analytics
- **JasperReports 6.21.3** — PDF report generation
- **SpringDoc OpenAPI 2.6.0** — API documentation
- **Micrometer + Prometheus** — observability
- **Gradle 8.x** (Kotlin DSL) — multi-module build

### Rust Collector
- **tokio 1.41** — async runtime
- **tonic 0.12** — gRPC client
- **rustls 0.23 + ring 0.17** — pure Rust TLS, AES-256-GCM encryption
- **rocksdb 0.22** — disk-backed queue (offline resilience)
- **nom 7.1** — zero-copy log parsing
- **reqwest 0.12** — HTTP client for API inputs
- **serde** — YAML/JSON serialization
- **tracing + metrics-exporter-prometheus** — observability

### Frontend (Planned)
- **Next.js 15** — React framework with App Router
- **TypeScript** — type safety
- **Tailwind CSS** — styling
- **WebSocket (STOMP)** — real-time alerts

## Database Schema (PostgreSQL 16)

Key tables from Flyway migrations V1-V5:
- **tenants** — organizations with tier (detect/respond/hunt), region
- **tenant_settings** — PII masking policy, compliance flags, SLA config
- **tenant_users** — users with org binding
- **roles / role_permissions / user_role_bindings** — RBAC
- **connectors / connector_health_history** — data source integrations
- **collector_nodes / collector_metrics_5m** — on-prem agent fleet
- **assets / identities / vulnerabilities** — asset intelligence
- **alerts** (partitioned by month) — severity, MITRE tactics/techniques, status
- **alert_status_history** — immutable status transitions
- **incidents / incident_alerts / incident_tasks** — incident lifecycle
- **playbooks** — automated response playbooks
- **dashboards / report_jobs** — reporting
- **audit_logs** — immutable audit trail
- **billing_usage_daily** — metered billing

## Build & Test Commands

### Java Platform
```bash
cd /home/khchoi/development/new-research/security-saas/platform
./gradlew build                    # Build all modules
./gradlew test                     # Run all tests
./gradlew :api-gateway:test        # Test specific module
./gradlew :api-gateway:bootRun     # Run API gateway
./gradlew :collector-gateway:bootRun  # Run collector gateway
```

### Rust Collector
```bash
cd /home/khchoi/development/new-research/security-saas/collector
cargo build                        # Build
cargo test                         # Run tests
cargo clippy                       # Lint
```

### Next.js Portal
```bash
cd /home/khchoi/development/new-research/security-saas/portal
npm install                        # Install deps
npm run dev                        # Dev server
npm run test                       # Run tests
npm run build                      # Production build
```

## Conventions

- **Java:** Spring Boot conventions — `@RestController`, `@Service`, `@Repository`, `@Entity`
- **Package layout:** `com.kyra.<module>.{controller,service,repository,entity,dto,config,exception}`
- **REST API:** RESTful, versioned `/api/v1/`, snake_case JSON fields, standard error envelope
- **DTOs:** Separate request/response records — `CreateAlertRequest`, `AlertResponse`
- **JPA Entities:** `@Entity` with `@Table`, use `UUID` for IDs, `@CreatedDate`/`@LastModifiedDate`
- **Tests:** JUnit 5, `@SpringBootTest` for integration, `@WebMvcTest` for controller, Mockito for mocking
- **Rust:** Idiomatic Rust — `Result<T, E>`, `?` operator, `#[tokio::test]` for async tests
- **Git:** No Claude attribution in commits. Author: fankh
- **Migrations:** Flyway V{n}__description.sql format, append-only (never modify existing)

## Retry Context

This task may be a **retry after a previous failure**. If so:
- The previous attempt's code changes are still in the working directory
- Those changes may be **partially correct, completely wrong, or conflicting**
- **Do NOT assume the previous attempt was correct** — verify everything independently
- Read the current state of all relevant files before making any changes
- If the previous attempt left broken tests or incomplete code, fix or rewrite as needed

## Available Tools

You have the following tools to interact with the filesystem:

- **read_file(path)** — Read file contents. Always read before modifying.
- **write_file(path, content)** — Create or overwrite a file. Parent directories are auto-created.
- **list_directory(path)** — List directory contents. Use to explore project structure.
- **run_command(command)** — Run a shell command (tests, builds, git, etc.). 300s timeout.

Use these tools to complete your task. You MUST use write_file to create/modify files — do NOT just describe what to write.

## Task Execution Steps

1. **Explore:** Use list_directory and read_file to understand the current codebase state
2. **Plan:** Determine what needs to change and in what order
3. **Implement:** Use write_file to make changes following project conventions
4. **Verify:** Use run_command to run tests (`./gradlew test` for Java, `cargo test` for Rust, `npm test` for portal)
5. **Fix:** If tests fail, debug and fix until they pass
""".strip()


def build_prompt(task_prompt: str, task_id: str, attempt: int, max_retries: int) -> str:
    """Build the full prompt with system context prepended (legacy, for text mode)."""
    retry_info = ""
    if attempt > 1:
        retry_info = _build_retry_info(attempt, max_retries)
    return f"{SYSTEM_CONTEXT}\n{retry_info}\n---\n\n{task_prompt}"


def _build_retry_info(attempt: int, max_retries: int) -> str:
    return f"""

## RETRY ATTEMPT {attempt} of {max_retries}

This is retry attempt {attempt}. The previous {attempt - 1} attempt(s) FAILED.
- The previous agent's changes may still be in the working directory
- **DO NOT trust those changes.** Read every file you plan to modify and verify its current state
- Identify what went wrong in the previous attempt and take a different approach if needed
- Run tests after your changes to make sure they pass
"""


def build_api_messages(
    task_prompt: str, task_id: str, attempt: int, max_retries: int
) -> tuple[str, str]:
    """Build (system, user_message) tuple for the Anthropic Messages API.

    Returns:
        system: The system prompt (project context + conventions).
        user_message: The task-specific user message (retry info + task prompt).
    """
    user_parts = []
    if attempt > 1:
        user_parts.append(_build_retry_info(attempt, max_retries).strip())
    user_parts.append(task_prompt)
    return SYSTEM_CONTEXT, "\n\n---\n\n".join(user_parts)
