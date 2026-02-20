# MxTac — Full Feature Checklist

> Track implementation and test coverage for every feature.
>
> **Legend**
> | Symbol | Meaning |
> |--------|---------|
> | `[ ]` | Not started |
> | `[~]` | Stub / partial (code exists, no real logic) |
> | `[x]` | Implemented |
> | `[T]` | Test written & passing |
> | **P0** | Must-have for MVP |
> | **P1** | Required for production |
> | **P2** | Important enhancement |
> | **P3** | Future / nice-to-have |

---

## 1. Authentication & Session

| # | Feature | Impl | Test | Priority | Notes |
|---|---------|:----:|:----:|----------|-------|
| 1.1 | `POST /auth/login` — email + password | `[x]` | `[ ]` | P0 | Returns JWT access + refresh token |
| 1.2 | `POST /auth/refresh` — renew access token | `[ ]` | `[ ]` | P0 | Refresh token rotation |
| 1.3 | `POST /auth/logout` — invalidate token | `[~]` | `[ ]` | P0 | Token blacklist via Valkey |
| 1.4 | JWT validation on every protected request | `[x]` | `[ ]` | P0 | `get_current_user` dependency |
| 1.5 | JWT expiry — 60 min access, 7 day refresh | `[~]` | `[ ]` | P0 | Config field exists, not enforced |
| 1.6 | Account lockout — 5 failed attempts → 30 min | `[ ]` | `[ ]` | P1 | Valkey counter + TTL |
| 1.7 | Inactive account lock — 90 days no login | `[ ]` | `[ ]` | P1 | Scheduled job or login-time check |
| 1.8 | First-login forced password change | `[ ]` | `[ ]` | P1 | `must_change_password` flag on User |
| 1.9 | SSO — OIDC (Keycloak, Okta, Azure AD) | `[ ]` | `[ ]` | P2 | `authlib` or `python-social-auth` |
| 1.10 | SSO — SAML 2.0 | `[ ]` | `[ ]` | P2 | `python3-saml` |
| 1.11 | API key creation and scoped access | `[ ]` | `[ ]` | P2 | `POST /auth/api-keys` |
| 1.12 | Generic login error (no user enumeration) | `[x]` | `[ ]` | P0 | Returns same error for wrong user/pass |

---

## 2. Password Policy

| # | Feature | Impl | Test | Priority | Notes |
|---|---------|:----:|:----:|----------|-------|
| 2.1 | Min 8 chars, 3 character types | `[ ]` | `[ ]` | P1 | Validate at create/change password |
| 2.2 | No more than 3 consecutive identical chars | `[ ]` | `[ ]` | P1 | Regex validator |
| 2.3 | Password expiry — 90 days | `[ ]` | `[ ]` | P1 | `password_changed_at` + login check |
| 2.4 | Password history — cannot reuse last 2 | `[ ]` | `[ ]` | P1 | Store hashed history |
| 2.5 | bcrypt hashing — 12 rounds | `[x]` | `[ ]` | P0 | `passlib[bcrypt]` |

---

## 3. RBAC — Role-Based Access Control

| # | Feature | Impl | Test | Priority | Notes |
|---|---------|:----:|:----:|----------|-------|
| 3.1 | Roles: viewer / analyst / hunter / engineer / admin | `[x]` | `[ ]` | P0 | `User.role` model field |
| 3.2 | Permission map — role → allowed actions | `[ ]` | `[ ]` | P0 | `app/core/rbac.py` (Task 4.1) |
| 3.3 | `require_permission()` FastAPI dependency | `[ ]` | `[ ]` | P0 | Applied to each endpoint |
| 3.4 | viewer: read-only dashboards + alerts | `[ ]` | `[ ]` | P0 | |
| 3.5 | analyst: view + investigate + resolve alerts | `[ ]` | `[ ]` | P0 | |
| 3.6 | hunter: analyst + query events + saved hunts | `[ ]` | `[ ]` | P0 | |
| 3.7 | engineer: hunter + manage rules + connectors | `[ ]` | `[ ]` | P0 | |
| 3.8 | admin: full access including user management | `[ ]` | `[ ]` | P0 | |
| 3.9 | Scoped API keys (per-permission set) | `[ ]` | `[ ]` | P2 | |

---

## 4. User Management API

| # | Feature | Impl | Test | Priority | Notes |
|---|---------|:----:|:----:|----------|-------|
| 4.1 | `GET /users` — list all users (admin only) | `[~]` | `[ ]` | P0 | Returns mock data |
| 4.2 | `POST /users` — create user | `[~]` | `[ ]` | P0 | No DB persistence |
| 4.3 | `GET /users/{id}` — get user detail | `[~]` | `[ ]` | P0 | |
| 4.4 | `PATCH /users/{id}` — update role / active status | `[~]` | `[ ]` | P0 | |
| 4.5 | `DELETE /users/{id}` — deactivate user | `[~]` | `[ ]` | P1 | Soft delete only |
| 4.6 | `POST /users/invite` — send email invite | `[ ]` | `[ ]` | P2 | SMTP integration |
| 4.7 | Conflict check — duplicate email → 409 | `[~]` | `[ ]` | P0 | In mock logic |
| 4.8 | DB persistence for all user operations | `[ ]` | `[ ]` | P0 | Task 1.1 |

---

## 5. Event Ingestion Pipeline

| # | Feature | Impl | Test | Priority | Notes |
|---|---------|:----:|:----:|----------|-------|
| 5.1 | Message queue abstraction (`MessageQueue` ABC) | `[x]` | `[ ]` | P0 | `pipeline/queue.py` |
| 5.2 | `InMemoryQueue` — asyncio, dev/test | `[x]` | `[ ]` | P0 | Single process |
| 5.3 | `RedisStreamQueue` — Valkey Streams, multi-instance | `[x]` | `[ ]` | P1 | Consumer groups |
| 5.4 | `KafkaQueue` — Kafka/Redpanda, enterprise | `[x]` | `[ ]` | P1 | aiokafka |
| 5.5 | Topics: `mxtac.raw.*`, `normalized`, `alerts`, `enriched` | `[x]` | `[ ]` | P0 | Constants defined |
| 5.6 | Pipeline wired in `main.py` startup | `[x]` | `[ ]` | P0 | Task 2.4 — structural wiring done |
| 5.7 | Graceful shutdown — drain queue before exit | `[ ]` | `[ ]` | P1 | `on_shutdown` handler |
| 5.8 | Dead letter queue — failed events | `[ ]` | `[ ]` | P2 | `mxtac.dlq` topic |
| 5.9 | Back-pressure handling — queue full → slow ingest | `[ ]` | `[ ]` | P2 | |

---

## 6. Data Connectors

### 6a. Wazuh Connector
| # | Feature | Impl | Test | Priority | Notes |
|---|---------|:----:|:----:|----------|-------|
| 6.1 | Authenticate to Wazuh API (Basic → JWT) | `[~]` | `[ ]` | P0 | Skeleton in `connectors/wazuh.py` |
| 6.2 | Poll `/alerts` endpoint — paginated | `[ ]` | `[ ]` | P0 | Task 2.3 |
| 6.3 | Track last-seen timestamp | `[ ]` | `[ ]` | P0 | Avoid re-ingesting |
| 6.4 | Token refresh on 401 | `[ ]` | `[ ]` | P0 | |
| 6.5 | Exponential backoff on failure | `[ ]` | `[ ]` | P1 | Max 60s |
| 6.6 | Update connector status in DB (`last_seen_at`, `error_message`) | `[ ]` | `[ ]` | P1 | |
| 6.7 | Publish raw events to `mxtac.raw.wazuh` | `[ ]` | `[ ]` | P0 | |
| 6.8 | Health check endpoint `POST /connectors/{id}/test` | `[~]` | `[ ]` | P1 | |

### 6b. Zeek Connector
| # | Feature | Impl | Test | Priority | Notes |
|---|---------|:----:|:----:|----------|-------|
| 6.9 | Tail Zeek log directory — `conn.log`, `dns.log`, `http.log`, `ssl.log` | `[~]` | `[ ]` | P0 | |
| 6.10 | Track file byte offset per log file | `[ ]` | `[ ]` | P0 | Survive restarts |
| 6.11 | Parse JSON-format Zeek logs | `[ ]` | `[ ]` | P0 | |
| 6.12 | Parse TSV-format Zeek logs (fallback) | `[ ]` | `[ ]` | P1 | |
| 6.13 | Add `_path` field from filename stem | `[ ]` | `[ ]` | P0 | Needed by normalizer |
| 6.14 | Publish raw events to `mxtac.raw.zeek` | `[ ]` | `[ ]` | P0 | |

### 6c. Suricata Connector
| # | Feature | Impl | Test | Priority | Notes |
|---|---------|:----:|:----:|----------|-------|
| 6.15 | Tail `eve.json` (newline-delimited JSON) | `[ ]` | `[ ]` | P0 | Task 2.3 |
| 6.16 | Filter by `event_type`: alert, dns, http, tls | `[ ]` | `[ ]` | P0 | |
| 6.17 | Track file offset across restarts | `[ ]` | `[ ]` | P0 | |
| 6.18 | Publish raw events to `mxtac.raw.suricata` | `[ ]` | `[ ]` | P0 | |

### 6d. Additional Connectors
| # | Feature | Impl | Test | Priority | Notes |
|---|---------|:----:|:----:|----------|-------|
| 6.19 | Prowler connector — cloud security findings | `[ ]` | `[ ]` | P1 | AWS/Azure/GCP |
| 6.20 | OpenCTI connector — threat intelligence feed | `[ ]` | `[ ]` | P1 | Enrichment |
| 6.21 | Generic webhook receiver (`POST /ingest`) | `[ ]` | `[ ]` | P1 | Any JSON source |
| 6.22 | Generic syslog receiver (UDP 514) | `[ ]` | `[ ]` | P2 | |
| 6.23 | Velociraptor connector — forensic artifacts | `[ ]` | `[ ]` | P2 | |
| 6.24 | Connector registry — load from DB on startup | `[ ]` | `[ ]` | P1 | Task 2.3 |

---

## 7. OCSF Normalization

| # | Feature | Impl | Test | Priority | Notes |
|---|---------|:----:|:----:|----------|-------|
| 7.1 | `OCSFEvent` Pydantic schema | `[x]` | `[ ]` | P0 | `normalizers/ocsf.py` |
| 7.2 | Wazuh → OCSF: `rule.level` → `severity_id` | `[x]` | `[x]` | P0 | 74 tests: all tiers, boundaries, classify, MITRE, round-trip |
| 7.3 | Wazuh → OCSF: MITRE tags → `attacks[]` | `[x]` | `[x]` | P0 | 29 tests: technique names, sub-techniques, full-name tactics, serialization |
| 7.4 | Wazuh → OCSF: `agent` → `dst_endpoint` | `[x]` | `[x]` | P0 | `agent.id→uid`, `name→hostname`, `ip→ip`, `os.name→os_name`; 34 tests |
| 7.5 | Wazuh → OCSF: Windows event data → `process` | `[ ]` | `[ ]` | P0 | |
| 7.6 | Zeek → OCSF: `conn` → `NetworkActivity` (class 4001) | `[~]` | `[ ]` | P0 | |
| 7.7 | Zeek → OCSF: `dns` → `DNSActivity` (class 4003) | `[ ]` | `[ ]` | P0 | |
| 7.8 | Zeek → OCSF: `http` → `HTTPActivity` (class 4002) | `[ ]` | `[ ]` | P0 | |
| 7.9 | Zeek → OCSF: `ssl` → `NetworkActivity` | `[ ]` | `[ ]` | P0 | |
| 7.10 | Suricata → OCSF: alert `severity` → `severity_id` | `[~]` | `[ ]` | P0 | |
| 7.11 | Suricata → OCSF: MITRE metadata → `attacks[]` | `[ ]` | `[ ]` | P0 | |
| 7.12 | Suricata → OCSF: IPs/ports → `src/dst_endpoint` | `[ ]` | `[ ]` | P0 | |
| 7.13 | `NormalizerPipeline` — subscribe + route + publish | `[ ]` | `[ ]` | P0 | Task 2.1 |
| 7.14 | Schema validation — reject malformed events | `[ ]` | `[ ]` | P1 | Log to DLQ |
| 7.15 | Custom field mapping config per connector | `[ ]` | `[ ]` | P2 | YAML overrides |

---

## 8. Sigma Detection Engine

| # | Feature | Impl | Test | Priority | Notes |
|---|---------|:----:|:----:|----------|-------|
| 8.1 | `SigmaRule` dataclass | `[x]` | `[ ]` | P0 | `engine/sigma_engine.py` |
| 8.2 | `SigmaAlert` dataclass | `[x]` | `[ ]` | P0 | |
| 8.3 | Load rules from YAML directory | `[ ]` | `[ ]` | P0 | Task 2.2 |
| 8.4 | Load single rule from YAML string | `[ ]` | `[ ]` | P0 | |
| 8.5 | Index rules by `logsource` (product/category/service) | `[ ]` | `[ ]` | P0 | Fast candidate lookup |
| 8.6 | Modifier: `contains` | `[ ]` | `[ ]` | P0 | |
| 8.7 | Modifier: `startswith` | `[ ]` | `[ ]` | P0 | |
| 8.8 | Modifier: `endswith` | `[ ]` | `[ ]` | P0 | |
| 8.9 | Modifier: `re` (regex) | `[ ]` | `[ ]` | P0 | |
| 8.10 | Modifier: `base64` | `[ ]` | `[ ]` | P1 | |
| 8.11 | Modifier: `cidr` | `[ ]` | `[ ]` | P1 | IP range matching |
| 8.12 | Modifier: `all` (AND for list values) | `[ ]` | `[ ]` | P0 | |
| 8.13 | Condition: `AND` / `OR` / `NOT` | `[ ]` | `[ ]` | P0 | |
| 8.14 | Condition: `1 of them` / `all of them` | `[ ]` | `[ ]` | P0 | |
| 8.15 | Condition: `1 of selection*` (wildcard group) | `[ ]` | `[ ]` | P1 | |
| 8.16 | ATT&CK tag extraction from `tags:` field | `[ ]` | `[ ]` | P0 | `attack.TXXXX` → `technique_ids` |
| 8.17 | `SigmaEngine.evaluate(event)` → `SigmaAlert` | `[ ]` | `[ ]` | P0 | Core matching |
| 8.18 | Field mapping: OCSF event → flat Sigma dict | `[ ]` | `[ ]` | P0 | Per logsource category |
| 8.19 | `sigma_consumer` — reads `mxtac.normalized`, publishes `mxtac.alerts` | `[ ]` | `[ ]` | P0 | Task 2.4 |
| 8.20 | Rule performance tracking — `hit_count`, `fp_count` | `[ ]` | `[ ]` | P1 | DB update on match |
| 8.21 | Bundled example rules — 5 default detections | `[ ]` | `[ ]` | P0 | In `sigma_rules/` directory |
| 8.22 | SigmaHQ rule import (`POST /rules/import`) | `[ ]` | `[ ]` | P1 | Bulk YAML multi-doc |
| 8.23 | Rule test endpoint (`POST /rules/test`) | `[~]` | `[ ]` | P1 | Against sample event |

---

## 9. Alert Manager

| # | Feature | Impl | Test | Priority | Notes |
|---|---------|:----:|:----:|----------|-------|
| 9.1 | Deduplication — MD5(rule_id + host) key | `[x]` | `[ ]` | P0 | `alert_manager.py` |
| 9.2 | Dedup window — 5 minutes TTL | `[x]` | `[ ]` | P0 | In-process dict (single instance) |
| 9.3 | Distributed dedup — Valkey SETEX NX | `[ ]` | `[ ]` | P1 | Task 3.2 |
| 9.4 | Risk score: severity × 0.60 | `[x]` | `[ ]` | P0 | |
| 9.5 | Risk score: asset criticality × 0.25 | `[x]` | `[ ]` | P0 | Prefix-based defaults |
| 9.6 | Risk score: recurrence bonus × 0.15 | `[~]` | `[ ]` | P1 | Placeholder, always 0 |
| 9.7 | Enrichment: threat intel (OpenCTI lookup) | `[ ]` | `[ ]` | P2 | Stub in `_enrich()` |
| 9.8 | Enrichment: GeoIP lookup | `[ ]` | `[ ]` | P2 | Stub in `_enrich()` |
| 9.9 | Enrichment: asset criticality from CMDB | `[ ]` | `[ ]` | P2 | Stub, currently hardcoded |
| 9.10 | Publish enriched alerts to `mxtac.enriched` | `[x]` | `[ ]` | P0 | |
| 9.11 | Alert suppression rules | `[ ]` | `[ ]` | P1 | Whitelist/tuning |
| 9.12 | Alert auto-close — no recurrence in N hours | `[ ]` | `[ ]` | P2 | |

---

## 10. Alerts / Detections API

| # | Feature | Impl | Test | Priority | Notes |
|---|---------|:----:|:----:|----------|-------|
| 10.1 | `GET /detections` — paginated list | `[x]` | `[x]` | P0 | DetectionRepo.list(); 19 tests pass |
| 10.2 | Filter by severity (multi-select) | `[x]` | `[x]` | P0 | `?severity=critical&severity=high` |
| 10.3 | Filter by status | `[x]` | `[x]` | P0 | `?status=active` |
| 10.4 | Filter by tactic | `[x]` | `[x]` | P0 | `?tactic=...` (ilike) |
| 10.5 | Filter by host | `[x]` | `[x]` | P0 | `?host=...` (ilike) |
| 10.6 | Full-text search across title + description | `[x]` | `[x]` | P0 | `?search=...` across name/technique_id/host |
| 10.7 | Sort by score / time / severity / host / tactic | `[x]` | `[x]` | P0 | `?sort=score&order=desc` |
| 10.8 | `GET /detections/{id}` — detail view | `[x]` | `[x]` | P0 | 404 on missing |
| 10.9 | `PATCH /detections/{id}` — update status / assignee | `[x]` | `[x]` | P0 | RBAC: detections:write (analyst+) |
| 10.10 | `POST /detections/bulk` — bulk status update | `[ ]` | `[ ]` | P1 | |
| 10.11 | DB persistence for all operations | `[x]` | `[x]` | P0 | SQLAlchemy async via DetectionRepo |

---

## 11. Event Search & Hunting

| # | Feature | Impl | Test | Priority | Notes |
|---|---------|:----:|:----:|----------|-------|
| 11.1 | `POST /events/search` — full-text + filters + time range | `[x]` | `[T]` | P0 | PostgreSQL via EventRepo; 19 tests pass |
| 11.2 | `GET /events/{id}` — single event by ID | `[x]` | `[T]` | P0 | EventRepo.get(); 404 on missing |
| 11.3 | `POST /events/aggregate` — terms / date_histogram | `[x]` | `[T]` | P1 | count_by_field() — terms aggregation |
| 11.4 | `GET /events/entity/{type}/{value}` — entity timeline | `[x]` | `[T]` | P1 | ip / host / user / hash; EventRepo.entity_events() |
| 11.5 | OpenSearch integration wired to endpoints | `[ ]` | `[ ]` | P0 | Task 4.2 — future enhancement |
| 11.6 | Query builder — Lucene DSL from filter params | `[ ]` | `[ ]` | P0 | |
| 11.7 | Save and name hunt queries | `[ ]` | `[ ]` | P2 | |
| 11.8 | ATT&CK-guided hunting suggestions | `[ ]` | `[ ]` | P3 | |

---

## 12. OpenSearch Storage

| # | Feature | Impl | Test | Priority | Notes |
|---|---------|:----:|:----:|----------|-------|
| 12.1 | `OpenSearchService.connect()` | `[x]` | `[ ]` | P0 | Graceful fallback if not installed |
| 12.2 | `ensure_indices()` — create index templates | `[~]` | `[ ]` | P0 | |
| 12.3 | `index_event()` — `mxtac-events-YYYY.MM.DD` | `[x]` | `[ ]` | P0 | Daily rotation |
| 12.4 | `index_alert()` — `mxtac-alerts-YYYY.MM.DD` | `[x]` | `[ ]` | P0 | |
| 12.5 | `search_events()` — bool query with filters | `[x]` | `[ ]` | P0 | |
| 12.6 | `get_event()` — fetch by `_id` | `[x]` | `[ ]` | P0 | |
| 12.7 | `aggregate()` — terms / histogram | `[ ]` | `[ ]` | P1 | |
| 12.8 | `entity_timeline()` — events for one entity | `[x]` | `[ ]` | P1 | |
| 12.9 | Index lifecycle management — 90-day retention | `[ ]` | `[ ]` | P1 | ILM policy |
| 12.10 | Index mapping templates — correct field types | `[ ]` | `[ ]` | P1 | IP, keyword, date, float |
| 12.11 | OpenSearch started and wired in `main.py` startup | `[ ]` | `[ ]` | P0 | Task 2.4 |

---

## 13. Sigma Rules API

| # | Feature | Impl | Test | Priority | Notes |
|---|---------|:----:|:----:|----------|-------|
| 13.1 | `GET /rules` — list with level / enabled filters | `[~]` | `[ ]` | P0 | Mock data |
| 13.2 | `GET /rules/{id}` — detail + YAML content | `[~]` | `[ ]` | P0 | |
| 13.3 | `POST /rules` — create from YAML | `[~]` | `[ ]` | P0 | |
| 13.4 | `PATCH /rules/{id}` — enable / disable / update | `[~]` | `[ ]` | P0 | |
| 13.5 | `DELETE /rules/{id}` — remove rule | `[~]` | `[ ]` | P1 | |
| 13.6 | `POST /rules/test` — validate YAML + test against sample | `[~]` | `[ ]` | P1 | |
| 13.7 | `POST /rules/import` — bulk YAML multi-doc import | `[x]` | `[x]` | P1 | |
| 13.8 | `GET /rules/stats/summary` — count by level | `[~]` | `[ ]` | P1 | |
| 13.9 | DB persistence for all rule operations | `[ ]` | `[ ]` | P0 | Task 1.1 |
| 13.10 | SigmaEngine reloads on rule create/update/delete | `[ ]` | `[ ]` | P1 | Hot reload |

---

## 14. Connectors API

| # | Feature | Impl | Test | Priority | Notes |
|---|---------|:----:|:----:|----------|-------|
| 14.1 | `GET /connectors` — list all | `[~]` | `[ ]` | P0 | Mock data |
| 14.2 | `GET /connectors/{id}` — detail | `[~]` | `[ ]` | P0 | |
| 14.3 | `POST /connectors` — create | `[~]` | `[ ]` | P0 | |
| 14.4 | `PATCH /connectors/{id}` — enable / disable / config | `[~]` | `[ ]` | P0 | |
| 14.5 | `DELETE /connectors/{id}` — remove | `[~]` | `[ ]` | P1 | |
| 14.6 | `POST /connectors/{id}/test` — verify connection | `[~]` | `[ ]` | P1 | |
| 14.7 | `GET /connectors/{id}/health` — live health status | `[~]` | `[ ]` | P1 | |
| 14.8 | DB persistence — connectors from DB on startup | `[ ]` | `[ ]` | P0 | Task 1.1 |
| 14.9 | Start/stop connector at runtime | `[ ]` | `[ ]` | P1 | |

---

## 15. Overview / Dashboard API

| # | Feature | Impl | Test | Priority | Notes |
|---|---------|:----:|:----:|----------|-------|
| 15.1 | `GET /overview/kpis` — alert counts, MTTR, coverage % | `[~]` | `[ ]` | P0 | Mock data |
| 15.2 | `GET /overview/timeline` — alerts over time | `[~]` | `[ ]` | P0 | Mock data |
| 15.3 | `GET /overview/tactics` — top ATT&CK tactics | `[~]` | `[ ]` | P0 | Mock data |
| 15.4 | `GET /overview/coverage/heatmap` — technique × tactic grid | `[~]` | `[ ]` | P0 | Mock data |
| 15.5 | `GET /overview/coverage/tactic-labels` | `[~]` | `[ ]` | P0 | Mock data |
| 15.6 | `GET /overview/integrations` — connector status | `[~]` | `[ ]` | P0 | Mock data |
| 15.7 | `GET /overview/recent-detections` | `[~]` | `[ ]` | P0 | Mock data |
| 15.8 | All overview endpoints use real DB / OpenSearch data | `[ ]` | `[ ]` | P0 | Task 1.1 |

---

## 16. ATT&CK Coverage

| # | Feature | Impl | Test | Priority | Notes |
|---|---------|:----:|:----:|----------|-------|
| 16.1 | `GET /coverage` — overall % + technique count | `[ ]` | `[ ]` | P0 | |
| 16.2 | `GET /coverage/gaps` — techniques with no rule | `[ ]` | `[ ]` | P1 | |
| 16.3 | `GET /coverage/navigator` — ATT&CK Navigator JSON | `[ ]` | `[ ]` | P1 | Export layer |
| 16.4 | Coverage calculated from active enabled rules | `[ ]` | `[ ]` | P0 | Query DB |
| 16.5 | Coverage by data source (Wazuh, Zeek, Suricata) | `[ ]` | `[ ]` | P1 | |
| 16.6 | Coverage trend over time | `[ ]` | `[ ]` | P2 | Daily snapshot |
| 16.7 | Coverage targets — alert when below threshold | `[ ]` | `[ ]` | P2 | |
| 16.8 | Coverage page in UI (heatmap + gap table) | `[x]` | `[ ]` | P0 | Uses mock data |

---

## 17. Real-time WebSocket

| # | Feature | Impl | Test | Priority | Notes |
|---|---------|:----:|:----:|----------|-------|
| 17.1 | `WS /ws/alerts` endpoint | `[x]` | `[ ]` | P0 | Framework present |
| 17.2 | Send `connected` handshake on connect | `[x]` | `[ ]` | P0 | |
| 17.3 | Ping every 30s to keep-alive | `[x]` | `[ ]` | P0 | |
| 17.4 | Accept `filter` message from client | `[x]` | `[ ]` | P1 | ACK response |
| 17.5 | Broadcast enriched alerts to all clients (single instance) | `[~]` | `[ ]` | P0 | Mock replay only |
| 17.6 | Distributed broadcast via Valkey pub/sub (multi-instance) | `[ ]` | `[ ]` | P1 | Task 3.1 |
| 17.7 | Frontend `useAlertStream` hook — connect + reconnect | `[ ]` | `[ ]` | P0 | Task 4.3 |
| 17.8 | Live indicator in UI — pulsing dot connected/reconnecting | `[ ]` | `[ ]` | P1 | |
| 17.9 | New alert badge — "Live" tag fades after 30s | `[ ]` | `[ ]` | P1 | |
| 17.10 | Unread count on Sidebar Detections link | `[ ]` | `[ ]` | P2 | |
| 17.11 | Auto-reconnect — 5s delay on disconnect | `[ ]` | `[ ]` | P0 | |

---

## 18. Database Persistence

| # | Feature | Impl | Test | Priority | Notes |
|---|---------|:----:|:----:|----------|-------|
| 18.1 | PostgreSQL async engine (`asyncpg`) | `[x]` | `[ ]` | P0 | `core/database.py` |
| 18.2 | SQLite option (`aiosqlite`) for single-node | `[ ]` | `[ ]` | P1 | Config switch |
| 18.3 | Alembic migration 0001 — users + detections | `[x]` | `[ ]` | P0 | |
| 18.4 | Alembic migration 0002 — rules + connectors | `[x]` | `[ ]` | P0 | |
| 18.5 | Repository layer — DetectionRepo | `[ ]` | `[ ]` | P0 | Task 1.1 |
| 18.6 | Repository layer — RuleRepo | `[ ]` | `[ ]` | P0 | Task 1.1 |
| 18.7 | Repository layer — ConnectorRepo | `[ ]` | `[ ]` | P0 | Task 1.1 |
| 18.8 | Repository layer — UserRepo | `[ ]` | `[ ]` | P0 | Task 1.1 |
| 18.9 | Seed data on first startup (idempotent) | `[x]` | `[ ]` | P0 | Task 1.2 — `seed.py` exists, called from `main.py` |
| 18.10 | `GET /ready` — check DB liveness | `[x]` | `[ ]` | P0 | Task 0.3 — checks PostgreSQL, Valkey, OpenSearch |

---

## 19. Horizontal Scaling

| # | Feature | Impl | Test | Priority | Notes |
|---|---------|:----:|:----:|----------|-------|
| 19.1 | Replace Redis → Valkey (BSD license) | `[x]` | `[ ]` | P0 | Task 0.1 — Valkey 8, `valkey[libvalkey]` |
| 19.2 | `RedisStreamQueue` uses Valkey Streams | `[x]` | `[ ]` | P1 | Coded, not default |
| 19.3 | `DistributedConnectionManager` — Valkey pub/sub | `[ ]` | `[ ]` | P1 | Task 3.1 |
| 19.4 | Dedup cache via Valkey SETEX NX (atomic) | `[ ]` | `[ ]` | P1 | Task 3.2 |
| 19.5 | `QUEUE_BACKEND=redis` as production default | `[ ]` | `[ ]` | P1 | docker-compose env var |
| 19.6 | `GET /ready` checks all dependencies | `[x]` | `[ ]` | P0 | Task 0.3 — PostgreSQL, Valkey, OpenSearch |
| 19.7 | Docker Swarm stack manifest | `[ ]` | `[ ]` | P1 | Task 3.3 |
| 19.8 | k3s / Kubernetes manifests | `[ ]` | `[ ]` | P1 | Task 3.3 |
| 19.9 | HAProxy config — `/ready` health check | `[ ]` | `[ ]` | P1 | Task 3.3 |
| 19.10 | HorizontalPodAutoscaler — CPU 70%, min 2 / max 8 | `[ ]` | `[ ]` | P2 | Task 3.3 |
| 19.11 | Stateless API — no in-process session state | `[ ]` | `[ ]` | P1 | Verify all endpoints |
| 19.12 | Rolling update — zero downtime deploy | `[ ]` | `[ ]` | P1 | Kubernetes rolling |

---

## 20. Headless / Autonomous Operation

| # | Feature | Impl | Test | Priority | Notes |
|---|---------|:----:|:----:|----------|-------|
| 20.1 | Pipeline runs without UI or user action | `[~]` | `[ ]` | P0 | Needs wiring (Task 2.4) |
| 20.2 | `systemd` service unit file | `[ ]` | `[ ]` | P1 | `app/deploy/systemd/mxtac.service` |
| 20.3 | Process supervisor `Restart=always` | `[ ]` | `[ ]` | P1 | |
| 20.4 | Alert output to file (JSON per line) | `[ ]` | `[ ]` | P1 | No dashboard needed |
| 20.5 | Alert output to syslog | `[ ]` | `[ ]` | P2 | |
| 20.6 | Alert output to webhook (configurable URL) | `[ ]` | `[ ]` | P1 | POST JSON |
| 20.7 | Alert output to email (SMTP) | `[ ]` | `[ ]` | P2 | High-severity only |
| 20.8 | SQLite mode — no external DB required | `[ ]` | `[ ]` | P1 | Single binary mode |
| 20.9 | DuckDB event store — no OpenSearch required | `[ ]` | `[ ]` | P2 | Embedded analytics |

---

## 21. Observability & Operations

| # | Feature | Impl | Test | Priority | Notes |
|---|---------|:----:|:----:|----------|-------|
| 21.1 | `GET /health` — always 200 | `[x]` | `[ ]` | P0 | `main.py` |
| 21.2 | `GET /ready` — 200/503 based on dependencies | `[x]` | `[ ]` | P0 | Task 0.3 — implemented |
| 21.3 | `GET /metrics` — Prometheus format | `[~]` | `[ ]` | P1 | Task 6.1 — instrumentator wired, custom metrics pending |
| 21.4 | Counter: `mxtac_alerts_processed_total{severity}` | `[ ]` | `[ ]` | P1 | |
| 21.5 | Counter: `mxtac_alerts_deduplicated_total` | `[ ]` | `[ ]` | P1 | |
| 21.6 | Counter: `mxtac_rule_matches_total{rule_id,level}` | `[ ]` | `[ ]` | P1 | |
| 21.7 | Histogram: `mxtac_pipeline_latency_seconds` | `[ ]` | `[ ]` | P1 | |
| 21.8 | Gauge: `mxtac_websocket_connections` | `[ ]` | `[ ]` | P1 | |
| 21.9 | Grafana dashboard — pre-built JSON | `[ ]` | `[ ]` | P2 | Task 6.1 |
| 21.10 | Structured JSON logging in production | `[x]` | `[ ]` | P0 | `core/logging.py` |
| 21.11 | Request access log — method, path, status, latency | `[~]` | `[ ]` | P1 | uvicorn access log |
| 21.12 | Audit log — user + action + resource + timestamp | `[ ]` | `[ ]` | P1 | Task 6.2 |
| 21.13 | Audit log viewable in Admin UI | `[ ]` | `[ ]` | P1 | Task 6.2 |
| 21.14 | Audit log retention — 3 years (OpenSearch ILM) | `[ ]` | `[ ]` | P2 | |

---

## 22. Frontend — Layout & Navigation

| # | Feature | Impl | Test | Priority | Notes |
|---|---------|:----:|:----:|----------|-------|
| 22.1 | Sidebar with nav links | `[x]` | `[ ]` | P0 | |
| 22.2 | Active route highlight | `[x]` | `[x]` | P0 | |
| 22.3 | TopBar with breadcrumb | `[x]` | `[ ]` | P0 | |
| 22.4 | ErrorBoundary wrapper | `[x]` | `[ ]` | P0 | |
| 22.5 | NotificationToast | `[x]` | `[ ]` | P0 | |
| 22.6 | Auth store (Zustand) | `[x]` | `[ ]` | P0 | |
| 22.7 | Detection store (Zustand) | `[x]` | `[ ]` | P0 | |
| 22.8 | UI store — sidebar, notifications, global error | `[x]` | `[ ]` | P0 | |
| 22.9 | Login page | `[ ]` | `[ ]` | P0 | Route guard if not authenticated |
| 22.10 | Route guard — redirect to login if no token | `[ ]` | `[ ]` | P0 | |

---

## 23. Frontend — Pages

| # | Feature | Impl | Test | Priority | Notes |
|---|---------|:----:|:----:|----------|-------|
| 23.1 | Overview dashboard (KPIs + timeline + heatmap + integrations) | `[x]` | `[ ]` | P0 | Mock data |
| 23.2 | Detections list (filter + sort + paginate) | `[x]` | `[ ]` | P0 | Mock data |
| 23.3 | Detection detail panel (slide-out) | `[~]` | `[ ]` | P0 | Partial |
| 23.4 | ATT&CK coverage page (heatmap + gap table) | `[x]` | `[ ]` | P0 | Mock data |
| 23.5 | Sigma rules list + YAML editor modal | `[x]` | `[ ]` | P0 | Not saving |
| 23.6 | Connectors management (card grid + detail) | `[x]` | `[ ]` | P0 | Mock data |
| 23.7 | Admin — users & roles table | `[x]` | `[ ]` | P0 | Mock data |
| 23.8 | Admin — audit log tab | `[~]` | `[ ]` | P1 | "Coming soon" |
| 23.9 | Event hunt / search page | `[ ]` | `[ ]` | P1 | |
| 23.10 | Incidents page | `[ ]` | `[ ]` | P2 | |
| 23.11 | Threat intel page | `[ ]` | `[ ]` | P2 | OpenCTI |
| 23.12 | Reports page | `[ ]` | `[ ]` | P2 | |
| 23.13 | All pages use real API data (not mock) | `[ ]` | `[ ]` | P0 | After Task 1.1 |

---

## 24. MxGuard — EDR Agent (Rust)

| # | Feature | Impl | Test | Priority | Notes |
|---|---------|:----:|:----:|----------|-------|
| 24.1 | Rust project skeleton (`Cargo.toml` + `src/`) | `[ ]` | `[ ]` | P2 | Task 5.1 |
| 24.2 | Process creation monitoring (`/proc` polling) | `[ ]` | `[ ]` | P2 | |
| 24.3 | File integrity monitoring (`inotify` / `kqueue`) | `[ ]` | `[ ]` | P2 | |
| 24.4 | Network connection tracking (`/proc/net/tcp`) | `[ ]` | `[ ]` | P2 | |
| 24.5 | Authentication monitoring (`/var/log/auth.log`) | `[ ]` | `[ ]` | P2 | |
| 24.6 | Windows Registry monitoring | `[ ]` | `[ ]` | P3 | Windows only |
| 24.7 | Scheduled task monitoring | `[ ]` | `[ ]` | P3 | |
| 24.8 | OCSF event serialization | `[ ]` | `[ ]` | P2 | |
| 24.9 | HTTP transport — POST batches to backend | `[ ]` | `[ ]` | P2 | |
| 24.10 | Config via TOML file + env overrides | `[ ]` | `[ ]` | P2 | |
| 24.11 | Health check endpoint (port 9001) | `[ ]` | `[ ]` | P2 | |
| 24.12 | Resource limits: < 1% CPU, < 30 MB RAM | `[ ]` | `[ ]` | P2 | Benchmark target |
| 24.13 | ATT&CK coverage: 30–40% techniques | `[ ]` | `[ ]` | P2 | Design target |

---

## 25. MxWatch — NDR Agent (Rust)

| # | Feature | Impl | Test | Priority | Notes |
|---|---------|:----:|:----:|----------|-------|
| 25.1 | Rust project skeleton | `[ ]` | `[ ]` | P2 | Task 5.2 |
| 25.2 | AF_PACKET + MMAP zero-copy capture | `[ ]` | `[ ]` | P2 | Linux only |
| 25.3 | libpcap capture (fallback / cross-platform) | `[ ]` | `[ ]` | P2 | |
| 25.4 | Protocol parser: TCP/UDP | `[ ]` | `[ ]` | P2 | |
| 25.5 | Protocol parser: DNS | `[ ]` | `[ ]` | P2 | |
| 25.6 | Protocol parser: HTTP | `[ ]` | `[ ]` | P2 | |
| 25.7 | Protocol parser: TLS (SNI extraction) | `[ ]` | `[ ]` | P2 | |
| 25.8 | Protocol parser: SMB / SSH / RDP | `[ ]` | `[ ]` | P3 | |
| 25.9 | Detection: DNS tunneling (long query / entropy) | `[ ]` | `[ ]` | P2 | |
| 25.10 | Detection: Port scan (many unique dst_ports) | `[ ]` | `[ ]` | P2 | |
| 25.11 | Detection: Protocol anomaly on known ports | `[ ]` | `[ ]` | P2 | |
| 25.12 | Detection: C2 beacon (periodic callback) | `[ ]` | `[ ]` | P2 | |
| 25.13 | Detection: Data exfiltration (large outbound) | `[ ]` | `[ ]` | P3 | |
| 25.14 | OCSF event serialization | `[ ]` | `[ ]` | P2 | |
| 25.15 | HTTP transport — POST to backend | `[ ]` | `[ ]` | P2 | |
| 25.16 | Resource limits: < 5% CPU, < 120 MB RAM | `[ ]` | `[ ]` | P2 | |
| 25.17 | Performance target: 1–5 Mpps | `[ ]` | `[ ]` | P2 | Benchmark |

---

## 26. Non-Functional: Performance

| # | Requirement | Target | Tested | Priority |
|---|-------------|--------|:------:|----------|
| 26.1 | Event ingestion rate | 50,000 EPS | `[ ]` | P1 |
| 26.2 | Sigma evaluation latency | < 100ms/event (10K rules) | `[ ]` | P1 |
| 26.3 | Alert end-to-end latency | < 30 seconds | `[ ]` | P1 |
| 26.4 | Search query response | < 5 seconds | `[ ]` | P1 |
| 26.5 | Dashboard load time | < 3 seconds | `[ ]` | P1 |
| 26.6 | API response time P95 | < 200ms | `[ ]` | P1 |
| 26.7 | Concurrent WebSocket clients | 100+ | `[ ]` | P1 |
| 26.8 | Concurrent API users | 100+ simultaneous | `[ ]` | P1 |

---

## 27. Non-Functional: Reliability

| # | Requirement | Target | Tested | Priority |
|---|-------------|--------|:------:|----------|
| 27.1 | Platform uptime | 99.9% | `[ ]` | P1 |
| 27.2 | Failover time | < 60 seconds | `[ ]` | P1 |
| 27.3 | No data loss on node failure | Zero events dropped | `[ ]` | P1 |
| 27.4 | Backup restore time | < 4 hours | `[ ]` | P2 |
| 27.5 | Disaster recovery RTO | < 24 hours | `[ ]` | P2 |
| 27.6 | Restart without data loss | Persists queue state | `[ ]` | P1 |

---

## 28. Test Coverage

| # | Test Area | Written | Passing | Priority | Notes |
|---|-----------|:-------:|:-------:|----------|-------|
| 28.1 | Auth: login success | `[x]` | `[x]` | P0 | |
| 28.2 | Auth: wrong password → 401 | `[x]` | `[T]` | P0 | |
| 28.3 | Auth: unknown user → 401 (same error) | `[x]` | `[T]` | P0 | No enumeration |
| 28.4 | Auth: expired token → 401 | `[x]` | `[T]` | P0 | 5 tests: access+refresh+role+epoch+no-prefix |
| 28.5 | Auth: token refresh | `[x]` | `[x]` | P0 | 18 tests: happy path, type validation, inactive/unknown user, 422 |
| 28.6 | RBAC: viewer cannot PATCH rules | `[x]` | `[T]` | P0 | 6 tests: viewer/analyst/hunter→403, engineer/admin→404, unauth→401/403 |
| 28.7 | RBAC: analyst can update detection status | `[x]` | `[T]` | P0 | 8 tests: viewer→403 (×2), analyst/hunter/engineer/admin→200, assigned_to, priority |
| 28.8 | RBAC: engineer can create rules | `[x]` | `[T]` | P0 | 8 tests: unauth→401/403, viewer/analyst/hunter→403, engineer/admin→201, invalid→422, disabled |
| 28.9 | RBAC: admin can manage users | `[ ]` | `[ ]` | P0 | |
| 28.10 | Normalizer: Wazuh level 14 → severity_id 5 | `[x]` | `[x]` | P0 | `test_level_14_maps_to_severity_5` |
| 28.11 | Normalizer: Wazuh MITRE tags → attacks[] | `[x]` | `[x]` | P0 | `test_wazuh_mitre_attacks.py` — 29 tests |
| 28.12 | Normalizer: Zeek conn → NetworkActivity | `[ ]` | `[ ]` | P0 | |
| 28.13 | Normalizer: Suricata severity 1 → severity_id 4 | `[ ]` | `[ ]` | P0 | |
| 28.14 | Sigma: rule loads from valid YAML | `[ ]` | `[ ]` | P0 | |
| 28.15 | Sigma: `contains` modifier matches | `[ ]` | `[ ]` | P0 | |
| 28.16 | Sigma: `startswith` modifier matches | `[ ]` | `[ ]` | P0 | |
| 28.17 | Sigma: `re` modifier matches regex | `[ ]` | `[ ]` | P0 | |
| 28.18 | Sigma: AND condition — both must match | `[ ]` | `[ ]` | P0 | |
| 28.19 | Sigma: OR condition — either matches | `[ ]` | `[ ]` | P0 | |
| 28.20 | Sigma: NOT condition — exclusion works | `[ ]` | `[ ]` | P0 | |
| 28.21 | Sigma: `1 of them` across selections | `[ ]` | `[ ]` | P0 | |
| 28.22 | Sigma: non-matching event yields no alert | `[ ]` | `[ ]` | P0 | |
| 28.23 | AlertManager: dedup blocks within 5 min | `[ ]` | `[ ]` | P0 | |
| 28.24 | AlertManager: same alert after 5 min accepted | `[ ]` | `[ ]` | P1 | TTL expiry |
| 28.25 | AlertManager: risk score formula correct | `[ ]` | `[ ]` | P0 | |
| 28.26 | AlertManager: distributed dedup (two instances) | `[ ]` | `[ ]` | P1 | Valkey SETEX NX |
| 28.27 | WebSocket: client receives broadcast alert | `[ ]` | `[ ]` | P0 | |
| 28.28 | WebSocket: client on instance-2 receives alert from instance-1 | `[ ]` | `[ ]` | P1 | Distributed |
| 28.29 | WebSocket: auto-reconnect after drop | `[ ]` | `[ ]` | P1 | |
| 28.30 | Detections API: pagination (page / page_size) | `[x]` | `[x]` | P0 | |
| 28.31 | Detections API: filter by severity | `[x]` | `[x]` | P0 | |
| 28.32 | Detections API: sort by score descending | `[x]` | `[x]` | P0 | |
| 28.33 | Detections API: 404 for unknown ID | `[x]` | `[x]` | P0 | |
| 28.34 | Detections API: unauthenticated → 401 | `[x]` | `[x]` | P0 | |
| 28.35 | Rules API: create rule persists to DB | `[ ]` | `[ ]` | P0 | |
| 28.36 | Rules API: invalid YAML → 422 | `[ ]` | `[ ]` | P0 | |
| 28.37 | Rules API: delete removes from engine | `[ ]` | `[ ]` | P1 | |
| 28.38 | Overview API: KPIs return expected shape | `[ ]` | `[ ]` | P0 | |
| 28.39 | /ready: 503 when PostgreSQL down | `[ ]` | `[ ]` | P0 | |
| 28.40 | /ready: 200 when all services healthy | `[ ]` | `[ ]` | P0 | |
| 28.41 | Pipeline: event flows end-to-end (integration) | `[ ]` | `[ ]` | P0 | Synthetic event |
| 28.42 | Performance: Sigma evaluates 10K rules in < 100ms | `[ ]` | `[ ]` | P1 | Benchmark test |
| 28.43 | Performance: 50K EPS ingestion rate | `[ ]` | `[ ]` | P1 | Load test |
| 28.44 | Frontend: SeverityBadge renders correct label | `[x]` | `[ ]` | P1 | Vitest |
| 28.45 | Frontend: StatusPill renders all statuses | `[x]` | `[ ]` | P1 | Vitest |
| 28.46 | Frontend: detectionStore setFilter resets page | `[x]` | `[ ]` | P1 | Vitest |

---

## 29. Theme System

| # | Feature | Impl | Test | Priority | Notes |
|---|---------|:----:|:----:|----------|-------|
| 29.1 | CSS custom properties theming (light/dark/matrix) | `[x]` | `[ ]` | P1 | `index.css` `[data-theme]` selectors |
| 29.2 | Theme switcher in Sidebar | `[x]` | `[ ]` | P1 | Three-way popup |
| 29.3 | Theme persistence (Zustand persist) | `[x]` | `[ ]` | P1 | localStorage `mxtac-ui` |
| 29.4 | Flash prevention on page load | `[x]` | `[ ]` | P1 | `main.tsx` pre-render |
| 29.5 | `themeVars.ts` for Recharts JS colors | `[x]` | `[ ]` | P1 | `cssVar()` + `chartColors()` |
| 29.6 | Tailwind CSS variable integration | `[x]` | `[ ]` | P1 | All colors via `var()` |

---

## 30. Security & Project Hygiene

| # | Feature | Impl | Test | Priority | Notes |
|---|---------|:----:|:----:|----------|-------|
| 30.1 | `.gitignore` for agent-scheduler | `[ ]` | n/a | P0 | TASK-0.5.1 |
| 30.2 | Remove exposed `.env` credentials | `[ ]` | n/a | P0 | TASK-0.5.1 |
| 30.3 | Production `secret_key` validation | `[ ]` | `[ ]` | P0 | TASK-0.5.1 |
| 30.4 | `CHANGELOG.md` | `[ ]` | n/a | P1 | TASK-0.5.2 |
| 30.5 | `SECURITY.md` | `[ ]` | n/a | P1 | TASK-0.5.2 |
| 30.6 | `LICENSE` | `[ ]` | n/a | P1 | TASK-0.5.2 |
| 30.7 | `.editorconfig` + `.prettierrc` | `[ ]` | n/a | P1 | TASK-0.5.2 |
| 30.8 | `ENV-REFERENCE.md` | `[ ]` | n/a | P1 | TASK-0.5.2 |
| 30.9 | `VERSION` single source of truth | `[ ]` | n/a | P1 | TASK-0.5.3 |
| 30.10 | Dependency spec sync | `[ ]` | n/a | P1 | TASK-0.5.3 |
| 30.11 | Agent-scheduler documentation | `[ ]` | n/a | P1 | TASK-0.5.4 |
| 30.12 | Docker consistency | `[ ]` | n/a | P1 | TASK-0.5.5 |

---

## 31. Agent Management

| # | Feature | Impl | Test | Priority | Notes |
|---|---------|:----:|:----:|----------|-------|
| 31.1 | `POST /events/ingest` endpoint | `[ ]` | `[ ]` | P0 | TASK-2.5 |
| 31.2 | API key auth for agents | `[ ]` | `[ ]` | P0 | TASK-2.5 |
| 31.3 | Agent registration API | `[ ]` | `[ ]` | P1 | TASK-4.5 |
| 31.4 | Agent heartbeat API | `[ ]` | `[ ]` | P1 | TASK-4.5 |
| 31.5 | Agent auto-degradation | `[ ]` | `[ ]` | P1 | TASK-4.5 |

---

## Progress Summary

> Auto-update this table after each implementation sprint.

| Section | Total | `[x]` Done | `[~]` Partial | `[ ]` Todo | Tests `[T]` |
|---------|------:|:----------:|:-------------:|:----------:|:-----------:|
| 1. Auth | 12 | 2 | 1 | 9 | 0 |
| 2. Password policy | 5 | 1 | 0 | 4 | 0 |
| 3. RBAC | 9 | 1 | 0 | 8 | 0 |
| 4. User management API | 8 | 0 | 5 | 3 | 0 |
| 5. Event pipeline | 9 | 6 | 0 | 3 | 0 |
| 6. Connectors | 24 | 0 | 3 | 21 | 0 |
| 7. OCSF normalizers | 15 | 2 | 4 | 9 | 1 |
| 8. Sigma engine | 23 | 2 | 0 | 21 | 0 |
| 9. Alert manager | 12 | 4 | 1 | 7 | 0 |
| 10. Detections API | 11 | 10 | 0 | 1 | 0 |
| 11. Event search | 8 | 0 | 4 | 4 | 0 |
| 12. OpenSearch | 11 | 5 | 1 | 5 | 0 |
| 13. Rules API | 10 | 0 | 8 | 2 | 0 |
| 14. Connectors API | 9 | 0 | 7 | 2 | 0 |
| 15. Overview API | 8 | 0 | 7 | 1 | 0 |
| 16. ATT&CK coverage | 8 | 1 | 0 | 7 | 0 |
| 17. WebSocket | 11 | 3 | 1 | 7 | 0 |
| 18. DB persistence | 10 | 5 | 0 | 5 | 0 |
| 19. Horizontal scaling | 12 | 3 | 1 | 8 | 0 |
| 20. Headless operation | 9 | 0 | 1 | 8 | 0 |
| 21. Observability | 14 | 3 | 2 | 9 | 0 |
| 22. Frontend layout | 10 | 8 | 0 | 2 | 0 |
| 23. Frontend pages | 13 | 6 | 1 | 6 | 0 |
| 24. MxGuard (EDR) | 13 | 0 | 0 | 13 | 0 |
| 25. MxWatch (NDR) | 17 | 0 | 0 | 17 | 0 |
| 26. Performance NFR | 8 | 0 | 0 | 8 | 0 |
| 27. Reliability NFR | 6 | 0 | 0 | 6 | 0 |
| 28. Tests | 46 | 6 | 0 | 40 | 3 |
| 29. Theme system | 6 | 6 | 0 | 0 | 0 |
| 30. Security & hygiene | 12 | 0 | 0 | 12 | 0 |
| 31. Agent management | 5 | 0 | 0 | 5 | 0 |
| **TOTAL** | **372** | **63 (17%)** | **56 (15%)** | **253 (68%)** | **3 (1%)** |

---

*Document version: 1.1 — 2026-02-20*
*Previous: 1.0 — 2026-02-19*
*Changes in 1.1: Marked 7 items done/partial (5.6, 18.9, 18.10, 19.1, 19.6, 21.2, 21.3); added sections 29 (Theme System, 6 features), 30 (Security & Hygiene, 12 features), 31 (Agent Management, 5 features); 372 total features (was 349)*
*Update this file as each feature is implemented and tested.*
