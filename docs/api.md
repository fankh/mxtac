# API reference

This file is generated from the FastAPI application (`app.main:app`) by `scripts/gen_api_docs.py`. Do not edit it by hand. It lists every route the backend registers. For request and response schemas, start the backend and open `/docs` (Swagger UI) or `/openapi.json`.

## Conventions

- All REST routes except the operations routes are under `/api/v1`.
- Send the access token as `Authorization: Bearer <token>`. `POST /api/v1/auth/login` returns it, together with the `email` and `role` of the account. When the account must set a new password first, or has MFA, the login answer carries a one-time token for `POST /api/v1/auth/change-password` or `POST /api/v1/auth/mfa/verify` instead.
- The role and the active flag of the account are read from the database on every request. A role change or a deactivation applies to the next request, also for tokens that were issued earlier.
- The **Auth** column shows the permission a route requires. The permission table below maps permissions to roles.
- A request without a valid token gets `401`. A role without the permission gets `403`.
- Rate limits apply per client IP and minute: 10 requests for login and MFA routes, 5 for export routes, 60 for other `POST`, `PUT`, `PATCH` and `DELETE` requests, and `RATE_LIMIT_PER_MINUTE` (default 300) for `GET` and `HEAD` requests. A limited request gets `429` with a `Retry-After` header. `/health`, `/ready` and `/metrics` are not limited.

## Permissions

Source: `app/backend/app/core/rbac.py`.

| Permission | viewer | analyst | hunter | engineer | admin |
|---|:-:|:-:|:-:|:-:|:-:|
| `detections:read` | yes | yes | yes | yes | yes |
| `detections:write` | - | yes | yes | yes | yes |
| `detections:delete` | - | - | - | - | yes |
| `incidents:read` | yes | yes | yes | yes | yes |
| `incidents:write` | - | yes | yes | yes | yes |
| `incidents:delete` | - | - | - | - | yes |
| `rules:read` | - | - | yes | yes | yes |
| `rules:write` | - | - | - | yes | yes |
| `connectors:read` | - | - | - | yes | yes |
| `connectors:write` | - | - | - | yes | yes |
| `users:read` | - | - | - | - | yes |
| `users:write` | - | - | - | - | yes |
| `events:search` | - | - | yes | yes | yes |
| `hunt_queries:read` | - | - | yes | yes | yes |
| `hunt_queries:write` | - | - | yes | yes | yes |

## Routes

### Operations

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/metrics` | Public | Endpoint that serves Prometheus metrics |
| GET | `/health` | Public | Health |
| GET | `/ready` | Public | Readiness probe - checks DB, Valkey, and OpenSearch |

### Authentication

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/api/v1/auth/login` | Public. Email and password in the body. Answers with a session (`access_token`, `refresh_token`, `email`, `role`), or with `mfa_required` and an MFA token, or with `password_change_required` and a password-change token | Login |
| POST | `/api/v1/auth/mfa/verify` | MFA token from the login response | Verify TOTP code (or backup code) after password authentication |
| POST | `/api/v1/auth/refresh` | Refresh token in the body | Refresh |
| POST | `/api/v1/auth/logout` | Bearer access token | Logout |
| POST | `/api/v1/auth/mfa/setup` | Any signed-in user | Generate a TOTP secret and QR code URI for the authenticated user |
| POST | `/api/v1/auth/mfa/verify-setup` | Any signed-in user | Verify a TOTP code and activate MFA for the authenticated user |
| GET | `/api/v1/auth/me` | Any signed-in user | Return the authenticated user's profile including MFA status |
| POST | `/api/v1/auth/mfa/disable` | `users:write` | Disable MFA for a given user (admin only) |
| POST | `/api/v1/auth/change-password` | Password-change token from the login response | Complete a forced first-login password change |
| POST | `/api/v1/auth/password` | Any signed-in user. Current and new password in the body | Change the password of the signed-in user |

### Overview

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/v1/overview/kpis` | `detections:read` | KPI metrics for the Security Overview dashboard header cards |
| GET | `/api/v1/overview/timeline` | `detections:read` | Detection counts per day broken down by severity |
| GET | `/api/v1/overview/tactics` | `detections:read` | Top ATT&CK tactic breakdown with counts and trend percentage (empty when no detections) |
| GET | `/api/v1/overview/coverage/heatmap` | `detections:read` | ATT&CK technique coverage heatmap - 4 rows x 9 tactic columns |
| GET | `/api/v1/overview/coverage/tactic-labels` | `detections:read` | Ordered tactic abbreviation labels for heatmap columns |
| GET | `/api/v1/overview/integrations` | `detections:read` | Integration status for all configured connectors (empty when none are registered) |
| GET | `/api/v1/overview/recent-detections` | `detections:read` | Recent critical/high detections for the overview table (empty when none exist) |

### Coverage

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/v1/coverage` | `detections:read` | Overall ATT&CK coverage percentage and technique count |
| GET | `/api/v1/coverage/gaps` | `detections:read` | ATT&CK techniques not covered by any enabled Sigma rule |
| GET | `/api/v1/coverage/navigator` | `detections:read` | Export ATT&CK Navigator-compatible layer JSON |
| GET | `/api/v1/coverage/by-datasource` | `detections:read` | ATT&CK coverage breakdown by data source connector |
| GET | `/api/v1/coverage/trend` | `detections:read` | ATT&CK coverage trend - daily snapshots over the last N days |
| GET | `/api/v1/coverage/target` | `detections:read` | Return the configured coverage target and current alert status |
| PUT | `/api/v1/coverage/target` | `detections:write` | Create or update the coverage target threshold |

### Detections

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/v1/detections` | `detections:read` | List detections |
| GET | `/api/v1/detections/export` | `detections:read` | Export filtered detections as CSV (max 10,000 rows) |
| GET | `/api/v1/detections/{detection_id}` | `detections:read` | Get detection |
| PATCH | `/api/v1/detections/{detection_id}` | `detections:write` | Update detection |
| POST | `/api/v1/detections/bulk` | `detections:write` | Bulk update detections |
| DELETE | `/api/v1/detections/{detection_id}` | `detections:delete` | Delete detection |

### Incidents

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/v1/incidents` | `incidents:read` | List incidents with pagination and optional filters |
| POST | `/api/v1/incidents` | `incidents:write` | Create a new incident, optionally linking existing detections |
| GET | `/api/v1/incidents/metrics` | `incidents:read` | Incident SLA metrics - MTTD, MTTR, open count, and severity breakdown |
| GET | `/api/v1/incidents/{incident_id}` | `incidents:read` | Get full incident detail including linked detections and timeline |
| PATCH | `/api/v1/incidents/{incident_id}` | `incidents:write` | Partially update an incident |
| POST | `/api/v1/incidents/{incident_id}/notes` | `incidents:write` | Add a timestamped note to an incident's timeline |
| DELETE | `/api/v1/incidents/{incident_id}` | `incidents:delete` | Soft-delete an incident by setting its status to 'closed' |
| GET | `/api/v1/incidents/{incident_id}/notes` | `incidents:read` | List all notes for an incident in chronological order (oldest first) |

### Sigma rules

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/v1/rules` | `rules:read` | List all Sigma rules. Supports filtering by enabled/level |
| GET | `/api/v1/rules/stats/summary` | `rules:read` | Rules summary |
| POST | `/api/v1/rules/test` | `rules:read` | Validate Sigma YAML structure and test it against a sample event (no save) |
| POST | `/api/v1/rules/import` | `rules:write` | Bulk import Sigma rules from YAML (single or multi-document) |
| POST | `/api/v1/rules/reload` | `rules:write` | Hot-reload all Sigma rules from DB into the in-process engine |
| GET | `/api/v1/rules/{rule_id}` | `rules:read` | Fetch a single Sigma rule by ID, including raw YAML content and metadata |
| POST | `/api/v1/rules` | `rules:write` | Create a custom Sigma rule from raw YAML |
| PATCH | `/api/v1/rules/{rule_id}` | `rules:write` | Update rule |
| DELETE | `/api/v1/rules/{rule_id}` | `rules:write` | Delete rule |
| POST | `/api/v1/rules/{rule_id}/mark_fp` | `detections:write` | Mark a rule match as a false positive - atomically increments fp_count |
| POST | `/api/v1/rules/{rule_id}/test` | `rules:read` | Test an existing stored rule against a sample event |

### Connectors

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/v1/connectors` | `connectors:read` | List connectors |
| GET | `/api/v1/connectors/{connector_id}` | `connectors:read` | Get connector |
| POST | `/api/v1/connectors` | `connectors:write` | Create connector |
| PATCH | `/api/v1/connectors/{connector_id}` | `connectors:write` | Update connector |
| DELETE | `/api/v1/connectors/{connector_id}` | `connectors:write` | Delete connector |
| POST | `/api/v1/connectors/{connector_id}/test` | `connectors:write` | Test connector |
| GET | `/api/v1/connectors/{connector_id}/health` | `connectors:read` | Connector health |
| POST | `/api/v1/connectors/{connector_id}/start` | `connectors:write` | Start a connector at runtime without restarting the server |
| POST | `/api/v1/connectors/{connector_id}/stop` | `connectors:write` | Stop a running connector at runtime without restarting the server |

### Users

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/v1/users` | `users:read` | List users |
| GET | `/api/v1/users/{user_id}` | `users:read` | Get user |
| POST | `/api/v1/users` | `users:write` | Create user |
| PATCH | `/api/v1/users/{user_id}` | `users:write` | Update user |
| DELETE | `/api/v1/users/{user_id}` | `users:write` | Delete user |

### Events

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/api/v1/events/search` | `events:search` | Full-text + filtered event search with time range |
| POST | `/api/v1/events/aggregate` | `events:search` | Aggregate events by field (terms) or over time (date_histogram) |
| GET | `/api/v1/events/entity/{entity_type}/{entity_value}` | `events:search` | Return all events involving a specific entity (IP, host, user, hash) |
| POST | `/api/v1/events/query-dsl` | `events:search` | Translate a SearchRequest into a Lucene query string |
| POST | `/api/v1/events/export` | `events:search` | Export event search results as CSV (max 10,000 rows) |
| GET | `/api/v1/events/{event_id}` | `events:search` | Retrieve a single event by its UUID primary key |

### Saved hunt queries

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/api/v1/hunt/queries` | `hunt_queries:write` | Save and name the current hunt query for later reuse |
| GET | `/api/v1/hunt/queries` | `hunt_queries:read` | Return all saved queries belonging to the authenticated user |
| GET | `/api/v1/hunt/queries/{query_id}` | `hunt_queries:read` | Fetch a single saved query by ID (must belong to the caller) |
| PUT | `/api/v1/hunt/queries/{query_id}` | `hunt_queries:write` | Update the name, description, or search parameters of a saved query |
| DELETE | `/api/v1/hunt/queries/{query_id}` | `hunt_queries:write` | Delete a saved query (must belong to the caller) |

### Webhook ingest

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/api/v1/ingest/test` | `X-MxTac-Source` and `X-MxTac-Token` headers of a `generic` connector | Connectivity probe for webhook senders |
| POST | `/api/v1/ingest` | `X-MxTac-Source` and `X-MxTac-Token` headers of a `generic` connector | Generic webhook receiver - connector-authenticated JSON ingest |

### WebSocket

| Path | Auth | Description |
|---|---|---|
| `/api/v1/ws/alerts?token=<access token>` | A valid access token of an account with `detections:read`. Otherwise the server refuses the handshake with close code 1008 and never accepts the connection; a browser sees a failed connection (HTTP 403) | Sends `{"type": "connected"}` first, then each new detection as `{"type": "alert", "data": {...}}`, and a `ping` message every 30 seconds |

### Interactive documentation

| Path | Description |
|---|---|
| `/docs` | Swagger UI |
| `/redoc` | ReDoc |
| `/openapi.json` | OpenAPI schema |
