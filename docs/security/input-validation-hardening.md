# Input Validation & SQL Injection Prevention — Audit Report

Feature: **MXTAC-33.3** | Priority: P1 | Status: Complete

---

## Summary

This document records the findings and fixes applied during the input validation hardening
audit of the MxTac API (FastAPI / SQLAlchemy backend).  All endpoints were reviewed for
injection vectors, missing field constraints, and insufficient sanitization.

---

## 1. SQL Injection — Status: SAFE

All database queries use SQLAlchemy ORM parameterized statements.  No raw string
interpolation into SQL was found.

### LIKE wildcard escaping (search/filter fields)

User-supplied strings passed to `LIKE`-based filters are escaped through `escape_like()`
in `app/core/validators.py` before being appended to the pattern:

| Endpoint | Field | Repo method | Escape applied |
|---|---|---|---|
| `GET /detections` | `search`, `tactic`, `host` | `DetectionRepo.list` | ✓ `escape_like()` |
| `POST /events/search` | `query` (full-text) | `EventRepo.search` | ✓ `escape_like()` |
| `POST /events/search` | `contains` operator filters | `EventRepo._apply_event_filter` | ✓ `escape_like()` |
| `GET /assets` | `search` | `AssetRepo.list` | ✓ (delegated to repo) |

### EventFilter field/operator whitelist

`EventFilter.field` is validated against `_ALLOWED_FILTER_FIELDS` (a `frozenset`) before
reaching the repository layer, preventing arbitrary field injection:

```python
_ALLOWED_FILTER_FIELDS = frozenset({
    "severity_id", "class_name", "class_uid",
    "src_ip", "dst_ip", "hostname", "username", "process_hash", "source",
    ...
})
```

---

## 2. OpenSearch Query Safety — Status: SAFE

User-supplied `query` strings in `POST /events/search` are passed to OpenSearch via
`simple_query_string` DSL (not `query_string`), which is sandboxed and does not allow
arbitrary DSL injection.  Structured filter clauses are built through `filter_to_dsl()`
which maps validated `EventFilter` objects to typed DSL clauses.

---

## 3. Pydantic Field Validators — Fixes Applied

### 3.1 Email format validation

| Schema | Field | Validator |
|---|---|---|
| `LoginRequest` | `email` | regex `^[^@\s]+@[^@\s]+\.[^@\s]+$` |
| `UserCreate` | `email` | regex (same pattern) |
| `IncidentCreate` / `IncidentUpdate` | `assigned_to` | regex (allows None) |
| `MfaVerifyRequest` / `MfaVerifyLoginRequest` | `code` / `mfa_token` | `pattern`, `max_length` |

### 3.2 IP address and CIDR validation

| Schema | Field | Validator |
|---|---|---|
| `AssetCreate` / `AssetUpdate` | `ip_addresses` | `validate_ip_address()` per element |
| `IOCCreate` | `value` (ioc_type=ip) | `validate_ip_address()` |
| `IOCCreate` | `value` (ioc_type=domain) | `validate_hostname()` |
| Validators module | standalone | `validate_cidr()` — available for future use |

### 3.3 Hostname format validation (NEW — MXTAC-33.3)

`AssetCreate.hostname` now calls `validate_hostname()` via `@field_validator`, enforcing
RFC 952/1123 rules:

- Maximum 253 characters total
- Labels separated by `.` are alphanumeric; may contain hyphens but not as first/last char
- Rejects strings like `-invalid-hostname` or labels exceeding 63 chars

**Before:** `hostname: str = Field(..., max_length=255)` (length-only check)
**After:** Added `validate_hostname_format` `@field_validator` on `AssetCreate.hostname`

### 3.4 Detection schema length constraints (NEW — MXTAC-33.3)

`DetectionUpdate` and `BulkStatusUpdate` were missing upper-bound constraints:

| Schema | Field | Before | After |
|---|---|---|---|
| `DetectionUpdate` | `assigned_to` | `str \| None` | `max_length=255` |
| `DetectionUpdate` | `priority` | `str \| None` | `max_length=20` (matches DB column `String(20)`) |
| `BulkStatusUpdate` | `ids` | `min_length=1` only | `min_length=1, max_length=500` |

### 3.5 Hash type validation

`IOCCreate.value` is validated against type-specific patterns:

| `ioc_type` | Constraint |
|---|---|
| `hash_md5` | Exactly 32 hex chars |
| `hash_sha256` | Exactly 64 hex chars |
| `url` | Must start with `http://` or `https://` |
| `email` | Same regex as LoginRequest |

### 3.6 Incident / Note length constraints

| Schema | Field | Constraint |
|---|---|---|
| `IncidentCreate` | `title` | `min_length=1, max_length=500` |
| `IncidentCreate` | `description` | `max_length=10000` |
| `IncidentCreate` | `assigned_to` | `max_length=254` + email format |
| `IncidentCreate` | `detection_ids` | `max_length=500` items |
| `NoteCreate` | `content` | `min_length=1, max_length=5000` |

---

## 4. Request Size Limits

### 4.1 Global body size (NEW — MXTAC-33.3)

`ContentSizeLimitMiddleware` in `app/main.py` rejects requests whose `Content-Length`
header exceeds 10 MB with HTTP 413:

```python
_MAX_BODY_SIZE = 10 * 1024 * 1024  # 10 MB
```

### 4.2 Bulk import limits

| Endpoint | Limit | Enforcement |
|---|---|---|
| `POST /events/ingest` | 1,000 events per request | `IngestRequest.events: max_length=1000` |
| `POST /assets/bulk` | 1,000 assets per request | Runtime check + HTTP 422 |
| `POST /rules/import` | 10 MB YAML | `RuleImportRequest.yaml_content: max_length=10_000_000` |
| `POST /detections/bulk` | 500 IDs per request | `BulkStatusUpdate.ids: max_length=500` |

---

## 5. Endpoint Path Parameter Validation

### 5.1 Entity timeline — entity_type whitelist (NEW — MXTAC-33.3)

`GET /events/entity/{entity_type}/{entity_value}` previously accepted any string for
`entity_type`, which silently fell back to `Event.hostname` for unknown types.

**Fix:** Explicit whitelist check against `_ALLOWED_ENTITY_TYPES`:

```python
_ALLOWED_ENTITY_TYPES = frozenset({"ip", "host", "user", "hash"})

if entity_type not in _ALLOWED_ENTITY_TYPES:
    raise HTTPException(
        status_code=422,
        detail=f"Invalid entity_type {entity_type!r}. Allowed: {sorted(_ALLOWED_ENTITY_TYPES)}",
    )
```

Additionally, `entity_value` and `time_from` now carry `max_length` constraints via
`Path(max_length=512)` and `Query(max_length=50)`.

### 5.2 Rule YAML validation

`POST /rules`, `POST /rules/import`, and `POST /rules/test` all parse YAML with
`yaml.safe_load` / `yaml.safe_load_all` (no arbitrary Python object deserialisation).
Validation phases ensure the parsed document:

1. Is a valid YAML mapping
2. Contains required Sigma fields (`title`, `detection`)
3. Has a `condition` key in the `detection` block
4. Compiles successfully through the SigmaEngine

---

## 6. Findings Not Requiring Code Changes

| Area | Status | Rationale |
|---|---|---|
| Connector `config` dict values | No change | Config is admin-only; values flow to DB as JSON blob, never interpolated into SQL |
| `GET /detections/{detection_id}` path | Safe | `Detection.id` is indexed by UUID; SQLAlchemy parameterizes the WHERE clause |
| Auth password hashing | Safe | bcrypt via `passlib`; passwords are never stored in plaintext |
| JWT validation | Safe | `python-jose` with HS256; token expiry enforced |

---

## 7. Test Coverage

All validations are covered in `tests/api/v1/test_input_validation.py`:

- Core helpers: `escape_like`, `validate_ip_address`, `validate_cidr`, `validate_hostname`
- Schema validators: `LoginRequest`, `MfaVerifyRequest`, `AssetCreate/Update`,
  `IncidentCreate/Update`, `IOCCreate`, `DetectionUpdate`, `BulkStatusUpdate`
- Endpoint validators: `EventFilter` whitelist, `SearchRequest` limits,
  `AggregationRequest` types, `RuleCreate` sizes, `ConnectorCreate` name length,
  `UserCreate` email + password
- HTTP integration: body size limit (413), invalid field/operator (422), search query too
  long (422), invalid entity_type (422), invalid hostname (422)
