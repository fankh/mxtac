# Security model

This document describes the security controls implemented in the backend. Each item names the file that implements it, relative to `app/backend/app/`. To report a vulnerability, see [SECURITY.md](../SECURITY.md).

## Authentication

| Item | Behaviour | Code |
|------|-----------|------|
| Login | `POST /api/v1/auth/login` with email and password returns an access token and a refresh token | `api/v1/endpoints/auth.py` |
| Token format | JWT signed with HS256 and `SECRET_KEY` | `core/security.py` |
| Access token lifetime | `ACCESS_TOKEN_EXPIRE_MINUTES`, default 60 | `core/config.py` |
| Refresh token lifetime | `REFRESH_TOKEN_EXPIRE_DAYS`, default 7 | `core/config.py` |
| Logout | The token ID is stored in Valkey until the token expires, and the token is rejected from then on | `core/valkey.py` |
| Invalidate all tokens | Increase `JWT_KEY_VERSION` and restart. Tokens carry the version they were issued with | `core/security.py` |
| Password hashing | bcrypt, cost factor 10 | `core/security.py` |
| Account lockout | 5 failed logins for one email lock that email for 30 minutes | `core/valkey.py` |
| Inactive accounts | An account that has not logged in for `ACCOUNT_INACTIVITY_DAYS` (default 90) is deactivated at the next login attempt. `0` disables the check | `api/v1/endpoints/auth.py` |
| Startup check | The backend refuses to start when `DEBUG=false` and `SECRET_KEY` is the development default | `core/config.py` |

The role is read from the access token. After an administrator changes a role or deactivates an account, tokens that were already issued keep working until they expire.

Lockout, token revocation and the MFA attempt counter depend on Valkey. When Valkey is not reachable these checks are skipped and the request is allowed.

The frontend stores the access token in the browser's `localStorage`.

## Multi-factor authentication

MFA is optional and set up per user under **Settings**.

| Item | Behaviour |
|------|-----------|
| Method | TOTP (RFC 6238), verified with a tolerance of one time step in each direction |
| Setup | `POST /api/v1/auth/mfa/setup` returns the secret, a provisioning URI for a QR code and 8 backup codes. `POST /api/v1/auth/mfa/verify-setup` activates MFA after one valid code |
| Login | When MFA is active, the login response contains an MFA token that is valid for 5 minutes instead of an access token. `POST /api/v1/auth/mfa/verify` exchanges it together with a TOTP code or a backup code |
| Attempts | At most 5 attempts per MFA token |
| Backup codes | 8 characters each, single use, stored as HMAC-SHA256 hashes |
| Secret storage | Encrypted with a key derived from `SECRET_KEY`. Changing `SECRET_KEY` makes stored MFA secrets unreadable; affected users need an MFA reset |
| Reset | An administrator disables MFA for a user with `POST /api/v1/auth/mfa/disable` or in **Settings**, **Users** |

## Roles and permissions

There are five roles. A user has exactly one. The matrix is defined in `core/rbac.py`.

| Permission | viewer | analyst | hunter | engineer | admin |
|------------|:------:|:-------:|:------:|:--------:|:-----:|
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

In terms of pages:

| Role | Can use |
|------|---------|
| viewer | Overview, Detections, Incidents and ATT&CK Coverage, read-only |
| analyst | The same, and can update detections and incidents and set the coverage target |
| hunter | The same, and Hunt, saved queries, and read access to Sigma Rules |
| engineer | The same, and can edit Sigma Rules and manage Sources |
| admin | Everything, including user management and deleting detections and incidents |

[api.md](api.md) lists the permission each route requires.

## Password policy

Applied when a user is created and when a password is changed (`core/validators.py`, `api/v1/endpoints/users.py`, `api/v1/endpoints/auth.py`).

| Rule | Value |
|------|-------|
| Length | 8 to 128 characters |
| Complexity | At least three of: upper case, lower case, digit, symbol |
| Repetition | No more than 3 identical characters in a row |
| History | A new password must differ from the current and the previous one |
| First login | Accounts created with `must_change_password` (the default for `POST /api/v1/users`) must set a new password at first login through `POST /api/v1/auth/change-password` |
| Expiry | After `PASSWORD_EXPIRY_DAYS` (default 90) the next login requires a new password. `0` disables expiry. The clock starts at the first password change |

The four accounts created on an empty database are written directly to the database and do not go through this policy. See [Current limitations](#current-limitations).

## HTTP protections

| Control | Behaviour | Code |
|---------|-----------|------|
| Security headers | Every response carries `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection: 0`, `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy: camera=(), microphone=(), geolocation=()` and `Cache-Control: no-store`. `Strict-Transport-Security` is added when `DEBUG=false` | `core/security_headers.py` |
| Rate limiting | Per client IP and minute: 10 for login and MFA routes, 5 for export routes, 60 for other write requests, 300 for read requests. Counters are kept in Valkey, or in process memory when Valkey is not reachable | `core/rate_limit.py` |
| Request size | Bodies over 10 MB are rejected. The webhook endpoint accepts at most 5 MB | `main.py`, `api/v1/endpoints/webhook_ingest.py` |
| CORS | Only origins in `CORS_ORIGINS` are allowed | `main.py` |
| SQL | All queries use SQLAlchemy with bound parameters. User input in `LIKE` filters is escaped with `escape_like()` | `core/validators.py` |
| Event filters | Filter fields in event search are checked against an allow-list | `api/v1/endpoints/events.py` |
| Webhook ingest | Requires the name of a `generic` connector and its token, compared in constant time. 100 requests per minute per source | `api/v1/endpoints/webhook_ingest.py` |
| Access log | One structured log record per request, without `/health`, `/ready` and `/metrics` | `core/access_log.py` |
| Audit log | Creating and updating incidents is written to the `mxtac-audit-*` index in OpenSearch. Other endpoints do not write audit records | `services/audit.py`, `api/v1/endpoints/incidents.py` |

The rate limiter takes the client IP from the `X-Forwarded-For` header when it is present. Run the backend behind a reverse proxy that sets this header, and do not expose the backend port directly.

## Current limitations

| Limitation | What to do |
|------------|------------|
| A new database gets four accounts with the published password `mxtac2026` and no forced change | Create your own admin account and deactivate the default accounts before exposing the instance. Steps are in the [README](../README.md#first-login) |
| No endpoint changes the password of an existing account, except the forced change at first login or after expiry | Create a new account when a password must be replaced |
| The WebSocket `/api/v1/ws/alerts` accepts connections without validating a token | Do not expose the API to untrusted networks |
| `/metrics`, `/docs`, `/redoc` and `/openapi.json` are public | Block them at the reverse proxy if needed |
| The development Compose file uses a fixed `SECRET_KEY`, a fixed database password, and OpenSearch without authentication | Use it for local evaluation only |
| The backend connects to OpenSearch without credentials. `OPENSEARCH_USERNAME` and `OPENSEARCH_PASSWORD` are not sent | Keep OpenSearch on a private network |
| Connector settings, including the Wazuh password and webhook tokens, are stored unencrypted in the `connectors` table | Restrict access to the database and its backups |
