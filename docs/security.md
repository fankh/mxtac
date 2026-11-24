# Security model

This document describes the security controls implemented in the backend. Each item names the file that implements it, relative to `app/backend/app/`. To report a vulnerability, see [SECURITY.md](../SECURITY.md).

## First account

There is no built-in password. When the `users` table is empty, the backend creates one account, `admin@mxtac.local` (`db/seed.py`).

| Item | Behaviour |
|------|-----------|
| Password | The value of `INITIAL_ADMIN_PASSWORD`, or a random 24-character password when the setting is empty |
| Where a generated password appears | Once, in the startup log, in a `WARNING` line that starts with `INITIAL ADMIN PASSWORD (generated, shown only once)`. A password from `INITIAL_ADMIN_PASSWORD` is never logged |
| Policy | `INITIAL_ADMIN_PASSWORD` must meet the password policy. The backend does not start with a weaker value |
| First sign-in | The account is created with a forced password change. A login with the first password returns only a password-change token, not a session |
| Lost first password | Cannot be recovered or reset. The account is only created again when the `users` table is empty |
| Demo accounts | Only with `SEED_DEMO_DATA=true`: `analyst@mxtac.local`, `hunter@mxtac.local` and `engineer@mxtac.local`, with the same first password and the same forced change |

Treat the startup log of the first start as a secret until the first sign-in is done. After the password change the logged value no longer works.

## Authentication

| Item | Behaviour | Code |
|------|-----------|------|
| Login | `POST /api/v1/auth/login` with email and password returns an access token and a refresh token, together with the `email` and `role` of the account. An account that must change its password, or has MFA, gets a one-time token for that step instead | `api/v1/endpoints/auth.py` |
| Token format | JWT signed with HS256 and `SECRET_KEY` | `core/security.py` |
| Access token lifetime | `ACCESS_TOKEN_EXPIRE_MINUTES`, default 60 | `core/config.py` |
| Refresh token lifetime | `REFRESH_TOKEN_EXPIRE_DAYS`, default 7 | `core/config.py` |
| Role and active flag | Read from the database on every request, not from the token. A role change or a deactivation applies to the next request. Refresh tokens, MFA tokens and password-change tokens are not accepted as access tokens | `core/security.py` |
| Logout | The token ID is stored in Valkey until the token expires, and the token is rejected from then on | `core/valkey.py` |
| Invalidate all tokens | Increase `JWT_KEY_VERSION` and restart. Tokens carry the version they were issued with | `core/security.py` |
| Password hashing | bcrypt, cost factor 10 | `core/security.py` |
| Account lockout | 5 failed logins for one email lock that email for 30 minutes. Wrong current passwords in the password-change form count as well | `core/valkey.py` |
| Inactive accounts | An account that has not logged in for `ACCOUNT_INACTIVITY_DAYS` (default 90) is deactivated at the next login attempt. `0` disables the check | `api/v1/endpoints/auth.py` |
| Startup check | The backend refuses to start when `DEBUG=false` and `SECRET_KEY` is the development default | `core/config.py` |
| Alert WebSocket | `/api/v1/ws/alerts?token=<access token>` is checked like an HTTP request and needs the `detections:read` permission. Otherwise the server refuses the connection with close code 1008 before accepting it | `api/v1/endpoints/websocket.py` |

Lockout, token revocation and the MFA attempt counter depend on Valkey. When Valkey is not reachable these checks are skipped and the request is allowed.

The frontend stores the access token in the browser's `localStorage`. It sends the token to the WebSocket in the URL, because browsers cannot set a header there. The Nginx configurations in this repository do not log that request.

## Passwords

### Policy

Applied when a user is created and when a password is changed (`core/validators.py`, `api/v1/endpoints/users.py`, `api/v1/endpoints/auth.py`). The first account goes through the same policy.

| Rule | Value |
|------|-------|
| Length | 8 to 128 characters |
| Complexity | At least three of: upper case, lower case, digit, symbol |
| Repetition | No more than 3 identical characters in a row |
| History | A new password must differ from the current and the previous one |
| Expiry | After `PASSWORD_EXPIRY_DAYS` (default 90) the next login requires a new password. `0` disables expiry. The clock starts at the first password change |

### Ways to set a password

| Case | Route | Notes |
|------|-------|-------|
| An administrator creates a user | `POST /api/v1/users` | The administrator sets a temporary password. The account always starts with a forced password change, so the temporary password only works to obtain a password-change token |
| Forced change at sign-in (new account, first account, expired password) | `POST /api/v1/auth/change-password` | Needs the password-change token from the login response. Returns a session, or an MFA token when the account has MFA |
| A signed-in user changes the own password | `POST /api/v1/auth/password` | Needs the current password. In the UI under **Settings**, **Profile and security** |

There is no route that sets a new password for another existing user, and no "forgot password" function.

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

Deleting a user through the API deactivates the account. The row is kept, and the email address cannot be used for a new account.

## HTTP protections

| Control | Behaviour | Code |
|---------|-----------|------|
| Security headers | Every response carries `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection: 0`, `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy: camera=(), microphone=(), geolocation=()` and `Cache-Control: no-store`. `Strict-Transport-Security` is added when `DEBUG=false` | `core/security_headers.py` |
| Rate limiting | Per client IP and minute: 10 for login and MFA routes, 5 for export routes, 60 for other write requests, and `RATE_LIMIT_PER_MINUTE` (default 300) for read requests. The `POST` routes that only query events (`/events/search`, `/events/aggregate`, `/events/query-dsl`) count as read requests. Counters are kept in Valkey, or in process memory when Valkey is not reachable | `core/rate_limit.py` |
| Request size | Bodies over 10 MB are rejected. The webhook endpoint accepts at most 5 MB | `main.py`, `api/v1/endpoints/webhook_ingest.py` |
| CORS | Only origins in `CORS_ORIGINS` are allowed | `main.py` |
| SQL | All queries use SQLAlchemy with bound parameters. User input in `LIKE` filters is escaped with `escape_like()` | `core/validators.py` |
| Event filters | Filter fields in event search are checked against an allow-list | `api/v1/endpoints/events.py` |
| Webhook ingest | Requires the name of a `generic` connector and its token, compared in constant time. 100 requests per minute per source | `api/v1/endpoints/webhook_ingest.py` |
| Access log | One structured log record per request, without `/health`, `/ready` and `/metrics` | `core/access_log.py` |
| Audit log | Creating and updating incidents is written to the `mxtac-audit-*` index in OpenSearch. Other endpoints do not write audit records | `services/audit.py`, `api/v1/endpoints/incidents.py` |
| OpenSearch credentials | `OPENSEARCH_USERNAME` and `OPENSEARCH_PASSWORD` are sent as HTTP basic authentication when the user name is set. With `OPENSEARCH_USE_SSL=true` the connection uses HTTPS without certificate verification | `core/config.py`, `services/opensearch_client.py` |

The rate limiter takes the client IP from the first entry of the `X-Forwarded-For` header when it is present. Run the backend behind a reverse proxy that sets this header to the client address, and do not expose the backend port directly. `app/nginx/nginx.conf`, `app/frontend/nginx.conf` and the configuration generated by `app/setup.sh` overwrite the header with the address of the connecting client.

## Current limitations

Each item was checked against the code.

| Limitation | What to do |
|------------|------------|
| A lost first password cannot be reset. The generated one is shown once in the startup log | Read it right after the first start, or set `INITIAL_ADMIN_PASSWORD`. Before the first sign-in, start again with an empty database |
| No password reset for existing users. An administrator cannot set a new password for another account, and a deactivated account keeps its email address | Create a new account under another email address, and deactivate the old one |
| Changing a password does not end other sessions. Access and refresh tokens issued before the change stay valid until they expire | Sign out on the other devices. To end every session of every user, increase `JWT_KEY_VERSION` and restart |
| A refresh token cannot be revoked on its own. Logout revokes the access token that is presented | Keep `REFRESH_TOKEN_EXPIRE_DAYS` short where this matters. Deactivating the account blocks its refresh tokens at once |
| The access token is kept in `localStorage` and passed to the WebSocket in the URL | Serve the UI over HTTPS only, and keep WebSocket URLs out of proxy logs |
| `/metrics`, `/docs`, `/redoc` and `/openapi.json` need no login | Do not publish the backend port. The Nginx configurations in this repository do not proxy these paths, except the Swarm configuration, which proxies `/docs` and `/openapi.json` |
| Lockout, token revocation and MFA attempt limits are skipped while Valkey is not reachable | Monitor `/ready`, which reports Valkey |
| The development Compose file uses a fixed `SECRET_KEY`, a fixed database password, and OpenSearch without authentication | Use it for local evaluation only |
| The Compose files and `app/setup.sh` run OpenSearch with the security plugin disabled. The production Compose file does not publish its port, `app/setup.sh` binds it to `127.0.0.1`, and the development file publishes it | Keep the OpenSearch port unreachable from other hosts, or connect a secured cluster with `OPENSEARCH_USERNAME`, `OPENSEARCH_PASSWORD` and `OPENSEARCH_USE_SSL` |
| TLS certificates of OpenSearch are not verified | Keep the connection on a trusted network |
| Connector settings, including the Wazuh password and webhook tokens, are stored unencrypted in the `connectors` table | Restrict access to the database and its backups |
| Only incident changes are written to the audit log | Use the access log for other actions |
