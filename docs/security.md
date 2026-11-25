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
| Login | `POST /api/v1/auth/login` with email and password returns an access token in the body, together with the `email` and `role` of the account, and sets the refresh token as a cookie (see [Sessions](#sessions)). An account that must change its password, or has MFA, gets a one-time token for that step instead | `api/v1/endpoints/auth.py` |
| Token format | JWT signed with HS256 and `SECRET_KEY` | `core/security.py` |
| Access token lifetime | `ACCESS_TOKEN_EXPIRE_MINUTES`, default 60 | `core/config.py` |
| Refresh token lifetime | `REFRESH_TOKEN_EXPIRE_DAYS`, default 7 | `core/config.py` |
| Role and active flag | Read from the database on every request, not from the token. A role change or a deactivation applies to the next request. Refresh tokens, MFA tokens and password-change tokens are not accepted as access tokens | `core/security.py` |
| Logout | `POST /api/v1/auth/logout` ends the session of the presented access token: the ID of the access token and the ID of the session are stored in Valkey until the tokens would have expired. The access token and every refresh token of that session are rejected from then on, and the refresh cookie is deleted | `api/v1/endpoints/auth.py`, `core/valkey.py` |
| Password change | Ends every session of the account, see [Sessions](#sessions) | `api/v1/endpoints/auth.py`, `core/security.py` |
| Invalidate all tokens | Increase `JWT_KEY_VERSION` and restart. Tokens carry the version they were issued with | `core/security.py` |
| Password hashing | bcrypt, cost factor 10 | `core/security.py` |
| Account lockout | 5 failed logins for one email lock that email for 30 minutes. Wrong current passwords in the password-change form count as well | `core/valkey.py` |
| Inactive accounts | An account that has not logged in for `ACCOUNT_INACTIVITY_DAYS` (default 90) is deactivated at the next login attempt. `0` disables the check | `api/v1/endpoints/auth.py` |
| Startup check | The backend refuses to start when `DEBUG=false` and `SECRET_KEY` is the development default | `core/config.py` |
| Alert WebSocket | `/api/v1/ws/alerts?token=<access token>` is checked like an HTTP request and needs the `detections:read` permission. Otherwise the server refuses the connection with close code 1008 before accepting it | `api/v1/endpoints/websocket.py` |

Lockout, token revocation (logout, single use of refresh tokens) and the MFA attempt counter depend on Valkey. When Valkey is not reachable these checks are skipped and the request is allowed. The end of all sessions after a password change does not depend on Valkey: it is checked in the database.

## Sessions

A sign-in starts a session with two tokens.

| Token | Lifetime | Where it lives | Sent to |
|-------|----------|----------------|---------|
| Access token | `ACCESS_TOKEN_EXPIRE_MINUTES`, default 60 | Response body. The web UI keeps it in the browser's `localStorage` | Every API request as `Authorization: Bearer`, and the alert WebSocket in the URL (browsers cannot set a header there; the Nginx configurations in this repository do not log that request) |
| Refresh token | `REFRESH_TOKEN_EXPIRE_DAYS`, default 7 | Cookie `mxtac_refresh` with `HttpOnly`, `Secure`, `SameSite=Strict` and `Path=/api/v1/auth/refresh`. It is never part of a response body | Only `POST /api/v1/auth/refresh`, by the browser itself |

### Where the refresh token is stored, and why

The refresh token is the long-lived credential of a session, so it is kept out of JavaScript altogether.

| Property of the cookie | Effect |
|------------------------|--------|
| `HttpOnly` | No script can read the token. A cross-site scripting flaw in the UI, or a compromised dependency, can use the session while the page is open, but cannot copy the refresh token and keep the session for days from another machine. The access token in `localStorage` can be copied this way; it is valid for at most 60 minutes and cannot be renewed without the cookie |
| `Path=/api/v1/auth/refresh` | The browser attaches the cookie to the refresh request only. It is not sent with ordinary API requests, the WebSocket handshake, or to anything else served from the same host, and so does not appear in their logs |
| `SameSite=Strict` | The browser does not send the cookie with a request that another site started. The refresh route is therefore not exposed to cross-site request forgery, and it changes nothing but the session it renews; its answer is not readable across origins |
| `Secure` | The cookie is only sent over HTTPS. Browsers treat `http://localhost` as secure, so the development stack works unchanged. Only a deployment over plain HTTP on another host name needs `REFRESH_COOKIE_SECURE=false`; use HTTPS instead where you can |

The alternatives were rejected for these reasons: `localStorage` is readable by any script on the page and survives the browser; `sessionStorage` and memory are still readable by scripts, and are lost with the tab. The backend needed only a small change to issue the cookie, so the token never has to reach a script.

The UI is served from the same origin as the API (the Vite dev server and the Nginx configurations proxy `/api`), which the `SameSite=Strict` cookie requires. A client that is not a browser signs in the same way and keeps the cookie in its cookie jar.

### Silent refresh

When a request is answered with `401`, the UI calls `POST /api/v1/auth/refresh` once, stores the new access token and repeats the request (`src/lib/api.ts`). Requests that fail at the same time share that one refresh. Browser tabs take turns through a Web Lock, and a tab that waited uses the token the other tab just obtained. The alert WebSocket reconnects with the new token. The user is signed out, with the notice "Your session has ended. Sign in again.", only when the refresh itself is refused. A refresh that fails for another reason (network, `5xx`) leaves the session alone and is tried again with the next request.

### Rotation and reuse detection

| Rule | Behaviour | Code |
|------|-----------|------|
| Rotation | Every refresh returns a new access token and sets a new refresh cookie. The refresh token that was presented is put on the revocation list in the same step (one atomic `SET NX` in Valkey, kept until the token would have expired) | `api/v1/endpoints/auth.py`, `core/valkey.py` |
| Reuse | A refresh token that is presented a second time is refused, and the session it belongs to is ended: the refresh token that replaced it stops working as well. A copied token is thus useless as soon as either party uses it twice. Other sessions of the account are not affected | `api/v1/endpoints/auth.py` |
| Session ID | Access and refresh tokens carry the ID of their session (`sid`). A refresh keeps it; a sign-in starts a new one | `api/v1/endpoints/auth.py` |
| Refusal | Every refused refresh deletes the cookie | `api/v1/endpoints/auth.py` |

### Ending sessions

| Event | What ends | How |
|-------|-----------|-----|
| Sign-out | The session that signed out: its access token and all its refresh tokens | Revocation list in Valkey (token ID and session ID) |
| Reuse of a refresh token | The refresh tokens of that session | Revocation list in Valkey (session ID) |
| Password change (`POST /api/v1/auth/password`, `POST /api/v1/auth/change-password`) | Every session of the account, on every device. The request that changed the password is answered with a new session, so that browser stays signed in | `users.token_version` is increased. Every token carries the version it was issued under (`tv`), and the lookup of the user that happens on every request anyway refuses a token with an older version. No Valkey involved |
| Deactivation of the account | Every session of the account | Active flag, read on every request |
| `JWT_KEY_VERSION` increased | Every session of every account | Version claim in every token |

Limits to know:

- Without Valkey, rotation and sign-out are not enforced (the checks fail open, like the lockout). A rotated or signed-out refresh token then stays usable until it expires. Password changes and deactivations still end sessions.
- When reuse is detected, access tokens that were already issued for that session stay valid until they expire (at most `ACCESS_TOKEN_EXPIRE_MINUTES`). They cannot be renewed.
- A refresh whose answer is lost on the way (the server rotated, the browser never got the new cookie) ends that session at the next attempt. The user signs in again.

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
| A signed-in user changes the own password | `POST /api/v1/auth/password` | Needs the current password. In the UI under **Settings**, **Profile and security**. Returns a new session for the caller |

Every password change ends all sessions of the account, see [Sessions](#sessions).

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
| There is no list of the sessions of an account, and no way to end one session from another device | Change the password: that ends every session of the account. To end every session of every user, increase `JWT_KEY_VERSION` and restart |
| The access token is kept in `localStorage` and passed to the WebSocket in the URL. A script that runs in the page can read it; it is valid for at most `ACCESS_TOKEN_EXPIRE_MINUTES` and cannot be renewed without the refresh cookie, which scripts cannot read | Serve the UI over HTTPS only, and keep WebSocket URLs out of proxy logs. Lower `ACCESS_TOKEN_EXPIRE_MINUTES` where this matters; the UI renews the token silently |
| The refresh cookie has the `Secure` attribute, so a browser does not store it when the UI is served over plain HTTP on a host other than `localhost`. Sessions then end when the access token expires | Serve the UI over HTTPS. `REFRESH_COOKIE_SECURE=false` removes the attribute for a plain-HTTP evaluation setup |
| `/metrics`, `/docs`, `/redoc` and `/openapi.json` need no login | Do not publish the backend port. The Nginx configurations in this repository do not proxy these paths, except the Swarm configuration, which proxies `/docs` and `/openapi.json` |
| Lockout, token revocation (sign-out, single use of refresh tokens) and MFA attempt limits are skipped while Valkey is not reachable. A password change still ends all sessions | Monitor `/ready`, which reports Valkey |
| The development Compose file uses a fixed `SECRET_KEY`, a fixed database password, and OpenSearch without authentication | Use it for local evaluation only |
| The Compose files and `app/setup.sh` run OpenSearch with the security plugin disabled. The production Compose file does not publish its port, `app/setup.sh` binds it to `127.0.0.1`, and the development file publishes it | Keep the OpenSearch port unreachable from other hosts, or connect a secured cluster with `OPENSEARCH_USERNAME`, `OPENSEARCH_PASSWORD` and `OPENSEARCH_USE_SSL` |
| TLS certificates of OpenSearch are not verified | Keep the connection on a trusted network |
| Connector settings, including the Wazuh password and webhook tokens, are stored unencrypted in the `connectors` table | Restrict access to the database and its backups |
| Only incident changes are written to the audit log | Use the access log for other actions |
