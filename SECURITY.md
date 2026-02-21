# Security Policy

## Supported Versions

Only the versions listed below receive security fixes. Patch releases are
issued on the **current minor version only**; earlier minor versions are
end-of-life as soon as the next minor is released.

| Version       | Supported        | Notes                          |
|---------------|------------------|--------------------------------|
| 2.0.x (alpha) | ✅ Active         | Current development line       |
| < 2.0.0       | ❌ End-of-life    | No security patches            |

> **Alpha stability notice.** The 2.0.x alpha series receives security fixes
> but may also receive breaking API changes without a deprecation notice.
> Pin to an exact version in production deployments.

---

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

### Preferred — GitHub Private Vulnerability Reporting

1. Navigate to the MxTac repository on GitHub.
2. Click **Security → Report a vulnerability**.
3. Fill in the form with as much detail as possible.

### Alternative — Email

Send a PGP-encrypted report to: **security@mxtac.io**

Include in your report:

- Affected component(s) and version(s)
- A clear description of the vulnerability and its impact
- Step-by-step reproduction instructions or proof-of-concept code
- Any proposed mitigations you are aware of
- Your contact information for follow-up

### Response Timeline

| Milestone                        | Target                              |
|----------------------------------|-------------------------------------|
| Initial acknowledgement          | ≤ 2 business days                   |
| Triage and severity assessment   | ≤ 5 business days                   |
| Patch (Critical / High)          | ≤ 7 days from confirmed report      |
| Patch (Medium)                   | ≤ 30 days from confirmed report     |
| Patch (Low)                      | Next scheduled release              |
| Public disclosure                | Coordinated with reporter           |

We follow a **coordinated disclosure** model. We will work with you to agree
on a disclosure date, typically after a patch is available. We credit reporters
in the release notes unless you prefer to remain anonymous. We will not take
legal action against researchers who follow this policy.

---

## Scope

**In scope:**

- `app/backend/` — FastAPI API server
- `app/frontend/` — React web application
- `agents/mxguard/` — EDR agent
- `agents/mxwatch/` — NDR agent
- `agent-scheduler/` — Task scheduler
- Docker images published to GitHub Container Registry
- Authentication, authorisation, and session management
- Data handling — secrets, credentials, PII

**Out of scope:**

- Third-party dependencies (report upstream to the respective project)
- Issues requiring physical access to the host
- Social engineering or phishing of maintainers
- Denial-of-service attacks against demo/development infrastructure

---

## Security Contacts

| Role              | Contact               |
|-------------------|-----------------------|
| Security reports  | security@mxtac.io     |
| Code of Conduct   | conduct@mxtac.io      |
| General enquiries | hello@mxtac.io        |

---

## Security Update Policy

- **Critical / High** vulnerabilities: patched within **7 days**
- **Medium** vulnerabilities: patched within **30 days**
- **Low** vulnerabilities: addressed in next scheduled release

---

## Known Vulnerabilities

The following vulnerabilities are **tracked, assessed, and accepted** with
documented mitigations. They are excluded from CI audit failures until
the corresponding fix is implemented.

### Python Backend

#### python-jose 3.3.0 — PYSEC-2024-232, PYSEC-2024-233

| Field       | Details |
|-------------|---------|
| Package     | `python-jose==3.3.0` |
| Severity    | High |
| CVE IDs     | PYSEC-2024-232 (algorithm confusion), PYSEC-2024-233 (improper signature verification) |
| Affects     | JWT token verification |
| Fix         | No upstream fix (python-jose is unmaintained; last release 2021) |
| Status      | **Accepted** — migration to `PyJWT` planned in sprint MXTAC-40 |
| Mitigation  | JWT tokens are short-lived (15 min access, 7 day refresh). All tokens validated server-side. RS256 is enforced in configuration. |

#### ecdsa 0.19.1 — CVE-2024-23342

| Field       | Details |
|-------------|---------|
| Package     | `ecdsa==0.19.1` (transitive via python-jose → cryptography) |
| Severity    | Medium |
| CVE ID      | CVE-2024-23342 (Minerva timing side-channel attack) |
| Affects     | ECDSA signature operations |
| Fix         | No upstream fix available |
| Status      | **Accepted** — resolves automatically when python-jose is replaced |
| Mitigation  | MxTac uses RSA (python-jose configured for RS256/HS256), not ECDSA for JWT signing. Timing side-channel is not exploitable in this configuration. |

#### starlette 0.41.3 — CVE-2025-54121, CVE-2025-62727

| Field       | Details |
|-------------|---------|
| Package     | `starlette==0.41.3` (transitive via `fastapi==0.115.5`) |
| Severity    | Medium |
| CVE IDs     | CVE-2025-54121 (fix: starlette ≥ 0.47.2), CVE-2025-62727 (fix: starlette ≥ 0.49.1) |
| Affects     | HTTP request handling (details per CVE advisories) |
| Fix         | Upgrade FastAPI to a version that depends on starlette ≥ 0.49.1 |
| Status      | **Tracked** — FastAPI upgrade planned in sprint MXTAC-41 |
| Mitigation  | MxTac is deployed behind nginx reverse proxy with request size limits and security headers. Direct exposure of the FastAPI port is blocked in production. |

---

### Node.js Frontend (devDependencies only)

All remaining Node.js vulnerabilities are in **devDependencies** only.
They do not affect the production build or deployed application.

#### minimatch < 10.2.1 — GHSA-3ppc-4f35-3m26

| Field       | Details |
|-------------|---------|
| Packages    | `eslint@9.x`, `typescript-eslint`, `glob`, `test-exclude` (all devDependencies) |
| Severity    | High (devDependencies only) |
| Advisory    | GHSA-3ppc-4f35-3m26 (ReDoS via repeated wildcards) |
| Affects     | Only local development linting — not production |
| Fix         | `npm audit fix --force` (installs eslint@10, breaking change) |
| Status      | **Accepted** — upgrade to eslint@10 + typescript-eslint@8 planned in MXTAC-42 |
| Mitigation  | ReDoS only possible with untrusted glob patterns. Linting runs on committed code with fixed patterns. No user-controlled input reaches these patterns. |

#### esbuild ≤ 0.24.2 — GHSA-67mh-4wv8-2f99

| Field       | Details |
|-------------|---------|
| Packages    | `vite@6.x`, `vitest@2.x`, `vite-node` (all devDependencies) |
| Severity    | Moderate |
| Advisory    | GHSA-67mh-4wv8-2f99 (dev server accepts cross-origin requests) |
| Affects     | Only local development server — **not the production build** |
| Fix         | `npm audit fix --force` (installs vitest@4, breaking change) |
| Status      | **Accepted** — upgrade to vitest@4 + vite@7 planned in MXTAC-42 |
| Mitigation  | The Vite dev server runs only on developer workstations on localhost. It is never exposed to the network in production (production uses a static build served by nginx). |

---

## Dependency Audit Procedures

### Python (Backend)

```bash
# Interactive scan (shows all findings)
./scripts/audit-deps.sh --python

# CI mode (exits non-zero on new findings, ignores accepted vulns)
./scripts/audit-deps.sh --python --ci

# Direct pip-audit invocation
uv run pip-audit --format columns
```

### Node.js (Frontend)

```bash
# Full audit (shows all findings including accepted dev-only ones)
./scripts/audit-deps.sh --node

# Production deps only (excludes devDependencies)
cd app/frontend && npm audit --omit=dev

# CI mode
./scripts/audit-deps.sh --node --ci
```

### Container Images

```bash
# Scan built images (requires Grype or Trivy)
./scripts/scan-images.sh

# Build then scan
./scripts/scan-images.sh --build

# CI mode (exits non-zero on HIGH/CRITICAL)
./scripts/scan-images.sh --ci

# Install Grype (recommended scanner)
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
```

---

## Security Headers

MxTac implements the following security headers via middleware
(`app/backend/app/core/middleware/security_headers.py`):

- `Strict-Transport-Security` (HSTS)
- `Content-Security-Policy`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy`

---

## Rate Limiting

API rate limiting is implemented via the `RateLimitMiddleware`
(`app/backend/app/core/middleware/rate_limit.py`):

- Default: 100 requests / minute per IP
- Auth endpoints: 10 requests / minute per IP (stricter)
- Configurable via `RATE_LIMIT_*` environment variables

---

## Authentication & Authorization

- JWT tokens with configurable expiry (default: 15 min access, 7 day refresh)
- Multi-factor authentication (TOTP) supported
- Role-based access control (RBAC) enforced at API layer
- Passwords hashed with bcrypt (12 rounds)
- All tokens validated server-side on every request
