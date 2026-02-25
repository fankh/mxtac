# Security Policy

## Reporting a Vulnerability

To report a security vulnerability in MxTac, **do not open a public GitHub issue**.
Instead, email **fankh111@gmail.com** with:

- A clear description of the vulnerability
- Steps to reproduce or a proof-of-concept
- The affected component and version
- Any suggested mitigations (optional)

We will acknowledge receipt within 48 hours and provide a remediation timeline.
Coordinated disclosure is preferred: please allow 90 days for a fix before public
disclosure.

---

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| v0.2.x  | ✅ Yes (pre-release) |
| v1.x    | ❌ No (planned)     |

---

## Security Update Policy

- **Critical / High** vulnerabilities in production dependencies: patched within 7 days
- **Moderate** vulnerabilities in production dependencies: patched within 30 days
- **Dev-only** vulnerabilities (test tooling, linters): addressed in the next release cycle
- Container base images are rebuilt monthly to pick up OS-level patches

---

## Dependency Audit

### Running Audits

```bash
# Python + Node.js (interactive)
./scripts/audit-deps.sh

# CI mode (exits non-zero on new HIGH/CRITICAL findings)
./scripts/audit-deps.sh --ci

# Container images (requires Grype or Trivy)
./scripts/scan-images.sh
```

### Python (`pip-audit`)

Tool: `pip-audit==2.10.0` (installed via `uv` dev dependencies).

#### Known / Accepted Vulnerabilities

| Package | Version | CVE / Advisory | Severity | Status |
|---------|---------|---------------|----------|--------|
| python-jose | 3.3.0 | PYSEC-2024-232 | High | Accepted — no upstream fix. Remediation: migrate to PyJWT (tracked in backlog). |
| python-jose | 3.3.0 | PYSEC-2024-233 | High | Accepted — no upstream fix. Remediation: migrate to PyJWT (tracked in backlog). |
| ecdsa | 0.19.1 | CVE-2024-23342 | Medium | Accepted — transitive dependency of python-jose; no available fix. Blocked on python-jose migration. |
| starlette | 0.41.3 | CVE-2025-54121 | High | Accepted — transitive dependency of fastapi==0.115.5; fixed in fastapi>=0.115.6. Upgrade blocked on regression testing. |
| starlette | 0.41.3 | CVE-2025-62727 | High | Accepted — same root cause as CVE-2025-54121; same remediation. |

**Rationale for python-jose acceptance**: python-jose is unmaintained (last release 2021).
The vulnerabilities (algorithm confusion and improper signature verification) are mitigated
by MxTac's configuration: RS256 is enforced, and the `algorithms` parameter is explicitly
set in all token validation calls. Migration to PyJWT is the long-term fix.

---

### Node.js (`npm audit`)

As of 2026-02-25, `npm audit --omit=dev` reports **0 production vulnerabilities**.

#### Remaining Dev-Only Findings (Moderate)

All remaining findings are in `devDependencies` used only during local development
and testing. They have **no impact on the production build or runtime**.

| Package | Advisory | Severity | Affected In | Notes |
|---------|---------|----------|-------------|-------|
| esbuild ≤ 0.24.2 | GHSA-67mh-4wv8-2f99 | Moderate | `vitest`, `vite-node` (devDependency) | Dev server only. Allows cross-origin requests to the Vite dev server. Not present in production builds. Fix requires vitest@4 (breaking). |

**Resolved** (by `npm audit fix`, 2026-02-25):

| Package | Advisory | Severity | Resolution |
|---------|---------|----------|------------|
| minimatch < 3.1.3 | GHSA-3ppc-4f35-3m26 | High | Upgraded to minimatch@3.1.4 via `npm audit fix`. |

---

## Container Images

Container images are scanned with **Grype** (primary) or **Trivy** (fallback):

```bash
# Build then scan
./scripts/scan-images.sh --build

# CI mode
./scripts/scan-images.sh --ci
```

Reports are saved to `security-reports/` (excluded from git via `.gitignore`).

The CI pipeline (`scan-images.sh --ci`) fails the build on any **HIGH** or **CRITICAL**
container-level vulnerability.

---

## Vulnerability Backlog

The following items are tracked for future remediation:

1. **Migrate python-jose → PyJWT** — resolves PYSEC-2024-232, PYSEC-2024-233, CVE-2024-23342
2. **Upgrade fastapi ≥ 0.115.6** — resolves CVE-2025-54121, CVE-2025-62727 (starlette)
3. **Upgrade vitest@4** — resolves GHSA-67mh-4wv8-2f99 (esbuild in dev tooling)
