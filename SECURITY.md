# Security Policy

## Reporting a Vulnerability

To report a security vulnerability in MxTac, **do not open a public GitHub issue**.
Instead, email **security@seekerslab.com** with:

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

## Security Update Process

- **Critical / High** vulnerabilities in production dependencies: patched within 7 days
- **Moderate** vulnerabilities in production dependencies: patched within 30 days
- **Dev-only** vulnerabilities (test tooling, linters): addressed in the next release cycle
- Container base images are rebuilt monthly to pick up OS-level patches

---

## Scope

This security policy covers the following components of the MxTac project:

- **Web application** (frontend)
- **API** (backend)
- **Database** (data layer)

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

Tool: `pip-audit==2.10.0` (installed via `uv` dev dependencies and `requirements.txt`).

#### Fixed Vulnerabilities (resolved in this release)

| Package | Old Version | CVE / Advisory | Severity | Resolution |
|---------|------------|---------------|----------|------------|
| python-jose | 3.3.0 → 3.5.0 | PYSEC-2024-232 | High | Upgraded to python-jose 3.5.0 (released 2025-05-28). |
| python-jose | 3.3.0 → 3.5.0 | PYSEC-2024-233 | High | Upgraded to python-jose 3.5.0 (released 2025-05-28). |
| python-multipart | 0.0.20 → 0.0.22 | CVE-2026-24486 | High | Upgraded to python-multipart 0.0.22. |

#### Known / Accepted Vulnerabilities

| Package | Version | CVE / Advisory | Severity | Status |
|---------|---------|---------------|----------|--------|
| ecdsa | 0.19.1 | CVE-2024-23342 | Medium | Accepted — transitive dependency of python-jose; no available fix. |
| starlette | 0.41.3 | CVE-2025-54121 | High | Accepted — transitive dependency of fastapi==0.115.5; fixed in fastapi>=0.133. Upgrade tracked in backlog. |
| starlette | 0.41.3 | CVE-2025-62727 | High | Accepted — same root cause as CVE-2025-54121; same remediation. |

**Rationale for ecdsa acceptance**: ecdsa is a transitive dependency of python-jose. There
is no available fix for CVE-2024-23342. The impact is limited: MxTac uses RS256 exclusively
and does not use the ecdsa signing paths that trigger the vulnerability.

**Rationale for starlette acceptance**: Fixing CVE-2025-54121 and CVE-2025-62727 requires
upgrading fastapi from 0.115.5 to ≥0.133.0 (≥17 minor versions). This upgrade carries
regression risk and is tracked in the backlog for a dedicated testing cycle.

---

### Node.js (`npm audit`)

`npm audit --omit=dev` reports **0 production vulnerabilities**.

#### Fixed Vulnerabilities (resolved in this release)

| Package | Advisory | Severity | Resolution |
|---------|---------|----------|------------|
| rollup 4.0.0–4.58.0 | GHSA-mw96-cpmx-2vgc | High | Forced rollup ≥ 4.59.0 via `overrides` in `package.json`. Run `npm install` to apply. |
| minimatch < 3.1.3 | GHSA-3ppc-4f35-3m26 | High | Upgraded to minimatch@3.1.4 via `npm audit fix` (2026-02-25). |

#### Remaining Dev-Only Findings (Moderate)

All remaining findings are in `devDependencies` used only during local development
and testing. They have **no impact on the production build or runtime**.

| Package | Advisory | Severity | Affected In | Notes |
|---------|---------|----------|-------------|-------|
| esbuild ≤ 0.24.2 | GHSA-67mh-4wv8-2f99 | Moderate | `vitest`, `vite-node` (devDependency) | Dev server only. Allows cross-origin requests to the Vite dev server. Not present in production builds. Fix requires vitest@4 (breaking upgrade). |

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

1. **Upgrade fastapi ≥ 0.133.0** — resolves CVE-2025-54121, CVE-2025-62727 (starlette). Requires regression testing cycle.
2. **Upgrade vitest@4** — resolves GHSA-67mh-4wv8-2f99 (esbuild in dev tooling, non-production impact).
