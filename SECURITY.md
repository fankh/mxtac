# Security policy

## Reporting a vulnerability

Do not open a public GitHub issue for a security vulnerability. Send an email to **security@seekerslab.com** with:

- a description of the vulnerability;
- steps to reproduce it, or a proof of concept;
- the affected component and commit or version;
- a suggested fix, if you have one.

Please give the maintainers time to fix the issue before you disclose it publicly.

## Supported versions

Security fixes are made on the `main` branch. There are no maintained release branches.

## Scope

| In scope | Path |
|----------|------|
| Backend API | `app/backend/` |
| Web frontend | `app/frontend/` |
| Deployment files and scripts | `app/docker-compose*.yml`, `app/setup.sh`, `app/deploy/`, `app/nginx/`, `scripts/` |

## Security model and known limitations

[docs/security.md](docs/security.md) describes authentication, MFA, roles, the password policy and HTTP protections. It also lists the current limitations, including the default accounts created on a new database. Read it before you expose an instance to a network.

## Dependency and image scanning

| Check | Command |
|-------|---------|
| Python and Node.js dependencies | `./scripts/audit-deps.sh` (`pip-audit` and `npm audit`) |
| Python only, Node.js only | `./scripts/audit-deps.sh --python`, `./scripts/audit-deps.sh --node` |
| Fail on findings | `./scripts/audit-deps.sh --ci` |
| Container images | `./scripts/scan-images.sh` (Grype, or Trivy when Grype is not installed). `--build` builds the images first. `--ci` exits non-zero on high or critical findings |

The CI workflow `.github/workflows/docker-build.yml` scans the published images with Trivy and uploads the result to GitHub code scanning.

### Known accepted finding

`python-jose` depends on `ecdsa`, which has the advisory CVE-2024-23342 without a fixed release. MxTac signs tokens with HS256 only (`app/backend/app/core/security.py`), which does not use `ecdsa`.

Run the audit script for the current state of all other dependencies.
