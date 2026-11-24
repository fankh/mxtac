# Contributing to MxTac

This file describes how the project is organised and what a change needs before it can be merged.

## Scope of the project

MxTac is kept small on purpose. The core covers event ingestion from Wazuh, Zeek and Suricata, OCSF normalization, Sigma rule evaluation, detections, incidents, event search and ATT&CK coverage.

Before you start a large feature, open an issue and describe it. Features outside the core (for example SSO, threat intelligence, compliance reporting, response automation) were removed from this repository deliberately and are unlikely to be merged back.

Good first contributions:

- A normalizer for syslog or generic webhook events (see "Current limitations" in [README.md](README.md)).
- Sigma engine improvements, with tests.
- Additional Sigma rules in `app/backend/sigma_rules/`.
- Documentation fixes. Every statement in the docs must match the code.

## Repository layout

| Path | Content |
|------|---------|
| `app/backend/` | FastAPI backend (Python 3.12) |
| `app/backend/app/api/v1/endpoints/` | HTTP endpoints |
| `app/backend/app/services/` | Pipeline services and normalizers |
| `app/backend/app/repositories/` | Database access |
| `app/backend/app/models/`, `schemas/` | SQLAlchemy models and Pydantic schemas |
| `app/backend/app/engine/` | Sigma engine and field mapper |
| `app/backend/app/connectors/` | Source connectors |
| `app/backend/alembic/` | Database migrations |
| `app/backend/sigma_rules/` | Rules loaded at startup |
| `app/backend/tests/` | Backend tests (pytest) |
| `app/frontend/` | React frontend (TypeScript, Vite, Tailwind) |
| `app/deploy/`, `app/nginx/` | Deployment files |
| `docs/` | Documentation |
| `scripts/` | Backup, restore, deploy and audit scripts |
| `brand/` | Logo and favicon files |

## Workflow

1. Fork the repository and create a branch from `main`.

   | Type | Branch name |
   |------|-------------|
   | Feature | `feature/<description>` |
   | Bug fix | `fix/<description>` |
   | Documentation | `docs/<description>` |
   | Refactoring | `refactor/<description>` |

2. Make one focused change per pull request. Do not mix unrelated refactoring with feature work.
3. Run the checks listed under [Checks](#checks).
4. Update the documentation when behaviour, API routes or settings change. `docs/api.md` must match the routes the backend registers (regenerate it with `python scripts/gen_api_docs.py`), and `ENV-REFERENCE.md` must match `app/backend/app/core/config.py`.
5. Add an entry to `CHANGELOG.md` under `[Unreleased]`.
6. Open a pull request. Describe what changed, why, and how you tested it. Link the related issue.

### Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/): `<type>(<scope>): <description>`.

| Type | Use for |
|------|---------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation |
| `refactor` | Code change without behaviour change |
| `test` | Tests |
| `chore` | Maintenance |

Example: `fix(sigma): handle empty detection conditions`

## Checks

Continuous integration runs these commands on every pull request that touches the backend or the frontend (`.github/workflows/`). Run them locally first.

Backend:

```bash
cd app/backend
pip install -e ".[dev]"
ruff check .
mypy app/
pytest tests/ -v --tb=short --cov=app --cov-report=term-missing
```

CI also applies the migrations to an empty PostgreSQL 16 database, downgrades to base, upgrades again, and runs `alembic check`. A change to a model needs a matching migration.

Frontend:

```bash
cd app/frontend
npm ci
npm run lint
npx tsc --noEmit
npm run test:coverage
npm run build
```

## Code standards

### Backend

- Keep the layers separate: endpoints call services and repositories; repositories contain the database queries.
- Use `async` for I/O and database work.
- Add type hints. `mypy` runs in strict mode (`pyproject.toml`).
- `ruff` enforces the rule sets `E`, `F`, `I`, `UP`, `B` and `SIM` with a line length of 100.
- Protect every new endpoint with `require_permission(...)` from `app/core/rbac.py`, or document why it is public.
- Validate external input with Pydantic schemas. Escape user input in `LIKE` filters with `escape_like()` from `app/core/validators.py`.
- Never put secrets, tokens or passwords in code, tests or logs. Read them from settings.

### Frontend

- TypeScript strict mode is on. `@typescript-eslint/no-explicit-any` is an error.
- Use the components in `src/components/ui/` and the color tokens in `src/index.css`. Do not hard-code colors in page components. See [docs/ui.md](docs/ui.md).
- Every change in behaviour needs a Vitest test.

### Versions and dependencies

- The version number lives in the `VERSION` file at the repository root. `app/backend/app/__init__.py` reads it. Update `app/backend/pyproject.toml` and `app/frontend/package.json` to the same value on a release.
- Backend dependencies are pinned in both `app/backend/pyproject.toml` and `app/backend/requirements.txt`. Change both together. The Docker image installs from `requirements.txt`.

### Files

`.editorconfig` defines the formatting: LF line endings, UTF-8, a final newline, 2 spaces for TypeScript, JSON, YAML, HTML and CSS, and 4 spaces for Python.

## Security

- Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md). Do not open a public issue.
- Do not commit credentials, private keys or `.env` files.

## Conduct

Be respectful and constructive. Harassment, personal attacks and publishing private information are not accepted. The maintainers may remove comments, commits and contributors that violate this.

## License

MxTac is licensed under the GNU Affero General Public License v3.0 ([LICENSE](LICENSE)). By submitting a contribution you agree that it is licensed under the same terms.
