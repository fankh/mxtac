# Development

## Requirements

| Tool | Version |
|------|---------|
| Docker with Compose v2 | For the full stack |
| Python | 3.12 or newer (backend) |
| Node.js | 20 or newer (frontend). CI uses 22 |

## Option 1: everything in Docker Compose

```bash
cd app
docker compose up -d --build
```

| Service | Host port | Notes |
|---------|-----------|-------|
| backend | 15000 | Source is mounted from `app/backend`. Uvicorn runs with `--reload` |
| frontend | 15001 | Source is mounted from `app/frontend`. Vite dev server with hot reload. Forwards `/api` to `http://backend:8080` (`VITE_PROXY_TARGET`) |
| postgres | 15002 | User `mxtac`, password `mxtac`, database `mxtac` |
| redis (Valkey) | 15003 | |
| opensearch | 15004, 15005 | Security plugin disabled |
| opensearch-dashboards | 15006 | Profile `dashboards` |
| prometheus | 15009 | Profile `monitoring` |
| grafana | 15010 | Profile `monitoring` |

The backend container runs `alembic upgrade head` before it starts. On an empty database it then creates the account `admin@mxtac.local` and imports the bundled Sigma rules. Read the generated password with:

```bash
docker compose logs backend | grep "INITIAL ADMIN PASSWORD"
```

For a fixed password in development, start the stack with `INITIAL_ADMIN_PASSWORD='<password>' docker compose up -d`. For sample content, add `SEED_DEMO_DATA=true`. Both only apply while the `users` table is empty; `docker compose down -v` gives you an empty database again. See [First login](../README.md#first-login).

To run a migration command by hand:

```bash
docker compose exec backend alembic current
docker compose exec backend alembic upgrade head
```

Useful commands:

```bash
docker compose logs -f backend
docker compose down        # keep data
docker compose down -v     # delete data
```

On Windows, check out the repository with LF line endings for shell scripts. `.gitattributes` enforces this for `*.sh`. A `docker-entrypoint.sh` with CRLF line endings stops the backend container at startup.

## Option 2: backend on the host

The backend image does not contain the test tools. Run tests and linters from a virtual environment on the host.

```bash
cd app/backend
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

The backend needs a database. Two ways:

| Way | Command | Notes |
|-----|---------|-------|
| SQLite | `SQLITE_MODE=true uvicorn app.main:app --reload --port 8080` | Creates `./mxtac.db` and applies migrations at startup. Valkey and OpenSearch are optional in this mode; without them, lockout and token revocation are not active and event search uses the database |
| PostgreSQL from Compose | `docker compose -f ../docker-compose.yml up -d postgres redis opensearch`, then set `DATABASE_URL`, `VALKEY_URL`, `OPENSEARCH_PORT` to the published ports and run `alembic upgrade head` and `uvicorn app.main:app --reload --port 8080` | See the example below |

Example `.env` in `app/backend/` for the Compose services:

```bash
DATABASE_URL=postgresql+asyncpg://mxtac:mxtac@localhost:15002/mxtac
VALKEY_URL=redis://localhost:15003/0
OPENSEARCH_HOST=localhost
OPENSEARCH_PORT=15004
```

Settings are documented in [ENV-REFERENCE.md](../ENV-REFERENCE.md). The backend does not start when `.env` contains a setting that does not exist in `app/core/config.py`.

The generated password of `admin@mxtac.local` is written to the output of `uvicorn` at the first start.

## Option 3: frontend on the host

```bash
cd app/frontend
npm ci
npm run dev
```

The frontend calls the API with relative URLs (`/api/v1/...`). In development, the Vite server forwards `/api` to a backend, including the alert WebSocket at `/api/v1/ws/alerts` (`vite.config.ts`). The target is the environment variable `VITE_PROXY_TARGET`.

| Backend | `VITE_PROXY_TARGET` |
|---------|---------------------|
| Compose backend, published on port 15000 | Not needed. The default is `http://localhost:15000` |
| Backend on the host on port 8080 (Option 2) | `http://localhost:8080` |
| Inside the Compose network | `http://backend:8080`. `app/docker-compose.yml` sets this for the frontend service |

```bash
VITE_PROXY_TARGET=http://localhost:8080 npm run dev
```

Open <http://localhost:5173>. The built frontend has no environment variables.

## Tests and checks

Backend, from `app/backend`:

| Command | Purpose |
|---------|---------|
| `pytest` | All tests with coverage (configured in `pyproject.toml`). Tests use an in-memory SQLite database |
| `pytest tests/engine -q` | One test directory |
| `ruff check .` | Lint |
| `mypy app/` | Type check (strict) |

Frontend, from `app/frontend`:

| Command | Purpose |
|---------|---------|
| `npm test` | Vitest, single run |
| `npm run test:watch` | Vitest in watch mode |
| `npm run test:coverage` | Vitest with coverage |
| `npm run lint` | ESLint |
| `npx tsc --noEmit` | Type check |
| `npm run build` | Type check and production build into `dist/` |

The frontend build (`npm run build`) type-checks with `tsc -b`.

CI runs the same commands (`.github/workflows/backend-ci.yml`, `frontend-ci.yml`). After both succeed on `main`, `docker-build.yml` builds and pushes the images to GitHub Container Registry and scans them with Trivy.

## Database migrations

Migrations live in `app/backend/alembic/versions/`. Alembic reads the database URL from the application settings.

```bash
cd app/backend
alembic revision --autogenerate -m "describe the change"
alembic upgrade head
alembic downgrade -1
```

CI checks that there is one migration head, that upgrade, downgrade and upgrade again succeed on PostgreSQL 16, and that `alembic check` finds no difference between models and migrations.

`alembic upgrade head` works on an empty PostgreSQL database. In SQLite mode the backend applies the migrations itself at startup.

## Adding things

| Task | Where |
|------|-------|
| New API route | Add a module in `app/api/v1/endpoints/`, register it in `app/api/v1/router.py`, protect it with `require_permission`, then run `python scripts/gen_api_docs.py` |
| New permission | `PERMISSIONS` in `app/core/rbac.py`, then `docs/security.md` |
| New setting | `Settings` in `app/core/config.py`, then `ENV-REFERENCE.md` and `app/backend/.env.example`. When you remove a setting, remove it from every `.env` example and deployment file as well |
| New connector | Subclass `BaseConnector` in `app/connectors/`, add it to `CONNECTOR_TYPES` in `app/connectors/registry.py` and in `app/api/v1/endpoints/connectors.py`, add a topic in `app/pipeline/queue.py`, add a normalizer in `app/services/normalizers/` and subscribe it in `NormalizerPipeline`. The normalizer must set `metadata_product`, which Sigma rules match as `logsource.product` |
| New Sigma rule shipped with the code | A YAML file with an `id` in `app/backend/sigma_rules/`, then `python scripts/gen_rule_table.py --write`. It is imported into the database at the next backend start. Use only the syntax listed in [sigma-engine.md](sigma-engine.md) |
| New field for Sigma rules | `app/engine/field_mapper.py`, then [sigma-engine.md](sigma-engine.md) |
| New page | A component under `src/components/features/`, a route in `src/App.tsx`, a link in `src/components/layout/Sidebar.tsx` |

## Scripts

| Script | Purpose |
|--------|---------|
| `scripts/gen_api_docs.py` | Regenerate `docs/api.md` from the routes the backend registers. Run it after adding or changing a route |
| `scripts/gen_rule_table.py` | Print the table of bundled Sigma rules, or with `--write` replace it in `docs/sigma-engine.md` |
| `scripts/audit-deps.sh` | `pip-audit` and `npm audit`. `--ci` exits non-zero on findings |
| `scripts/scan-images.sh` | Scan the backend and frontend images with Grype or Trivy. `--build` builds them first |
| `scripts/backup-db.sh` | PostgreSQL dump with retention |
| `scripts/restore-db.sh` | Restore a dump |
| `scripts/deploy.sh` | Pull images and restart a Compose or k3s deployment |
