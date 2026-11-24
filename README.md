# MxTac

[![License: AGPL v3](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)
[![Backend CI](https://github.com/fankh/mxtac/actions/workflows/backend-ci.yml/badge.svg)](https://github.com/fankh/mxtac/actions/workflows/backend-ci.yml)
[![Frontend CI](https://github.com/fankh/mxtac/actions/workflows/frontend-ci.yml/badge.svg)](https://github.com/fankh/mxtac/actions/workflows/frontend-ci.yml)

MxTac is an open-source detection platform built around MITRE ATT&CK. It collects security events from Wazuh, Zeek, Suricata, syslog and a JSON webhook, normalizes them to OCSF, evaluates Sigma rules against them, and shows the resulting detections, incidents and ATT&CK coverage in a web UI.

This repository is a deliberately small core. It is meant to be read, run and extended. The same company also operates a managed service, [KYRA MDR](https://kyramdr.com/en/?utm_source=mxtac&utm_medium=readme), which is a separate product. See [MxTac and KYRA MDR](#mxtac-and-kyra-mdr) for the difference.

## Features

| Area | What it does |
|------|--------------|
| Overview | KPI cards, detection timeline, top tactics, coverage heatmap, source status, recent detections |
| Detections | List, filter, sort, export to CSV, change status, assign, bulk update |
| Incidents | Create incidents, link detections, add notes, track status. High-severity detections on the same host and tactic are grouped into an incident automatically |
| Hunt | Search and aggregate stored events, view one event or one entity (IP, host, user, hash), export to CSV, save queries |
| ATT&CK Coverage | Coverage percentage from enabled Sigma rules, gaps, trend, per-source breakdown, ATT&CK Navigator layer export, coverage target |
| Sigma Rules | 20 bundled rules. Create, edit, import (YAML), enable or disable, test a rule against a sample event, hot reload |
| Sources | Connectors for Wazuh, Zeek, Suricata, syslog and a generic webhook, with start, stop, test and health |
| Settings | Profile, password change, TOTP MFA, user management (admin), light and dark theme |
| Access control | JWT login with optional TOTP MFA. Five roles: viewer, analyst, hunter, engineer, admin |

A new installation contains no detections, incidents or events. Every page shows zeros and empty states until a source delivers events.

## Screenshots

The screenshots use sample data. A new installation starts empty.

| Overview (light) | Overview (dark) |
|------------------|-----------------|
| ![Overview page, light theme](docs/images/overview-light.png) | ![Overview page, dark theme](docs/images/overview-dark.png) |

## Quick start

You need Docker with Compose v2 and Git. The stack starts five containers: backend, frontend, PostgreSQL, Valkey and OpenSearch.

1. Clone the repository and start the stack.

   ```bash
   git clone https://github.com/fankh/mxtac.git
   cd mxtac/app
   docker compose up -d --build
   ```

   The backend container applies the database migrations (`alembic upgrade head`) before it starts the API.

2. Wait until the backend is ready. OpenSearch takes the longest to start.

   ```bash
   curl http://localhost:15000/ready
   ```

   The response contains `"status": "ready"` when PostgreSQL, Valkey and OpenSearch all answer.

3. Read the password of the first account from the backend log, open the UI at <http://localhost:15001> and sign in (see [First login](#first-login)).

   ```bash
   docker compose logs backend | grep "INITIAL ADMIN PASSWORD"
   ```

| Service | URL |
|---------|-----|
| Web UI | <http://localhost:15001> |
| API | <http://localhost:15000> |
| API reference (Swagger UI) | <http://localhost:15000/docs> |
| Prometheus metrics | <http://localhost:15000/metrics> |

Stop the stack with `docker compose down`. Add `-v` to delete the data volumes as well.

`app/docker-compose.yml` is a development setup: debug mode is on, the signing key and database password are fixed development values, OpenSearch runs without authentication, and every service port is published on the host. Use it on a trusted machine only. For anything else, read [docs/deployment.md](docs/deployment.md).

### First login

When the `users` table is empty, the backend creates exactly one account at startup: `admin@mxtac.local` with the `admin` role. The code is in `app/backend/app/db/seed.py`. There is no built-in or shared password.

| `INITIAL_ADMIN_PASSWORD` | Password of `admin@mxtac.local` |
|--------------------------|----------------------------------|
| Not set (default) | A random 24-character password. It is written once to the backend log, in a `WARNING` line that starts with `INITIAL ADMIN PASSWORD (generated, shown only once)` |
| Set | The value you set. It is never logged. It must meet the password policy, otherwise the backend does not start |

Steps:

1. Read the generated password.

   ```bash
   docker compose logs backend | grep "INITIAL ADMIN PASSWORD"
   ```

   To choose the password yourself, set the variable for the first start instead:

   ```bash
   INITIAL_ADMIN_PASSWORD='<your password>' docker compose up -d --build
   ```

2. Sign in at <http://localhost:15001> as `admin@mxtac.local`. The UI asks for a new password before it opens. The first password cannot be used for anything else.
3. Add the other users under **Settings**, **Users**. You give each user a temporary password, and the user must replace it at the first sign-in.

A password needs 8 to 128 characters, three of the four character types (upper case, lower case, digit, symbol), and no character more than three times in a row. Every user can change the password later under **Settings**, **Profile and security**.

Things to know:

- The log line exists only in the log of the backend container that created the account. Read it before you remove that container (`docker compose down`).
- A lost first password cannot be recovered or reset. Before the first sign-in the only way out is an empty `users` table, for example a new database (`docker compose down -v` deletes all data).
- `INITIAL_ADMIN_PASSWORD` is only read while the `users` table is empty. Changing it later has no effect.

### Demo data

`SEED_DEMO_DATA=true` makes the first start also create the accounts `analyst@mxtac.local`, `hunter@mxtac.local` and `engineer@mxtac.local` and a set of invented detections, incidents, connectors and rules. The three accounts get the same first password as the admin account and must also change it at the first sign-in. Like the admin account, this only happens while the `users` table is empty.

```bash
SEED_DEMO_DATA=true docker compose up -d --build
```

Use this for a demonstration only. The sample rows cannot be told apart from real findings. The default is `false`.

### Optional services

| Profile | Command | Adds |
|---------|---------|------|
| `dashboards` | `docker compose --profile dashboards up -d` | OpenSearch Dashboards on <http://localhost:15006> |
| `monitoring` | `docker compose --profile monitoring up -d` | Prometheus on <http://localhost:15009> and Grafana on <http://localhost:15010>. The compose file sets the Grafana login to `admin` / `admin`; change it |

## Architecture

```
                   +--------------------+
  browser -------> | frontend           |  React 18, Vite, Tailwind
                   | (port 15001)       |
                   +---------+----------+
                             | /api/v1 (REST), /api/v1/ws/alerts (WebSocket)
                             v
                   +--------------------+        +----------------------------+
  Wazuh API -----> | backend            | -----> | PostgreSQL 16              |
  Zeek logs -----> | FastAPI            |        | users, rules, detections,  |
  Suricata EVE --> | (port 15000)       |        | incidents, connectors,     |
  syslog --------> |                    |        | events                     |
  JSON webhook --> |  connectors        |        +----------------------------+
                   |  -> normalizers    | -----> | Valkey 8                   |
                   |  -> Sigma engine   |        | rate limits, lockout,      |
                   |  -> alert manager  |        | dedup, live alert fan-out  |
                   |                    |        +----------------------------+
                   |                    | -----> | OpenSearch 2.17            |
                   +--------------------+        | event index for Hunt       |
                                                 +----------------------------+
```

Inside the backend, an event moves through these steps:

1. A connector, the syslog receiver or the webhook endpoint publishes a raw event to a queue topic. The queue is in-memory by default; Valkey Streams is the alternative for more than one backend process.
2. The normalizer converts the event to OCSF. There is one normalizer for each of the five source types.
3. The event persister writes the normalized event to PostgreSQL and OpenSearch.
4. The Sigma engine evaluates the enabled rules from the `rules` table against the event.
5. The alert manager drops duplicates (same rule and host within 5 minutes), scores the alert, stores it as a detection, and may open or extend an incident.
6. The detection is pushed to signed-in browsers over a WebSocket.

More detail: [docs/architecture.md](docs/architecture.md).

## Configuration

The backend reads its settings from environment variables or `app/backend/.env`. [docs/configuration.md](docs/configuration.md) lists every setting. `app/backend/.env.example` is a starting point.

## Development

Backend (Python 3.12):

```bash
cd app/backend
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
uvicorn app.main:app --reload --port 8080
pytest
ruff check .
```

Frontend (Node.js 20 or newer):

```bash
cd app/frontend
npm ci
npm run dev        # Vite dev server on port 5173, forwards /api to http://localhost:15000
npm test           # Vitest
npm run lint
npm run build
```

Set `VITE_PROXY_TARGET` to forward `/api` to another backend address, for example `VITE_PROXY_TARGET=http://localhost:8080 npm run dev`. See [docs/development.md](docs/development.md) for the database, the dev proxy and the test setup.

## Documentation

| Document | Content |
|----------|---------|
| [docs/installation.md](docs/installation.md) | Installation and upgrade steps |
| [docs/configuration.md](docs/configuration.md) | Environment variables |
| [docs/architecture.md](docs/architecture.md) | Components and the event pipeline |
| [docs/api.md](docs/api.md) | REST API routes and required permissions |
| [docs/sigma-engine.md](docs/sigma-engine.md) | Supported Sigma features and the bundled rules |
| [docs/attack-coverage.md](docs/attack-coverage.md) | How coverage is calculated |
| [docs/integration-guide.md](docs/integration-guide.md) | Connecting Wazuh, Zeek, Suricata, syslog and webhooks |
| [docs/ui.md](docs/ui.md) | Pages and the UI token system |
| [docs/security.md](docs/security.md) | Authentication, roles, password policy, headers |
| [docs/deployment.md](docs/deployment.md) | Deployment files in this repository |
| [docs/development.md](docs/development.md) | Development workflow |

## MxTac and KYRA MDR

MxTac is the open-source detection core. KYRA MDR is a managed detection and response service from the same company. The table lists what each one covers.

| Capability | MxTac (this repository) | KYRA MDR (managed service) |
|------------|-------------------------|----------------------------|
| Sigma rule detection with ATT&CK mapping | Yes | Yes |
| Detections, incidents, event search, coverage views | Yes | Yes |
| Operation | You install and run it | Run for you, with 24/7 monitoring by analysts |
| AI triage and investigation | No | Yes |
| Automated response | No | Yes |
| Threat intelligence | No | Yes |
| Compliance reporting | No | Yes |
| EDR and NDR agents | No | Yes |
| Single sign-on (SSO) | No | Yes |

More about the managed service: <https://kyramdr.com/en/?utm_source=mxtac&utm_medium=readme>

## Current limitations

Each item was checked against the code at the time of writing.

- **Sigma support is a subset.** Selections, the common value modifiers, wildcards and boolean conditions with `1 of` / `all of` work. Aggregations (`| count()`, `| near`), `timeframe` and correlation rules are rejected with an error when a rule is created, imported or tested. Rules are evaluated one event at a time. See [docs/sigma-engine.md](docs/sigma-engine.md).
- **Hunt search is limited while OpenSearch is the search backend.** Free-text search only matches the exact event class name, the result table shows no host, user, address, source or summary, and the Host filter only looks at the source endpoint. Exact-match filters on source, class and severity work. The same searches work as expected on the PostgreSQL fallback, which is used when OpenSearch is not reachable. See [docs/architecture.md](docs/architecture.md#current-limitations).
- **The Overview heatmap stays empty for pipeline detections.** It groups detections by tactic name, and the pipeline stores the tactic ID (for example `TA0006`).
- **Coverage uses a fixed scope** of 105 techniques across 9 tactics, not the full ATT&CK matrix. See [docs/attack-coverage.md](docs/attack-coverage.md).
- **No password reset.** A lost first password cannot be recovered (see [First login](#first-login)). An administrator cannot set a new password for an existing user; a user who forgot the password needs a new account under another email address.
- **Changing a password does not end other sessions.** Tokens that were issued before the change stay valid until they expire (60 minutes for access tokens, 7 days for refresh tokens by default).
- **The default queue is in memory.** Events that are in the queue are lost when the backend stops, and the queue works with one backend process only. Use `QUEUE_BACKEND=redis` otherwise.
- **`/metrics`, `/docs`, `/redoc` and `/openapi.json` of the backend need no login.** Do not publish the backend port; publish a reverse proxy.
- **Connector settings are stored without encryption** in the database, including the Wazuh password and webhook tokens.

More limitations of the security model are listed in [docs/security.md](docs/security.md#current-limitations).

## License

MxTac is licensed under the GNU Affero General Public License v3.0. See [LICENSE](LICENSE).

## Contributing and security

The documentation index is [docs/README.md](docs/README.md). Questions and bug reports: [SUPPORT.md](SUPPORT.md). Conduct: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

- Contributions: [CONTRIBUTING.md](CONTRIBUTING.md)
- Reporting a vulnerability: [SECURITY.md](SECURITY.md)
- Release notes: [CHANGELOG.md](CHANGELOG.md)
