# Type Coverage Baseline

> Established: 2026-02-27
> Task: TASK-0.5.3 — Code Quality Standards Alignment

---

## Backend (Python — mypy strict)

Configuration in `app/backend/pyproject.toml`:

```toml
[tool.mypy]
python_version = "3.12"
strict = true
ignore_missing_imports = true
```

**Baseline status**: mypy strict mode enabled. `ignore_missing_imports = true` allows
third-party packages without bundled stubs (e.g. `valkey`, `opensearch-py`).

| Metric | Value |
|--------|-------|
| mypy mode | strict |
| `--no-implicit-reexport` | enabled (via strict) |
| `--disallow-untyped-defs` | enabled (via strict) |
| `--disallow-any-generics` | enabled (via strict) |
| Known stub gaps | `valkey`, `opensearch-py`, `croniter`, `geoip2` |

**Run**:
```bash
cd app/backend
uv run mypy app/
```

---

## Frontend (TypeScript — ESLint rules)

Configuration in `app/frontend/eslint.config.js`:

| Rule | Level | Notes |
|------|-------|-------|
| `@typescript-eslint/no-explicit-any` | **error** | Blocks `any` usage at CI |
| `@typescript-eslint/explicit-function-return-type` | **warn** | Enforces return types; allows expressions/HOF |
| `@typescript-eslint/no-unused-vars` | warn | Args prefixed `_` are exempt |

TypeScript compiler options in `tsconfig.json` provide the underlying static
type checking; ESLint rules layer on top as developer-facing guardrails.

**Run**:
```bash
cd app/frontend
npm run lint
npx tsc --noEmit
```

---

## Goals

- Backend: zero mypy errors in `app/` (strict mode, no `# type: ignore` additions)
- Frontend: zero `no-explicit-any` errors; `explicit-function-return-type` warnings
  resolved incrementally per PR

---

## Known Exceptions

| File / Module | Exception | Reason |
|---------------|-----------|--------|
| `app/backend/app/__init__.py` | `ignore_missing_imports` stubs | `importlib.metadata` stubs bundled in typeshed |
| Third-party adapters | `ignore_missing_imports` | `valkey`, `opensearch-py` lack complete type stubs |
