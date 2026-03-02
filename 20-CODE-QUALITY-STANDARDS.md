# Code Quality Standards

> **Established:** 2026-02-21 (TASK-0.5.3)
> **Version source:** `VERSION` at repo root (current: `2.0.0`)

---

## 1. Version Management

The canonical version is maintained in a single `VERSION` file at the repository root.

| Artifact | Source |
|----------|--------|
| `VERSION` | **Single source of truth** |
| `app/backend/app/__init__.py` | Reads `VERSION` at import time via `Path(__file__).parents[3] / "VERSION"` |
| `pyproject.toml` | `dynamic = ["version"]` → `{attr = "app.__version__"}` |
| `package.json` | Update manually alongside `VERSION` on each release |

### Updating the Version

```bash
echo "2.1.0" > VERSION
# Then update package.json "version" field to match
```

---

## 2. Python Type Coverage Baseline

**Tool:** mypy `1.13.0` — `strict = true` mode

**Baseline snapshot (2026-02-21):**

| Metric | Count |
|--------|-------|
| Source files checked | 97 |
| Files with errors | 52 |
| Total errors | 390 |

**Error breakdown by category:**

| Category | Count | Description |
|----------|-------|-------------|
| `[type-arg]` | 194 | Missing generic type parameters (e.g., `dict` → `dict[str, Any]`) |
| `[no-untyped-def]` | 124 | Missing function type annotations |
| `[arg-type]` | 13 | Incompatible argument types |
| `[valid-type]` | 9 | Invalid type expressions |
| `[no-any-return]` | 9 | Implicit `Any` return in typed function |
| `[attr-defined]` | 9 | Attribute access on unresolved type |
| `[no-untyped-call]` | 8 | Call to untyped function from typed context |
| `[assignment]` | 8 | Incompatible assignments |

**Primary remediation targets:**
1. `app/api/v1/endpoints/assets.py` — untyped endpoint functions + bare `dict` usage
2. `app/main.py` — missing function annotations, `dict` type args

**Goal:** Reduce to ≤ 50 errors per sprint.

---

## 3. TypeScript Type Coverage Baseline

**Tool:** typescript-eslint `8.x` via ESLint `9.x`

**Baseline snapshot (2026-02-21):**

| Rule | Severity | Violations |
|------|----------|------------|
| `@typescript-eslint/no-explicit-any` | **error** | **0** — codebase is `any`-clean |
| `@typescript-eslint/explicit-function-return-type` | warn | 105 |
| `@typescript-eslint/no-unused-vars` | warn | 8 |
| `react-hooks/exhaustive-deps` | warn | 2 |
| `react-refresh/only-export-components` | warn | 1 |

**Key finding:** Zero `any` type usages — the ESLint rule is promoted to `error` without breaking the build.

**`explicit-function-return-type` rule options** (see `eslint.config.js`):
- `allowExpressions: true` — permits inline callbacks
- `allowTypedFunctionExpressions: true` — permits typed variable declarations
- `allowHigherOrderFunctions: true` — permits HOF return types inferred
- `allowDirectConstAssertionInArrowFunctions: true` — permits `as const` arrow functions
- `allowConciseArrowFunctionExpressionsStartingWithVoid: true` — permits `void` arrow callbacks

**Goal:** Reduce `explicit-function-return-type` warnings to ≤ 20 over the next sprint by annotating React component and hook return types.

---

## 4. ESLint Configuration

Location: `app/frontend/eslint.config.js`

| Rule | Level | Notes |
|------|-------|-------|
| `@typescript-eslint/no-explicit-any` | **error** | Zero tolerance; upgraded from warn in TASK-0.5.3 |
| `@typescript-eslint/explicit-function-return-type` | warn | Added in TASK-0.5.3; see options above |
| `@typescript-eslint/no-unused-vars` | warn | Ignores `_`-prefixed args |
| `react-hooks/exhaustive-deps` | warn | React hooks dependency checks |
| `react-refresh/only-export-components` | warn | Vite HMR compatibility |

---

## 5. Dependency Alignment

`pyproject.toml` and `requirements.txt` are kept in sync:

- **`pyproject.toml`** — version constraints (lower bounds or pinned) for package metadata and `uv`/`pip` resolution
- **`requirements.txt`** — exact pinned versions for reproducible deployments

Run `uv pip compile` to regenerate pinned requirements after updating `pyproject.toml`.

**Discrepancy check (TASK-0.5.3 alignment):**

| Package | pyproject.toml | requirements.txt |
|---------|---------------|-----------------|
| `pydantic[email]` | `==2.10.3` | `==2.10.3` ✓ |
| `aiohttp` | `==3.13.3` | `==3.13.3` ✓ |
| `pyyaml` | `==6.0.3` | `==6.0.3` ✓ |
| `aiosqlite` | `==0.22.1` | `==0.22.1` ✓ |
| `prometheus-client` | `==0.24.1` | `==0.24.1` ✓ |
| `opensearch-py[async]` | `==3.1.0` | `==3.1.0` ✓ |
| `valkey` | `==6.1.1` | `==6.1.1` ✓ |
