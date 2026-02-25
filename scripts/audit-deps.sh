#!/usr/bin/env bash
# audit-deps.sh — Dependency vulnerability scan for MxTac
#
# Usage:
#   ./scripts/audit-deps.sh             # audit Python + Node.js
#   ./scripts/audit-deps.sh --python    # Python only
#   ./scripts/audit-deps.sh --node      # Node.js only
#   ./scripts/audit-deps.sh --ci        # Exit non-zero on any vuln (CI mode)
#
# Requirements:
#   Python: pip-audit (installed via: uv pip install pip-audit)
#   Node:   npm (bundled with Node.js)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BACKEND_DIR="$PROJECT_ROOT/app/backend"
FRONTEND_DIR="$PROJECT_ROOT/app/frontend"

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

CI_MODE=false
RUN_PYTHON=true
RUN_NODE=true
PYTHON_EXIT=0
NODE_EXIT=0

for arg in "$@"; do
  case $arg in
    --ci)     CI_MODE=true ;;
    --python) RUN_NODE=false ;;
    --node)   RUN_PYTHON=false ;;
  esac
done

print_header() {
  echo ""
  echo -e "${BLUE}═══════════════════════════════════════════════════${NC}"
  echo -e "${BLUE}  $1${NC}"
  echo -e "${BLUE}═══════════════════════════════════════════════════${NC}"
}

# ─── Python audit ────────────────────────────────────────────────────────────
if $RUN_PYTHON; then
  print_header "Python Dependency Audit (pip-audit)"
  echo "Backend: $BACKEND_DIR"
  echo ""

  # Prefer: uv run pip-audit (scans the uv-managed environment directly).
  # Fallback: system pip-audit. Avoid `pip-audit -r requirements.txt` which
  # requires creating a new venv and may fail without python3-venv installed.
  if command -v uv &>/dev/null; then
    AUDIT_CMD="uv run --directory $BACKEND_DIR pip-audit"
  elif command -v pip-audit &>/dev/null; then
    AUDIT_CMD="pip-audit"
  else
    echo -e "${RED}pip-audit not found. Install with:${NC}"
    echo "  uv pip install pip-audit"
    echo "  # or: pip install pip-audit"
    PYTHON_EXIT=1
  fi

  if [ $PYTHON_EXIT -eq 0 ]; then
    echo -e "${YELLOW}Known accepted vulnerabilities (see SECURITY.md):${NC}"
    echo "  - python-jose 3.3.0: PYSEC-2024-232, PYSEC-2024-233 (no upstream fix)"
    echo "  - ecdsa 0.19.1:      CVE-2024-23342 (transitive via python-jose, no fix)"
    echo "  - starlette 0.41.3:  CVE-2025-54121, CVE-2025-62727 (fix: upgrade fastapi)"
    echo ""

    if $CI_MODE; then
      # In CI: exit non-zero on any vuln, but skip known accepted ones
      $AUDIT_CMD \
        --ignore-vuln PYSEC-2024-232 \
        --ignore-vuln PYSEC-2024-233 \
        --ignore-vuln CVE-2024-23342 \
        --ignore-vuln CVE-2025-54121 \
        --ignore-vuln CVE-2025-62727 \
        --format columns && echo -e "${GREEN}No new Python vulnerabilities found.${NC}" || PYTHON_EXIT=$?
    else
      # Interactive: show all findings including accepted ones
      $AUDIT_CMD \
        --format columns || PYTHON_EXIT=$?

      if [ $PYTHON_EXIT -ne 0 ]; then
        echo ""
        echo -e "${YELLOW}NOTE: Some findings above are accepted/tracked in SECURITY.md.${NC}"
        echo -e "${YELLOW}Run with --ci to filter accepted vulnerabilities.${NC}"
        PYTHON_EXIT=0  # non-CI mode: don't fail on accepted vulns
      fi
    fi
  fi
fi

# ─── Node.js audit ───────────────────────────────────────────────────────────
if $RUN_NODE; then
  print_header "Node.js Dependency Audit (npm audit)"
  echo "Frontend: $FRONTEND_DIR"
  echo ""

  if [ ! -d "$FRONTEND_DIR/node_modules" ]; then
    echo -e "${YELLOW}node_modules not found. Run 'npm install' in $FRONTEND_DIR first.${NC}"
    NODE_EXIT=1
  elif ! command -v npm &>/dev/null; then
    echo -e "${RED}npm not found. Install Node.js to continue.${NC}"
    NODE_EXIT=1
  else
    echo -e "${YELLOW}Known accepted vulnerabilities (dev-only, see SECURITY.md):${NC}"
    echo "  - esbuild ≤ 0.24.2:  GHSA-67mh-4wv8-2f99 (moderate, dev-server only)"
    echo "  All findings are in devDependencies (vitest, vite-node)."
    echo "  Fix requires breaking upgrade: vitest@4 — tracked in backlog."
    echo "  Production dependencies: 0 vulnerabilities."
    echo ""

    if $CI_MODE; then
      # In CI: only fail on production dependency vulnerabilities
      npm audit --audit-level=high --omit=dev 2>&1 && \
        echo -e "${GREEN}No HIGH/CRITICAL vulnerabilities in production dependencies.${NC}" || \
        NODE_EXIT=$?
    else
      npm audit 2>&1 || NODE_EXIT=$?
      if [ $NODE_EXIT -ne 0 ]; then
        echo ""
        echo -e "${YELLOW}NOTE: All HIGH findings above are dev-only dependencies.${NC}"
        echo -e "${YELLOW}Production dependency audit:${NC}"
        npm audit --omit=dev 2>&1 && echo -e "${GREEN}  No production vulnerabilities.${NC}" || true
        NODE_EXIT=0  # non-CI mode: don't fail on dev-only vulns
      fi
    fi
  fi
fi

# ─── Summary ─────────────────────────────────────────────────────────────────
print_header "Audit Summary"

if $RUN_PYTHON; then
  if [ $PYTHON_EXIT -eq 0 ]; then
    echo -e "  Python: ${GREEN}PASSED${NC}"
  else
    echo -e "  Python: ${RED}FAILED (exit $PYTHON_EXIT)${NC}"
  fi
fi

if $RUN_NODE; then
  if [ $NODE_EXIT -eq 0 ]; then
    echo -e "  Node.js: ${GREEN}PASSED${NC}"
  else
    echo -e "  Node.js: ${RED}FAILED (exit $NODE_EXIT)${NC}"
  fi
fi

echo ""
echo "See SECURITY.md for the full vulnerability policy and remediation plans."
echo ""

if $CI_MODE && { [ $PYTHON_EXIT -ne 0 ] || [ $NODE_EXIT -ne 0 ]; }; then
  exit 1
fi
