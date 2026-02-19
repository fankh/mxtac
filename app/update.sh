#!/usr/bin/env bash
# =============================================================================
# MxTac — Zero-Downtime Update
# Usage: sudo bash update.sh
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; BOLD='\033[1m'; NC='\033[0m'
log() { echo -e "${GREEN}[update]${NC} $*"; }
err() { echo -e "${RED}[ERR]${NC} $*" >&2; }

DEPLOY_DIR="/opt/mxtac"
REPO_DIR="$(cd "$(dirname "$0")" && pwd)"

[[ $EUID -ne 0 ]] && { err "Run as root: sudo bash update.sh"; exit 1; }

cd "${DEPLOY_DIR}"

log "Syncing updated source files..."
rsync -a --exclude='.venv' --exclude='node_modules' --exclude='__pycache__' \
  --exclude='.git' --exclude='*.pyc' --exclude='.env' \
  "${REPO_DIR}/" "${DEPLOY_DIR}/"

log "Rebuilding images..."
docker compose build --quiet

log "Rolling update — backend..."
docker compose up -d --no-deps --build backend

log "Rolling update — frontend..."
docker compose up -d --no-deps --build frontend

log "Running migrations..."
docker compose exec -T backend sh -c "cd /app && alembic upgrade head"

log "Reloading Nginx..."
docker compose exec -T nginx nginx -s reload

log "Update complete."
docker compose ps
