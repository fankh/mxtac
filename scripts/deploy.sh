#!/usr/bin/env bash
# deploy.sh — Production deployment automation for MxTac
#
# Pulls the latest images from GHCR, runs database migrations,
# performs a rolling service restart, and verifies deployment health.
# Rolls back automatically on health check failure.
#
# Usage:
#   ./scripts/deploy.sh [options]
#   ./scripts/deploy.sh --mode compose
#   ./scripts/deploy.sh --mode k3s
#   ./scripts/deploy.sh --mode compose --tag sha-abc1234
#   ./scripts/deploy.sh --mode compose --dry-run
#
# Options:
#   --mode compose     Docker Compose deployment (default)
#   --mode k3s         k3s / Kubernetes deployment
#   --tag TAG          Image tag to deploy (default: latest)
#   --skip-backup      Skip pre-deployment PostgreSQL backup
#   --skip-pull        Skip image pull (use locally cached images)
#   --dry-run          Print actions without executing any changes
#   -h, --help         Show this help message
#
# Required environment:
#   REPO_OWNER          GitHub org/user owning the GHCR packages
#                       (auto-detected from git remote if not set)
#
# Optional environment:
#   POSTGRES_PASSWORD   PostgreSQL password (required for backup only)
#   DEPLOY_HOST         Host to target for health checks (default: localhost)
#   DEPLOY_PORT         Backend API port (default: 8080)
#   K8S_NAMESPACE       Kubernetes namespace for k3s mode (default: mxtac)
#   GHCR_TOKEN          GHCR personal access token for authenticated pulls
#
# Notes:
#   - Migration rollback is NOT performed automatically (risk of data loss).
#     If needed, run: alembic downgrade <previous-revision>
#   - compose mode: brief downtime (~seconds) during backend restart.
#   - k3s mode: true rolling update with zero downtime.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
APP_DIR="$PROJECT_ROOT/app"
DEPLOY_LOG="$PROJECT_ROOT/deploy.log"
BACKUP_DIR="$PROJECT_ROOT/backups"

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# ─── Defaults ──────────────────────────────────────────────────────────────────
MODE="compose"
TAG="latest"
SKIP_BACKUP=false
SKIP_PULL=false
DRY_RUN=false
DEPLOY_HOST="${DEPLOY_HOST:-localhost}"
DEPLOY_PORT="${DEPLOY_PORT:-8080}"
K8S_NAMESPACE="${K8S_NAMESPACE:-mxtac}"
REPO_OWNER="${REPO_OWNER:-}"
MIN_DISK_GB=5
HEALTH_TIMEOUT=120   # seconds to wait for healthy state
HEALTH_INTERVAL=5    # seconds between health check polls

# Deployment state — used for rollback coordination
ROLLBACK_NEEDED=false
BACKUP_FILE=""
BACKEND_IMAGE_BASE=""
FRONTEND_IMAGE_BASE=""
BACKEND_IMAGE=""
FRONTEND_IMAGE=""
PREV_BACKEND_TAG=""
PREV_FRONTEND_TAG=""
PREV_MIGRATION_REV=""

# ─── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)        MODE="$2"; shift 2 ;;
    --mode=*)      MODE="${1#*=}"; shift ;;
    --tag)         TAG="$2"; shift 2 ;;
    --tag=*)       TAG="${1#*=}"; shift ;;
    --skip-backup) SKIP_BACKUP=true; shift ;;
    --skip-pull)   SKIP_PULL=true; shift ;;
    --dry-run)     DRY_RUN=true; shift ;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \?//' | sed -n '/^Usage:/,/^Notes:/p'
      exit 0 ;;
    *)
      echo -e "${RED}Unknown option: $1${NC}"
      echo "Run with --help for usage."
      exit 1 ;;
  esac
done

if [[ "$MODE" != "compose" && "$MODE" != "k3s" ]]; then
  echo -e "${RED}Invalid mode: '$MODE'. Use 'compose' or 'k3s'.${NC}"
  exit 1
fi

# ─── Helpers ───────────────────────────────────────────────────────────────────
print_header() {
  echo ""
  echo -e "${BLUE}═══════════════════════════════════════════════════${NC}"
  echo -e "${BLUE}  $1${NC}"
  echo -e "${BLUE}═══════════════════════════════════════════════════${NC}"
}

log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
log_step()  { echo -e "${CYAN}[STEP]${NC}  $*"; }

run_cmd() {
  if $DRY_RUN; then
    echo -e "${CYAN}[DRY-RUN]${NC} $*"
  else
    "$@"
  fi
}

# Append a structured JSON line to deploy.log
log_audit() {
  local event="$1"
  local status="${2:-info}"
  local detail="${3:-}"
  local ts; ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  local entry
  # shellcheck disable=SC2059
  entry=$(printf '{"ts":"%s","event":"%s","status":"%s","mode":"%s","tag":"%s","detail":"%s"}\n' \
    "$ts" "$event" "$status" "$MODE" "$TAG" "${detail//\"/\'}")
  if ! $DRY_RUN; then
    echo "$entry" >> "$DEPLOY_LOG"
  fi
  log_info "Audit → $event [$status]${detail:+ ($detail)}"
}

# ─── Resolve GHCR image names ──────────────────────────────────────────────────
setup_image_refs() {
  if [[ -z "$REPO_OWNER" ]]; then
    local url
    url=$(git -C "$PROJECT_ROOT" remote get-url origin 2>/dev/null || true)
    if [[ "$url" =~ github\.com[:/]([^/]+)/ ]]; then
      REPO_OWNER="${BASH_REMATCH[1]}"
      log_info "Auto-detected REPO_OWNER=$REPO_OWNER from git remote"
    else
      log_error "Cannot resolve REPO_OWNER. Set: export REPO_OWNER=<github-org>"
      exit 1
    fi
  fi
  BACKEND_IMAGE_BASE="ghcr.io/$REPO_OWNER/mxtac-backend"
  FRONTEND_IMAGE_BASE="ghcr.io/$REPO_OWNER/mxtac-frontend"
  BACKEND_IMAGE="$BACKEND_IMAGE_BASE:$TAG"
  FRONTEND_IMAGE="$FRONTEND_IMAGE_BASE:$TAG"
}

# ─── Pre-deployment checks ─────────────────────────────────────────────────────
check_tools_compose() {
  log_step "Checking required tools..."
  local missing=()
  for cmd in docker curl; do
    command -v "$cmd" &>/dev/null || missing+=("$cmd")
  done
  docker compose version &>/dev/null 2>&1 || missing+=("docker-compose-plugin")
  if [[ ${#missing[@]} -gt 0 ]]; then
    if $DRY_RUN; then
      log_warn "Missing tools (dry-run, continuing): ${missing[*]}"
    else
      log_error "Missing required tools: ${missing[*]}"
      exit 1
    fi
  else
    log_info "Tools: OK (docker, docker compose, curl)"
  fi
}

check_tools_k3s() {
  log_step "Checking required tools..."
  local missing=()
  for cmd in kubectl curl; do
    command -v "$cmd" &>/dev/null || missing+=("$cmd")
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    if $DRY_RUN; then
      log_warn "Missing tools (dry-run, continuing): ${missing[*]}"
    else
      log_error "Missing required tools: ${missing[*]}"
      exit 1
    fi
  else
    log_info "Tools: OK (kubectl, curl)"
  fi
}

check_disk_space() {
  local mount="${1:-/}"
  local available_gb

  # Fall back to / if the specified path does not exist or is not a mount point
  if ! df -BG "$mount" &>/dev/null; then
    log_warn "Mount '$mount' not found; checking root filesystem instead."
    mount="/"
  fi

  # df -BG outputs size in GiB blocks; strip the G suffix
  available_gb=$(df -BG "$mount" 2>/dev/null | awk 'NR==2 {gsub(/G/,"",$4); print $4}')
  available_gb="${available_gb:-0}"

  log_info "Disk space on $mount: ${available_gb}GB available (minimum: ${MIN_DISK_GB}GB)"
  if [[ "$available_gb" -lt "$MIN_DISK_GB" ]]; then
    if $DRY_RUN; then
      log_warn "Insufficient disk space (dry-run, continuing): ${available_gb}GB < ${MIN_DISK_GB}GB"
    else
      log_error "Insufficient disk space: ${available_gb}GB < ${MIN_DISK_GB}GB required"
      exit 1
    fi
  fi
}

check_db_compose() {
  log_step "Verifying database connectivity..."
  if $DRY_RUN; then
    echo -e "${CYAN}[DRY-RUN]${NC} docker compose exec -T postgres pg_isready -U mxtac"
    return
  fi
  if ! docker compose -f "$APP_DIR/docker-compose.prod.yml" \
      exec -T postgres pg_isready -U mxtac &>/dev/null; then
    log_error "PostgreSQL is not ready. Is the postgres container running?"
    exit 1
  fi
  log_info "Database connectivity: OK"
}

check_db_k3s() {
  log_step "Verifying database connectivity..."
  if $DRY_RUN; then
    echo -e "${CYAN}[DRY-RUN]${NC} kubectl exec -n $K8S_NAMESPACE deploy/postgres -- pg_isready -U mxtac"
    return
  fi
  if ! kubectl exec -n "$K8S_NAMESPACE" deploy/postgres -- pg_isready -U mxtac &>/dev/null; then
    log_error "PostgreSQL is not ready in namespace $K8S_NAMESPACE."
    exit 1
  fi
  log_info "Database connectivity: OK"
}

# ─── Backup ────────────────────────────────────────────────────────────────────
backup_compose() {
  if $SKIP_BACKUP; then
    log_warn "Skipping pre-deployment backup (--skip-backup)."
    return
  fi
  mkdir -p "$BACKUP_DIR"
  local ts; ts=$(date +%Y%m%d-%H%M%S)
  BACKUP_FILE="$BACKUP_DIR/mxtac-pre-deploy-$ts.sql.gz"
  log_step "Creating PostgreSQL backup → $BACKUP_FILE"
  # pg_dump connects locally within the container (no password needed)
  run_cmd bash -c "docker compose -f '$APP_DIR/docker-compose.prod.yml' \
    exec -T postgres pg_dump -U mxtac mxtac | gzip > '$BACKUP_FILE'"
  if ! $DRY_RUN; then
    log_info "Backup complete: $(du -sh "$BACKUP_FILE" | cut -f1)"
  fi
}

backup_k3s() {
  if $SKIP_BACKUP; then
    log_warn "Skipping pre-deployment backup (--skip-backup)."
    return
  fi
  mkdir -p "$BACKUP_DIR"
  local ts; ts=$(date +%Y%m%d-%H%M%S)
  BACKUP_FILE="$BACKUP_DIR/mxtac-pre-deploy-$ts.sql.gz"
  log_step "Creating PostgreSQL backup → $BACKUP_FILE"
  run_cmd bash -c "kubectl exec -n '$K8S_NAMESPACE' deploy/postgres -- \
    pg_dump -U mxtac mxtac | gzip > '$BACKUP_FILE'"
  if ! $DRY_RUN; then
    log_info "Backup complete: $(du -sh "$BACKUP_FILE" | cut -f1)"
  fi
}

# ─── Image management ──────────────────────────────────────────────────────────
save_rollback_images() {
  if $SKIP_PULL; then return; fi
  log_step "Saving current images for potential rollback..."
  PREV_BACKEND_TAG="$BACKEND_IMAGE_BASE:rollback"
  PREV_FRONTEND_TAG="$FRONTEND_IMAGE_BASE:rollback"
  # Tag currently deployed images as :rollback — silently skip if image absent
  docker tag "$BACKEND_IMAGE_BASE:latest" "$PREV_BACKEND_TAG" 2>/dev/null \
    && log_info "Saved backend rollback image: $PREV_BACKEND_TAG" || true
  docker tag "$FRONTEND_IMAGE_BASE:latest" "$PREV_FRONTEND_TAG" 2>/dev/null \
    && log_info "Saved frontend rollback image: $PREV_FRONTEND_TAG" || true
}

pull_images() {
  if $SKIP_PULL; then
    log_warn "Skipping image pull (--skip-pull). Using locally cached images."
    return
  fi

  log_step "Authenticating to GHCR..."
  if [[ -n "${GHCR_TOKEN:-}" ]]; then
    run_cmd echo "$GHCR_TOKEN" | docker login ghcr.io -u "$REPO_OWNER" --password-stdin
    log_info "GHCR authentication: OK"
  else
    log_warn "GHCR_TOKEN not set — assuming public images or pre-existing docker login."
  fi

  log_step "Pulling images from GHCR..."
  run_cmd docker pull "$BACKEND_IMAGE"
  run_cmd docker pull "$FRONTEND_IMAGE"

  # Ensure the :latest tag always resolves to the deployed version so that
  # docker compose up (without explicit image override) uses the new images.
  if [[ "$TAG" != "latest" ]]; then
    run_cmd docker tag "$BACKEND_IMAGE" "$BACKEND_IMAGE_BASE:latest"
    run_cmd docker tag "$FRONTEND_IMAGE" "$FRONTEND_IMAGE_BASE:latest"
    log_info "Tagged $TAG → $BACKEND_IMAGE_BASE:latest, $FRONTEND_IMAGE_BASE:latest"
  fi
}

# ─── Migrations ────────────────────────────────────────────────────────────────
record_migration_head() {
  log_step "Recording current database migration revision..."
  if $DRY_RUN; then
    echo -e "${CYAN}[DRY-RUN]${NC} docker compose exec -T backend alembic current"
    return
  fi
  # Capture the current head revision from the running backend (if online).
  # Ignore errors — backend may not be running on a fresh deployment.
  PREV_MIGRATION_REV=$(
    docker compose -f "$APP_DIR/docker-compose.prod.yml" \
      exec -T backend alembic current 2>/dev/null \
    | awk '{print $1}' | head -1 || echo "unknown"
  )
  log_info "Current migration revision: ${PREV_MIGRATION_REV:-none}"
}

run_migrations_compose() {
  log_step "Running database migrations (alembic upgrade head)..."
  # Run in a disposable container that shares the backend's service configuration.
  # BACKEND_IMAGE and FRONTEND_IMAGE are exported so compose picks them up.
  run_cmd env \
    BACKEND_IMAGE="$BACKEND_IMAGE" \
    FRONTEND_IMAGE="$FRONTEND_IMAGE" \
    docker compose -f "$APP_DIR/docker-compose.prod.yml" \
    run --rm --no-build \
    backend alembic upgrade head
  log_info "Migrations: complete"
}

run_migrations_k3s() {
  log_step "Running database migrations via Kubernetes Job..."
  local job_name="mxtac-migrate-$(date +%s)"
  run_cmd kubectl run "$job_name" \
    -n "$K8S_NAMESPACE" \
    --image="$BACKEND_IMAGE" \
    --restart=Never \
    --rm \
    --attach \
    --pod-running-timeout=120s \
    -- alembic upgrade head
  log_info "Migrations: complete"
}

# ─── Rolling restart — Docker Compose ──────────────────────────────────────────
# Rolling strategy for single-host compose deployments:
#   1. Restart backend first (brief ~5-10 s downtime while new process initialises)
#   2. Wait for backend to report healthy before touching other services
#   3. Restart frontend (static-file container, no downtime risk)
#   4. Reload nginx config (graceful reload, in-flight requests are not dropped)
rolling_restart_compose() {
  log_step "Rolling restart — backend..."
  run_cmd env \
    BACKEND_IMAGE="$BACKEND_IMAGE" \
    FRONTEND_IMAGE="$FRONTEND_IMAGE" \
    docker compose -f "$APP_DIR/docker-compose.prod.yml" \
    up -d --no-build --no-deps backend

  wait_healthy_container "backend"

  log_step "Rolling restart — frontend..."
  run_cmd env \
    BACKEND_IMAGE="$BACKEND_IMAGE" \
    FRONTEND_IMAGE="$FRONTEND_IMAGE" \
    docker compose -f "$APP_DIR/docker-compose.prod.yml" \
    up -d --no-build --no-deps frontend

  log_step "Reloading nginx..."
  if $DRY_RUN; then
    echo -e "${CYAN}[DRY-RUN]${NC} nginx -s reload"
  else
    # Prefer graceful reload; fall back to container restart
    docker compose -f "$APP_DIR/docker-compose.prod.yml" \
      exec -T nginx nginx -s reload 2>/dev/null \
    || docker compose -f "$APP_DIR/docker-compose.prod.yml" restart nginx
  fi
  log_info "Rolling restart complete."
}

# Wait until a compose service's container reports 'healthy' (Docker healthcheck).
wait_healthy_container() {
  local service="$1"
  local elapsed=0

  if $DRY_RUN; then
    echo -e "${CYAN}[DRY-RUN]${NC} wait for $service docker healthcheck → healthy"
    return
  fi

  log_info "Waiting for '$service' to become healthy (timeout: ${HEALTH_TIMEOUT}s)..."
  while [[ $elapsed -lt $HEALTH_TIMEOUT ]]; do
    local container_id health_status
    container_id=$(docker compose -f "$APP_DIR/docker-compose.prod.yml" ps -q "$service" 2>/dev/null | head -1 || true)
    if [[ -n "$container_id" ]]; then
      health_status=$(docker inspect --format='{{.State.Health.Status}}' "$container_id" 2>/dev/null || echo "unknown")
      if [[ "$health_status" == "healthy" ]]; then
        log_info "'$service' is healthy (${elapsed}s elapsed)."
        return 0
      fi
    fi
    sleep "$HEALTH_INTERVAL"
    elapsed=$((elapsed + HEALTH_INTERVAL))
    printf '.'
  done
  echo ""
  log_error "'$service' did not become healthy within ${HEALTH_TIMEOUT}s."
  return 1
}

rollback_compose() {
  ROLLBACK_NEEDED=true
  log_warn "Rolling back to previous images..."

  # Restore the :rollback tags as :latest so compose picks them up
  run_cmd docker tag "$PREV_BACKEND_TAG"  "$BACKEND_IMAGE_BASE:latest"  2>/dev/null || true
  run_cmd docker tag "$PREV_FRONTEND_TAG" "$FRONTEND_IMAGE_BASE:latest" 2>/dev/null || true

  # Restart services with the restored images
  run_cmd env \
    BACKEND_IMAGE="$BACKEND_IMAGE_BASE:rollback" \
    FRONTEND_IMAGE="$FRONTEND_IMAGE_BASE:rollback" \
    docker compose -f "$APP_DIR/docker-compose.prod.yml" \
    up -d --no-build --no-deps backend frontend 2>/dev/null || true

  # Reload nginx to pick up any reverted frontend static files
  if ! $DRY_RUN; then
    docker compose -f "$APP_DIR/docker-compose.prod.yml" \
      exec -T nginx nginx -s reload 2>/dev/null \
    || docker compose -f "$APP_DIR/docker-compose.prod.yml" restart nginx 2>/dev/null || true
  fi

  if [[ -n "$PREV_MIGRATION_REV" && "$PREV_MIGRATION_REV" != "unknown" ]]; then
    log_warn "────────────────────────────────────────────────────────"
    log_warn "Database migrations are NOT automatically rolled back."
    log_warn "Previous revision: $PREV_MIGRATION_REV"
    log_warn "To roll back manually:  alembic downgrade $PREV_MIGRATION_REV"
    log_warn "────────────────────────────────────────────────────────"
  fi

  log_audit "rollback" "completed" "restored backend/frontend to :rollback images"
}

# ─── Rolling restart — k3s ─────────────────────────────────────────────────────
# k3s/Kubernetes performs a true rolling update: new pods are started before
# old pods are terminated, achieving zero downtime.
rolling_restart_k3s() {
  log_step "Updating deployment images in namespace $K8S_NAMESPACE..."
  run_cmd kubectl -n "$K8S_NAMESPACE" set image \
    deployment/mxtac-backend backend="$BACKEND_IMAGE"
  run_cmd kubectl -n "$K8S_NAMESPACE" set image \
    deployment/mxtac-frontend frontend="$FRONTEND_IMAGE"

  log_step "Waiting for rollouts to complete..."
  run_cmd kubectl -n "$K8S_NAMESPACE" rollout status \
    deployment/mxtac-backend --timeout="${HEALTH_TIMEOUT}s"
  run_cmd kubectl -n "$K8S_NAMESPACE" rollout status \
    deployment/mxtac-frontend --timeout="${HEALTH_TIMEOUT}s"
  log_info "Rolling restart complete."
}

rollback_k3s() {
  ROLLBACK_NEEDED=true
  log_warn "Rolling back k3s deployments..."
  run_cmd kubectl -n "$K8S_NAMESPACE" rollout undo deployment/mxtac-backend  2>/dev/null || true
  run_cmd kubectl -n "$K8S_NAMESPACE" rollout undo deployment/mxtac-frontend 2>/dev/null || true
  if ! $DRY_RUN; then
    kubectl -n "$K8S_NAMESPACE" rollout status \
      deployment/mxtac-backend --timeout="${HEALTH_TIMEOUT}s" 2>/dev/null || true
  fi

  if [[ -n "$PREV_MIGRATION_REV" && "$PREV_MIGRATION_REV" != "unknown" ]]; then
    log_warn "────────────────────────────────────────────────────────"
    log_warn "Database migrations are NOT automatically rolled back."
    log_warn "Previous revision: $PREV_MIGRATION_REV"
    log_warn "To roll back manually:  alembic downgrade $PREV_MIGRATION_REV"
    log_warn "────────────────────────────────────────────────────────"
  fi

  log_audit "rollback" "completed" "kubectl rollout undo applied"
}

# ─── Post-deployment verification ──────────────────────────────────────────────
verify_ready_endpoint() {
  local url="http://$DEPLOY_HOST:$DEPLOY_PORT/ready"
  local elapsed=0

  if $DRY_RUN; then
    echo -e "${CYAN}[DRY-RUN]${NC} curl -sf $url  → expect HTTP 200"
    return
  fi

  log_step "Verifying /ready endpoint at $url..."
  while [[ $elapsed -lt $HEALTH_TIMEOUT ]]; do
    local http_code
    http_code=$(curl -sf -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
    if [[ "$http_code" == "200" ]]; then
      log_info "/ready returned HTTP 200 after ${elapsed}s — deployment verified."
      return 0
    fi
    log_info "  HTTP $http_code — retrying in ${HEALTH_INTERVAL}s (${elapsed}/${HEALTH_TIMEOUT}s)"
    sleep "$HEALTH_INTERVAL"
    elapsed=$((elapsed + HEALTH_INTERVAL))
  done
  log_error "/ready did not return HTTP 200 within ${HEALTH_TIMEOUT}s."
  return 1
}

verify_services_compose() {
  log_step "Verifying all critical services are running..."
  if $DRY_RUN; then
    echo -e "${CYAN}[DRY-RUN]${NC} docker compose ps"
    return
  fi
  docker compose -f "$APP_DIR/docker-compose.prod.yml" ps

  local failed=()
  for svc in backend postgres redis nginx; do
    local container_id state
    container_id=$(docker compose -f "$APP_DIR/docker-compose.prod.yml" ps -q "$svc" 2>/dev/null | head -1 || true)
    if [[ -z "$container_id" ]]; then
      failed+=("$svc (not found)")
      continue
    fi
    state=$(docker inspect --format='{{.State.Status}}' "$container_id" 2>/dev/null || echo "unknown")
    if [[ "$state" != "running" ]]; then
      failed+=("$svc ($state)")
    fi
  done

  if [[ ${#failed[@]} -gt 0 ]]; then
    log_error "Services not running: ${failed[*]}"
    return 1
  fi
  log_info "All critical services are running."
}

verify_services_k3s() {
  log_step "Verifying pod readiness in namespace $K8S_NAMESPACE..."
  if $DRY_RUN; then
    echo -e "${CYAN}[DRY-RUN]${NC} kubectl get pods -n $K8S_NAMESPACE"
    return
  fi
  kubectl -n "$K8S_NAMESPACE" get pods
  kubectl -n "$K8S_NAMESPACE" wait pod \
    --for=condition=Ready \
    -l "app in (mxtac-backend,mxtac-frontend)" \
    --timeout="${HEALTH_TIMEOUT}s"
  log_info "All pods are ready."
}

# ─── Deployment summary ────────────────────────────────────────────────────────
print_deploy_summary() {
  print_header "MxTac Deployment — $(date '+%Y-%m-%d %H:%M:%S %Z')"
  echo "  Mode:          $MODE"
  echo "  Tag:           $TAG"
  echo "  Backend:       $BACKEND_IMAGE"
  echo "  Frontend:      $FRONTEND_IMAGE"
  echo "  Health URL:    http://$DEPLOY_HOST:$DEPLOY_PORT/ready"
  echo "  Skip backup:   $SKIP_BACKUP"
  echo "  Skip pull:     $SKIP_PULL"
  if $DRY_RUN; then
    echo ""
    echo -e "  ${CYAN}*** DRY-RUN MODE — no changes will be made ***${NC}"
  fi
  echo ""
}

# ─── Unexpected-failure trap ───────────────────────────────────────────────────
on_exit() {
  local exit_code=$?
  if [[ $exit_code -ne 0 ]] && ! $ROLLBACK_NEEDED && ! $DRY_RUN; then
    log_error "Unexpected failure (exit $exit_code) before planned rollback."
    log_audit "deploy_error" "error" "unexpected exit=$exit_code; attempting auto-rollback"
    if [[ "$MODE" == "compose" ]]; then
      rollback_compose 2>/dev/null || true
    else
      rollback_k3s 2>/dev/null || true
    fi
  fi
}
trap on_exit EXIT

# ─── Main ──────────────────────────────────────────────────────────────────────
main() {
  setup_image_refs
  print_deploy_summary
  log_audit "deploy_start" "info" "mode=$MODE tag=$TAG host=$DEPLOY_HOST:$DEPLOY_PORT"

  # ── 1. Pre-deployment checks ─────────────────────────────────────────────────
  print_header "1/5 — Pre-deployment Checks"
  if [[ "$MODE" == "compose" ]]; then
    check_tools_compose
    local docker_root
    docker_root=$(docker info --format '{{.DockerRootDir}}' 2>/dev/null || echo "/var/lib/docker")
    check_disk_space "$docker_root"
    check_db_compose
    backup_compose
  else
    check_tools_k3s
    check_disk_space "/var/lib/rancher/k3s"
    check_db_k3s
    backup_k3s
  fi
  log_audit "pre_checks" "ok"

  # ── 2. Image pull ────────────────────────────────────────────────────────────
  print_header "2/5 — Image Pull"
  if $SKIP_PULL; then
    log_warn "Skipping image pull."
  else
    save_rollback_images
    pull_images
  fi
  log_audit "images_pulled" "ok" "$BACKEND_IMAGE $FRONTEND_IMAGE"

  # ── 3. Database migrations ───────────────────────────────────────────────────
  print_header "3/5 — Database Migrations"
  if [[ "$MODE" == "compose" ]]; then
    record_migration_head
    run_migrations_compose
  else
    record_migration_head
    run_migrations_k3s
  fi
  log_audit "migrations" "ok" "prev=$PREV_MIGRATION_REV"

  # ── 4. Rolling restart ───────────────────────────────────────────────────────
  print_header "4/5 — Rolling Restart"
  if [[ "$MODE" == "compose" ]]; then
    rolling_restart_compose
  else
    rolling_restart_k3s
  fi
  log_audit "restart" "ok"

  # ── 5. Post-deployment verification ─────────────────────────────────────────
  print_header "5/5 — Post-deployment Verification"
  local health_ok=true

  if ! verify_ready_endpoint; then
    health_ok=false
  else
    if [[ "$MODE" == "compose" ]]; then
      verify_services_compose || health_ok=false
    else
      verify_services_k3s || health_ok=false
    fi
  fi

  if ! $health_ok; then
    log_error "Post-deployment health check failed. Initiating rollback."
    log_audit "health_check" "failed" "triggering rollback"
    if [[ "$MODE" == "compose" ]]; then
      rollback_compose
    else
      rollback_k3s
    fi
    log_error "Deployment FAILED and was rolled back."
    log_audit "deploy_end" "failed" "rolled back; previous revision=$PREV_MIGRATION_REV"
    trap - EXIT
    exit 1
  fi

  # ── Success ──────────────────────────────────────────────────────────────────
  print_header "Deployment Complete"
  log_info "MxTac deployed successfully."
  log_info "  Tag:    $TAG"
  log_info "  Images: $BACKEND_IMAGE"
  log_info "          $FRONTEND_IMAGE"
  log_info "  Health: http://$DEPLOY_HOST:$DEPLOY_PORT/ready"
  [[ -n "$BACKUP_FILE" ]] && log_info "  Backup: $BACKUP_FILE"
  echo ""
  log_audit "deploy_end" "success" "tag=$TAG"

  trap - EXIT
}

main "$@"
