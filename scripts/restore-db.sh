#!/usr/bin/env bash
# restore-db.sh — PostgreSQL restore script for MxTac
#
# Usage:
#   ./scripts/restore-db.sh <backup-file>
#   ./scripts/restore-db.sh /var/backups/mxtac/mxtac_backup_2024-01-15_02-00.sql.gz
#
# Options:
#   -y, --yes          Skip confirmation prompt (non-interactive)
#   --host HOST        PostgreSQL host (env: PGHOST; default: localhost)
#   --port PORT        PostgreSQL port (env: PGPORT; default: 5432)
#   --user USER        App database user (env: PGUSER; default: mxtac)
#   --admin-user USER  Admin user for DROP/CREATE database (env: PGADMINUSER; default: postgres)
#   --db-name NAME     Database to restore into (env: PGDATABASE; default: mxtac)
#   -h, --help         Show this help message
#
# Environment variables:
#   PGHOST             PostgreSQL host          (default: localhost)
#   PGPORT             PostgreSQL port          (default: 5432)
#   PGUSER             App database user        (default: mxtac)
#   PGPASSWORD         App user password
#   PGADMINUSER        Admin user for DROP/CREATE (default: postgres)
#   PGADMINPASSWORD    Admin user password
#   PGDATABASE         Database name            (default: mxtac)
#
# WARNING: This script DROPS and RECREATES the target database.
#          ALL EXISTING DATA WILL BE PERMANENTLY LOST.
#          A pre-restore backup is strongly recommended.
#
# Process:
#   1. Validate the backup file
#   2. Confirm the destructive operation (unless -y/--yes)
#   3. Terminate active connections to the database
#   4. Drop the database
#   5. Create a fresh empty database
#   6. Restore from the compressed backup
#
# Notes:
#   - The admin user (--admin-user) must have CREATEDB and CONNECT privileges
#     on the postgres maintenance database
#   - The app user (--user) must be the database owner or have CONNECT + schema
#     privileges on the restored database
#   - psql must be installed (package: postgresql-client)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# ─── Defaults ────────────────────────────────────────────────────────────────
PG_HOST="${PGHOST:-localhost}"
PG_PORT="${PGPORT:-5432}"
PG_USER="${PGUSER:-mxtac}"
PG_ADMIN_USER="${PGADMINUSER:-postgres}"
PG_DB="${PGDATABASE:-mxtac}"
CONFIRM=false
BACKUP_FILE=""

# ─── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { echo -e "$(date -u '+%Y-%m-%dT%H:%M:%SZ') ${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "$(date -u '+%Y-%m-%dT%H:%M:%SZ') ${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "$(date -u '+%Y-%m-%dT%H:%M:%SZ') ${RED}[ERROR]${NC} $*" >&2; }

# ─── Argument parsing ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    -y|--yes)          CONFIRM=true; shift ;;
    --host)            PG_HOST="$2"; shift 2 ;;
    --host=*)          PG_HOST="${1#*=}"; shift ;;
    --port)            PG_PORT="$2"; shift 2 ;;
    --port=*)          PG_PORT="${1#*=}"; shift ;;
    --user)            PG_USER="$2"; shift 2 ;;
    --user=*)          PG_USER="${1#*=}"; shift ;;
    --admin-user)      PG_ADMIN_USER="$2"; shift 2 ;;
    --admin-user=*)    PG_ADMIN_USER="${1#*=}"; shift ;;
    --db-name)         PG_DB="$2"; shift 2 ;;
    --db-name=*)       PG_DB="${1#*=}"; shift ;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \?//'
      exit 0 ;;
    -*)
      log_error "Unknown option: $1"
      echo "Run with --help for usage."
      exit 1 ;;
    *)
      if [[ -z "$BACKUP_FILE" ]]; then
        BACKUP_FILE="$1"
        shift
      else
        log_error "Unexpected argument: $1"
        exit 1
      fi ;;
  esac
done

# ─── Validate inputs ──────────────────────────────────────────────────────────
if [[ -z "$BACKUP_FILE" ]]; then
  log_error "No backup file specified."
  echo ""
  echo "Usage: $0 <backup-file> [options]"
  echo "Run with --help for full usage."
  exit 1
fi

if [[ ! -f "$BACKUP_FILE" ]]; then
  log_error "Backup file not found: $BACKUP_FILE"
  exit 1
fi

if [[ ! -r "$BACKUP_FILE" ]]; then
  log_error "Backup file is not readable: $BACKUP_FILE"
  exit 1
fi

# ─── Prerequisite check ───────────────────────────────────────────────────────
for cmd in psql zcat; do
  if ! command -v "$cmd" &>/dev/null; then
    log_error "$cmd not found. Install postgresql-client (and gzip) and try again."
    exit 1
  fi
done

# ─── Show restore summary ─────────────────────────────────────────────────────
BACKUP_SIZE=$(du -sh "$BACKUP_FILE" | cut -f1)
BACKUP_NAME=$(basename "$BACKUP_FILE")

echo ""
echo -e "${RED}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║            ⚠  DESTRUCTIVE OPERATION WARNING  ⚠           ║${NC}"
echo -e "${RED}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Backup file : ${CYAN}$BACKUP_NAME${NC} ($BACKUP_SIZE)"
echo -e "  Target DB   : ${CYAN}$PG_DB${NC} on $PG_HOST:$PG_PORT"
echo -e "  Admin user  : ${CYAN}$PG_ADMIN_USER${NC} (for DROP/CREATE)"
echo -e "  App user    : ${CYAN}$PG_USER${NC} (for restore)"
echo ""
echo -e "  ${RED}ALL EXISTING DATA IN '$PG_DB' WILL BE PERMANENTLY DELETED.${NC}"
echo ""

# ─── Confirmation ─────────────────────────────────────────────────────────────
if ! $CONFIRM; then
  read -r -p "  Type 'yes' to confirm the restore: " ANSWER
  if [[ "$ANSWER" != "yes" ]]; then
    echo ""
    log_warn "Restore cancelled — you typed '$ANSWER' instead of 'yes'."
    exit 1
  fi
  echo ""
fi

# Helper: run a psql command as the admin user against the postgres maintenance DB
_psql_admin() {
  PGPASSWORD="${PGADMINPASSWORD:-}" \
    psql \
    -h "$PG_HOST" \
    -p "$PG_PORT" \
    -U "$PG_ADMIN_USER" \
    -d postgres \
    --no-password \
    -v ON_ERROR_STOP=1 \
    "$@"
}

# ─── Step 1: Terminate active connections ─────────────────────────────────────
log_info "Terminating active connections to '$PG_DB'..."
_psql_admin -c "
  SELECT pg_terminate_backend(pid)
  FROM   pg_stat_activity
  WHERE  datname = '$PG_DB'
    AND  pid <> pg_backend_pid();
" -q

# ─── Step 2: Drop database ───────────────────────────────────────────────────
log_info "Dropping database '$PG_DB'..."
_psql_admin -c "DROP DATABASE IF EXISTS \"$PG_DB\";"

# ─── Step 3: Create fresh database ───────────────────────────────────────────
log_info "Creating fresh database '$PG_DB' (owner: $PG_USER)..."
_psql_admin -c "CREATE DATABASE \"$PG_DB\" OWNER \"$PG_USER\";"

# ─── Step 4: Restore from backup ─────────────────────────────────────────────
log_info "Restoring from backup: $BACKUP_NAME"
log_info "This may take a while for large databases..."

PGPASSWORD="${PGPASSWORD:-}" \
  zcat "$BACKUP_FILE" | \
  psql \
  -h "$PG_HOST" \
  -p "$PG_PORT" \
  -U "$PG_USER" \
  -d "$PG_DB" \
  --no-password \
  -v ON_ERROR_STOP=1 \
  -q

# ─── Done ─────────────────────────────────────────────────────────────────────
echo ""
log_info "Restore complete."
log_info "  Database : $PG_DB"
log_info "  Source   : $BACKUP_NAME ($BACKUP_SIZE)"
log_info "  Host     : $PG_HOST:$PG_PORT"
echo ""
log_warn "Next steps:"
log_warn "  1. Verify application connectivity: curl http://localhost:8080/ready"
log_warn "  2. Run database migrations if needed: alembic upgrade head"
log_warn "  3. Restart the application if it was running during restore"
