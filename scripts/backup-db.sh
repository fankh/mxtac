#!/usr/bin/env bash
# backup-db.sh — PostgreSQL backup with retention policy for MxTac
#
# Usage:
#   ./scripts/backup-db.sh [options]
#   ./scripts/backup-db.sh --dir /var/backups/mxtac
#   ./scripts/backup-db.sh --host db.example.com --db-name mxtac
#
# Options:
#   --dir DIR          Backup directory (env: BACKUP_DIR; default: <project-root>/backups)
#   --host HOST        PostgreSQL host (env: PGHOST; default: localhost)
#   --port PORT        PostgreSQL port (env: PGPORT; default: 5432)
#   --user USER        PostgreSQL user (env: PGUSER; default: mxtac)
#   --db-name NAME     Database name (env: PGDATABASE; default: mxtac)
#   --no-retain        Skip retention cleanup after backup
#   -h, --help         Show this help message
#
# Environment variables (all overridable via --options):
#   PGHOST             PostgreSQL host          (default: localhost)
#   PGPORT             PostgreSQL port          (default: 5432)
#   PGUSER             PostgreSQL user          (default: mxtac)
#   PGPASSWORD         PostgreSQL password      (required for remote connections)
#   PGDATABASE         PostgreSQL database      (default: mxtac)
#   BACKUP_DIR         Backup directory         (default: <project-root>/backups)
#
# Retention policy (applied after each backup):
#   Daily  — keep the 7 most recent backup files
#   Weekly — keep 1 backup per ISO calendar week for the next 4 older weeks
#   Monthly— keep 1 backup per calendar month   for the next 3 older months
#   Delete — everything else
#
# Backup file naming:
#   mxtac_backup_YYYY-MM-DD_HH-MM.sql.gz
#
# Cron examples (add to /etc/cron.d/mxtac-backup or crontab -e):
#
#   # Daily at 02:00, log to /var/log/mxtac-backup.log
#   0 2 * * * mxtac /opt/mxtac/scripts/backup-db.sh >> /var/log/mxtac-backup.log 2>&1
#
#   # Daily at 02:00 with explicit credentials and backup dir
#   0 2 * * * mxtac PGPASSWORD=secret BACKUP_DIR=/var/backups/mxtac \
#       /opt/mxtac/scripts/backup-db.sh >> /var/log/mxtac-backup.log 2>&1
#
# Notes:
#   - pg_dump must be installed (package: postgresql-client)
#   - PGPASSWORD is passed via the environment variable, not --password, to
#     avoid exposing it in the process list
#   - The backup is written atomically: pg_dump pipes directly into gzip so
#     no uncompressed SQL is written to disk

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# ─── Defaults ────────────────────────────────────────────────────────────────
PG_HOST="${PGHOST:-localhost}"
PG_PORT="${PGPORT:-5432}"
PG_USER="${PGUSER:-mxtac}"
PG_DB="${PGDATABASE:-mxtac}"
BACKUP_DIR="${BACKUP_DIR:-$PROJECT_ROOT/backups}"
SKIP_RETAIN=false

DAILY_KEEP=7
WEEKLY_KEEP=4
MONTHLY_KEEP=3

# ─── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

log_info()  { echo -e "$(date -u '+%Y-%m-%dT%H:%M:%SZ') ${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "$(date -u '+%Y-%m-%dT%H:%M:%SZ') ${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "$(date -u '+%Y-%m-%dT%H:%M:%SZ') ${RED}[ERROR]${NC} $*" >&2; }

# ─── Argument parsing ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dir)        BACKUP_DIR="$2"; shift 2 ;;
    --dir=*)      BACKUP_DIR="${1#*=}"; shift ;;
    --host)       PG_HOST="$2"; shift 2 ;;
    --host=*)     PG_HOST="${1#*=}"; shift ;;
    --port)       PG_PORT="$2"; shift 2 ;;
    --port=*)     PG_PORT="${1#*=}"; shift ;;
    --user)       PG_USER="$2"; shift 2 ;;
    --user=*)     PG_USER="${1#*=}"; shift ;;
    --db-name)    PG_DB="$2"; shift 2 ;;
    --db-name=*)  PG_DB="${1#*=}"; shift ;;
    --no-retain)  SKIP_RETAIN=true; shift ;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \?//'
      exit 0 ;;
    *)
      log_error "Unknown option: $1"
      echo "Run with --help for usage."
      exit 1 ;;
  esac
done

# ─── Prerequisite check ───────────────────────────────────────────────────────
if ! command -v pg_dump &>/dev/null; then
  log_error "pg_dump not found. Install postgresql-client and try again."
  exit 1
fi

# ─── Create backup ────────────────────────────────────────────────────────────
mkdir -p "$BACKUP_DIR"

TIMESTAMP=$(date '+%Y-%m-%d_%H-%M')
BACKUP_FILE="$BACKUP_DIR/mxtac_backup_${TIMESTAMP}.sql.gz"

log_info "Starting backup — db=$PG_DB host=$PG_HOST:$PG_PORT user=$PG_USER"
log_info "Output: $BACKUP_FILE"

# pg_dump with --clean --if-exists generates DROP TABLE IF EXISTS statements
# before each CREATE, allowing a clean restore into an existing database.
PGPASSWORD="${PGPASSWORD:-}" \
  pg_dump \
  -h "$PG_HOST" \
  -p "$PG_PORT" \
  -U "$PG_USER" \
  --no-password \
  --clean \
  --if-exists \
  "$PG_DB" | gzip > "$BACKUP_FILE"

SIZE=$(du -sh "$BACKUP_FILE" | cut -f1)
log_info "Backup complete — $BACKUP_FILE ($SIZE)"

# ─── Retention cleanup ────────────────────────────────────────────────────────
if $SKIP_RETAIN; then
  log_info "Retention cleanup skipped (--no-retain)."
  exit 0
fi

log_info "Applying retention: ${DAILY_KEEP} daily / ${WEEKLY_KEEP} weekly / ${MONTHLY_KEEP} monthly"

# Collect all backup files sorted newest-first (ls -t is reliable for this)
mapfile -t ALL_FILES < <(ls -t "$BACKUP_DIR"/mxtac_backup_*.sql.gz 2>/dev/null || true)

if [[ ${#ALL_FILES[@]} -eq 0 ]]; then
  log_info "No backup files to clean up."
  exit 0
fi

declare -A KEEP_SET    # filepath → 1  (files to keep)
declare -A SEEN_WEEKS  # ISO week key → 1
declare -A SEEN_MONTHS # year-month key → 1

DAILY_COUNT=0
WEEKLY_COUNT=0
MONTHLY_COUNT=0
DELETED=0

for f in "${ALL_FILES[@]}"; do
  fname=$(basename "$f")

  # Extract YYYY-MM-DD from filename: mxtac_backup_YYYY-MM-DD_HH-MM.sql.gz
  if [[ "$fname" =~ ^mxtac_backup_([0-9]{4}-[0-9]{2}-[0-9]{2})_ ]]; then
    file_date="${BASH_REMATCH[1]}"
  else
    # Unrecognised format — keep to be safe
    KEEP_SET["$f"]=1
    log_warn "Skipping unrecognised filename: $fname"
    continue
  fi

  # Validate date parses cleanly on this system
  if ! date -d "$file_date" &>/dev/null 2>&1; then
    KEEP_SET["$f"]=1
    log_warn "Cannot parse date '$file_date' in $fname — keeping file"
    continue
  fi

  # ── Daily window: keep the 7 newest files ──────────────────────────────────
  if [[ $DAILY_COUNT -lt $DAILY_KEEP ]]; then
    KEEP_SET["$f"]=1
    DAILY_COUNT=$((DAILY_COUNT + 1))
    continue
  fi

  # ── Weekly window: 1 per ISO week, up to WEEKLY_KEEP additional weeks ──────
  week_key=$(date -d "$file_date" '+%G-W%V')  # ISO year + ISO week number
  if [[ -z "${SEEN_WEEKS[$week_key]:-}" ]] && [[ $WEEKLY_COUNT -lt $WEEKLY_KEEP ]]; then
    KEEP_SET["$f"]=1
    SEEN_WEEKS["$week_key"]=1
    WEEKLY_COUNT=$((WEEKLY_COUNT + 1))
    continue
  fi

  # ── Monthly window: 1 per month, up to MONTHLY_KEEP additional months ──────
  month_key=$(date -d "$file_date" '+%Y-%m')
  if [[ -z "${SEEN_MONTHS[$month_key]:-}" ]] && [[ $MONTHLY_COUNT -lt $MONTHLY_KEEP ]]; then
    KEEP_SET["$f"]=1
    SEEN_MONTHS["$month_key"]=1
    MONTHLY_COUNT=$((MONTHLY_COUNT + 1))
    continue
  fi

  # ── Outside all retention windows — delete ─────────────────────────────────
  log_info "Removing expired backup: $fname"
  rm -f "$f"
  DELETED=$((DELETED + 1))
done

KEPT=$((DAILY_COUNT + WEEKLY_COUNT + MONTHLY_COUNT))
log_info "Retention complete — kept ${KEPT} (${DAILY_COUNT}d + ${WEEKLY_COUNT}w + ${MONTHLY_COUNT}m), deleted ${DELETED}"
