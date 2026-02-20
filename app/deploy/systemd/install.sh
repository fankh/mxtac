#!/usr/bin/env bash
# install.sh — Install MxTac as a standalone systemd service
#
# Usage (run as root or with sudo):
#   sudo bash install.sh [--app-dir /opt/mxtac] [--port 8080] [--uninstall]
#
# What this script does:
#   1. Creates the 'mxtac' system user and group
#   2. Installs application files to APP_DIR (/opt/mxtac by default)
#   3. Creates a Python virtual environment and installs dependencies
#   4. Installs the systemd unit and prompts to edit /etc/mxtac/mxtac.env
#   5. Enables and starts the service
#
# Requirements:
#   - Python 3.12+ (python3 on PATH)
#   - systemd (Linux only)
#   - Root or sudo access

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
APP_DIR="${APP_DIR:-/opt/mxtac}"
APP_PORT="${APP_PORT:-8080}"
APP_USER="mxtac"
APP_GROUP="mxtac"
ENV_FILE="/etc/mxtac/mxtac.env"
SERVICE_FILE="/etc/systemd/system/mxtac.service"
LOG_DIR="/var/log/mxtac"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
BACKEND_DIR="${REPO_ROOT}/app/backend"

# ── Argument parsing ───────────────────────────────────────────────────────────
UNINSTALL=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --app-dir)   APP_DIR="$2"; shift 2 ;;
        --port)      APP_PORT="$2"; shift 2 ;;
        --uninstall) UNINSTALL=true; shift ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# ── Helpers ───────────────────────────────────────────────────────────────────
info()  { echo "[INFO]  $*"; }
warn()  { echo "[WARN]  $*" >&2; }
die()   { echo "[ERROR] $*" >&2; exit 1; }
check_root() { [[ $EUID -eq 0 ]] || die "Run this script as root (sudo bash install.sh)"; }

# ── Uninstall ─────────────────────────────────────────────────────────────────
uninstall() {
    check_root
    info "Stopping and disabling mxtac service..."
    systemctl stop mxtac  2>/dev/null || true
    systemctl disable mxtac 2>/dev/null || true

    info "Removing systemd unit..."
    rm -f "${SERVICE_FILE}"
    systemctl daemon-reload

    info "Removing application directory ${APP_DIR}..."
    rm -rf "${APP_DIR}"

    info "Removing log directory ${LOG_DIR}..."
    rm -rf "${LOG_DIR}"

    warn "Environment file ${ENV_FILE} was NOT removed (may contain secrets)."
    warn "Remove manually if no longer needed: sudo rm -f ${ENV_FILE}"

    warn "System user '${APP_USER}' was NOT removed."
    warn "Remove manually if no longer needed: sudo userdel ${APP_USER}"

    info "Uninstall complete."
}

if $UNINSTALL; then
    uninstall
    exit 0
fi

# ── Install ───────────────────────────────────────────────────────────────────
check_root

# 1. System user
info "Creating system user '${APP_USER}'..."
if ! id "${APP_USER}" &>/dev/null; then
    useradd --system \
        --shell /usr/sbin/nologin \
        --home-dir "${APP_DIR}" \
        --no-create-home \
        --comment "MxTac service account" \
        "${APP_USER}"
fi

# 2. Application directory
info "Creating application directory ${APP_DIR}..."
install -d -m 755 -o "${APP_USER}" -g "${APP_GROUP}" "${APP_DIR}"
install -d -m 750 -o "${APP_USER}" -g "${APP_GROUP}" "${APP_DIR}/data"

# 3. Copy application files
info "Installing application files..."
rsync -a --delete \
    --exclude __pycache__ \
    --exclude "*.pyc" \
    --exclude ".pytest_cache" \
    --exclude "tests/" \
    --exclude ".env" \
    "${BACKEND_DIR}/" "${APP_DIR}/"

chown -R "${APP_USER}:${APP_GROUP}" "${APP_DIR}"

# 4. Python virtual environment
info "Creating Python virtual environment..."
PYTHON_BIN="$(command -v python3.12 || command -v python3 || die 'python3 not found')"
PY_VERSION=$("${PYTHON_BIN}" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
info "Using Python ${PY_VERSION} at ${PYTHON_BIN}"

if [[ "${PY_VERSION}" < "3.12" ]]; then
    die "Python 3.12+ is required (found ${PY_VERSION})"
fi

sudo -u "${APP_USER}" "${PYTHON_BIN}" -m venv "${APP_DIR}/venv"
sudo -u "${APP_USER}" "${APP_DIR}/venv/bin/pip" install --quiet --upgrade pip
sudo -u "${APP_USER}" "${APP_DIR}/venv/bin/pip" install --quiet -r "${APP_DIR}/requirements.txt"

# 5. Log directory
info "Creating log directory ${LOG_DIR}..."
install -d -m 750 -o "${APP_USER}" -g "${APP_GROUP}" "${LOG_DIR}"

# 6. Environment file
info "Installing environment file template..."
install -d -m 750 -o root -g "${APP_GROUP}" /etc/mxtac
if [[ ! -f "${ENV_FILE}" ]]; then
    install -m 640 -o root -g "${APP_GROUP}" \
        "${SCRIPT_DIR}/mxtac.env.example" "${ENV_FILE}"
    warn "--------------------------------------------------------------"
    warn "  ACTION REQUIRED: Edit ${ENV_FILE}"
    warn "  At minimum, set:"
    warn "    SECRET_KEY      — generate with: python3 -c \"import secrets; print(secrets.token_hex(32))\""
    warn "    DATABASE_URL    — PostgreSQL connection string"
    warn "--------------------------------------------------------------"
else
    info "Environment file ${ENV_FILE} already exists — skipping."
fi

# 7. systemd unit
info "Installing systemd unit..."
# Patch the port in case --port was provided
sed "s|--port 8080|--port ${APP_PORT}|g" \
    "${SCRIPT_DIR}/mxtac.service" > "${SERVICE_FILE}"
chmod 644 "${SERVICE_FILE}"

systemctl daemon-reload
systemctl enable mxtac

# 8. Start (only if env file has been edited)
if grep -q "CHANGE_ME" "${ENV_FILE}" 2>/dev/null; then
    warn "Service NOT started: ${ENV_FILE} still contains placeholder values."
    warn "Edit the file, then run: sudo systemctl start mxtac"
else
    info "Starting mxtac service..."
    systemctl start mxtac
    systemctl status mxtac --no-pager
fi

info "Installation complete."
info ""
info "Useful commands:"
info "  sudo systemctl status mxtac        — service status"
info "  sudo journalctl -u mxtac -f        — follow logs"
info "  sudo systemctl restart mxtac       — restart"
info "  sudo systemctl stop mxtac          — stop"
info "  sudo bash install.sh --uninstall   — remove"
