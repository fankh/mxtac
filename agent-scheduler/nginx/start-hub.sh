#!/usr/bin/env bash
set -euo pipefail

# ──────────────────────────────────────────────────
# AI Scheduler Hub — start all services
#
# Services:
#   :13000  nginx reverse proxy (hub)
#   :13001  MxTac frontend   (BASE_PATH=/mxtac, API→:13002)
#   :13002  MxTac backend    (already running)
#   :13003  KYRA backend     (already running)
#   :13004  KYRA frontend    (BASE_PATH=/kyra,  API→:13003)
# ──────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCHEDULER_DIR="$(dirname "$SCRIPT_DIR")"
FRONTEND_DIR="$SCHEDULER_DIR/frontend"
NGINX_CONF="$SCRIPT_DIR/scheduler-proxy.conf"
NGINX_PID="/tmp/scheduler-hub-nginx.pid"

echo "=== AI Scheduler Hub ==="
echo ""

# ── 1. Check backends are running ──
echo "[1/4] Checking backends..."

check_port() {
    local name=$1 port=$2
    if curl -sf "http://localhost:$port/health" > /dev/null 2>&1; then
        echo "  $name (:$port) — running"
    else
        echo "  $name (:$port) — NOT RUNNING"
        echo "  Start it first, then re-run this script."
        return 1
    fi
}

check_port "MxTac backend" 13002
check_port "KYRA backend" 13003
echo ""

# ── 2. Rebuild MxTac frontend with basePath=/mxtac ──
echo "[2/4] Starting MxTac frontend (:13001, basePath=/mxtac)..."

# Kill existing frontend on 13001
PIDS=$(pgrep -f "next.*13001" || true)
if [ -n "$PIDS" ]; then
    echo "  Stopping existing MxTac frontend (pids: $PIDS)..."
    kill $PIDS 2>/dev/null || true
    sleep 2
fi

cd "$FRONTEND_DIR"
BASE_PATH=/mxtac API_PORT=13002 npx next build > /tmp/mxtac-frontend-build.log 2>&1 || {
    echo "  Build failed. Check /tmp/mxtac-frontend-build.log"
    exit 1
}
nohup env BASE_PATH=/mxtac API_PORT=13002 npx next start --port 13001 > /tmp/mxtac-frontend.log 2>&1 &
MXTAC_FE_PID=$!
echo "  Started (pid=$MXTAC_FE_PID, log=/tmp/mxtac-frontend.log)"
echo ""

# ── 3. Start KYRA frontend with basePath=/kyra ──
echo "[3/4] Starting KYRA frontend (:13004, basePath=/kyra)..."

# Kill existing frontend on 13004
PIDS=$(pgrep -f "next.*13004" || true)
if [ -n "$PIDS" ]; then
    echo "  Stopping existing KYRA frontend (pids: $PIDS)..."
    kill $PIDS 2>/dev/null || true
    sleep 2
fi

BASE_PATH=/kyra API_PORT=13003 npx next build > /tmp/kyra-frontend-build.log 2>&1 || {
    echo "  Build failed. Check /tmp/kyra-frontend-build.log"
    exit 1
}
nohup env BASE_PATH=/kyra API_PORT=13003 npx next start --port 13004 > /tmp/kyra-frontend.log 2>&1 &
KYRA_FE_PID=$!
echo "  Started (pid=$KYRA_FE_PID, log=/tmp/kyra-frontend.log)"
echo ""

# ── 4. Start nginx ──
echo "[4/4] Starting nginx reverse proxy (:13000)..."

# Stop existing nginx for this config
if [ -f "$NGINX_PID" ]; then
    OLD_PID=$(cat "$NGINX_PID" 2>/dev/null || true)
    if [ -n "$OLD_PID" ] && kill -0 "$OLD_PID" 2>/dev/null; then
        echo "  Stopping existing nginx (pid=$OLD_PID)..."
        kill "$OLD_PID" 2>/dev/null || true
        sleep 1
    fi
fi

# Write a minimal nginx.conf wrapper (needed since nginx requires a top-level config)
NGINX_MAIN="/tmp/scheduler-hub-nginx.conf"
cat > "$NGINX_MAIN" <<NGINXEOF
worker_processes auto;
pid $NGINX_PID;
error_log /tmp/scheduler-hub-nginx-error.log;

events {
    worker_connections 256;
}

http {
    access_log /tmp/scheduler-hub-nginx-access.log;

    include $NGINX_CONF;
}
NGINXEOF

nginx -t -c "$NGINX_MAIN" 2>&1 || {
    echo "  Nginx config test failed!"
    exit 1
}

nginx -c "$NGINX_MAIN"
echo "  Nginx started"
echo ""

# ── Summary ──
echo "=== Hub Ready ==="
echo ""
echo "  Hub:            http://localhost:13000"
echo "  MxTac:          http://localhost:13000/mxtac/"
echo "  KYRA MDR:       http://localhost:13000/kyra/"
echo ""
echo "  Direct access (still works):"
echo "    MxTac FE:     http://localhost:13001/mxtac/"
echo "    MxTac API:    http://localhost:13002"
echo "    KYRA API:     http://localhost:13003"
echo "    KYRA FE:      http://localhost:13004/kyra/"
echo ""
echo "  Logs:"
echo "    Nginx:        /tmp/scheduler-hub-nginx-error.log"
echo "    MxTac FE:     /tmp/mxtac-frontend.log"
echo "    KYRA FE:      /tmp/kyra-frontend.log"
echo ""
echo "  Stop: nginx -s stop -c $NGINX_MAIN"
