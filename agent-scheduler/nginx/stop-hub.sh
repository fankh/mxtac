#!/usr/bin/env bash
set -euo pipefail

echo "=== Stopping AI Scheduler Hub ==="

# Stop nginx
NGINX_MAIN="/tmp/scheduler-hub-nginx.conf"
if [ -f "$NGINX_MAIN" ]; then
    nginx -s stop -c "$NGINX_MAIN" 2>/dev/null && echo "Nginx stopped" || echo "Nginx not running"
fi

# Stop KYRA frontend (:13004)
PIDS=$(pgrep -f "next.*13004" || true)
if [ -n "$PIDS" ]; then
    kill $PIDS 2>/dev/null && echo "KYRA frontend stopped (pids: $PIDS)" || true
fi

# Stop MxTac frontend (:13001)
PIDS=$(pgrep -f "next.*13001" || true)
if [ -n "$PIDS" ]; then
    kill $PIDS 2>/dev/null && echo "MxTac frontend stopped (pids: $PIDS)" || true
fi

echo ""
echo "Hub stopped. Backends (:13002, :13003) are still running."
echo "To stop backends:"
echo "  MxTac:  kill \$(pgrep -f 'uvicorn.*13002')"
echo "  KYRA:   kill \$(pgrep -f 'uvicorn.*13003')"
