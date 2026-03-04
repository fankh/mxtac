#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
APP="agent_scheduler.main:app"
HOST="0.0.0.0"
PORT="13002"
LOG="/tmp/agent-scheduler.log"

# Kill existing processes (port-specific to avoid killing other schedulers)
PIDS=$(pgrep -f "uvicorn $APP --host $HOST --port $PORT" || true)
if [ -n "$PIDS" ]; then
    echo "Stopping existing processes (pids: $(echo $PIDS))..."
    kill $PIDS 2>/dev/null || true
    sleep 2
    # Force kill any survivors
    for p in $PIDS; do
        if kill -0 "$p" 2>/dev/null; then
            kill -9 "$p" 2>/dev/null || true
        fi
    done
    sleep 1
    echo "Stopped."
else
    echo "No existing process found."
fi

# Start
echo "Starting uvicorn on $HOST:$PORT..."
cd "$DIR"
nohup .venv/bin/uvicorn "$APP" --host "$HOST" --port "$PORT" > "$LOG" 2>&1 &
NEW_PID=$!
sleep 2

if kill -0 "$NEW_PID" 2>/dev/null; then
    echo "Started (pid=$NEW_PID). Logs: $LOG"
    echo "--- Recent logs ---"
    tail -15 "$LOG"
else
    echo "Failed to start. Check $LOG"
    tail -20 "$LOG"
    exit 1
fi
