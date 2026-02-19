"""
WebSocket endpoint for real-time alert streaming.

Protocol:
  Client connects to: ws://host/api/v1/ws/alerts?token=<jwt>
  Server pushes JSON messages:
    {"type": "alert",    "data": {...}}
    {"type": "ping",     "ts": "..."}
    {"type": "error",    "message": "..."}
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from ....core.logging import get_logger
from ....services.mock_data import DETECTIONS

logger = get_logger(__name__)

router = APIRouter(prefix="/ws", tags=["websocket"])


class ConnectionManager:
    """Manages active WebSocket connections and broadcasts messages."""

    def __init__(self) -> None:
        self._connections: set[WebSocket] = set()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._connections.add(ws)
        logger.info("WebSocket connected total=%d", len(self._connections))

    def disconnect(self, ws: WebSocket) -> None:
        self._connections.discard(ws)
        logger.info("WebSocket disconnected total=%d", len(self._connections))

    async def broadcast(self, message: dict[str, Any]) -> None:
        if not self._connections:
            return
        payload = json.dumps(message)
        dead = set()
        for ws in self._connections:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.add(ws)
        for ws in dead:
            self._connections.discard(ws)

    async def send_to(self, ws: WebSocket, message: dict[str, Any]) -> None:
        try:
            await ws.send_text(json.dumps(message))
        except Exception:
            self.disconnect(ws)


manager = ConnectionManager()


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.websocket("/alerts")
async def alerts_ws(ws: WebSocket):
    """
    Real-time alert stream.
    Sends a 'ping' every 30s and pushes new alerts from the queue.
    In production: subscribe to mxtac.enriched queue and forward messages.
    """
    await manager.connect(ws)

    # Send initial handshake
    await manager.send_to(ws, {
        "type": "connected",
        "message": "Subscribed to real-time alert stream",
        "ts": datetime.now(timezone.utc).isoformat(),
    })

    try:
        ping_task   = asyncio.create_task(_ping_loop(ws))
        # In dev: replay mock alerts slowly so the UI is not empty
        replay_task = asyncio.create_task(_mock_replay(ws))

        # Keep alive — wait for client messages (e.g. filter updates)
        while True:
            try:
                raw = await asyncio.wait_for(ws.receive_text(), timeout=60)
                msg = json.loads(raw)
                if msg.get("type") == "filter":
                    await manager.send_to(ws, {"type": "ack", "filter": msg.get("data")})
            except asyncio.TimeoutError:
                pass   # No client message — normal

    except WebSocketDisconnect:
        pass
    except Exception:
        logger.exception("WebSocket error")
    finally:
        ping_task.cancel()
        replay_task.cancel()
        manager.disconnect(ws)


async def _ping_loop(ws: WebSocket) -> None:
    while True:
        await asyncio.sleep(30)
        try:
            await manager.send_to(ws, {
                "type": "ping",
                "ts": datetime.now(timezone.utc).isoformat(),
            })
        except Exception:
            break


async def _mock_replay(ws: WebSocket) -> None:
    """In dev mode: stream mock detections one by one at 3s intervals."""
    for det in DETECTIONS:
        await asyncio.sleep(3)
        try:
            await manager.send_to(ws, {
                "type": "alert",
                "data": {
                    "id":           det.id,
                    "score":        det.score,
                    "severity":     det.severity,
                    "technique_id": det.technique_id,
                    "name":         det.name,
                    "host":         det.host,
                    "status":       det.status,
                    "time":         det.time.isoformat(),
                },
            })
        except Exception:
            break


# ── Broadcast helper (called by alert manager) ────────────────────────────────

async def broadcast_alert(alert: dict[str, Any]) -> None:
    """Called externally to push an enriched alert to all connected clients."""
    await manager.broadcast({"type": "alert", "data": alert})
