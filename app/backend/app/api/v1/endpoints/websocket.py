"""
WebSocket endpoint for real-time alert streaming.

Protocol:
  Client connects to: ws://host/api/v1/ws/alerts?token=<jwt>
  Server pushes JSON messages:
    {"type": "alert",    "data": {...}}
    {"type": "ping",     "ts": "..."}
    {"type": "error",    "message": "..."}

Distributed mode:
  When multiple backend replicas run behind a load-balancer each instance
  maintains its own set of local WebSocket connections.  Broadcasts go
  through a Valkey (Redis-compatible) pub/sub channel so every replica
  fans the message out to its local clients.

  Single-instance deployments work identically -- the pub/sub channel is
  just local to one subscriber.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any

import valkey.asyncio as aioredis
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from ....core.config import settings
from ....core.logging import get_logger
from ....core.metrics import websocket_connections
from ....services.mock_data import DETECTIONS

logger = get_logger(__name__)

router = APIRouter(prefix="/ws", tags=["websocket"])

# Valkey pub/sub channel for cross-replica alert fan-out
_CHANNEL = "mxtac:alerts"


class DistributedConnectionManager:
    """Manages local WebSocket connections with Valkey pub/sub fan-out.

    Broadcasting flow:
        1. ``broadcast()`` publishes a JSON payload to the Valkey channel.
        2. A background subscriber task receives the message on *every*
           replica (including the one that published it).
        3. The subscriber calls ``_fanout_local()`` which sends the
           payload to all WebSocket connections held by *this* process.

    Backward compatibility:
        A single-instance deployment works identically -- the pub/sub
        round-trip is effectively a local loopback.
    """

    def __init__(self, valkey_url: str) -> None:
        self._valkey_url = valkey_url
        self._connections: set[WebSocket] = set()
        self._pub_client: aioredis.Valkey | None = None
        self._sub_client: aioredis.Valkey | None = None
        self._subscriber_task: asyncio.Task | None = None
        self._started = False
        self._lock = asyncio.Lock()

    # ── Connection lifecycle ──────────────────────────────────────────

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._connections.add(ws)
        websocket_connections.inc()
        logger.info("WebSocket connected total=%d", len(self._connections))
        # Lazily start the Valkey subscriber on first connection
        await self._ensure_subscriber()

    def disconnect(self, ws: WebSocket) -> None:
        was_present = ws in self._connections
        self._connections.discard(ws)
        if was_present:
            websocket_connections.dec()
        logger.info("WebSocket disconnected total=%d", len(self._connections))

    # ── Publishing (goes through Valkey) ──────────────────────────────

    async def broadcast(self, message: dict[str, Any]) -> None:
        """Publish *message* to the Valkey channel.

        All replicas (including this one) will receive it and fan out to
        their local WebSocket connections.
        """
        payload = json.dumps(message)
        try:
            pub = await self._get_pub_client()
            await pub.publish(_CHANNEL, payload)
        except Exception:
            logger.exception("DistributedConnectionManager publish error, falling back to local fanout")
            # Graceful degradation: deliver locally even if Valkey is down
            await self._fanout_local(payload)

    async def send_to(self, ws: WebSocket, message: dict[str, Any]) -> None:
        """Send a message to a single local WebSocket (not broadcast)."""
        try:
            await ws.send_text(json.dumps(message))
        except Exception:
            self.disconnect(ws)

    # ── Valkey subscriber ─────────────────────────────────────────────

    async def _ensure_subscriber(self) -> None:
        """Start the background Valkey subscriber if not already running."""
        if self._started:
            return
        async with self._lock:
            if self._started:
                return
            self._started = True
            self._subscriber_task = asyncio.create_task(
                self._subscriber_loop(), name="ws-valkey-subscriber"
            )
            logger.info("DistributedConnectionManager subscriber started channel=%s", _CHANNEL)

    async def _subscriber_loop(self) -> None:
        """Long-running task: subscribe to Valkey and fan out messages."""
        retry_delay = 1.0
        max_retry_delay = 30.0

        while True:
            try:
                self._sub_client = aioredis.from_url(
                    self._valkey_url, decode_responses=True
                )
                pubsub = self._sub_client.pubsub()
                await pubsub.subscribe(_CHANNEL)
                logger.info("Valkey subscriber connected channel=%s", _CHANNEL)
                retry_delay = 1.0  # reset on successful connect

                async for raw_message in pubsub.listen():
                    if raw_message["type"] != "message":
                        continue
                    await self._fanout_local(raw_message["data"])

            except asyncio.CancelledError:
                logger.info("Valkey subscriber cancelled, shutting down")
                break
            except Exception:
                logger.exception(
                    "Valkey subscriber error, reconnecting in %.0fs", retry_delay
                )
                await asyncio.sleep(retry_delay)
                retry_delay = min(retry_delay * 2, max_retry_delay)
            finally:
                if self._sub_client:
                    try:
                        await self._sub_client.aclose()
                    except Exception:
                        pass
                    self._sub_client = None

    async def _fanout_local(self, payload: str) -> None:
        """Send *payload* (already JSON-encoded) to every local WebSocket."""
        if not self._connections:
            return
        dead: set[WebSocket] = set()
        for ws in list(self._connections):
            try:
                await ws.send_text(payload)
            except Exception:
                dead.add(ws)
        for ws in dead:
            self._connections.discard(ws)
            websocket_connections.dec()

    # ── Valkey publish client (lazy singleton) ────────────────────────

    async def _get_pub_client(self) -> aioredis.Valkey:
        if self._pub_client is None:
            self._pub_client = aioredis.from_url(
                self._valkey_url, decode_responses=True
            )
        return self._pub_client

    # ── Shutdown ──────────────────────────────────────────────────────

    async def shutdown(self) -> None:
        """Gracefully close Valkey connections and cancel the subscriber."""
        if self._subscriber_task and not self._subscriber_task.done():
            self._subscriber_task.cancel()
            try:
                await self._subscriber_task
            except asyncio.CancelledError:
                pass
        if self._pub_client:
            await self._pub_client.aclose()
            self._pub_client = None
        self._started = False
        logger.info("DistributedConnectionManager shut down")


# Module-level singleton — backward-compatible: ``manager`` is still the
# single import used by the rest of the application.
manager = DistributedConnectionManager(valkey_url=settings.valkey_url)


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
        ping_task = asyncio.create_task(_ping_loop(ws))

        # Keep alive -- wait for client messages (e.g. filter updates).
        # Real alerts arrive via broadcast_alert() → manager.broadcast() → _fanout_local(),
        # driven by the ws_broadcaster service subscribed to mxtac.enriched.
        while True:
            try:
                raw = await asyncio.wait_for(ws.receive_text(), timeout=60)
                msg = json.loads(raw)
                if msg.get("type") == "filter":
                    await manager.send_to(ws, {"type": "ack", "filter": msg.get("data")})
            except asyncio.TimeoutError:
                pass   # No client message -- normal

    except WebSocketDisconnect:
        pass
    except Exception:
        logger.exception("WebSocket error")
    finally:
        ping_task.cancel()
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
