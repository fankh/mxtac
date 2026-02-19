"""WebSocket broadcaster — reads enriched alerts from queue and broadcasts to connected clients."""

from __future__ import annotations

from ..core.logging import get_logger
from ..pipeline.queue import MessageQueue, Topic

logger = get_logger(__name__)


async def websocket_broadcaster(queue: MessageQueue) -> None:
    """Subscribe to mxtac.enriched and broadcast to all WebSocket clients."""

    async def _handle(alert: dict) -> None:
        try:
            from ..api.v1.endpoints.websocket import broadcast_alert
            await broadcast_alert(alert)
        except Exception:
            logger.exception("WebSocket broadcast error")

    await queue.subscribe(Topic.ENRICHED, "ws-broadcaster", _handle)
    logger.info("WebSocket broadcaster subscribed to %s", Topic.ENRICHED)
