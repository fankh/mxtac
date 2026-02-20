import asyncio
import json

from fastapi import APIRouter
from sse_starlette.sse import EventSourceResponse

from ..scheduler import sse_broadcaster

router = APIRouter(prefix="/api")


@router.get("/events")
async def sse_stream():
    """Server-Sent Events endpoint for real-time updates."""

    async def event_generator():
        queue = sse_broadcaster.subscribe()
        try:
            # Send initial connection event
            yield {
                "event": "connected",
                "data": json.dumps({"status": "connected"}),
            }

            while True:
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=30)
                    yield {
                        "event": msg["event"],
                        "data": json.dumps(msg["data"]),
                    }
                except asyncio.TimeoutError:
                    # Send keepalive
                    yield {"event": "keepalive", "data": "{}"}
        except asyncio.CancelledError:
            pass
        finally:
            sse_broadcaster.unsubscribe(queue)

    return EventSourceResponse(event_generator())
