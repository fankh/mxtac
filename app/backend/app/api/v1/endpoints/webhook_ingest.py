"""Generic webhook ingest endpoint — Feature 6.21.

Accepts any JSON payload from any source and publishes each event to the
``mxtac.raw.webhook`` topic for downstream normalizer processing.

Authentication:
  X-API-Key header — same API key mechanism used by the agent ingest endpoint.

Source tagging:
  Optional ``X-Webhook-Source`` header embeds the origin label into each event
  as ``_webhook_source`` so normalizers can branch on it.  Defaults to
  ``"generic"`` when the header is absent.

Payload:
  Any valid JSON — a single object ``{...}`` or an array of objects
  ``[{...}, ...]``.  Arrays are limited to 1,000 items per request.

Rate limiting:
  10,000 events per minute per API key (distributed via Valkey, fail-open
  when Valkey is unavailable so ingestion is never silently dropped).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status

from ....core.api_key_auth import get_api_key
from ....core.valkey import check_ingest_rate_limit
from ....models.api_key import APIKey
from ....pipeline.queue import MessageQueue, Topic, get_queue

router = APIRouter(prefix="/ingest", tags=["ingest"])

_MAX_EVENTS        = 1_000    # max events per single request
_RATE_LIMIT_EVENTS = 10_000   # max events per rate-limit window
_RATE_WINDOW_SECS  = 60       # rate-limit window in seconds


@router.post("/test", status_code=200)
async def webhook_ingest_test(
    _api_key: APIKey = Depends(get_api_key),
) -> dict[str, str]:
    """Connectivity probe for webhook senders.

    Returns 200 ``{"status": "ok"}`` when the X-API-Key is valid.
    Returns 401 when the header is absent, 403 when the key is unknown.
    """
    return {"status": "ok"}


@router.post("", status_code=202)
async def webhook_ingest(
    request: Request,
    api_key: APIKey = Depends(get_api_key),
    queue: MessageQueue = Depends(get_queue),
    x_webhook_source: str | None = Header(default=None, alias="X-Webhook-Source"),
) -> dict[str, Any]:
    """Generic webhook receiver — accepts any JSON source.

    Accepts a single JSON object or an array of JSON objects and publishes
    each event to the ``mxtac.raw.webhook`` topic.

    The optional ``X-Webhook-Source`` header is embedded in every published
    event as ``_webhook_source`` so downstream normalizers can identify the
    origin system (e.g. ``"github"``, ``"pagerduty"``, ``"custom"``).  A
    ``_received_at`` field (ISO 8601 UTC) is also injected automatically.

    Rate limited to 10,000 events/minute per API key (fail-open on Valkey
    outage so events are never silently dropped).

    Returns ``202 Accepted`` with the count of queued events on success.

    Errors:
      - ``400`` — body is not valid JSON, or not an object / array of objects.
      - ``422`` — array exceeds the 1,000-event per-request limit, or is empty.
      - ``429`` — rate limit exceeded.
    """
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Request body must be valid JSON",
        )

    source = x_webhook_source or "generic"

    # Normalise to a list of events
    if isinstance(body, dict):
        events: list[Any] = [body]
    elif isinstance(body, list):
        events = body
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="JSON body must be an object or an array of objects",
        )

    if len(events) == 0:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Payload must contain at least one event",
        )

    if len(events) > _MAX_EVENTS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Batch too large: maximum {_MAX_EVENTS} events per request",
        )

    # Validate every item in the array is a JSON object
    for i, event in enumerate(events):
        if not isinstance(event, dict):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Event at index {i} must be a JSON object, got {type(event).__name__}",
            )

    # Distributed rate limiting via Valkey (fail-open on outage)
    n = len(events)
    if not await check_ingest_rate_limit(api_key.id, n, _RATE_LIMIT_EVENTS, _RATE_WINDOW_SECS):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded: 10,000 events per minute per API key",
        )

    # Publish each event with source metadata injected
    received_at = datetime.now(timezone.utc).isoformat()
    for event in events:
        payload: dict[str, Any] = {
            "_webhook_source": source,
            "_received_at": received_at,
            **event,
        }
        await queue.publish(Topic.RAW_WEBHOOK, payload)

    return {
        "accepted": n,
        "topic": Topic.RAW_WEBHOOK,
        "source": source,
        "status": "queued",
    }
