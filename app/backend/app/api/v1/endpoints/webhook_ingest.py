"""Generic webhook ingest endpoint — Feature 35.3 (extends 6.21).

Accepts arbitrary JSON payloads from registered "generic" connectors and
publishes each event to a dynamic ``mxtac.raw.{source_name}`` topic for
downstream normalizer processing.

Authentication:
  X-MxTac-Source — registered connector name (must be type "generic"), required.
  X-MxTac-Token  — webhook token from connector's config_json.webhook_token, required.

Payload:
  Any valid JSON — a single object ``{...}`` or an array of objects
  ``[{...}, ...]``.  Maximum body size: 5 MB.

Rate limiting:
  100 requests per minute per source (distributed via Valkey, fail-open when
  Valkey is unavailable so ingestion is never silently dropped).
"""

from __future__ import annotations

import hmac
import json
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from ....core.database import get_db
from ....core.valkey import check_webhook_source_rate_limit
from ....pipeline.queue import MessageQueue, get_queue
from ....repositories.connector_repo import ConnectorRepo

router = APIRouter(prefix="/ingest", tags=["ingest"])

_MAX_BODY_BYTES    = 5 * 1024 * 1024  # 5 MB per request
_RATE_LIMIT_REQS   = 100              # max requests per rate-limit window
_RATE_WINDOW_SECS  = 60               # rate-limit window in seconds


async def _resolve_connector(source_name: str, token: str, db: AsyncSession):
    """Look up a generic connector by name and validate its webhook token.

    Raises ``401 Unauthorized`` when the source is unknown, not a generic
    connector, or the token does not match.
    """
    connector = await ConnectorRepo.get_by_name(db, source_name)
    if connector is None or connector.connector_type != "generic":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unknown source or source is not a generic connector",
        )
    config = json.loads(connector.config_json or "{}")
    expected = config.get("webhook_token", "")
    if not expected or not hmac.compare_digest(token, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook token",
        )
    return connector


@router.post("/test", status_code=200)
async def webhook_ingest_test(
    x_mxtac_source: str = Header(alias="X-MxTac-Source"),
    x_mxtac_token: str = Header(alias="X-MxTac-Token"),
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    """Connectivity probe for webhook senders.

    Returns 200 ``{"status": "ok"}`` when the source connector exists, is of
    type "generic", and the token is correct.
    Returns 401 when the source is unknown or the token is incorrect.
    """
    await _resolve_connector(x_mxtac_source, x_mxtac_token, db)
    return {"status": "ok"}


@router.post("", status_code=202)
async def webhook_ingest(
    request: Request,
    x_mxtac_source: str = Header(alias="X-MxTac-Source"),
    x_mxtac_token: str = Header(alias="X-MxTac-Token"),
    queue: MessageQueue = Depends(get_queue),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Generic webhook receiver — connector-authenticated JSON ingest.

    Validates the source connector (type must be "generic") and webhook token,
    then publishes each event to ``mxtac.raw.{source_name}``.

    Rate limited to 100 requests/minute per source (fail-open on Valkey outage
    so events are never silently dropped).

    Returns ``202 Accepted`` with accepted / rejected event counts.

    Errors:
      - ``400`` — body is not valid JSON, or not an object / array of objects.
      - ``401`` — unknown source, not a generic connector, or token mismatch.
      - ``413`` — body exceeds the 5 MB limit.
      - ``429`` — rate limit exceeded (100 req/min per source).
    """
    # 1. Rate limit — cheap check before touching the DB
    if not await check_webhook_source_rate_limit(
        x_mxtac_source, _RATE_LIMIT_REQS, _RATE_WINDOW_SECS
    ):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded: 100 requests per minute per source",
        )

    # 2. Validate connector + token
    await _resolve_connector(x_mxtac_source, x_mxtac_token, db)

    # 3. Enforce 5 MB body limit — check Content-Length first for early rejection
    content_length = request.headers.get("Content-Length")
    if content_length is not None and int(content_length) > _MAX_BODY_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Request body exceeds the 5 MB limit",
        )

    body_bytes = await request.body()
    if len(body_bytes) > _MAX_BODY_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Request body exceeds the 5 MB limit",
        )

    # 4. Parse JSON
    try:
        body = json.loads(body_bytes)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Request body must be valid JSON",
        )

    # 5. Normalise to a list of events
    if isinstance(body, dict):
        events: list[Any] = [body]
    elif isinstance(body, list):
        events = body
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="JSON body must be an object or an array of objects",
        )

    # 6. Publish valid events; skip and count non-object array items
    topic = f"mxtac.raw.{x_mxtac_source}"
    received_at = datetime.now(timezone.utc).isoformat()
    accepted = 0
    rejected = 0

    for event in events:
        if not isinstance(event, dict):
            rejected += 1
            continue
        await queue.publish(topic, {
            "_webhook_source": x_mxtac_source,
            "_received_at": received_at,
            **event,
        })
        accepted += 1

    return {"accepted": accepted, "rejected": rejected}
