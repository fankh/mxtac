"""Event search and retrieval endpoints.

Search path (POST /search):
  1. Use OpenSearch when a live connection is available — enables full-text
     query_string DSL and nested-field filtering.
  2. Fall back to PostgreSQL (EventRepo) when OpenSearch is unavailable so
     the platform works without a running OpenSearch cluster.

All other endpoints (GET /{id}, POST /aggregate, GET /entity/…) always use
PostgreSQL as the authoritative store.

Ingest path (POST /ingest):
  - Accepts batched OCSF events from agents authenticated with X-API-Key.
  - Validates batch size (max 1000 per request).
  - Rate limited to 10,000 events/minute per API key.
  - Publishes events to the internal message queue.
"""

from __future__ import annotations

import time
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from ....core.api_key_auth import get_api_key
from ....core.database import get_db
from ....core.rbac import require_permission
from ....models.api_key import APIKey
from ....models.event import Event
from ....pipeline.queue import MessageQueue, Topic, get_queue
from ....repositories.event_repo import EventRepo
from ....services.opensearch_client import (
    OpenSearchService,
    filter_to_dsl,
    get_opensearch_dep,
)
from ....services.query_builder import build_lucene_query

router = APIRouter(prefix="/events", tags=["events"])

# ── Rate limiter (in-memory, per API key) ────────────────────────────────────

_RATE_LIMIT_EVENTS = 10_000   # max events per window
_RATE_WINDOW_SECS  = 60.0     # sliding window in seconds

# Maps api_key_id → (event_count, window_start_epoch)
_rate_counters: dict[str, tuple[int, float]] = {}


def _check_rate_limit(api_key_id: str, n_events: int) -> bool:
    """Return True if the request is within the rate limit, False if exceeded."""
    now = time.monotonic()
    count, window_start = _rate_counters.get(api_key_id, (0, now))
    if now - window_start >= _RATE_WINDOW_SECS:
        count, window_start = 0, now
    if count + n_events > _RATE_LIMIT_EVENTS:
        return False
    _rate_counters[api_key_id] = (count + n_events, window_start)
    return True


# ── Schemas ──────────────────────────────────────────────────────────────────


class IngestRequest(BaseModel):
    events: Annotated[list[dict[str, Any]], Field(min_length=1, max_length=1000)]


class EventFilter(BaseModel):
    field: str
    operator: str  # eq, ne, gt, lt, gte, lte, contains
    value: Any


class SearchRequest(BaseModel):
    query: str | None = None
    filters: list[EventFilter] = []
    time_from: str = "now-7d"
    time_to: str = "now"
    size: int = 100
    from_: int = 0


class AggregationRequest(BaseModel):
    field: str
    agg_type: str = "terms"  # terms, date_histogram, stats
    size: int = 10
    time_from: str = "now-7d"
    time_to: str = "now"


# ── Serialization ─────────────────────────────────────────────────────────────


def _event_to_dict(e: Event) -> dict:
    """Serialize an Event ORM object to a JSON-safe dict."""
    base: dict[str, Any] = {
        "id":           e.id,
        "event_uid":    e.event_uid,
        "time":         e.time.isoformat() if isinstance(e.time, datetime) else e.time,
        "class_name":   e.class_name,
        "class_uid":    e.class_uid,
        "severity_id":  e.severity_id,
        "src_ip":       e.src_ip,
        "dst_ip":       e.dst_ip,
        "hostname":     e.hostname,
        "username":     e.username,
        "process_hash": e.process_hash,
        "source":       e.source,
        "summary":      e.summary,
    }
    # Merge the full raw payload on top so callers get all OCSF fields
    if e.raw:
        base.update(e.raw)
    return base


def _os_hit_to_dict(hit: dict) -> dict:
    """Normalize an OpenSearch search hit into the event response format.

    The hit ``_source`` is the full OCSF event dict indexed by the event
    persister.  We surface the OpenSearch document ``_id`` as ``id`` when
    the source does not already carry one (e.g. legacy documents).
    """
    src: dict[str, Any] = dict(hit.get("_source") or {})
    if "id" not in src:
        src["id"] = hit.get("_id", "")
    return src


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.post("/search")
async def search_events(
    body: SearchRequest,
    db: AsyncSession = Depends(get_db),
    os_client: OpenSearchService = Depends(get_opensearch_dep),
    _: dict = Depends(require_permission("events:search")),
):
    """Full-text + filtered event search with time range.

    Delegates to OpenSearch when a live connection is available, enabling
    query_string DSL and nested OCSF field filtering.  Falls back to
    PostgreSQL (EventRepo) when OpenSearch is unavailable.
    """
    if os_client.is_available:
        # Build OpenSearch DSL filter clauses from structured filters
        dsl_filters = [
            clause
            for f in body.filters
            if (clause := filter_to_dsl(f.field, f.operator, f.value)) is not None
        ]
        resp = await os_client.search_events(
            query=body.query,
            filters=dsl_filters or None,
            time_from=body.time_from,
            time_to=body.time_to,
            size=body.size,
            from_=body.from_,
        )
        hits = resp.get("hits", {})
        total_val = hits.get("total", {})
        total = total_val.get("value", 0) if isinstance(total_val, dict) else int(total_val)
        items = [_os_hit_to_dict(h) for h in hits.get("hits", [])]
        return {
            "total": total,
            "items": items,
            "from_": body.from_,
            "size":  body.size,
            "backend": "opensearch",
        }

    # Fallback: PostgreSQL
    items_pg, total = await EventRepo.search(
        db,
        query=body.query,
        filters=body.filters,
        time_from=body.time_from,
        time_to=body.time_to,
        size=body.size,
        from_=body.from_,
    )
    return {
        "total": total,
        "items": [_event_to_dict(e) for e in items_pg],
        "from_": body.from_,
        "size":  body.size,
        "backend": "postgres",
    }


@router.post("/aggregate")
async def aggregate_events(
    body: AggregationRequest,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("events:search")),
):
    """Aggregate events by a field (terms aggregation)."""
    buckets = await EventRepo.count_by_field(
        db,
        field=body.field,
        time_from=body.time_from,
        time_to=body.time_to,
        limit=body.size,
    )
    return {"field": body.field, "buckets": buckets}


@router.get("/entity/{entity_type}/{entity_value}")
async def entity_timeline(
    entity_type: str,
    entity_value: str,
    time_from: str = "now-7d",
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("events:search")),
):
    """Return all events involving a specific entity (IP, host, user, hash)."""
    events, total = await EventRepo.entity_events(
        db,
        entity_type=entity_type,
        entity_value=entity_value,
        time_from=time_from,
        size=200,
    )
    return {
        "entity_type":  entity_type,
        "entity_value": entity_value,
        "total":        total,
        "events":       [_event_to_dict(e) for e in events],
    }


@router.post("/query-dsl")
async def build_query_dsl(
    body: SearchRequest,
    _: dict = Depends(require_permission("events:search")),
):
    """Translate a SearchRequest into a Lucene query string.

    Returns the Lucene DSL that represents the same search as the supplied
    *query* + *filters* + time range.  The string can be used directly in
    OpenSearch / Elasticsearch ``query_string.query``, or pasted into
    OpenSearch Dashboards / Kibana for interactive hunting.

    No database or OpenSearch call is made — this is a pure translation.
    """
    lucene = build_lucene_query(
        query=body.query,
        filters=body.filters,
        time_from=body.time_from,
        time_to=body.time_to,
    )
    return {"lucene": lucene}


@router.post("/ingest/test", status_code=200)
async def ingest_test(
    _api_key: APIKey = Depends(get_api_key),
) -> dict[str, str]:
    """Connectivity test for agents. Returns 200 when the API key is valid."""
    return {"status": "ok"}


@router.post("/ingest", status_code=202)
async def ingest_events(
    body: IngestRequest,
    api_key: APIKey = Depends(get_api_key),
    queue: MessageQueue = Depends(get_queue),
) -> dict[str, Any]:
    """Batch-ingest OCSF events from agents.

    Validates batch size (≤ 1,000), enforces per-key rate limit (10,000 events/min),
    then publishes each event to the internal message queue.
    Returns 202 Accepted on success.
    """
    n = len(body.events)
    if not _check_rate_limit(api_key.id, n):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded: 10,000 events per minute per API key",
        )

    for event in body.events:
        await queue.publish(Topic.NORMALIZED, event)

    return {"accepted": n, "status": "queued"}


@router.get("/{event_id}")
async def get_event(
    event_id: str,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("events:search")),
):
    """Retrieve a single event by its UUID primary key."""
    event = await EventRepo.get(db, event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return _event_to_dict(event)
