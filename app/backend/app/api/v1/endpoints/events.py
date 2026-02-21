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
  - Rate limited to 10,000 events/minute per API key (distributed via Valkey).
  - Publishes events to the internal message queue.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from ....core.api_key_auth import get_api_key
from ....core.database import get_db
from ....core.rbac import require_permission
from ....core.valkey import check_ingest_rate_limit
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

# ── Rate limiting (distributed via Valkey) ────────────────────────────────────
# The counter is stored in Valkey so the limit is shared across all API replicas.
# Falls back to allowing requests when Valkey is unavailable (fail-open).

_RATE_LIMIT_EVENTS = 10_000   # max events per window
_RATE_WINDOW_SECS  = 60       # window duration in seconds


# ── Schemas ──────────────────────────────────────────────────────────────────

# Known safe event filter fields — must match _FIELD_MAP keys in event_repo.py
_ALLOWED_FILTER_FIELDS = frozenset({
    "severity_id", "class_name", "class_uid",
    "src_ip", "dst_ip", "hostname", "username", "process_hash", "source",
    # OpenSearch nested aliases
    "src_endpoint.ip", "dst_endpoint.ip", "dst_endpoint.hostname",
    "actor_user.name", "process.hash_sha256",
})

EventOperator = Literal["eq", "ne", "gt", "lt", "gte", "lte", "contains"]

AggType = Literal["terms", "date_histogram"]

AggInterval = Literal["1m", "minute", "1h", "hour", "1d", "24h", "day", "1w", "week", "1M", "month"]


class IngestRequest(BaseModel):
    events: Annotated[list[dict[str, Any]], Field(min_length=1, max_length=1000)]


class EventFilter(BaseModel):
    field: str = Field(..., max_length=128)
    operator: EventOperator
    value: Any

    @field_validator("field")
    @classmethod
    def validate_field(cls, v: str) -> str:
        if v not in _ALLOWED_FILTER_FIELDS:
            raise ValueError(
                f"Unknown filter field {v!r}. Allowed fields: {sorted(_ALLOWED_FILTER_FIELDS)}"
            )
        return v


class SearchRequest(BaseModel):
    query: str | None = Field(default=None, max_length=2048)
    filters: list[EventFilter] = Field(default_factory=list, max_length=50)
    time_from: str = Field(default="now-7d", max_length=50)
    time_to: str = Field(default="now", max_length=50)
    size: int = Field(default=100, ge=1, le=1000)
    from_: int = Field(default=0, ge=0, le=100000)


class AggregationRequest(BaseModel):
    field: str | None = Field(default=None, max_length=128)
    agg_type: AggType = "terms"
    interval: AggInterval = "1h"
    size: int = Field(default=10, ge=1, le=1000)
    time_from: str = Field(default="now-7d", max_length=50)
    time_to: str = Field(default="now", max_length=50)


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
    os_client: OpenSearchService = Depends(get_opensearch_dep),
    _: dict = Depends(require_permission("events:search")),
):
    """Aggregate events by field (terms) or over time (date_histogram).

    Delegates to OpenSearch when a live connection is available, falling back
    to PostgreSQL (EventRepo) otherwise.

    - ``agg_type=terms`` — count events grouped by a field value; requires *field*.
    - ``agg_type=date_histogram`` — count events bucketed by time; uses *interval*.
    """
    if os_client.is_available:
        buckets = await os_client.aggregate(
            body.agg_type,
            field=body.field,
            interval=body.interval,
            time_from=body.time_from,
            time_to=body.time_to,
            size=body.size,
        )
        if body.agg_type == "date_histogram":
            return {
                "agg_type": "date_histogram",
                "interval": body.interval,
                "buckets":  buckets,
                "backend":  "opensearch",
            }
        return {"field": body.field, "buckets": buckets, "backend": "opensearch"}

    # Fallback: PostgreSQL
    if body.agg_type == "date_histogram":
        buckets = await EventRepo.histogram_by_time(
            db,
            interval=body.interval,
            time_from=body.time_from,
            time_to=body.time_to,
        )
        return {
            "agg_type": "date_histogram",
            "interval": body.interval,
            "buckets":  buckets,
        }

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

    Validates batch size (≤ 1,000), enforces per-key rate limit (10,000 events/min)
    via a shared Valkey counter so the limit is consistent across all replicas.
    Returns 202 Accepted on success.
    """
    n = len(body.events)
    if not await check_ingest_rate_limit(api_key.id, n, _RATE_LIMIT_EVENTS, _RATE_WINDOW_SECS):
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
