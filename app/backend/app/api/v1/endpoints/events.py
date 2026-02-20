"""Event search and retrieval endpoints — backed by PostgreSQL (EventRepo).

PostgreSQL is the primary store so the platform works without a running
OpenSearch cluster.  Full OpenSearch integration is tracked in feature 11.5.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from ....core.database import get_db
from ....core.rbac import require_permission
from ....models.event import Event
from ....repositories.event_repo import EventRepo

router = APIRouter(prefix="/events", tags=["events"])


# ── Schemas ──────────────────────────────────────────────────────────────────


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


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.post("/search")
async def search_events(
    body: SearchRequest,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("events:search")),
):
    """Full-text + filtered event search with time range — backed by PostgreSQL."""
    items, total = await EventRepo.search(
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
        "items": [_event_to_dict(e) for e in items],
        "from_": body.from_,
        "size":  body.size,
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
