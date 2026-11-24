"""Event search and retrieval endpoints.

Search path (POST /search, POST /aggregate, POST /export):
  1. Use OpenSearch when a live connection is available.
  2. Fall back to PostgreSQL (EventRepo) when OpenSearch is unavailable or a
     query fails, so the platform always works regardless of configuration.

Both stores hold the same event document (``services/event_document.py``) and
answer a search with the same rows: same match rules, same order, same fields.

All other endpoints (GET /{id}, GET /entity/…) always use PostgreSQL as the
authoritative store.
"""

from __future__ import annotations

import csv
import io
import re
from datetime import date
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from ....core.database import get_db
from ....core.logging import get_logger
from ....core.rbac import require_permission
from ....repositories.event_repo import EventRepo
from ....services.event_document import FILTER_FIELDS, event_to_dict
from ....services.opensearch_client import (
    OpenSearchQueryError,
    OpenSearchService,
    filter_to_dsl,
    get_opensearch_dep,
)
from ....services.query_builder import build_lucene_query

logger = get_logger(__name__)

router = APIRouter(prefix="/events", tags=["events"])

# ── Time range validation ─────────────────────────────────────────────────────
# Whitelist of characters allowed in time_from / time_to to prevent Lucene
# query-string injection via the time range clause (feature 33.3).
# Allows: relative dates (now-7d, now/d), ISO 8601 (2026-01-01T00:00:00Z),
#         and timezone offsets (+00:00).  Rejects ] [ { } * ? ( ) space etc.
_SAFE_TIME_RE = re.compile(r'^[A-Za-z0-9+\-:.Z/]+$')


def _validate_time_range(v: str) -> str:
    if not _SAFE_TIME_RE.match(v):
        raise ValueError(
            "time_from / time_to must be a relative date (e.g. 'now-7d') "
            "or ISO 8601 timestamp. Special characters are not allowed."
        )
    return v


# ── Schemas ──────────────────────────────────────────────────────────────────

# Known safe event filter fields (flat fields and their nested OCSF aliases)
_ALLOWED_FILTER_FIELDS = frozenset(FILTER_FIELDS)

EventOperator = Literal["eq", "ne", "gt", "lt", "gte", "lte", "contains"]

AggType = Literal["terms", "date_histogram"]

AggInterval = Literal["1m", "minute", "1h", "hour", "1d", "24h", "day", "1w", "week", "1M", "month"]


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

    @field_validator("time_from", "time_to")
    @classmethod
    def validate_time_range_format(cls, v: str) -> str:
        return _validate_time_range(v)


class AggregationRequest(BaseModel):
    field: str | None = Field(default=None, max_length=128)
    agg_type: AggType = "terms"
    interval: AggInterval = "1h"
    size: int = Field(default=10, ge=1, le=1000)
    time_from: str = Field(default="now-7d", max_length=50)
    time_to: str = Field(default="now", max_length=50)

    @field_validator("time_from", "time_to")
    @classmethod
    def validate_time_range_format(cls, v: str) -> str:
        return _validate_time_range(v)


# ── Serialization ─────────────────────────────────────────────────────────────


# Serialize an Event row to the event document returned by these endpoints.
_event_to_dict = event_to_dict


def _os_hit_to_dict(hit: dict) -> dict:
    """Return the event document of an OpenSearch search hit.

    The hit ``_source`` is the document the event persister indexed — the
    same dict ``_event_to_dict`` builds from the PostgreSQL row.
    """
    src: dict[str, Any] = dict(hit.get("_source") or {})
    if "id" not in src:
        src["id"] = hit.get("_id", "")
    return src


async def _search_opensearch(
    os_client: OpenSearchService, body: SearchRequest, *, size: int, from_: int,
) -> tuple[list[dict], int] | None:
    """Run the search on OpenSearch.  Returns ``(items, total)``.

    Returns ``None`` when OpenSearch is not connected or the query fails; the
    caller then answers from PostgreSQL.
    """
    if not os_client.is_available:
        return None
    dsl_filters = [
        clause
        for f in body.filters
        if (clause := filter_to_dsl(f.field, f.operator, f.value)) is not None
    ]
    try:
        resp = await os_client.search_events(
            query=body.query,
            filters=dsl_filters or None,
            time_from=body.time_from,
            time_to=body.time_to,
            size=size,
            from_=from_,
        )
    except OpenSearchQueryError:
        logger.warning("Event search falls back to PostgreSQL")
        return None
    hits = resp.get("hits", {})
    total_val = hits.get("total", {})
    total = total_val.get("value", 0) if isinstance(total_val, dict) else int(total_val)
    return [_os_hit_to_dict(h) for h in hits.get("hits", [])], total


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.post("/search")
async def search_events(
    body: SearchRequest,
    db: AsyncSession = Depends(get_db),
    os_client: OpenSearchService = Depends(get_opensearch_dep),
    _: dict = Depends(require_permission("events:search")),
):
    """Full-text + filtered event search with time range.

    Backend priority:
      1. OpenSearch — when a live connection is available (full-text DSL).
      2. PostgreSQL — always available as the authoritative fallback.
    """
    found = await _search_opensearch(os_client, body, size=body.size, from_=body.from_)
    if found is not None:
        items, total = found
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

    Backend priority:
      1. OpenSearch — when a live connection is available.
      2. PostgreSQL — always available as the authoritative fallback.

    - ``agg_type=terms`` — count events grouped by a field value; requires *field*.
    - ``agg_type=date_histogram`` — count events bucketed by time; uses *interval*.
    """
    buckets: list[dict] | None = None
    if os_client.is_available:
        try:
            buckets = await os_client.aggregate(
                body.agg_type,
                field=body.field,
                interval=body.interval,
                time_from=body.time_from,
                time_to=body.time_to,
                size=body.size,
            )
        except OpenSearchQueryError:
            logger.warning("Event aggregation falls back to PostgreSQL")
    if buckets is not None:
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


_ALLOWED_ENTITY_TYPES = frozenset({"ip", "host", "user", "hash"})


@router.get("/entity/{entity_type}/{entity_value}")
async def entity_timeline(
    entity_type: str = Path(..., max_length=20),
    entity_value: str = Path(..., max_length=512),
    time_from: str = Query("now-7d", max_length=50),
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("events:search")),
):
    """Return all events involving a specific entity (IP, host, user, hash)."""
    if entity_type not in _ALLOWED_ENTITY_TYPES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid entity_type {entity_type!r}. Allowed: {sorted(_ALLOWED_ENTITY_TYPES)}",
        )
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


_EXPORT_MAX_ROWS = 10_000
_EVENT_CSV_COLS = (
    "id", "time", "class_name", "severity_id",
    "src_ip", "dst_ip", "hostname", "username", "source", "summary",
)


@router.post("/export")
async def export_events(
    body: SearchRequest,
    db: AsyncSession = Depends(get_db),
    os_client: OpenSearchService = Depends(get_opensearch_dep),
    _: dict = Depends(require_permission("events:search")),
):
    """Export event search results as CSV (max 10,000 rows).

    Accepts the same request body as POST /search.
    Returns a streaming text/csv file with columns:
    id, time, class_name, severity_id, src_ip, dst_ip, hostname, username, source, summary.
    """
    found = await _search_opensearch(os_client, body, size=_EXPORT_MAX_ROWS, from_=0)
    if found is not None:
        items: list[dict] = found[0]
    else:
        items_pg, _ = await EventRepo.search(
            db,
            query=body.query,
            filters=body.filters,
            time_from=body.time_from,
            time_to=body.time_to,
            size=_EXPORT_MAX_ROWS,
            from_=0,
        )
        items = [_event_to_dict(e) for e in items_pg]

    def _iter_csv():
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(_EVENT_CSV_COLS)
        yield buf.getvalue()
        for item in items:
            buf.seek(0)
            buf.truncate(0)
            writer.writerow(tuple(str(item.get(col) or "") for col in _EVENT_CSV_COLS))
            yield buf.getvalue()

    filename = f"events_{date.today().isoformat()}.csv"
    return StreamingResponse(
        _iter_csv(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


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
