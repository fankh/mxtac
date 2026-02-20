"""Event search and retrieval endpoints (backed by OpenSearch)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ....core.rbac import require_permission
from ....services.opensearch_client import get_opensearch

router = APIRouter(prefix="/events", tags=["events"])

# ── Schemas ──────────────────────────────────────────────────────────────────

class EventFilter(BaseModel):
    field: str
    operator: str   # eq, ne, gt, lt, gte, lte, contains
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
    agg_type: str = "terms"   # terms, date_histogram, stats
    size: int = 10
    time_from: str = "now-7d"
    time_to: str = "now"

# ── Helpers ───────────────────────────────────────────────────────────────────

def _build_os_filter(f: EventFilter) -> dict:
    op_map = {
        "eq":       lambda: {"term":  {f.field: f.value}},
        "ne":       lambda: {"bool": {"must_not": [{"term": {f.field: f.value}}]}},
        "contains": lambda: {"match": {f.field: f.value}},
        "gt":       lambda: {"range": {f.field: {"gt": f.value}}},
        "lt":       lambda: {"range": {f.field: {"lt": f.value}}},
        "gte":      lambda: {"range": {f.field: {"gte": f.value}}},
        "lte":      lambda: {"range": {f.field: {"lte": f.value}}},
    }
    builder = op_map.get(f.operator)
    return builder() if builder else {"term": {f.field: f.value}}

# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/search")
async def search_events(body: SearchRequest, _: dict = Depends(require_permission("events:search"))):
    """Full-text + filtered event search across all indexed data sources."""
    os_filters = [_build_os_filter(f) for f in body.filters]
    result = await get_opensearch().search_events(
        query=body.query,
        filters=os_filters,
        time_from=body.time_from,
        time_to=body.time_to,
        size=body.size,
        from_=body.from_,
    )
    hits = result.get("hits", {})
    return {
        "total":  hits.get("total", {}).get("value", 0),
        "items":  [h.get("_source", {}) for h in hits.get("hits", [])],
        "from_":  body.from_,
        "size":   body.size,
    }


@router.get("/{event_id}")
async def get_event(event_id: str, _: dict = Depends(require_permission("events:search"))):
    """Retrieve a single event by ID."""
    event = await get_opensearch().get_event(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event


@router.post("/aggregate")
async def aggregate_events(body: AggregationRequest, _: dict = Depends(require_permission("events:search"))):
    """Aggregate events by a field (terms, date_histogram)."""
    os = get_opensearch()
    if os._client is None:
        # Return mock aggregation when OpenSearch not available
        return {
            "field": body.field,
            "buckets": [
                {"key": "critical", "count": 23},
                {"key": "high", "count": 187},
                {"key": "medium", "count": 512},
                {"key": "low", "count": 1204},
            ],
        }

    agg_body = {
        "query": {"range": {"time": {"gte": body.time_from, "lte": body.time_to}}},
        "aggs": {
            "result": {
                body.agg_type: {"field": body.field, "size": body.size}
                if body.agg_type == "terms"
                else {"field": body.field, "calendar_interval": "day"}
            }
        },
        "size": 0,
    }
    try:
        resp = await os._client.search(index="mxtac-events-*", body=agg_body)
        buckets = resp.get("aggregations", {}).get("result", {}).get("buckets", [])
        return {
            "field":   body.field,
            "buckets": [{"key": b["key"], "count": b["doc_count"]} for b in buckets],
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/entity/{entity_type}/{entity_value}")
async def entity_timeline(
    entity_type: str,
    entity_value: str,
    time_from: str = "now-7d",
    _: dict = Depends(require_permission("events:search")),
):
    """Return all events involving a specific entity (IP, host, user, hash)."""
    field_map = {
        "ip":   ["src_endpoint.ip", "dst_endpoint.ip"],
        "host": ["dst_endpoint.hostname"],
        "user": ["actor_user.name"],
        "hash": ["process.hash_sha256"],
    }
    fields = field_map.get(entity_type, ["dst_endpoint.hostname"])
    should = [{"term": {f: entity_value}} for f in fields]

    result = await get_opensearch().search_events(
        filters=[{"bool": {"should": should, "minimum_should_match": 1}}],
        time_from=time_from,
        size=200,
    )
    hits = result.get("hits", {})
    return {
        "entity_type":  entity_type,
        "entity_value": entity_value,
        "total":        hits.get("total", {}).get("value", 0),
        "events":       [h.get("_source", {}) for h in hits.get("hits", [])],
    }
