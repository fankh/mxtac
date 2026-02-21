"""Saved hunt query endpoints — Feature 11.7.

Users (hunter role and above) can persist named hunt queries so they can be
loaded and replayed later without re-typing the search.  Queries are scoped
to the authenticated user — each user only sees and manages their own.

Routes:
    POST   /hunt/queries           — save a new query
    GET    /hunt/queries           — list the caller's saved queries
    GET    /hunt/queries/{id}      — fetch one saved query
    PUT    /hunt/queries/{id}      — update name / description / search params
    DELETE /hunt/queries/{id}      — delete a saved query
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from ....core.database import get_db
from ....core.rbac import require_permission
from ....repositories.saved_query_repo import SavedQueryRepo

router = APIRouter(prefix="/hunt/queries", tags=["hunt"])


# ── Schemas ───────────────────────────────────────────────────────────────────


class FilterItem(BaseModel):
    """One structured filter row (mirrors EventFilter on the events endpoint)."""

    field: str = Field(..., max_length=128)
    operator: str = Field(..., max_length=20)
    value: Any


class SavedQueryCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=1000)
    query: str | None = Field(default=None, max_length=2048)
    filters: list[FilterItem] = Field(default_factory=list, max_length=50)
    time_from: str = Field(default="now-24h", max_length=50)
    time_to: str = Field(default="now", max_length=50)


class SavedQueryUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=1000)
    query: str | None = Field(default=None, max_length=2048)
    filters: list[FilterItem] | None = Field(default=None, max_length=50)
    time_from: str | None = Field(default=None, max_length=50)
    time_to: str | None = Field(default=None, max_length=50)


# ── Serialization ─────────────────────────────────────────────────────────────


def _to_dict(sq) -> dict:
    return {
        "id":          sq.id,
        "name":        sq.name,
        "description": sq.description,
        "query":       sq.query,
        "filters":     sq.filters or [],
        "time_from":   sq.time_from,
        "time_to":     sq.time_to,
        "created_by":  sq.created_by,
        "created_at":  sq.created_at.isoformat() if isinstance(sq.created_at, datetime) else sq.created_at,
        "updated_at":  sq.updated_at.isoformat() if isinstance(sq.updated_at, datetime) else sq.updated_at,
    }


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_saved_query(
    body: SavedQueryCreate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission("hunt_queries:write")),
):
    """Save and name the current hunt query for later reuse."""
    sq = await SavedQueryRepo.create(
        db,
        name=body.name,
        description=body.description,
        query=body.query,
        filters=[f.model_dump() for f in body.filters],
        time_from=body.time_from,
        time_to=body.time_to,
        created_by=current_user["email"],
    )
    await db.commit()
    await db.refresh(sq)
    return _to_dict(sq)


@router.get("")
async def list_saved_queries(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission("hunt_queries:read")),
):
    """Return all saved queries belonging to the authenticated user."""
    queries = await SavedQueryRepo.list_for_user(db, current_user["email"])
    return {"items": [_to_dict(sq) for sq in queries], "total": len(queries)}


@router.get("/{query_id}")
async def get_saved_query(
    query_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission("hunt_queries:read")),
):
    """Fetch a single saved query by ID (must belong to the caller)."""
    sq = await SavedQueryRepo.get(db, query_id, current_user["email"])
    if sq is None:
        raise HTTPException(status_code=404, detail="Saved query not found")
    return _to_dict(sq)


@router.put("/{query_id}")
async def update_saved_query(
    query_id: str,
    body: SavedQueryUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission("hunt_queries:write")),
):
    """Update the name, description, or search parameters of a saved query."""
    sq = await SavedQueryRepo.get(db, query_id, current_user["email"])
    if sq is None:
        raise HTTPException(status_code=404, detail="Saved query not found")
    filters_data = [f.model_dump() for f in body.filters] if body.filters is not None else None
    sq = await SavedQueryRepo.update(
        db,
        sq,
        name=body.name,
        description=body.description,
        query=body.query,
        filters=filters_data,
        time_from=body.time_from,
        time_to=body.time_to,
    )
    await db.commit()
    await db.refresh(sq)
    return _to_dict(sq)


@router.delete("/{query_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_saved_query(
    query_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission("hunt_queries:write")),
):
    """Delete a saved query (must belong to the caller)."""
    sq = await SavedQueryRepo.get(db, query_id, current_user["email"])
    if sq is None:
        raise HTTPException(status_code=404, detail="Saved query not found")
    await SavedQueryRepo.delete(db, sq)
    await db.commit()
