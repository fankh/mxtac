"""Audit log endpoints — Feature 21.12.

Provides read-only access to the database-backed audit trail.
Only admin users may query audit logs.

Routes:
    GET  /audit-logs          — paginated list with optional filters
    GET  /audit-logs/{id}     — single audit log entry
"""

from math import ceil
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from sqlalchemy.ext.asyncio import AsyncSession

from ....core.database import get_db
from ....core.rbac import require_permission
from ....repositories.audit_log_repo import AuditLogRepo
from ....schemas.audit_log import AuditLogResponse
from ....schemas.common import Pagination, PaginatedResponse

router = APIRouter(prefix="/audit-logs", tags=["audit-logs"])


def _entry_to_schema(entry) -> dict:
    return {
        "id": entry.id,
        "timestamp": entry.timestamp,
        "actor": entry.actor,
        "action": entry.action,
        "resource_type": entry.resource_type,
        "resource_id": entry.resource_id,
        "details": entry.details,
        "request_ip": entry.request_ip,
        "request_method": entry.request_method,
        "request_path": entry.request_path,
        "user_agent": entry.user_agent,
    }


# ---------------------------------------------------------------------------
# GET /audit-logs — paginated list
# ---------------------------------------------------------------------------


@router.get("", response_model=PaginatedResponse[AuditLogResponse])
async def list_audit_logs(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    actor: str | None = Query(None, description="Filter by actor email"),
    action: str | None = Query(None, description="Filter by action verb (create/update/delete/…)"),
    resource_type: str | None = Query(None, description="Filter by resource type"),
    from_ts: datetime | None = Query(None, description="Earliest timestamp (ISO 8601)"),
    to_ts: datetime | None = Query(None, description="Latest timestamp (ISO 8601)"),
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("audit_logs:read")),
):
    """List audit log entries, newest first.

    All filter parameters are optional and combinable.
    """
    skip = (page - 1) * page_size
    items, total = await AuditLogRepo.list(
        db,
        skip=skip,
        limit=page_size,
        actor=actor,
        action=action,
        resource_type=resource_type,
        from_ts=from_ts,
        to_ts=to_ts,
    )
    return PaginatedResponse(
        items=[_entry_to_schema(e) for e in items],
        pagination=Pagination(
            page=page,
            page_size=page_size,
            total=total,
            total_pages=max(1, ceil(total / page_size)),
        ),
    )


# ---------------------------------------------------------------------------
# GET /audit-logs/{id} — single entry
# ---------------------------------------------------------------------------


@router.get("/{entry_id}", response_model=AuditLogResponse)
async def get_audit_log(
    entry_id: str = Path(..., description="Audit log entry UUID"),
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("audit_logs:read")),
):
    """Retrieve a single audit log entry by ID."""
    entry = await AuditLogRepo.get_by_id(db, entry_id)
    if not entry:
        raise HTTPException(status_code=404, detail=f"Audit log entry {entry_id!r} not found")
    return _entry_to_schema(entry)
