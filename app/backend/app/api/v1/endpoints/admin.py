"""Admin endpoints — audit log access and platform administration."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from typing import Any

from ....core.security import get_current_user
from ....services.audit import get_audit_logger

router = APIRouter(prefix="/admin", tags=["admin"])


# ── Schemas ──────────────────────────────────────────────────────────────────

class AuditLogEntry(BaseModel):
    id: str
    timestamp: str
    actor: str
    action: str
    resource_type: str
    resource_id: str = ""
    details: dict[str, Any] = {}
    request_ip: str | None = None
    request_method: str | None = None
    request_path: str | None = None
    user_agent: str | None = None


class AuditLogResponse(BaseModel):
    total: int
    page: int
    page_size: int
    items: list[AuditLogEntry]


# ── Helpers ──────────────────────────────────────────────────────────────────

def _require_admin(user: dict) -> None:
    """Raise 403 if the authenticated user is not an admin."""
    if user.get("role") not in ("admin", "superadmin"):
        raise HTTPException(
            status_code=403,
            detail="Admin access required",
        )


# ── Endpoints ────────────────────────────────────────────────────────────────

@router.get("/audit-log", response_model=AuditLogResponse)
async def get_audit_log(
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(50, ge=1, le=500, description="Items per page"),
    actor: str | None = Query(None, description="Filter by actor email"),
    action: str | None = Query(None, description="Filter by action verb"),
    resource_type: str | None = Query(None, description="Filter by resource type"),
    time_from: str = Query("now-7d", description="Start time (OpenSearch date math)"),
    time_to: str = Query("now", description="End time (OpenSearch date math)"),
    current_user: dict = Depends(get_current_user),
) -> AuditLogResponse:
    """
    Retrieve paginated audit log entries from the mxtac-audit index.

    Requires admin role. Supports filtering by actor, action, resource type, and time range.
    """
    _require_admin(current_user)

    audit = get_audit_logger()
    from_ = (page - 1) * page_size

    result = await audit.search(
        actor=actor,
        action=action,
        resource_type=resource_type,
        time_from=time_from,
        time_to=time_to,
        size=page_size,
        from_=from_,
    )

    return AuditLogResponse(
        total=result["total"],
        page=page,
        page_size=page_size,
        items=[AuditLogEntry(**item) for item in result["items"]],
    )
