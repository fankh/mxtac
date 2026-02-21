"""Admin endpoints — audit log access and platform administration."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Any

from ....core.config import settings
from ....core.database import get_db
from ....core.security import get_current_user
from ....services.audit import get_audit_logger
from ....services.opensearch_client import get_opensearch_dep
from ....services.retention import get_retention_storage_stats

router = APIRouter(prefix="/admin", tags=["admin"])

# OpenSearch snapshot repository identifier (logical name within OpenSearch).
# The filesystem path is configured via settings.opensearch_snapshot_repo.
_SNAPSHOT_REPO_NAME = "mxtac-snapshots"


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


class SnapshotInfo(BaseModel):
    name: str
    state: str
    start_time: str
    end_time: str
    duration_millis: int
    indices: list[str]
    size_bytes: int
    shards_total: int
    shards_successful: int
    shards_failed: int


class SnapshotListResponse(BaseModel):
    repo: str
    snapshots: list[SnapshotInfo]


class CreateSnapshotResponse(BaseModel):
    snapshot: str
    repo: str
    status: str


class RestoreSnapshotResponse(BaseModel):
    snapshot: str
    repo: str
    status: str


class RetentionPolicy(BaseModel):
    retention_events_days: int
    retention_alerts_days: int
    retention_incidents_days: int
    retention_audit_days: int
    retention_iocs_days: int


class RetentionStorageStats(BaseModel):
    detections_total: int
    incidents_total: int
    iocs_total: int
    detections_eligible_for_deletion: int
    incidents_eligible_for_deletion: int
    iocs_eligible_for_deletion: int


class RetentionResponse(BaseModel):
    policy: RetentionPolicy
    storage: RetentionStorageStats


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
    actor: str | None = Query(None, max_length=254, description="Filter by actor email"),
    action: str | None = Query(None, max_length=100, description="Filter by action verb"),
    resource_type: str | None = Query(None, max_length=100, description="Filter by resource type"),
    time_from: str = Query("now-7d", max_length=50, description="Start time (OpenSearch date math)"),
    time_to: str = Query("now", max_length=50, description="End time (OpenSearch date math)"),
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


# ── Snapshot endpoints — feature 38.3 ────────────────────────────────────────


@router.post("/snapshots", response_model=CreateSnapshotResponse, status_code=202)
async def create_snapshot(
    current_user: dict = Depends(get_current_user),
    os_client=Depends(get_opensearch_dep),
) -> CreateSnapshotResponse:
    """
    Initiate an OpenSearch snapshot of all mxtac-* indices.

    The snapshot runs asynchronously in the cluster; the response returns
    immediately with ``status: "initiated"``.  Requires admin role.
    """
    _require_admin(current_user)

    if not os_client.is_available:
        raise HTTPException(status_code=503, detail="OpenSearch is not available")

    snapshot_name = f"mxtac-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"

    # Ensure the filesystem repository is registered (idempotent PUT).
    await os_client.create_snapshot_repo(_SNAPSHOT_REPO_NAME, settings.opensearch_snapshot_repo)

    result = await os_client.create_snapshot(_SNAPSHOT_REPO_NAME, snapshot_name)
    if result is None:
        raise HTTPException(status_code=500, detail="Snapshot creation failed")

    return CreateSnapshotResponse(
        snapshot=snapshot_name,
        repo=_SNAPSHOT_REPO_NAME,
        status="initiated",
    )


@router.get("/snapshots", response_model=SnapshotListResponse)
async def list_snapshots(
    current_user: dict = Depends(get_current_user),
    os_client=Depends(get_opensearch_dep),
) -> SnapshotListResponse:
    """
    List all OpenSearch snapshots with their state and size.

    Requires admin role.
    """
    _require_admin(current_user)

    if not os_client.is_available:
        raise HTTPException(status_code=503, detail="OpenSearch is not available")

    snapshots = await os_client.list_snapshots(_SNAPSHOT_REPO_NAME)
    return SnapshotListResponse(
        repo=_SNAPSHOT_REPO_NAME,
        snapshots=[SnapshotInfo(**s) for s in snapshots],
    )


@router.post(
    "/snapshots/{name}/restore",
    response_model=RestoreSnapshotResponse,
    status_code=202,
)
async def restore_snapshot(
    name: str = Path(
        ...,
        max_length=200,
        pattern=r"^[a-zA-Z0-9._-]+$",
        description="Snapshot name to restore",
    ),
    current_user: dict = Depends(get_current_user),
    os_client=Depends(get_opensearch_dep),
) -> RestoreSnapshotResponse:
    """
    Restore all mxtac-* indices from a named snapshot.

    The restore runs asynchronously in the cluster; the response returns
    immediately with ``status: "initiated"``.  Requires admin role.
    """
    _require_admin(current_user)

    if not os_client.is_available:
        raise HTTPException(status_code=503, detail="OpenSearch is not available")

    success = await os_client.restore_snapshot(_SNAPSHOT_REPO_NAME, name)
    if not success:
        raise HTTPException(status_code=500, detail="Snapshot restore failed")

    return RestoreSnapshotResponse(
        snapshot=name,
        repo=_SNAPSHOT_REPO_NAME,
        status="initiated",
    )


# ── Retention endpoint — feature 38.4 ────────────────────────────────────────


@router.get("/retention", response_model=RetentionResponse)
async def get_retention(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> RetentionResponse:
    """
    Return current data retention policy and PostgreSQL storage usage.

    The ``policy`` block shows the configured retention periods for each data
    type.  The ``storage`` block shows total row counts and how many records
    are currently eligible for deletion by the next cleanup run.

    Requires admin role.
    """
    _require_admin(current_user)

    policy = RetentionPolicy(
        retention_events_days=settings.retention_events_days,
        retention_alerts_days=settings.retention_alerts_days,
        retention_incidents_days=settings.retention_incidents_days,
        retention_audit_days=settings.retention_audit_days,
        retention_iocs_days=settings.retention_iocs_days,
    )

    stats = await get_retention_storage_stats(db)

    return RetentionResponse(
        policy=policy,
        storage=RetentionStorageStats(**stats),
    )
