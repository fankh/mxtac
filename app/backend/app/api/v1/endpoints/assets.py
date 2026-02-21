from math import ceil

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from sqlalchemy import cast, func, select, String
from sqlalchemy.ext.asyncio import AsyncSession

from ....core.database import get_db
from ....core.rbac import require_permission
from ....models.detection import Detection
from ....models.incident import Incident
from ....repositories.asset_repo import AssetRepo
from ....schemas.asset import (
    AssetCreate,
    AssetResponse,
    AssetStats,
    AssetUpdate,
    BulkAssetResult,
)
from ....schemas.common import Pagination, PaginatedResponse

router = APIRouter(prefix="/assets", tags=["assets"])


def _asset_to_schema(asset) -> dict:
    return {
        "id": asset.id,
        "hostname": asset.hostname,
        "ip_addresses": asset.ip_addresses,
        "os": asset.os,
        "os_family": asset.os_family,
        "asset_type": asset.asset_type,
        "criticality": asset.criticality,
        "owner": asset.owner,
        "department": asset.department,
        "location": asset.location,
        "tags": asset.tags,
        "is_active": asset.is_active,
        "last_seen_at": asset.last_seen_at,
        "agent_id": asset.agent_id,
        "detection_count": asset.detection_count,
        "incident_count": asset.incident_count,
        "created_at": asset.created_at,
        "updated_at": asset.updated_at,
    }


async def _list_asset_detections(
    db: AsyncSession, hostname: str, skip: int, limit: int
) -> tuple[list, int]:
    """Query detections linked to an asset by hostname."""
    base_q = select(Detection).where(Detection.host == hostname)
    count_q = select(func.count()).select_from(base_q.subquery())
    total = await db.scalar(count_q) or 0
    result = await db.execute(
        base_q.order_by(Detection.time.desc()).offset(skip).limit(limit)
    )
    return list(result.scalars().all()), total


async def _list_asset_incidents(
    db: AsyncSession, hostname: str, skip: int, limit: int
) -> tuple[list, int]:
    """Query incidents whose hosts JSON array contains the given hostname."""
    base_q = select(Incident).where(
        cast(Incident.hosts, String).contains(f'"{hostname}"')
    )
    count_q = select(func.count()).select_from(base_q.subquery())
    total = await db.scalar(count_q) or 0
    result = await db.execute(
        base_q.order_by(Incident.id.desc()).offset(skip).limit(limit)
    )
    return list(result.scalars().all()), total


# ---------------------------------------------------------------------------
# GET /assets — paginated list
# ---------------------------------------------------------------------------


@router.get("", response_model=PaginatedResponse[AssetResponse])
async def list_assets(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    asset_type: str | None = Query(None),
    criticality: int | None = Query(None, ge=1, le=5),
    is_active: bool | None = Query(None),
    search: str | None = Query(None, max_length=255),
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("assets:read")),
):
    skip = (page - 1) * page_size
    items, total = await AssetRepo.list(
        db,
        skip=skip,
        limit=page_size,
        asset_type=asset_type,
        criticality=criticality,
        is_active=is_active,
        search=search,
    )
    return PaginatedResponse(
        items=[_asset_to_schema(a) for a in items],
        pagination=Pagination(
            page=page,
            page_size=page_size,
            total=total,
            total_pages=max(1, ceil(total / page_size)),
        ),
    )


# ---------------------------------------------------------------------------
# GET /assets/stats — aggregate counts (must precede /{id})
# ---------------------------------------------------------------------------


@router.get("/stats", response_model=AssetStats)
async def get_stats(
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("assets:read")),
):
    data = await AssetRepo.stats(db)
    return AssetStats(**data)


# ---------------------------------------------------------------------------
# POST /assets/bulk — bulk import (must precede /{id})
# ---------------------------------------------------------------------------


@router.post("/bulk", response_model=BulkAssetResult)
async def bulk_import_assets(
    body: list[AssetCreate],
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("assets:write")),
):
    created = 0
    skipped = 0
    for asset_data in body:
        existing = await AssetRepo.get_by_hostname(db, asset_data.hostname)
        if existing:
            skipped += 1
        else:
            await AssetRepo.create(db, **asset_data.model_dump())
            created += 1
    return BulkAssetResult(created=created, skipped=skipped)


# ---------------------------------------------------------------------------
# GET /assets/{id} — asset detail
# ---------------------------------------------------------------------------


@router.get("/{asset_id}", response_model=AssetResponse)
async def get_asset(
    asset_id: int = Path(..., description="Asset ID"),
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("assets:read")),
):
    asset = await AssetRepo.get_by_id(db, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail=f"Asset {asset_id} not found")
    return _asset_to_schema(asset)


# ---------------------------------------------------------------------------
# POST /assets — create asset
# ---------------------------------------------------------------------------


@router.post("", response_model=AssetResponse, status_code=201)
async def create_asset(
    body: AssetCreate,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("assets:write")),
):
    existing = await AssetRepo.get_by_hostname(db, body.hostname)
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"Asset with hostname '{body.hostname}' already exists",
        )
    asset = await AssetRepo.create(db, **body.model_dump())
    return _asset_to_schema(asset)


# ---------------------------------------------------------------------------
# PATCH /assets/{id} — update asset
# ---------------------------------------------------------------------------


@router.patch("/{asset_id}", response_model=AssetResponse)
async def update_asset(
    asset_id: int = Path(..., description="Asset ID"),
    body: AssetUpdate = ...,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("assets:write")),
):
    asset = await AssetRepo.update(db, asset_id, **body.model_dump(exclude_none=True))
    if not asset:
        raise HTTPException(status_code=404, detail=f"Asset {asset_id} not found")
    return _asset_to_schema(asset)


# ---------------------------------------------------------------------------
# DELETE /assets/{id} — deactivate (soft delete)
# ---------------------------------------------------------------------------


@router.delete("/{asset_id}", response_model=AssetResponse)
async def deactivate_asset(
    asset_id: int = Path(..., description="Asset ID"),
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("assets:write")),
):
    """Soft-delete: sets is_active=False rather than removing the record."""
    asset = await AssetRepo.update(db, asset_id, is_active=False)
    if not asset:
        raise HTTPException(status_code=404, detail=f"Asset {asset_id} not found")
    return _asset_to_schema(asset)


# ---------------------------------------------------------------------------
# GET /assets/{id}/detections — detections for this asset
# ---------------------------------------------------------------------------


@router.get("/{asset_id}/detections", response_model=PaginatedResponse[dict])
async def list_asset_detections(
    asset_id: int = Path(..., description="Asset ID"),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("assets:read")),
):
    asset = await AssetRepo.get_by_id(db, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail=f"Asset {asset_id} not found")

    skip = (page - 1) * page_size
    items, total = await _list_asset_detections(db, asset.hostname, skip, page_size)

    detection_items = [
        {
            "id": d.id,
            "name": d.name,
            "severity": d.severity,
            "technique_id": d.technique_id,
            "technique_name": d.technique_name,
            "tactic": d.tactic,
            "status": d.status,
            "host": d.host,
            "time": d.time,
            "created_at": d.created_at,
        }
        for d in items
    ]
    return PaginatedResponse(
        items=detection_items,
        pagination=Pagination(
            page=page,
            page_size=page_size,
            total=total,
            total_pages=max(1, ceil(total / page_size)),
        ),
    )


# ---------------------------------------------------------------------------
# GET /assets/{id}/incidents — incidents for this asset
# ---------------------------------------------------------------------------


@router.get("/{asset_id}/incidents", response_model=PaginatedResponse[dict])
async def list_asset_incidents(
    asset_id: int = Path(..., description="Asset ID"),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("assets:read")),
):
    asset = await AssetRepo.get_by_id(db, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail=f"Asset {asset_id} not found")

    skip = (page - 1) * page_size
    items, total = await _list_asset_incidents(db, asset.hostname, skip, page_size)

    incident_items = [
        {
            "id": i.id,
            "title": i.title,
            "severity": i.severity,
            "status": i.status,
            "priority": i.priority,
            "assigned_to": i.assigned_to,
            "hosts": i.hosts,
            "created_at": i.created_at,
        }
        for i in items
    ]
    return PaginatedResponse(
        items=incident_items,
        pagination=Pagination(
            page=page,
            page_size=page_size,
            total=total,
            total_pages=max(1, ceil(total / page_size)),
        ),
    )
