from fastapi import APIRouter, Query, HTTPException, Path, Depends, status
from math import ceil

from sqlalchemy.ext.asyncio import AsyncSession

from ....core.database import get_db
from ....core.rbac import require_permission
from ....repositories.ioc_repo import IOCRepo
from ....schemas.ioc import (
    IOCCreate,
    IOCType,
    IOCUpdate,
    IOCResponse,
    IOCLookupRequest,
    BulkImportResult,
    IOCStats,
)
from ....schemas.common import PaginatedResponse, Pagination

router = APIRouter(prefix="/threat-intel", tags=["threat-intel"])

_MAX_BULK_IOCS = 1000


def _ioc_to_schema(ioc) -> dict:
    return {
        "id": ioc.id,
        "ioc_type": ioc.ioc_type,
        "value": ioc.value,
        "source": ioc.source,
        "confidence": ioc.confidence,
        "severity": ioc.severity,
        "description": ioc.description,
        "tags": ioc.tags,
        "first_seen": ioc.first_seen,
        "last_seen": ioc.last_seen,
        "expires_at": ioc.expires_at,
        "is_active": ioc.is_active,
        "hit_count": ioc.hit_count,
        "last_hit_at": ioc.last_hit_at,
        "created_at": ioc.created_at,
        "updated_at": ioc.updated_at,
    }


@router.get("/iocs", response_model=PaginatedResponse[IOCResponse])
async def list_iocs(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    ioc_type: IOCType | None = Query(None),
    source: str | None = Query(None),
    is_active: bool | None = Query(None),
    search: str | None = Query(None, max_length=255),
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("threat_intel:read")),
):
    skip = (page - 1) * page_size
    items, total = await IOCRepo.list(
        db,
        skip=skip,
        limit=page_size,
        ioc_type=ioc_type,
        source=source,
        is_active=is_active,
        search=search,
    )
    return PaginatedResponse(
        items=[_ioc_to_schema(i) for i in items],
        pagination=Pagination(
            page=page,
            page_size=page_size,
            total=total,
            total_pages=max(1, ceil(total / page_size)),
        ),
    )


@router.get("/stats", response_model=IOCStats)
async def get_stats(
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("threat_intel:read")),
):
    data = await IOCRepo.stats(db)
    return IOCStats(**data)


@router.get("/iocs/{ioc_id}", response_model=IOCResponse)
async def get_ioc(
    ioc_id: int = Path(..., description="IOC ID"),
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("threat_intel:read")),
):
    ioc = await IOCRepo.get_by_id(db, ioc_id)
    if not ioc:
        raise HTTPException(status_code=404, detail=f"IOC {ioc_id} not found")
    return _ioc_to_schema(ioc)


@router.post("/iocs", response_model=IOCResponse, status_code=201)
async def create_ioc(
    body: IOCCreate,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("threat_intel:write")),
):
    ioc = await IOCRepo.create(db, **body.model_dump())
    return _ioc_to_schema(ioc)


@router.post("/iocs/bulk", response_model=BulkImportResult)
async def bulk_import_iocs(
    body: list[IOCCreate],
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("threat_intel:write")),
):
    if len(body) > _MAX_BULK_IOCS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Bulk import limited to {_MAX_BULK_IOCS} items per request",
        )
    items = [ioc.model_dump() for ioc in body]
    created, skipped = await IOCRepo.bulk_create(db, items)
    return BulkImportResult(created=created, skipped=skipped)


@router.post("/iocs/lookup", response_model=IOCResponse)
async def lookup_ioc(
    body: IOCLookupRequest,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("threat_intel:read")),
):
    ioc = await IOCRepo.lookup(db, body.ioc_type, body.value)
    if not ioc:
        raise HTTPException(
            status_code=404,
            detail=f"No IOC found for {body.ioc_type}:{body.value}",
        )
    return _ioc_to_schema(ioc)


@router.patch("/iocs/{ioc_id}", response_model=IOCResponse)
async def update_ioc(
    ioc_id: int = Path(..., description="IOC ID"),
    body: IOCUpdate = ...,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("threat_intel:write")),
):
    ioc = await IOCRepo.update(db, ioc_id, **body.model_dump(exclude_none=True))
    if not ioc:
        raise HTTPException(status_code=404, detail=f"IOC {ioc_id} not found")
    return _ioc_to_schema(ioc)


@router.delete("/iocs/{ioc_id}", response_model=IOCResponse)
async def deactivate_ioc(
    ioc_id: int = Path(..., description="IOC ID"),
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("threat_intel:write")),
):
    """Soft-delete: sets is_active=False rather than removing the record."""
    ioc = await IOCRepo.update(db, ioc_id, is_active=False)
    if not ioc:
        raise HTTPException(status_code=404, detail=f"IOC {ioc_id} not found")
    return _ioc_to_schema(ioc)
