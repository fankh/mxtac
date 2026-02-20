from fastapi import APIRouter, Query, HTTPException, Path, Depends
from typing import Literal
from math import ceil

from sqlalchemy.ext.asyncio import AsyncSession

from ....core.database import get_db
from ....core.rbac import require_permission
from ....core.security import get_current_user
from ....schemas.detection import Detection, DetectionUpdate, SeverityLevel, DetectionStatus
from ....schemas.common import PaginatedResponse, Pagination
from ....repositories.detection_repo import DetectionRepo

router = APIRouter(prefix="/detections", tags=["detections"])

SortField = Literal["score", "time", "severity", "host", "tactic"]


def _detection_to_schema(d) -> dict:
    """Convert ORM Detection model to schema dict."""
    return {
        "id": d.id,
        "score": d.score,
        "severity": d.severity,
        "technique_id": d.technique_id,
        "technique_name": d.technique_name,
        "name": d.name,
        "host": d.host,
        "tactic": d.tactic,
        "status": d.status,
        "time": d.time,
        "user": d.user,
        "process": d.process,
        "rule_name": d.rule_name,
        "log_source": d.log_source,
        "event_id": d.event_id,
        "occurrence_count": d.occurrence_count,
        "description": d.description,
        "cvss_v3": d.cvss_v3,
        "confidence": d.confidence,
        "tactic_id": d.tactic_id,
        "related_technique_ids": [],
        "assigned_to": d.assigned_to,
        "priority": d.priority,
    }


@router.get("", response_model=PaginatedResponse[Detection])
async def list_detections(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    severity: list[SeverityLevel] | None = Query(None),
    status: list[DetectionStatus] | None = Query(None),
    tactic: str | None = Query(None),
    host: str | None = Query(None),
    search: str | None = Query(None),
    sort: SortField = Query("time"),
    order: Literal["asc", "desc"] = Query("desc"),
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(get_current_user),
):
    items, total = await DetectionRepo.list(
        db,
        page=page,
        page_size=page_size,
        severity=severity,
        status=status,
        tactic=tactic,
        host=host,
        search=search,
        sort=sort,
        order=order,
    )
    return PaginatedResponse(
        items=[_detection_to_schema(d) for d in items],
        pagination=Pagination(
            page=page,
            page_size=page_size,
            total=total,
            total_pages=max(1, ceil(total / page_size)),
        ),
    )


@router.get("/{detection_id}", response_model=Detection)
async def get_detection(
    detection_id: str = Path(..., description="Detection ID"),
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(get_current_user),
):
    d = await DetectionRepo.get(db, detection_id)
    if not d:
        raise HTTPException(status_code=404, detail=f"Detection {detection_id} not found")
    return _detection_to_schema(d)


@router.patch("/{detection_id}", response_model=Detection)
async def update_detection(
    detection_id: str,
    body: DetectionUpdate,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("detections:write")),
):
    d = await DetectionRepo.update(db, detection_id, **body.model_dump(exclude_none=True))
    if not d:
        raise HTTPException(status_code=404, detail=f"Detection {detection_id} not found")
    return _detection_to_schema(d)
