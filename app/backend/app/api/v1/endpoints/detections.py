import csv
import io
from collections.abc import Iterator
from datetime import date
from math import ceil
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from ....core.database import get_db
from ....core.rbac import require_permission
from ....engine.attack_tags import tactic_name
from ....models.detection import Detection as DetectionModel
from ....repositories.detection_repo import DetectionRepo
from ....schemas.common import PaginatedResponse, Pagination
from ....schemas.detection import (
    BulkStatusUpdate,
    BulkUpdateResult,
    Detection,
    DetectionStatus,
    DetectionUpdate,
    SeverityLevel,
)
from ....services.attack_techniques import resolve_technique_name

router = APIRouter(prefix="/detections", tags=["detections"])

SortField = Literal["score", "time", "severity", "host", "tactic"]


def _detection_to_schema(d: DetectionModel) -> dict[str, Any]:
    """Convert ORM Detection model to schema dict."""
    return {
        "id": d.id,
        "score": d.score,
        "severity": d.severity,
        "technique_id": d.technique_id,
        "technique_name": resolve_technique_name(d.technique_id, d.technique_name),
        "name": d.name,
        "host": d.host,
        "tactic": tactic_name(d.tactic),
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
    tactic: str | None = Query(None, max_length=100),
    host: str | None = Query(None, max_length=255),
    search: str | None = Query(None, max_length=255),
    sort: SortField = Query("time"),
    order: Literal["asc", "desc"] = Query("desc"),
    db: AsyncSession = Depends(get_db),
    _: dict[str, Any] = Depends(require_permission("detections:read")),
) -> PaginatedResponse[dict[str, Any]]:
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


_EXPORT_MAX_ROWS = 10_000
_DETECTION_CSV_COLS = ("id", "name", "severity", "tactic", "technique_id", "host", "status", "score", "time")


@router.get("/export")
async def export_detections(
    severity: list[SeverityLevel] | None = Query(None),
    status: list[DetectionStatus] | None = Query(None),
    tactic: str | None = Query(None, max_length=100),
    host: str | None = Query(None, max_length=255),
    search: str | None = Query(None, max_length=255),
    sort: SortField = Query("time"),
    order: Literal["asc", "desc"] = Query("desc"),
    db: AsyncSession = Depends(get_db),
    _: dict[str, Any] = Depends(require_permission("detections:read")),
) -> StreamingResponse:
    """Export filtered detections as CSV (max 10,000 rows).

    Accepts the same filter parameters as GET /detections.
    Returns a streaming text/csv file with columns:
    id, name, severity, tactic, technique_id, host, status, score, time.
    """
    items, _total = await DetectionRepo.list(
        db,
        page=1,
        page_size=_EXPORT_MAX_ROWS,
        severity=severity,
        status=status,
        tactic=tactic,
        host=host,
        search=search,
        sort=sort,
        order=order,
    )

    def _iter_csv() -> Iterator[str]:
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(_DETECTION_CSV_COLS)
        yield buf.getvalue()
        for d in items:
            buf.seek(0)
            buf.truncate(0)
            writer.writerow((
                d.id,
                d.name,
                d.severity,
                tactic_name(d.tactic),
                d.technique_id,
                d.host,
                d.status,
                d.score,
                d.time.isoformat() if hasattr(d.time, "isoformat") else d.time,
            ))
            yield buf.getvalue()

    filename = f"detections_{date.today().isoformat()}.csv"
    return StreamingResponse(
        _iter_csv(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{detection_id}", response_model=Detection)
async def get_detection(
    detection_id: str = Path(..., description="Detection ID"),
    db: AsyncSession = Depends(get_db),
    _: dict[str, Any] = Depends(require_permission("detections:read")),
) -> dict[str, Any]:
    d = await DetectionRepo.get(db, detection_id)
    if not d:
        raise HTTPException(status_code=404, detail=f"Detection {detection_id} not found")
    return _detection_to_schema(d)


@router.patch("/{detection_id}", response_model=Detection)
async def update_detection(
    detection_id: str,
    body: DetectionUpdate,
    db: AsyncSession = Depends(get_db),
    _: dict[str, Any] = Depends(require_permission("detections:write")),
) -> dict[str, Any]:
    d = await DetectionRepo.update(db, detection_id, **body.model_dump(exclude_none=True))
    if not d:
        raise HTTPException(status_code=404, detail=f"Detection {detection_id} not found")
    return _detection_to_schema(d)


@router.post("/bulk", response_model=BulkUpdateResult)
async def bulk_update_detections(
    body: BulkStatusUpdate,
    db: AsyncSession = Depends(get_db),
    _: dict[str, Any] = Depends(require_permission("detections:write")),
) -> dict[str, Any]:
    result = await DetectionRepo.bulk_update_status(db, body.ids, body.status)
    return result


@router.delete("/{detection_id}", response_model=None, status_code=204)
async def delete_detection(
    detection_id: str = Path(..., description="Detection ID"),
    db: AsyncSession = Depends(get_db),
    _: dict[str, Any] = Depends(require_permission("detections:delete")),
) -> None:
    deleted = await DetectionRepo.delete(db, detection_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Detection {detection_id} not found")
