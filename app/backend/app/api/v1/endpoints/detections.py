from fastapi import APIRouter, Query, HTTPException, Path
from typing import Literal
from math import ceil
from ....schemas.detection import Detection, DetectionUpdate, SeverityLevel, DetectionStatus
from ....schemas.common import PaginatedResponse, Pagination
from ....services.mock_data import DETECTIONS

router = APIRouter(prefix="/detections", tags=["detections"])

SortField = Literal["score", "time", "severity", "host", "tactic"]


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
):
    """
    List detections with filtering, sorting, and pagination.

    Filters combine with AND logic.
    """
    items = list(DETECTIONS)

    # Apply filters
    if severity:
        items = [d for d in items if d.severity in severity]
    if status:
        items = [d for d in items if d.status in status]
    if tactic:
        items = [d for d in items if tactic.lower() in d.tactic.lower()]
    if host:
        items = [d for d in items if host.lower() in d.host.lower()]
    if search:
        q = search.lower()
        items = [
            d for d in items
            if q in d.name.lower()
            or q in d.technique_id.lower()
            or q in d.host.lower()
        ]

    # Sort
    reverse = order == "desc"
    sort_key = {
        "score": lambda d: d.score,
        "time": lambda d: d.time,
        "severity": lambda d: {"critical": 4, "high": 3, "medium": 2, "low": 1}[d.severity],
        "host": lambda d: d.host,
        "tactic": lambda d: d.tactic,
    }[sort]
    items.sort(key=sort_key, reverse=reverse)

    # Paginate
    total = len(items)
    start = (page - 1) * page_size
    page_items = items[start : start + page_size]

    return PaginatedResponse(
        data=page_items,
        pagination=Pagination(
            page=page,
            page_size=page_size,
            total=total,
            total_pages=max(1, ceil(total / page_size)),
        ),
    )


@router.get("/{detection_id}", response_model=Detection)
async def get_detection(detection_id: str = Path(..., description="Detection ID")):
    """Get full detail for a single detection (used by the slide-out panel)."""
    for d in DETECTIONS:
        if d.id == detection_id:
            return d
    raise HTTPException(status_code=404, detail=f"Detection {detection_id} not found")


@router.patch("/{detection_id}", response_model=Detection)
async def update_detection(
    detection_id: str,
    body: DetectionUpdate,
):
    """Update status, assignment, or priority of a detection."""
    for d in DETECTIONS:
        if d.id == detection_id:
            updated = d.model_copy(update=body.model_dump(exclude_none=True))
            # In production: persist to DB; here mutate in-place
            idx = DETECTIONS.index(d)
            DETECTIONS[idx] = updated
            return updated
    raise HTTPException(status_code=404, detail=f"Detection {detection_id} not found")
