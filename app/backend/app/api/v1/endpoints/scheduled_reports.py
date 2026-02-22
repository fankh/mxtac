"""Scheduled report CRUD endpoints — feature 31.4."""

from __future__ import annotations

from math import ceil

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.ext.asyncio import AsyncSession

from ....core.database import get_db
from ....core.rbac import require_permission
from ....models.base import new_uuid
from ....repositories.scheduled_report_repo import ScheduledReportRepo
from ....schemas.common import Pagination, PaginatedResponse
from ....schemas.scheduled_report import (
    ScheduledReportCreate,
    ScheduledReportResponse,
    ScheduledReportUpdate,
)
from ....services.report_scheduler import calculate_next_run

router = APIRouter(prefix="/reports/scheduled", tags=["reports"])


# ---------------------------------------------------------------------------
# GET /reports/scheduled
# ---------------------------------------------------------------------------


@router.get(
    "",
    response_model=PaginatedResponse[ScheduledReportResponse],
    summary="List scheduled report configurations",
)
async def list_scheduled_reports(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    enabled: bool | None = Query(None, description="Filter by enabled/disabled"),
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("reports:read")),
) -> PaginatedResponse:
    """
    List all scheduled report configurations.

    - Requires analyst+ role (reports:read).
    - Results are paginated, ordered by name.
    """
    skip = (page - 1) * page_size
    items, total = await ScheduledReportRepo.list(
        db, skip=skip, limit=page_size, enabled=enabled
    )
    return PaginatedResponse(
        items=[ScheduledReportResponse.model_validate(sr) for sr in items],
        pagination=Pagination(
            page=page,
            page_size=page_size,
            total=total,
            total_pages=ceil(total / page_size) if total else 0,
        ),
    )


# ---------------------------------------------------------------------------
# POST /reports/scheduled
# ---------------------------------------------------------------------------


@router.post(
    "",
    response_model=ScheduledReportResponse,
    status_code=201,
    summary="Create a scheduled report",
)
async def create_scheduled_report(
    body: ScheduledReportCreate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission("reports:write")),
) -> ScheduledReportResponse:
    """
    Create a new scheduled report configuration.

    - Requires analyst+ role (reports:write).
    - ``schedule`` must be a valid 5-field cron expression (UTC).
    - ``params_json.period_days`` (int, default 7) controls the look-back window.
    - ``next_run_at`` is automatically computed from the cron expression.
    """
    try:
        next_run = calculate_next_run(body.schedule)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Invalid cron expression: {exc}") from exc

    sr = await ScheduledReportRepo.create(
        db,
        id=new_uuid(),
        name=body.name,
        template_type=body.template_type,
        schedule=body.schedule,
        params_json=body.params_json,
        format=body.format,
        enabled=body.enabled,
        notification_channel_id=body.notification_channel_id,
        next_run_at=next_run,
        created_by=current_user["email"],
    )
    await db.commit()
    await db.refresh(sr)
    return ScheduledReportResponse.model_validate(sr)


# ---------------------------------------------------------------------------
# PATCH /reports/scheduled/{id}
# ---------------------------------------------------------------------------


@router.patch(
    "/{scheduled_report_id}",
    response_model=ScheduledReportResponse,
    summary="Update a scheduled report",
)
async def update_scheduled_report(
    scheduled_report_id: str,
    body: ScheduledReportUpdate,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("reports:write")),
) -> ScheduledReportResponse:
    """
    Partially update a scheduled report configuration.

    - Requires analyst+ role (reports:write).
    - When ``schedule`` is changed, ``next_run_at`` is recalculated automatically.
    - To remove the notification channel set ``clear_notification_channel=true``.
    """
    existing = await ScheduledReportRepo.get_by_id(db, scheduled_report_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="Scheduled report not found")

    # Recompute next_run_at only if the cron schedule changed
    next_run_at = None
    if body.schedule is not None:
        try:
            next_run_at = calculate_next_run(body.schedule)
        except Exception as exc:
            raise HTTPException(
                status_code=422, detail=f"Invalid cron expression: {exc}"
            ) from exc

    sr = await ScheduledReportRepo.update(
        db,
        scheduled_report_id,
        name=body.name,
        schedule=body.schedule,
        params_json=body.params_json,
        format=body.format,
        enabled=body.enabled,
        notification_channel_id=body.notification_channel_id,
        clear_notification_channel=body.clear_notification_channel,
        next_run_at=next_run_at,
    )
    # sr cannot be None here — we checked above
    await db.commit()
    await db.refresh(sr)  # type: ignore[arg-type]
    return ScheduledReportResponse.model_validate(sr)


# ---------------------------------------------------------------------------
# DELETE /reports/scheduled/{id}
# ---------------------------------------------------------------------------


@router.delete(
    "/{scheduled_report_id}",
    status_code=204,
    summary="Delete a scheduled report",
)
async def delete_scheduled_report(
    scheduled_report_id: str,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("reports:delete")),
) -> Response:
    """
    Hard-delete a scheduled report configuration.

    - Requires analyst+ role (reports:delete).
    - Returns 204 No Content on success, 404 if not found.
    - Previously generated Report records are **not** removed.
    """
    deleted = await ScheduledReportRepo.delete(db, scheduled_report_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Scheduled report not found")
    await db.commit()
    return Response(status_code=204)
