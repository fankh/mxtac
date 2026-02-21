"""Report generation, listing, download, and deletion endpoints."""

from __future__ import annotations

import asyncio
import csv
import io
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.ext.asyncio import AsyncSession

from ....core.database import AsyncSessionLocal, get_db
from ....core.rbac import require_permission
from ....models.base import new_uuid
from ....repositories.report_repo import ReportRepo
from ....schemas.common import Pagination, PaginatedResponse
from ....schemas.report import (
    ReportDetail,
    ReportGenerateRequest,
    ReportGenerateResponse,
    ReportSummary,
)
from ....services.report_engine import ReportEngine

router = APIRouter(prefix="/reports", tags=["reports"])


# ---------------------------------------------------------------------------
# Background task
# ---------------------------------------------------------------------------


async def _generate_report_bg(
    report_id: str,
    template_type: str,
    params: dict[str, Any],
) -> None:
    """Run in the background: generate the report and persist results."""
    async with AsyncSessionLocal() as session:
        try:
            engine = ReportEngine(session)
            content = await engine.generate(template_type, params)
            await ReportRepo.update_status(
                session, report_id, "ready", content_json=content
            )
            await session.commit()
        except Exception as exc:
            await session.rollback()
            # Open a new session to record the failure
            try:
                async with AsyncSessionLocal() as err_session:
                    await ReportRepo.update_status(
                        err_session, report_id, "failed", error=str(exc)
                    )
                    await err_session.commit()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# CSV helpers
# ---------------------------------------------------------------------------


def _to_csv(content: dict[str, Any]) -> str:
    """Convert report content dict to a CSV string."""
    template = content.get("template", "")
    rows: list[dict[str, Any]] = []

    if template == "detection_report":
        for sev_data in content.get("by_severity", {}).values():
            rows.extend(sev_data.get("detections", []))
    elif template == "incident_report":
        rows = content.get("incidents", [])
    elif template == "executive_summary":
        kpis = content.get("kpis", {})
        rows = [{"metric": k, "value": v} for k, v in kpis.items()]
    elif template == "coverage_report":
        rows = content.get("uncovered_techniques", [])
        if not rows:
            rows = content.get("rules_by_technique", [])
    elif template == "compliance_summary":
        rows = content.get("nist_800_53") or content.get("pci_dss") or []
    else:
        rows = [content]

    if not rows:
        return ""

    output = io.StringIO()
    # Flatten any nested dicts/lists in cells to strings
    flat_rows = [
        {k: (str(v) if not isinstance(v, str) else v) for k, v in row.items()}
        for row in rows
    ]
    writer = csv.DictWriter(
        output, fieldnames=list(flat_rows[0].keys()), extrasaction="ignore"
    )
    writer.writeheader()
    writer.writerows(flat_rows)
    return output.getvalue()


def _report_to_params(req: ReportGenerateRequest) -> dict[str, Any]:
    """Build the params dict passed to ReportEngine.generate()."""
    params: dict[str, Any] = {
        "from_date": req.from_date.replace(tzinfo=timezone.utc)
        if req.from_date.tzinfo is None
        else req.from_date,
        "to_date": req.to_date.replace(tzinfo=timezone.utc)
        if req.to_date.tzinfo is None
        else req.to_date,
    }
    if req.extra_params:
        params.update(req.extra_params)
    return params


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/generate",
    response_model=ReportGenerateResponse,
    status_code=202,
    summary="Trigger async report generation",
)
async def generate_report(
    body: ReportGenerateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission("reports:write")),
) -> ReportGenerateResponse:
    """
    Queue an async report generation job.

    - Requires analyst+ role (reports:write).
    - Returns immediately with report_id and status='generating'.
    - Poll GET /reports/{id} for status updates.
    """
    report_id = new_uuid()
    params = _report_to_params(body)

    # Persist the record as 'generating' before launching the task
    await ReportRepo.create(
        db,
        id=report_id,
        template_type=body.template_type,
        format=body.format,
        params_json={
            "from_date": params["from_date"].isoformat(),
            "to_date": params["to_date"].isoformat(),
            **(body.extra_params or {}),
        },
        created_by=current_user["email"],
    )
    await db.commit()

    asyncio.create_task(
        _generate_report_bg(report_id, body.template_type, params)
    )

    return ReportGenerateResponse(report_id=report_id)


@router.get(
    "",
    response_model=PaginatedResponse[ReportSummary],
    summary="List generated reports",
)
async def list_reports(
    page: int = Query(1, ge=1, description="Page number (1-based)"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    template_type: str | None = Query(None, description="Filter by template type"),
    status: str | None = Query(None, description="Filter by status: generating, ready, failed"),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission("reports:read")),
) -> PaginatedResponse:
    """
    List all reports accessible to the current user.

    - Requires analyst+ role (reports:read).
    - Results are paginated (newest first).
    """
    skip = (page - 1) * page_size
    items, total = await ReportRepo.list(
        db,
        skip=skip,
        limit=page_size,
        template_type=template_type,
        status=status,
    )
    from math import ceil

    return PaginatedResponse(
        items=[ReportSummary.model_validate(r) for r in items],
        pagination=Pagination(
            page=page,
            page_size=page_size,
            total=total,
            total_pages=ceil(total / page_size) if total else 0,
        ),
    )


@router.get(
    "/{report_id}",
    response_model=ReportDetail,
    summary="Get report metadata",
)
async def get_report(
    report_id: str,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("reports:read")),
) -> ReportDetail:
    """
    Return metadata for a single report (no content).

    - Requires analyst+ role (reports:read).
    """
    report = await ReportRepo.get_by_id(db, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return ReportDetail.model_validate(report)


@router.get(
    "/{report_id}/download",
    summary="Download report content",
)
async def download_report(
    report_id: str,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("reports:read")),
) -> Response:
    """
    Download the generated report content.

    - Returns JSON or CSV based on the report's format field.
    - 404 if the report does not exist.
    - 409 if the report is still generating or has failed.
    - Requires analyst+ role (reports:read).
    """
    report = await ReportRepo.get_by_id(db, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    if report.status == "generating":
        raise HTTPException(
            status_code=409, detail="Report is still being generated"
        )
    if report.status == "failed":
        raise HTTPException(
            status_code=409,
            detail=f"Report generation failed: {report.error or 'unknown error'}",
        )
    if report.content_json is None:
        raise HTTPException(status_code=409, detail="Report content is not available")

    filename = f"report_{report_id[:8]}.{report.format}"

    if report.format == "csv":
        csv_content = _to_csv(report.content_json)
        return Response(
            content=csv_content,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    import json

    return Response(
        content=json.dumps(report.content_json, default=str),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.delete(
    "/{report_id}",
    status_code=204,
    summary="Delete a report",
)
async def delete_report(
    report_id: str,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("reports:delete")),
) -> Response:
    """
    Hard-delete a report and its content.

    - Requires analyst+ role (reports:delete).
    - Returns 204 No Content on success, 404 if the report does not exist.
    """
    deleted = await ReportRepo.delete(db, report_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Report not found")
    await db.commit()
    return Response(status_code=204)
