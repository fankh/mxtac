"""Repository for Report model — CRUD operations."""

from __future__ import annotations

from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.report import Report


class ReportRepo:
    @staticmethod
    async def create(
        session: AsyncSession,
        *,
        id: str,
        template_type: str,
        format: str,
        params_json: dict[str, Any],
        created_by: str,
    ) -> Report:
        """Persist a new Report record with status='generating'."""
        report = Report(
            id=id,
            template_type=template_type,
            status="generating",
            format=format,
            params_json=params_json,
            created_by=created_by,
        )
        session.add(report)
        await session.flush()
        return report

    @staticmethod
    async def get_by_id(
        session: AsyncSession,
        report_id: str,
    ) -> Report | None:
        result = await session.execute(
            select(Report).where(Report.id == report_id)
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def list(
        session: AsyncSession,
        *,
        skip: int = 0,
        limit: int = 50,
        created_by: str | None = None,
        template_type: str | None = None,
        status: str | None = None,
    ) -> tuple[list[Report], int]:
        """Return (items, total_count) with optional filters."""
        from sqlalchemy import func

        q = select(Report)
        count_q = select(func.count()).select_from(Report)

        if created_by is not None:
            q = q.where(Report.created_by == created_by)
            count_q = count_q.where(Report.created_by == created_by)
        if template_type is not None:
            q = q.where(Report.template_type == template_type)
            count_q = count_q.where(Report.template_type == template_type)
        if status is not None:
            q = q.where(Report.status == status)
            count_q = count_q.where(Report.status == status)

        total = await session.scalar(count_q) or 0
        q = q.order_by(Report.created_at.desc()).offset(skip).limit(limit)
        result = await session.execute(q)
        return list(result.scalars().all()), total

    @staticmethod
    async def update_status(
        session: AsyncSession,
        report_id: str,
        status: str,
        *,
        content_json: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> bool:
        """Update status, optionally setting content_json or error.

        Returns True if a row was updated, False if the report was not found.
        """
        report = await ReportRepo.get_by_id(session, report_id)
        if report is None:
            return False
        report.status = status
        if content_json is not None:
            report.content_json = content_json
        if error is not None:
            report.error = error
        await session.flush()
        return True

    @staticmethod
    async def delete(
        session: AsyncSession,
        report_id: str,
    ) -> bool:
        """Hard-delete a report. Returns True if a row was deleted."""
        result = await session.execute(
            delete(Report).where(Report.id == report_id)
        )
        return result.rowcount > 0
