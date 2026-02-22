"""Repository for ScheduledReport model — CRUD + scheduler queries."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.scheduled_report import ScheduledReport


class ScheduledReportRepo:
    @staticmethod
    async def create(
        session: AsyncSession,
        *,
        id: str,
        name: str,
        template_type: str,
        schedule: str,
        params_json: dict[str, Any],
        format: str,
        enabled: bool,
        notification_channel_id: int | None,
        next_run_at: datetime | None,
        created_by: str,
    ) -> ScheduledReport:
        """Persist a new ScheduledReport."""
        sr = ScheduledReport(
            id=id,
            name=name,
            template_type=template_type,
            schedule=schedule,
            params_json=params_json,
            format=format,
            enabled=enabled,
            notification_channel_id=notification_channel_id,
            next_run_at=next_run_at,
            created_by=created_by,
        )
        session.add(sr)
        await session.flush()
        return sr

    @staticmethod
    async def get_by_id(
        session: AsyncSession,
        scheduled_report_id: str,
    ) -> ScheduledReport | None:
        result = await session.execute(
            select(ScheduledReport).where(ScheduledReport.id == scheduled_report_id)
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def list(
        session: AsyncSession,
        *,
        skip: int = 0,
        limit: int = 50,
        enabled: bool | None = None,
    ) -> tuple[list[ScheduledReport], int]:
        """Return (items, total_count) ordered by name."""
        q = select(ScheduledReport)
        count_q = select(func.count()).select_from(ScheduledReport)

        if enabled is not None:
            q = q.where(ScheduledReport.enabled == enabled)
            count_q = count_q.where(ScheduledReport.enabled == enabled)

        total = await session.scalar(count_q) or 0
        q = q.order_by(ScheduledReport.name).offset(skip).limit(limit)
        result = await session.execute(q)
        return list(result.scalars().all()), total

    @staticmethod
    async def update(
        session: AsyncSession,
        scheduled_report_id: str,
        *,
        name: str | None = None,
        schedule: str | None = None,
        params_json: dict[str, Any] | None = None,
        format: str | None = None,
        enabled: bool | None = None,
        notification_channel_id: int | None = None,
        clear_notification_channel: bool = False,
        next_run_at: datetime | None = None,
    ) -> ScheduledReport | None:
        """Partial update. Returns updated record or None if not found.

        Pass ``clear_notification_channel=True`` to explicitly set
        notification_channel_id to NULL.
        """
        sr = await ScheduledReportRepo.get_by_id(session, scheduled_report_id)
        if sr is None:
            return None

        if name is not None:
            sr.name = name
        if schedule is not None:
            sr.schedule = schedule
        if params_json is not None:
            sr.params_json = params_json
        if format is not None:
            sr.format = format
        if enabled is not None:
            sr.enabled = enabled
        if clear_notification_channel:
            sr.notification_channel_id = None
        elif notification_channel_id is not None:
            sr.notification_channel_id = notification_channel_id
        if next_run_at is not None:
            sr.next_run_at = next_run_at

        await session.flush()
        return sr

    @staticmethod
    async def update_run_times(
        session: AsyncSession,
        scheduled_report_id: str,
        *,
        last_run_at: datetime,
        next_run_at: datetime | None,
    ) -> bool:
        """Record a completed run — updates last_run_at and next_run_at.

        Returns True if the record was found and updated.
        """
        sr = await ScheduledReportRepo.get_by_id(session, scheduled_report_id)
        if sr is None:
            return False
        sr.last_run_at = last_run_at
        sr.next_run_at = next_run_at
        await session.flush()
        return True

    @staticmethod
    async def find_due(session: AsyncSession) -> list[ScheduledReport]:
        """Return all enabled schedules whose next_run_at is <= now (UTC)."""
        now = datetime.now(timezone.utc)
        result = await session.execute(
            select(ScheduledReport).where(
                ScheduledReport.enabled.is_(True),
                ScheduledReport.next_run_at <= now,
                ScheduledReport.next_run_at.is_not(None),
            )
        )
        return list(result.scalars().all())

    @staticmethod
    async def delete(
        session: AsyncSession,
        scheduled_report_id: str,
    ) -> bool:
        """Hard-delete. Returns True if a row was deleted."""
        result = await session.execute(
            delete(ScheduledReport).where(ScheduledReport.id == scheduled_report_id)
        )
        return result.rowcount > 0
