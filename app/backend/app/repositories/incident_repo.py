"""Incident repository — async DB operations for the incidents table."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Literal

from sqlalchemy import and_, case, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.incident import Incident

# Severity order: critical first (1) → low last (4)
_SEVERITY_ORDER = case(
    {"critical": 1, "high": 2, "medium": 3, "low": 4},
    value=Incident.severity,
    else_=5,
)

# Status order: active states first, closed last
_STATUS_ORDER = case(
    {"new": 1, "investigating": 2, "contained": 3, "resolved": 4, "closed": 5},
    value=Incident.status,
    else_=6,
)

SortField = Literal["created_at", "severity", "status"]


class IncidentRepo:

    @staticmethod
    async def list(
        session: AsyncSession,
        *,
        skip: int = 0,
        limit: int = 25,
        severity: list[str] | None = None,
        status: list[str] | None = None,
        assigned_to: str | None = None,
        search: str | None = None,
        sort: SortField = "created_at",
    ) -> tuple[list[Incident], int]:
        """Return (items, total_count) with filtering and pagination.

        Default sort: created_at desc. Severity sort orders critical→low.
        Status sort orders new→closed (most active first).
        """
        q = select(Incident)

        if severity:
            q = q.where(Incident.severity.in_(severity))
        if status:
            q = q.where(Incident.status.in_(status))
        if assigned_to:
            q = q.where(Incident.assigned_to == assigned_to)
        if search:
            pattern = f"%{search}%"
            q = q.where(
                or_(
                    Incident.title.ilike(pattern),
                    Incident.description.ilike(pattern),
                )
            )

        # Count before pagination
        count_q = select(func.count()).select_from(q.subquery())
        total = await session.scalar(count_q) or 0

        # Sort and paginate
        if sort == "severity":
            order_clause = _SEVERITY_ORDER.asc()
        elif sort == "status":
            order_clause = _STATUS_ORDER.asc()
        else:
            order_clause = Incident.created_at.desc()
        q = q.order_by(order_clause).offset(skip).limit(limit)

        result = await session.execute(q)
        return list(result.scalars().all()), total

    @staticmethod
    async def get_by_id(session: AsyncSession, incident_id: int) -> Incident | None:
        result = await session.execute(
            select(Incident).where(Incident.id == incident_id)
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def create(session: AsyncSession, **kwargs) -> Incident:
        incident = Incident(**kwargs)
        session.add(incident)
        await session.flush()
        return incident

    @staticmethod
    async def update(session: AsyncSession, incident_id: int, **kwargs) -> Incident | None:
        incident = await IncidentRepo.get_by_id(session, incident_id)
        if not incident:
            return None
        for k, v in kwargs.items():
            if v is not None:
                setattr(incident, k, v)
        await session.flush()
        return incident

    @staticmethod
    async def delete(session: AsyncSession, incident_id: int) -> bool:
        incident = await IncidentRepo.get_by_id(session, incident_id)
        if not incident:
            return False
        await session.delete(incident)
        await session.flush()
        return True

    @staticmethod
    async def count(session: AsyncSession) -> int:
        result = await session.scalar(select(func.count()).select_from(Incident))
        return result or 0

    @staticmethod
    async def get_by_detection(session: AsyncSession, detection_id: str) -> list[Incident]:
        """Return all incidents that reference the given detection_id in their detection_ids JSON array."""
        result = await session.execute(
            select(Incident)
            .where(Incident.detection_ids.contains([detection_id]))
            .order_by(Incident.created_at.desc())
        )
        return list(result.scalars().all())

    @staticmethod
    async def get_metrics(
        session: AsyncSession,
        from_date: datetime,
        to_date: datetime,
    ) -> dict:
        """Compute incident SLA metrics within the given date range.

        Returns a dict with keys:
          status_counts, avg_ttr, avg_ttd, open_count,
          severity_counts, week_count, month_count
        """
        date_filter = and_(
            Incident.created_at >= from_date,
            Incident.created_at <= to_date,
        )

        # Counts by status within range
        status_result = await session.execute(
            select(Incident.status, func.count().label("cnt"))
            .where(date_filter)
            .group_by(Incident.status)
        )
        status_counts: dict[str, int] = {row.status: row.cnt for row in status_result}

        # Average TTR for closed incidents in range
        avg_ttr = await session.scalar(
            select(func.avg(Incident.ttr_seconds))
            .where(date_filter)
            .where(Incident.status == "closed")
            .where(Incident.ttr_seconds.is_not(None))
        )

        # Average TTD for all incidents with TTD set in range
        avg_ttd = await session.scalar(
            select(func.avg(Incident.ttd_seconds))
            .where(date_filter)
            .where(Incident.ttd_seconds.is_not(None))
        )

        # Open incidents (not resolved or closed) within range
        open_count = await session.scalar(
            select(func.count())
            .select_from(Incident)
            .where(date_filter)
            .where(Incident.status.not_in(["resolved", "closed"]))
        ) or 0

        # Counts by severity within range
        severity_result = await session.execute(
            select(Incident.severity, func.count().label("cnt"))
            .where(date_filter)
            .group_by(Incident.severity)
        )
        severity_counts: dict[str, int] = {row.severity: row.cnt for row in severity_result}

        # Incidents created this calendar week (Monday 00:00 UTC)
        now = datetime.now(timezone.utc)
        week_start = (now - timedelta(days=now.weekday())).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        week_count = await session.scalar(
            select(func.count())
            .select_from(Incident)
            .where(Incident.created_at >= week_start)
        ) or 0

        # Incidents created this calendar month (1st day 00:00 UTC)
        month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        month_count = await session.scalar(
            select(func.count())
            .select_from(Incident)
            .where(Incident.created_at >= month_start)
        ) or 0

        return {
            "status_counts": status_counts,
            "avg_ttr": float(avg_ttr) if avg_ttr is not None else None,
            "avg_ttd": float(avg_ttd) if avg_ttd is not None else None,
            "open_count": open_count,
            "severity_counts": severity_counts,
            "week_count": week_count,
            "month_count": month_count,
        }
