"""Incident repository — async DB operations for the incidents table."""

from __future__ import annotations

from typing import Literal

from sqlalchemy import case, func, or_, select
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
