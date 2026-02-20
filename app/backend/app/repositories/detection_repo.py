"""Detection repository — async DB operations for the detections table."""

from __future__ import annotations

from math import ceil

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.detection import Detection


class DetectionRepo:

    @staticmethod
    async def list(
        session: AsyncSession,
        *,
        page: int = 1,
        page_size: int = 25,
        severity: list[str] | None = None,
        status: list[str] | None = None,
        tactic: str | None = None,
        host: str | None = None,
        search: str | None = None,
        sort: str = "time",
        order: str = "desc",
    ) -> tuple[list[Detection], int]:
        """Return (items, total_count) with filtering, sorting, and pagination."""
        q = select(Detection)

        if severity:
            q = q.where(Detection.severity.in_(severity))
        if status:
            q = q.where(Detection.status.in_(status))
        if tactic:
            q = q.where(Detection.tactic.ilike(f"%{tactic}%"))
        if host:
            q = q.where(Detection.host.ilike(f"%{host}%"))
        if search:
            pattern = f"%{search}%"
            q = q.where(
                Detection.name.ilike(pattern)
                | Detection.description.ilike(pattern)
                | Detection.technique_id.ilike(pattern)
                | Detection.host.ilike(pattern)
            )

        # Count
        count_q = select(func.count()).select_from(q.subquery())
        total = await session.scalar(count_q) or 0

        # Sort
        sort_col = getattr(Detection, sort, Detection.time)
        q = q.order_by(sort_col.desc() if order == "desc" else sort_col.asc())

        # Paginate
        offset = (page - 1) * page_size
        q = q.offset(offset).limit(page_size)

        result = await session.execute(q)
        return list(result.scalars().all()), total

    @staticmethod
    async def get(session: AsyncSession, detection_id: str) -> Detection | None:
        result = await session.execute(
            select(Detection).where(Detection.id == detection_id)
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def create(session: AsyncSession, **kwargs) -> Detection:
        det = Detection(**kwargs)
        session.add(det)
        await session.flush()
        return det

    @staticmethod
    async def update(session: AsyncSession, detection_id: str, **kwargs) -> Detection | None:
        det = await DetectionRepo.get(session, detection_id)
        if not det:
            return None
        for k, v in kwargs.items():
            if v is not None:
                setattr(det, k, v)
        await session.flush()
        return det

    @staticmethod
    async def delete(session: AsyncSession, detection_id: str) -> bool:
        det = await DetectionRepo.get(session, detection_id)
        if not det:
            return False
        await session.delete(det)
        await session.flush()
        return True

    @staticmethod
    async def count(session: AsyncSession) -> int:
        result = await session.scalar(select(func.count()).select_from(Detection))
        return result or 0
