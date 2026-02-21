"""CoverageSnapshot repository — daily ATT&CK coverage trend persistence."""

from __future__ import annotations

from datetime import date, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.coverage_snapshot import CoverageSnapshot
from ..models.base import new_uuid


class CoverageSnapshotRepo:

    @staticmethod
    async def upsert(
        session: AsyncSession,
        *,
        snapshot_date: date,
        coverage_pct: float,
        covered_count: int,
        total_count: int,
    ) -> CoverageSnapshot:
        """Insert or update a coverage snapshot for the given date.

        If a snapshot already exists for ``snapshot_date`` it is overwritten
        with the latest values, ensuring the stored data always reflects the
        most recent state for that calendar day.
        """
        result = await session.execute(
            select(CoverageSnapshot).where(CoverageSnapshot.snapshot_date == snapshot_date)
        )
        existing = result.scalar_one_or_none()

        if existing is not None:
            existing.coverage_pct = coverage_pct
            existing.covered_count = covered_count
            existing.total_count = total_count
            await session.flush()
            return existing

        snapshot = CoverageSnapshot(
            id=new_uuid(),
            snapshot_date=snapshot_date,
            coverage_pct=coverage_pct,
            covered_count=covered_count,
            total_count=total_count,
        )
        session.add(snapshot)
        await session.flush()
        return snapshot

    @staticmethod
    async def get_trend(
        session: AsyncSession,
        *,
        days: int = 30,
    ) -> list[CoverageSnapshot]:
        """Return daily coverage snapshots for the last ``days`` calendar days.

        Results are ordered ascending by date (oldest first) so the caller can
        render a left-to-right trend chart directly.

        ``days`` is clamped to [1, 365].
        """
        days = max(1, min(days, 365))
        since = date.today() - timedelta(days=days - 1)

        result = await session.execute(
            select(CoverageSnapshot)
            .where(CoverageSnapshot.snapshot_date >= since)
            .order_by(CoverageSnapshot.snapshot_date.asc())
        )
        return list(result.scalars().all())
