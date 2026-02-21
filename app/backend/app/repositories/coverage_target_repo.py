"""CoverageTarget repository — singleton coverage threshold persistence."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.coverage_target import CoverageTarget

_SINGLETON_ID = "singleton"


class CoverageTargetRepo:

    @staticmethod
    async def get(session: AsyncSession) -> CoverageTarget | None:
        """Return the single configured coverage target, or None if not set."""
        result = await session.execute(
            select(CoverageTarget).where(CoverageTarget.id == _SINGLETON_ID)
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def upsert(
        session: AsyncSession,
        *,
        target_pct: float,
        enabled: bool = True,
        label: str | None = None,
    ) -> CoverageTarget:
        """Create or update the singleton coverage target.

        Clamps ``target_pct`` to [0.0, 100.0] before persisting.
        """
        target_pct = max(0.0, min(100.0, target_pct))

        result = await session.execute(
            select(CoverageTarget).where(CoverageTarget.id == _SINGLETON_ID)
        )
        existing = result.scalar_one_or_none()

        if existing is not None:
            existing.target_pct = target_pct
            existing.enabled = enabled
            existing.label = label
            await session.flush()
            return existing

        target = CoverageTarget(
            id=_SINGLETON_ID,
            target_pct=target_pct,
            enabled=enabled,
            label=label,
        )
        session.add(target)
        await session.flush()
        return target
