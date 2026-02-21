"""IOC repository — async DB operations for the iocs table."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import func, select, update as sa_update
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.validators import escape_like
from ..models.ioc import IOC


class IOCRepo:

    @staticmethod
    async def list(
        session: AsyncSession,
        *,
        skip: int = 0,
        limit: int = 25,
        ioc_type: str | None = None,
        source: str | None = None,
        is_active: bool | None = None,
        search: str | None = None,
    ) -> tuple[list[IOC], int]:
        """Return (items, total) with optional filtering and offset/limit pagination."""
        q = select(IOC)

        if ioc_type is not None:
            q = q.where(IOC.ioc_type == ioc_type)
        if source is not None:
            q = q.where(IOC.source == source)
        if is_active is not None:
            q = q.where(IOC.is_active == is_active)
        if search is not None:
            pattern = f"%{escape_like(search)}%"
            q = q.where(
                IOC.value.ilike(pattern, escape="\\")
                | IOC.description.ilike(pattern, escape="\\")
            )

        # Count total matching rows before pagination
        count_q = select(func.count()).select_from(q.subquery())
        total = await session.scalar(count_q) or 0

        q = q.order_by(IOC.id.desc()).offset(skip).limit(limit)
        result = await session.execute(q)
        return list(result.scalars().all()), total

    @staticmethod
    async def get_by_id(session: AsyncSession, ioc_id: int) -> IOC | None:
        result = await session.execute(select(IOC).where(IOC.id == ioc_id))
        return result.scalar_one_or_none()

    @staticmethod
    async def lookup(
        session: AsyncSession, ioc_type: str, value: str
    ) -> IOC | None:
        """Fast exact-match lookup on the (ioc_type, value) unique index."""
        result = await session.execute(
            select(IOC).where(IOC.ioc_type == ioc_type, IOC.value == value)
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def bulk_lookup(
        session: AsyncSession, ioc_type: str, values: list[str]
    ) -> list[IOC]:
        """Batch exact-match for a single ioc_type across multiple values."""
        if not values:
            return []
        result = await session.execute(
            select(IOC).where(IOC.ioc_type == ioc_type, IOC.value.in_(values))
        )
        return list(result.scalars().all())

    @staticmethod
    async def create(session: AsyncSession, **kwargs) -> IOC:
        ioc = IOC(**kwargs)
        session.add(ioc)
        await session.flush()
        return ioc

    @staticmethod
    async def bulk_create(
        session: AsyncSession, items: list[dict]
    ) -> tuple[int, int]:
        """Insert multiple IOCs, skipping duplicates by (ioc_type, value).

        Returns (created_count, skipped_count).
        Handles intra-batch duplicates as well as conflicts with existing rows.
        """
        if not items:
            return 0, 0

        # Build a per-type lookup of values that already exist in the DB.
        # One query per distinct ioc_type in the batch (avoids tuple-IN dialect issues).
        type_to_values: dict[str, set[str]] = {}
        for item in items:
            type_to_values.setdefault(item["ioc_type"], set()).add(item["value"])

        existing_pairs: set[tuple[str, str]] = set()
        for ioc_type, vals in type_to_values.items():
            result = await session.execute(
                select(IOC.ioc_type, IOC.value)
                .where(IOC.ioc_type == ioc_type)
                .where(IOC.value.in_(list(vals)))
            )
            for row in result.all():
                existing_pairs.add((row.ioc_type, row.value))

        created = 0
        skipped = 0
        seen: set[tuple[str, str]] = set()  # track intra-batch duplicates
        for item in items:
            pair = (item["ioc_type"], item["value"])
            if pair in existing_pairs or pair in seen:
                skipped += 1
            else:
                session.add(IOC(**item))
                seen.add(pair)
                created += 1

        if created:
            await session.flush()

        return created, skipped

    @staticmethod
    async def update(session: AsyncSession, ioc_id: int, **kwargs) -> IOC | None:
        ioc = await IOCRepo.get_by_id(session, ioc_id)
        if not ioc:
            return None
        for k, v in kwargs.items():
            if v is not None:
                setattr(ioc, k, v)
        await session.flush()
        return ioc

    @staticmethod
    async def delete(session: AsyncSession, ioc_id: int) -> bool:
        ioc = await IOCRepo.get_by_id(session, ioc_id)
        if not ioc:
            return False
        await session.delete(ioc)
        await session.flush()
        return True

    @staticmethod
    async def increment_hit(session: AsyncSession, ioc_id: int) -> None:
        """Atomically increment hit_count and stamp last_hit_at for an IOC."""
        now = datetime.now(timezone.utc)
        await session.execute(
            sa_update(IOC)
            .where(IOC.id == ioc_id)
            .values(hit_count=IOC.hit_count + 1, last_hit_at=now)
        )
        await session.flush()

    @staticmethod
    async def expire_old(session: AsyncSession) -> int:
        """Set is_active=False on all IOCs whose expires_at is in the past.

        Returns the number of IOCs deactivated.
        """
        now = datetime.now(timezone.utc)

        # Count first so we can return the affected row count portably
        # (avoids RETURNING which has inconsistent support across dialects).
        count = (
            await session.scalar(
                select(func.count())
                .select_from(IOC)
                .where(IOC.expires_at.is_not(None))
                .where(IOC.expires_at <= now)
                .where(IOC.is_active.is_(True))
            )
            or 0
        )

        if count:
            await session.execute(
                sa_update(IOC)
                .where(IOC.expires_at.is_not(None))
                .where(IOC.expires_at <= now)
                .where(IOC.is_active.is_(True))
                .values(is_active=False)
            )
            await session.flush()

        return count

    @staticmethod
    async def stats(session: AsyncSession) -> dict:
        """Return aggregate statistics: total, by_type, by_source, active, expired, total_hits counts."""
        total = await session.scalar(select(func.count()).select_from(IOC)) or 0

        type_rows = await session.execute(
            select(IOC.ioc_type, func.count().label("cnt")).group_by(IOC.ioc_type)
        )
        by_type = {row.ioc_type: row.cnt for row in type_rows}

        source_rows = await session.execute(
            select(IOC.source, func.count().label("cnt")).group_by(IOC.source)
        )
        by_source = {row.source: row.cnt for row in source_rows}

        active = await session.scalar(
            select(func.count()).select_from(IOC).where(IOC.is_active.is_(True))
        ) or 0

        total_hits = await session.scalar(
            select(func.sum(IOC.hit_count)).select_from(IOC)
        ) or 0

        return {
            "total": total,
            "by_type": by_type,
            "by_source": by_source,
            "active": active,
            "expired": total - active,
            "total_hits": total_hits,
        }
