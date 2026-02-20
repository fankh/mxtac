"""Asset repository — async DB operations for the assets table."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import cast, func, select, String, update as sa_update
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.asset import Asset

_DEFAULT_CRITICALITY = 3  # fallback when no asset is found


class AssetRepo:

    @staticmethod
    async def list(
        session: AsyncSession,
        *,
        skip: int = 0,
        limit: int = 25,
        asset_type: str | None = None,
        criticality: int | None = None,
        is_active: bool | None = None,
        search: str | None = None,
    ) -> tuple[list[Asset], int]:
        """Return (items, total) with optional filtering and offset/limit pagination."""
        q = select(Asset)

        if asset_type is not None:
            q = q.where(Asset.asset_type == asset_type)
        if criticality is not None:
            q = q.where(Asset.criticality == criticality)
        if is_active is not None:
            q = q.where(Asset.is_active == is_active)
        if search is not None:
            pattern = f"%{search}%"
            q = q.where(
                Asset.hostname.ilike(pattern)
                | Asset.owner.ilike(pattern)
                | Asset.department.ilike(pattern)
                | Asset.os.ilike(pattern)
            )

        count_q = select(func.count()).select_from(q.subquery())
        total = await session.scalar(count_q) or 0

        q = q.order_by(Asset.id.desc()).offset(skip).limit(limit)
        result = await session.execute(q)
        return list(result.scalars().all()), total

    @staticmethod
    async def get_by_id(session: AsyncSession, asset_id: int) -> Asset | None:
        result = await session.execute(select(Asset).where(Asset.id == asset_id))
        return result.scalar_one_or_none()

    @staticmethod
    async def get_by_hostname(session: AsyncSession, hostname: str) -> Asset | None:
        result = await session.execute(select(Asset).where(Asset.hostname == hostname))
        return result.scalar_one_or_none()

    @staticmethod
    async def get_by_ip(session: AsyncSession, ip: str) -> list[Asset]:
        """Return all assets whose ip_addresses JSON array contains the given IP.

        Uses a cast-to-string substring match so it works on both SQLite (tests)
        and PostgreSQL (production) without dialect-specific JSON operators.
        Wrapping the IP in double quotes (``"ip"``) avoids partial-prefix matches
        (e.g. "10.0.0.1" will not incorrectly match "10.0.0.10").
        """
        result = await session.execute(
            select(Asset).where(
                cast(Asset.ip_addresses, String).contains(f'"{ip}"')
            )
        )
        return list(result.scalars().all())

    @staticmethod
    async def create(session: AsyncSession, **kwargs) -> Asset:
        asset = Asset(**kwargs)
        session.add(asset)
        await session.flush()
        return asset

    @staticmethod
    async def upsert_by_hostname(
        session: AsyncSession, hostname: str, **kwargs
    ) -> Asset:
        """Create or fully update the asset identified by *hostname*.

        If no asset with *hostname* exists a new row is inserted.
        If an asset already exists every key in *kwargs* is overwritten.
        """
        asset = await AssetRepo.get_by_hostname(session, hostname)
        if asset is None:
            asset = Asset(hostname=hostname, **kwargs)
            session.add(asset)
        else:
            for k, v in kwargs.items():
                setattr(asset, k, v)
        await session.flush()
        return asset

    @staticmethod
    async def update(session: AsyncSession, asset_id: int, **kwargs) -> Asset | None:
        asset = await AssetRepo.get_by_id(session, asset_id)
        if not asset:
            return None
        for k, v in kwargs.items():
            if v is not None:
                setattr(asset, k, v)
        await session.flush()
        return asset

    @staticmethod
    async def delete(session: AsyncSession, asset_id: int) -> bool:
        asset = await AssetRepo.get_by_id(session, asset_id)
        if not asset:
            return False
        await session.delete(asset)
        await session.flush()
        return True

    @staticmethod
    async def get_criticality(session: AsyncSession, hostname_or_ip: str) -> int:
        """Return the criticality score for an asset identified by hostname or IP.

        Lookup order:
          1. Exact hostname match (indexed, fast).
          2. IP address match across all assets (JSON substring search).
          3. ``_DEFAULT_CRITICALITY`` (3) when no asset is found.

        When multiple assets share the same IP the highest criticality is returned
        so that alert risk scoring is always conservative.
        """
        asset = await AssetRepo.get_by_hostname(session, hostname_or_ip)
        if asset is not None:
            return asset.criticality

        assets = await AssetRepo.get_by_ip(session, hostname_or_ip)
        if assets:
            return max(a.criticality for a in assets)

        return _DEFAULT_CRITICALITY

    @staticmethod
    async def update_last_seen(session: AsyncSession, hostname: str) -> None:
        """Stamp last_seen_at to now for the asset identified by *hostname*."""
        now = datetime.now(timezone.utc)
        await session.execute(
            sa_update(Asset)
            .where(Asset.hostname == hostname)
            .values(last_seen_at=now)
        )
        await session.flush()

    @staticmethod
    async def increment_detection_count(session: AsyncSession, hostname: str) -> None:
        """Atomically increment detection_count for the asset identified by *hostname*."""
        await session.execute(
            sa_update(Asset)
            .where(Asset.hostname == hostname)
            .values(detection_count=Asset.detection_count + 1)
        )
        await session.flush()
