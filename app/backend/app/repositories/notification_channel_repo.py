"""NotificationChannel repository — async DB operations for the notification_channels table."""

from __future__ import annotations

from math import ceil

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.notification import NotificationChannel


class NotificationChannelRepo:

    @staticmethod
    async def list_enabled(session: AsyncSession) -> list[NotificationChannel]:
        """Return all enabled notification channels."""
        result = await session.execute(
            select(NotificationChannel).where(NotificationChannel.enabled.is_(True))
        )
        return list(result.scalars().all())

    @staticmethod
    async def list(
        session: AsyncSession,
        *,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[NotificationChannel], int]:
        """Return (items, total_count) with pagination."""
        q = select(NotificationChannel).order_by(NotificationChannel.id)

        count_q = select(func.count()).select_from(q.subquery())
        total = await session.scalar(count_q) or 0

        offset = (page - 1) * page_size
        q = q.offset(offset).limit(page_size)

        result = await session.execute(q)
        return list(result.scalars().all()), total

    @staticmethod
    async def get_by_id(session: AsyncSession, channel_id: int) -> NotificationChannel | None:
        result = await session.execute(
            select(NotificationChannel).where(NotificationChannel.id == channel_id)
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def create(session: AsyncSession, **kwargs) -> NotificationChannel:
        channel = NotificationChannel(**kwargs)
        session.add(channel)
        await session.flush()
        return channel

    @staticmethod
    async def update(
        session: AsyncSession, channel_id: int, **kwargs
    ) -> NotificationChannel | None:
        channel = await NotificationChannelRepo.get_by_id(session, channel_id)
        if not channel:
            return None
        for k, v in kwargs.items():
            if v is not None:
                setattr(channel, k, v)
        await session.flush()
        return channel

    @staticmethod
    async def delete(session: AsyncSession, channel_id: int) -> bool:
        channel = await NotificationChannelRepo.get_by_id(session, channel_id)
        if not channel:
            return False
        await session.delete(channel)
        await session.flush()
        return True

    @staticmethod
    async def count(session: AsyncSession) -> int:
        result = await session.scalar(
            select(func.count()).select_from(NotificationChannel)
        )
        return result or 0
