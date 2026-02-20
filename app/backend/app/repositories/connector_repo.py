"""Connector repository — async DB operations for the connectors table."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.connector import Connector


class ConnectorRepo:

    @staticmethod
    async def list(session: AsyncSession) -> list[Connector]:
        result = await session.execute(
            select(Connector).order_by(Connector.name)
        )
        return list(result.scalars().all())

    @staticmethod
    async def get_by_id(session: AsyncSession, connector_id: str) -> Connector | None:
        result = await session.execute(
            select(Connector).where(Connector.id == connector_id)
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def create(session: AsyncSession, **kwargs) -> Connector:
        conn = Connector(**kwargs)
        session.add(conn)
        await session.flush()
        return conn

    @staticmethod
    async def update(session: AsyncSession, connector_id: str, **kwargs) -> Connector | None:
        conn = await ConnectorRepo.get_by_id(session, connector_id)
        if not conn:
            return None
        for k, v in kwargs.items():
            if v is not None:
                setattr(conn, k, v)
        await session.flush()
        return conn

    @staticmethod
    async def update_status(
        session: AsyncSession,
        connector_id: str,
        status: str,
        error_message: str | None = None,
    ) -> Connector | None:
        conn = await ConnectorRepo.get_by_id(session, connector_id)
        if not conn:
            return None
        conn.status = status
        conn.last_seen_at = datetime.now(timezone.utc).isoformat()
        conn.error_message = error_message
        await session.flush()
        return conn

    @staticmethod
    async def delete(session: AsyncSession, connector_id: str) -> bool:
        conn = await ConnectorRepo.get_by_id(session, connector_id)
        if not conn:
            return False
        await session.delete(conn)
        await session.flush()
        return True

    @staticmethod
    async def count(session: AsyncSession) -> int:
        result = await session.scalar(select(func.count()).select_from(Connector))
        return result or 0

    @staticmethod
    async def get_status_counts(session: AsyncSession) -> dict:
        """Return active (enabled + connected/active status) and total connector counts."""
        total = await session.scalar(select(func.count()).select_from(Connector)) or 0
        active = await session.scalar(
            select(func.count())
            .select_from(Connector)
            .where(Connector.enabled == True)  # noqa: E712
            .where(Connector.status.in_(["active", "connected"]))
        ) or 0
        return {"active": active, "total": total}
