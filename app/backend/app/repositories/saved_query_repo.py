"""Repository — async CRUD operations for the saved_queries table."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.saved_query import SavedQuery


class SavedQueryRepo:

    @staticmethod
    async def create(
        session: AsyncSession,
        *,
        name: str,
        created_by: str,
        description: str | None = None,
        query: str | None = None,
        filters: list | None = None,
        time_from: str = "now-24h",
        time_to: str = "now",
    ) -> SavedQuery:
        """Insert a new saved query and flush (caller manages the transaction)."""
        sq = SavedQuery(
            name=name,
            description=description,
            query=query,
            filters=filters or [],
            time_from=time_from,
            time_to=time_to,
            created_by=created_by,
        )
        session.add(sq)
        await session.flush()
        return sq

    @staticmethod
    async def list_for_user(
        session: AsyncSession,
        created_by: str,
    ) -> list[SavedQuery]:
        """Return all saved queries belonging to *created_by*, newest first."""
        result = await session.execute(
            select(SavedQuery)
            .where(SavedQuery.created_by == created_by)
            .order_by(SavedQuery.created_at.desc())
        )
        return list(result.scalars().all())

    @staticmethod
    async def get(
        session: AsyncSession,
        query_id: str,
        created_by: str,
    ) -> SavedQuery | None:
        """Fetch a single saved query by id, scoped to *created_by*."""
        result = await session.execute(
            select(SavedQuery).where(
                SavedQuery.id == query_id,
                SavedQuery.created_by == created_by,
            )
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def update(
        session: AsyncSession,
        sq: SavedQuery,
        *,
        name: str | None = None,
        description: str | None = None,
        query: str | None = None,
        filters: list | None = None,
        time_from: str | None = None,
        time_to: str | None = None,
    ) -> SavedQuery:
        """Apply partial updates to *sq* and flush."""
        if name is not None:
            sq.name = name
        if description is not None:
            sq.description = description
        if query is not None:
            sq.query = query
        if filters is not None:
            sq.filters = filters
        if time_from is not None:
            sq.time_from = time_from
        if time_to is not None:
            sq.time_to = time_to
        await session.flush()
        return sq

    @staticmethod
    async def delete(session: AsyncSession, sq: SavedQuery) -> None:
        """Delete *sq* and flush."""
        await session.delete(sq)
        await session.flush()
