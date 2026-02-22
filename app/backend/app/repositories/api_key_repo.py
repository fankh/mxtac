from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.api_key import APIKey, hash_api_key


class APIKeyRepo:

    @staticmethod
    async def get_by_raw_key(db: AsyncSession, raw_key: str) -> APIKey | None:
        """Look up an active API key by its raw (unhashed) value.

        Returns None when the key is unknown, inactive, or expired.
        """
        key_hash = hash_api_key(raw_key)
        result = await db.execute(
            select(APIKey).where(APIKey.key_hash == key_hash, APIKey.is_active == True)  # noqa: E712
        )
        api_key = result.scalar_one_or_none()
        if api_key is None:
            return None
        # Reject keys that have passed their expiry date
        if api_key.expires_at is not None and api_key.expires_at < datetime.now(timezone.utc):
            return None
        return api_key

    @staticmethod
    async def create(
        db: AsyncSession,
        raw_key: str,
        label: str | None = None,
        owner_id: str | None = None,
        scopes: list[str] | None = None,
        expires_at: datetime | None = None,
        permission_set_id: str | None = None,
    ) -> APIKey:
        api_key = APIKey(
            key_hash=hash_api_key(raw_key),
            label=label,
            owner_id=owner_id,
            scopes=scopes,
            expires_at=expires_at,
            permission_set_id=permission_set_id,
        )
        db.add(api_key)
        await db.flush()
        return api_key

    @staticmethod
    async def list_by_owner(db: AsyncSession, owner_id: str) -> list[APIKey]:
        """Return all active API keys owned by *owner_id*, newest first."""
        result = await db.execute(
            select(APIKey)
            .where(APIKey.owner_id == owner_id, APIKey.is_active == True)  # noqa: E712
            .order_by(APIKey.created_at.desc())
        )
        return list(result.scalars().all())

    @staticmethod
    async def get_by_id(db: AsyncSession, key_id: str) -> APIKey | None:
        result = await db.execute(select(APIKey).where(APIKey.id == key_id))
        return result.scalar_one_or_none()

    @staticmethod
    async def revoke(
        db: AsyncSession, key_id: str, owner_id: str | None = None
    ) -> bool:
        """Deactivate an API key.  Returns True if found and revoked.

        When *owner_id* is provided the key must belong to that owner.
        Admins call this with ``owner_id=None`` to revoke any key.
        """
        query = select(APIKey).where(APIKey.id == key_id)
        if owner_id is not None:
            query = query.where(APIKey.owner_id == owner_id)
        result = await db.execute(query)
        api_key = result.scalar_one_or_none()
        if api_key is None:
            return False
        api_key.is_active = False
        await db.flush()
        return True

    @staticmethod
    async def update_last_used(db: AsyncSession, key_id: str) -> None:
        """Stamp last_used_at on the key.  Silently no-ops if the key is missing."""
        result = await db.execute(select(APIKey).where(APIKey.id == key_id))
        api_key = result.scalar_one_or_none()
        if api_key:
            api_key.last_used_at = datetime.now(timezone.utc)
            await db.flush()
