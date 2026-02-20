from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.api_key import APIKey, hash_api_key


class APIKeyRepo:
    @staticmethod
    async def get_by_raw_key(db: AsyncSession, raw_key: str) -> APIKey | None:
        key_hash = hash_api_key(raw_key)
        result = await db.execute(
            select(APIKey).where(APIKey.key_hash == key_hash, APIKey.is_active == True)  # noqa: E712
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def create(db: AsyncSession, raw_key: str, label: str | None = None) -> APIKey:
        api_key = APIKey(key_hash=hash_api_key(raw_key), label=label)
        db.add(api_key)
        await db.flush()
        return api_key
