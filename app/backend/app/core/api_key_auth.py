"""FastAPI dependency for X-API-Key authentication (agent ingest endpoints)."""

from __future__ import annotations

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from .database import get_db
from ..models.api_key import APIKey
from ..repositories.api_key_repo import APIKeyRepo


async def get_api_key(
    x_api_key: str | None = Header(None, alias="X-API-Key"),
    db: AsyncSession = Depends(get_db),
) -> APIKey:
    """Resolve and validate the X-API-Key header.

    Raises 401 when the header is absent or the key is unknown / inactive.
    """
    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="X-API-Key header required",
        )
    api_key = await APIKeyRepo.get_by_raw_key(db, x_api_key)
    if api_key is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or inactive API key",
        )
    return api_key
