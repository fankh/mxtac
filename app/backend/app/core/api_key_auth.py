"""FastAPI dependencies for X-API-Key authentication (agent / webhook ingest)."""

from __future__ import annotations

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from .database import get_db
from .rbac import PERMISSIONS
from ..models.api_key import APIKey
from ..repositories.api_key_repo import APIKeyRepo


async def get_api_key(
    x_api_key: str | None = Header(None, alias="X-API-Key"),
    db: AsyncSession = Depends(get_db),
) -> APIKey:
    """Resolve and validate the X-API-Key header.

    Raises 401 when the header is absent or the key is unknown / inactive /
    expired.  Updates last_used_at on the key (best-effort, fail-open).
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
    # Stamp last_used_at — fail-open so a transient error never blocks ingest
    try:
        await APIKeyRepo.update_last_used(db, api_key.id)
    except Exception:
        pass
    return api_key


def require_api_key_scope(scope: str):
    """Return a FastAPI dependency that enforces a specific scope on the API key.

    Keys whose ``scopes`` field is ``None`` (pre-1.11 unrestricted keys) pass
    all scope checks for backward compatibility.

    Usage::

        @router.get("/events")
        async def get_events(
            api_key: APIKey = Depends(require_api_key_scope("events:search")),
        ):
            ...
    """
    if scope not in PERMISSIONS:
        raise ValueError(
            f"Unknown scope '{scope}'. "
            f"Valid scopes: {', '.join(sorted(PERMISSIONS))}"
        )

    async def _check(api_key: APIKey = Depends(get_api_key)) -> APIKey:
        # None scopes = unrestricted (backward compat with pre-1.11 keys)
        if api_key.scopes is not None and scope not in api_key.scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"API key does not have '{scope}' scope",
            )
        return api_key

    return _check
