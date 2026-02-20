import hashlib

from fastapi import Depends, HTTPException, Query, Request

from .config import settings


def hash_password(password: str) -> str:
    """SHA-256 hash of the password."""
    return hashlib.sha256(password.encode()).hexdigest()


async def require_auth(
    request: Request,
    token: str | None = Query(default=None, alias="token"),
) -> None:
    """FastAPI dependency — checks Bearer token or ?token= query param.

    When AUTH_PASSWORD is empty, all requests pass through.
    """
    if not settings.auth_password:
        return

    expected = hash_password(settings.auth_password)

    # Try Authorization header first
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        if auth_header[7:] == expected:
            return

    # Fall back to ?token= query param (needed for SSE EventSource)
    if token and token == expected:
        return

    raise HTTPException(status_code=401, detail="Unauthorized")
