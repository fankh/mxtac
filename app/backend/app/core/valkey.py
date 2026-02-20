"""Valkey (Redis-compatible) async client and token blacklist utilities."""

from __future__ import annotations

import logging

import valkey.asyncio as aioredis

from .config import settings

logger = logging.getLogger(__name__)

_client: aioredis.Valkey | None = None


async def get_valkey_client() -> aioredis.Valkey:
    """Return (or lazily create) the shared Valkey async client."""
    global _client
    if _client is None:
        _client = aioredis.from_url(settings.valkey_url, decode_responses=True)
    return _client


async def is_token_blacklisted(jti: str) -> bool:
    """Return True if the token JTI is in the revocation list.

    Fails open (returns False) when Valkey is unreachable so that a Valkey
    outage does not lock out all authenticated users.
    """
    try:
        client = await get_valkey_client()
        result = await client.get(f"blacklist:{jti}")
        return result is not None
    except Exception:
        logger.debug("Valkey unavailable — skipping blacklist check for jti=%s", jti)
        return False


async def blacklist_token(jti: str, ttl_seconds: int) -> None:
    """Revoke a token by storing its JTI in Valkey with TTL = remaining token lifetime."""
    try:
        client = await get_valkey_client()
        await client.setex(f"blacklist:{jti}", max(ttl_seconds, 1), "1")
    except Exception:
        logger.warning(
            "Valkey unavailable — token jti=%s could not be blacklisted; "
            "it will expire naturally at its exp time.",
            jti,
        )
