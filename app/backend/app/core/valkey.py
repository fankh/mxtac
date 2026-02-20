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


# ── Distributed ingest rate limiting ─────────────────────────────────────────
# Atomic fixed-window counter: INCRBY the key by n, set EXPIRE only on creation
# so the window resets automatically.  Single round-trip via Lua eval.
_RATE_LIMIT_LUA = """
local key     = KEYS[1]
local n       = tonumber(ARGV[1])
local window  = tonumber(ARGV[2])
local current = redis.call('INCRBY', key, n)
if current == n then
    redis.call('EXPIRE', key, window)
end
return current
"""


async def check_ingest_rate_limit(
    api_key_id: str,
    n_events: int,
    limit: int = 10_000,
    window_secs: int = 60,
) -> bool:
    """Return True if the ingest request is within the rate limit, False if exceeded.

    Uses a Valkey fixed-window counter shared across all API replicas so the
    limit is enforced consistently in a horizontally-scaled deployment.

    Falls back to allowing requests (fail-open) when Valkey is unavailable —
    availability is preferred over strict enforcement during a Valkey outage.
    """
    try:
        client = await get_valkey_client()
        key = f"rate_limit:ingest:{api_key_id}"
        current = await client.eval(_RATE_LIMIT_LUA, 1, key, n_events, window_secs)
        return int(current) <= limit
    except Exception:
        logger.debug(
            "Valkey unavailable — skipping rate limit check for api_key_id=%s", api_key_id
        )
        return True  # fail-open: prefer availability over strict enforcement


# ── Rule-change pub/sub ───────────────────────────────────────────────────────
RULE_RELOAD_CHANNEL = "mxtac:rules:reload"


async def publish_rule_reload() -> None:
    """Publish a rule-reload signal so peer replicas refresh their SigmaEngine.

    Called after any rule create / update / delete / import so that each API
    replica reloads from the database without a manual POST /rules/reload call.
    Fails silently when Valkey is unavailable.
    """
    try:
        client = await get_valkey_client()
        await client.publish(RULE_RELOAD_CHANNEL, "reload")
    except Exception:
        logger.debug("Valkey unavailable — rule reload signal not published")
