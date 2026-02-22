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


# ── MFA attempt rate limiting ─────────────────────────────────────────────────


async def increment_mfa_attempts(jti: str) -> int:
    """Increment and return the MFA attempt count for a given mfa_token JTI.

    Key auto-expires in 300 seconds (5 minutes, matching the mfa_token TTL).
    Returns 0 on Valkey failure (fail-open: prefer availability).
    """
    try:
        client = await get_valkey_client()
        key = f"mfa_attempts:{jti}"
        count = await client.incr(key)
        if count == 1:
            await client.expire(key, 300)
        return int(count)
    except Exception:
        logger.debug("Valkey unavailable — skipping MFA rate limit for jti=%s", jti)
        return 0  # fail-open


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


# ── Account lockout ───────────────────────────────────────────────────────────
LOCKOUT_MAX_ATTEMPTS = 5
LOCKOUT_WINDOW_SECONDS = 1800  # 30 minutes


async def is_account_locked(email: str) -> bool:
    """Return True if the account has exceeded the failed login attempt threshold.

    Fails open (returns False) when Valkey is unreachable so that a Valkey
    outage does not lock out all users.
    """
    try:
        client = await get_valkey_client()
        value = await client.get(f"login_attempts:{email}")
        return value is not None and int(value) >= LOCKOUT_MAX_ATTEMPTS
    except Exception:
        logger.debug("Valkey unavailable — skipping lockout check for %s", email)
        return False  # fail-open


async def increment_login_attempts(email: str) -> int:
    """Increment and return the failed login count for the given email.

    Key auto-expires in 1800 seconds (30 minutes). Returns 0 on Valkey failure
    (fail-open: prefer availability over strict enforcement).
    """
    try:
        client = await get_valkey_client()
        key = f"login_attempts:{email}"
        count = await client.incr(key)
        if count == 1:
            await client.expire(key, LOCKOUT_WINDOW_SECONDS)
        return int(count)
    except Exception:
        logger.debug("Valkey unavailable — skipping login attempt tracking for %s", email)
        return 0  # fail-open


async def clear_login_attempts(email: str) -> None:
    """Clear the failed login counter after a successful authentication."""
    try:
        client = await get_valkey_client()
        await client.delete(f"login_attempts:{email}")
    except Exception:
        logger.debug("Valkey unavailable — could not clear login attempts for %s", email)


# ── OIDC state (CSRF) ────────────────────────────────────────────────────────
# State tokens are short-lived and stored in Valkey with a 10-minute TTL.
# An in-memory dict acts as a fail-safe when Valkey is unavailable.
_oidc_state_store: dict[str, str] = {}
OIDC_STATE_TTL = 600  # 10 minutes


async def store_oidc_state(state: str, provider_name: str) -> None:
    """Persist an OIDC state token mapped to its provider_name."""
    try:
        client = await get_valkey_client()
        await client.setex(f"oidc:state:{state}", OIDC_STATE_TTL, provider_name)
    except Exception:
        logger.debug("Valkey unavailable — storing OIDC state in-memory")
        _oidc_state_store[state] = provider_name


async def validate_and_consume_oidc_state(state: str) -> str | None:
    """Return the provider_name for *state* and delete it (one-time use).

    Returns None if the state is unknown or expired.
    """
    try:
        client = await get_valkey_client()
        key = f"oidc:state:{state}"
        value = await client.getdel(key)
        if value is not None:
            return value
        # Fall through to in-memory store on cache miss (Valkey was down when stored)
    except Exception:
        logger.debug("Valkey unavailable — checking in-memory OIDC state store")

    return _oidc_state_store.pop(state, None)


# ── Webhook source rate limiting ──────────────────────────────────────────────


async def check_webhook_source_rate_limit(
    source_name: str,
    limit: int = 100,
    window_secs: int = 60,
) -> bool:
    """Return True if the webhook request is within the rate limit, False if exceeded.

    Rate-limits by request count per source name (100 req/min by default).
    Uses a Valkey fixed-window counter shared across all API replicas so the
    limit is enforced consistently in a horizontally-scaled deployment.

    Falls back to allowing requests (fail-open) when Valkey is unavailable —
    availability is preferred over strict enforcement during a Valkey outage.
    """
    try:
        client = await get_valkey_client()
        key = f"rate_limit:webhook:{source_name}"
        current = await client.eval(_RATE_LIMIT_LUA, 1, key, 1, window_secs)
        return int(current) <= limit
    except Exception:
        logger.debug(
            "Valkey unavailable — skipping webhook rate limit for source=%s", source_name
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
