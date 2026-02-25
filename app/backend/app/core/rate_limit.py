"""API rate limiting middleware — feature 33.1.

Enforces per-IP, per-endpoint-group rate limits using a Valkey fixed-window
counter with an in-memory fallback when Valkey is unavailable.

Endpoint groups and their per-minute limits:
  auth   — 10/min  (login + MFA; brute-force mitigation)
  export — 5/min   (data export endpoints)
  write  — 60/min  (POST / PATCH / PUT / DELETE)
  read   — 300/min (GET / HEAD; matches settings.rate_limit_per_minute default)

Responses for rate-limited requests:
  429 Too Many Requests
  Retry-After: <seconds>
  X-RateLimit-Limit: <limit>
  X-RateLimit-Remaining: 0
  X-RateLimit-Reset: <epoch>

All non-limited responses also carry the X-RateLimit-* headers so clients
can track their quota without triggering 429s.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Awaitable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

import valkey.asyncio as aioredis

from .config import settings
from .logging import get_logger

_logger = get_logger(__name__)

# ── Valkey client ──────────────────────────────────────────────────────────────

_valkey_client: aioredis.Valkey | None = None


def get_valkey_client() -> aioredis.Valkey:
    """Return (or lazily create) the Valkey client for rate limiting.

    This is **synchronous** so that tests can patch it with
    ``patch(return_value=mock_client)`` without needing an extra ``await``.
    ``aioredis.from_url`` is itself synchronous — it only constructs the
    connection pool; no I/O is performed until the first command.
    """
    global _valkey_client
    if _valkey_client is None:
        _valkey_client = aioredis.from_url(settings.valkey_url, decode_responses=True)
    return _valkey_client

# Lua: atomic INCR + conditional EXPIRE + TTL read — single round-trip.
# Returns [count, ttl] where ttl is remaining seconds in the current window.
_RATE_LUA = """
local key    = KEYS[1]
local window = tonumber(ARGV[1])
local count  = redis.call('INCR', key)
if count == 1 then
    redis.call('EXPIRE', key, window)
end
local ttl = redis.call('TTL', key)
return {count, ttl}
"""

# Probe paths — skip rate limiting for ops/health traffic.
_SKIP_PATHS: frozenset[str] = frozenset({"/health", "/ready", "/metrics"})

# Fixed window duration (seconds).
_WINDOW_SECS = 60

# Per-group request limits (requests per window).
_LIMITS: dict[str, int] = {
    "auth": 10,
    "export": 5,
    "write": 60,
    "read": 300,
}


def _classify(method: str, path: str) -> tuple[str, int]:
    """Map (method, path) to (group_name, limit).

    Precedence: auth > export > write > read.
    """
    if "/auth/login" in path or "/auth/mfa" in path:
        return "auth", _LIMITS["auth"]
    if "/export" in path:
        return "export", _LIMITS["export"]
    if method.upper() in {"POST", "PATCH", "PUT", "DELETE"}:
        return "write", _LIMITS["write"]
    return "read", _LIMITS["read"]


def _client_ip(request: Request) -> str:
    """Extract the most-specific client IP from the request.

    Checks X-Forwarded-For, then X-Real-IP, then falls back to the
    direct connection IP.  Does not validate or sanitise values — callers
    should not trust IPs from untrusted proxy headers in security-critical
    contexts.
    """
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    xri = request.headers.get("X-Real-IP")
    if xri:
        return xri.strip()
    return request.client.host if request.client else "unknown"


class RateLimiter:
    """Fixed-window rate counter backed by Valkey with an in-memory fallback.

    Each call to :meth:`check` atomically increments the counter for ``key``
    and returns ``(allowed, remaining, reset_at_epoch)``.

    Valkey backend:
      Single atomic Lua round-trip — no TOCTOU race between INCR and EXPIRE.

    In-memory fallback:
      Used only when Valkey is unreachable.  State is per-process so limits
      are not enforced consistently across multiple API replicas.
    """

    def __init__(self) -> None:
        # key -> (count, window_start_epoch)
        self._mem: dict[str, tuple[int, float]] = {}

    async def check(self, key: str, limit: int) -> tuple[bool, int, int]:
        """Increment counter and return (allowed, remaining, reset_at_epoch)."""
        try:
            client = get_valkey_client()
            result = await client.eval(_RATE_LUA, 1, key, _WINDOW_SECS)
            count, ttl = int(result[0]), int(result[1])
            reset_at = int(time.time()) + max(ttl, 0)
            remaining = max(0, limit - count)
            return count <= limit, remaining, reset_at
        except Exception:
            _logger.debug(
                "Valkey unavailable — using in-memory rate limiting key=%s", key
            )
            return self._mem_check(key, limit)

    def _mem_check(self, key: str, limit: int) -> tuple[bool, int, int]:
        now = time.time()
        entry = self._mem.get(key)
        if entry is None or now - entry[1] >= _WINDOW_SECS:
            self._mem[key] = (1, now)
            return True, limit - 1, int(now) + _WINDOW_SECS
        count, start = entry
        count += 1
        self._mem[key] = (count, start)
        remaining = max(0, limit - count)
        return count <= limit, remaining, int(start) + _WINDOW_SECS


# Module-level singleton — shared across all requests in a process.
_rate_limiter = RateLimiter()


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Enforce per-IP, per-endpoint-group rate limits.

    Skips probe paths (/health, /ready, /metrics).
    Returns 429 with Retry-After and X-RateLimit-* headers when exceeded.
    Appends X-RateLimit-* headers to all non-limited responses.
    """

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        path = request.url.path
        if path in _SKIP_PATHS:
            return await call_next(request)

        group, limit = _classify(request.method, path)
        ip = _client_ip(request)
        key = f"rate:{ip}:{group}"
        allowed, remaining, reset_at = await _rate_limiter.check(key, limit)

        if not allowed:
            retry_after = max(0, reset_at - int(time.time()))
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Too Many Requests",
                    "group": group,
                    "limit": limit,
                    "retry_after": retry_after,
                },
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(reset_at),
                },
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(reset_at)
        return response
