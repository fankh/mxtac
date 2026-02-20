"""Tests for RateLimitMiddleware and RateLimiter — feature 33.1.

Coverage:
  _classify — auth / export / write / read group assignment
  _client_ip — XFF, X-Real-IP, direct client host, unknown fallback
  RateLimiter._mem_check — allows within limit, blocks over limit, window reset
  RateLimiter.check — Valkey allowed, Valkey blocked, Valkey error fallback
  RateLimitMiddleware — 200 + X-RateLimit-* headers on allowed requests
  RateLimitMiddleware — 429 + Retry-After + X-RateLimit-* on exceeded limit
  RateLimitMiddleware — probe paths (/health /ready /metrics) bypassed
  RateLimitMiddleware — correct group/limit forwarded to rate limiter
"""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient

import app.core.rate_limit as rl_module
from app.core.rate_limit import RateLimiter, _classify, _client_ip


# ---------------------------------------------------------------------------
# TestClassify — endpoint group classification
# ---------------------------------------------------------------------------


class TestClassify:
    def test_auth_login_post(self) -> None:
        group, limit = _classify("POST", "/api/v1/auth/login")
        assert group == "auth"
        assert limit == 10

    def test_auth_mfa_path(self) -> None:
        group, limit = _classify("POST", "/api/v1/auth/mfa/verify")
        assert group == "auth"
        assert limit == 10

    def test_auth_login_takes_priority_over_write(self) -> None:
        """POST to auth/login is 'auth', not 'write'."""
        group, _ = _classify("POST", "/api/v1/auth/login")
        assert group == "auth"

    def test_export_get(self) -> None:
        group, limit = _classify("GET", "/api/v1/rules/export")
        assert group == "export"
        assert limit == 5

    def test_export_takes_priority_over_read(self) -> None:
        group, _ = _classify("GET", "/api/v1/detections/export")
        assert group == "export"

    def test_write_post(self) -> None:
        group, limit = _classify("POST", "/api/v1/rules")
        assert group == "write"
        assert limit == 60

    def test_write_patch(self) -> None:
        group, limit = _classify("PATCH", "/api/v1/rules/abc")
        assert group == "write"
        assert limit == 60

    def test_write_put(self) -> None:
        group, limit = _classify("PUT", "/api/v1/rules/abc")
        assert group == "write"
        assert limit == 60

    def test_write_delete(self) -> None:
        group, limit = _classify("DELETE", "/api/v1/rules/abc")
        assert group == "write"
        assert limit == 60

    def test_read_get(self) -> None:
        group, limit = _classify("GET", "/api/v1/rules")
        assert group == "read"
        assert limit == 300

    def test_read_head(self) -> None:
        group, limit = _classify("HEAD", "/api/v1/rules")
        assert group == "read"
        assert limit == 300

    def test_method_case_insensitive(self) -> None:
        group, _ = _classify("post", "/api/v1/rules")
        assert group == "write"


# ---------------------------------------------------------------------------
# TestClientIp — IP extraction from headers / connection
# ---------------------------------------------------------------------------


class TestClientIp:
    def _req(
        self, headers: dict[str, str], client_host: str | None = "127.0.0.1"
    ) -> MagicMock:
        req = MagicMock()
        req.headers = headers
        if client_host is not None:
            req.client = MagicMock()
            req.client.host = client_host
        else:
            req.client = None
        return req

    def test_xff_first_ip(self) -> None:
        req = self._req({"X-Forwarded-For": "203.0.113.1, 10.0.0.1"})
        assert _client_ip(req) == "203.0.113.1"

    def test_xff_single(self) -> None:
        req = self._req({"X-Forwarded-For": "203.0.113.5"})
        assert _client_ip(req) == "203.0.113.5"

    def test_xff_strips_whitespace(self) -> None:
        req = self._req({"X-Forwarded-For": "  203.0.113.9  , 10.0.0.1"})
        assert _client_ip(req) == "203.0.113.9"

    def test_real_ip_header(self) -> None:
        req = self._req({"X-Real-IP": "203.0.113.20"})
        assert _client_ip(req) == "203.0.113.20"

    def test_xff_takes_priority_over_real_ip(self) -> None:
        req = self._req({"X-Forwarded-For": "1.2.3.4", "X-Real-IP": "5.6.7.8"})
        assert _client_ip(req) == "1.2.3.4"

    def test_direct_client_host(self) -> None:
        req = self._req({})
        assert _client_ip(req) == "127.0.0.1"

    def test_unknown_when_no_client(self) -> None:
        req = self._req({}, client_host=None)
        assert _client_ip(req) == "unknown"


# ---------------------------------------------------------------------------
# TestRateLimiterMemoryFallback — in-memory counter when Valkey unavailable
# ---------------------------------------------------------------------------


class TestRateLimiterMemoryFallback:
    @pytest.fixture
    def limiter(self) -> RateLimiter:
        return RateLimiter()

    async def test_first_request_allowed(self, limiter: RateLimiter) -> None:
        with patch("app.core.rate_limit.get_valkey_client", side_effect=Exception("no valkey")):
            allowed, remaining, reset_at = await limiter.check("k1", 5)
        assert allowed is True
        assert remaining == 4
        assert reset_at > int(time.time())

    async def test_requests_within_limit_all_allowed(self, limiter: RateLimiter) -> None:
        with patch("app.core.rate_limit.get_valkey_client", side_effect=Exception("no valkey")):
            for _ in range(5):
                allowed, _, _ = await limiter.check("k2", 5)
                assert allowed is True

    async def test_request_over_limit_rejected(self, limiter: RateLimiter) -> None:
        with patch("app.core.rate_limit.get_valkey_client", side_effect=Exception("no valkey")):
            for _ in range(6):
                allowed, remaining, _ = await limiter.check("k3", 5)
        assert allowed is False
        assert remaining == 0

    async def test_remaining_decrements(self, limiter: RateLimiter) -> None:
        with patch("app.core.rate_limit.get_valkey_client", side_effect=Exception("no valkey")):
            _, r1, _ = await limiter.check("k4", 10)
            _, r2, _ = await limiter.check("k4", 10)
            _, r3, _ = await limiter.check("k4", 10)
        assert r1 == 9
        assert r2 == 8
        assert r3 == 7

    async def test_expired_window_resets_count(self, limiter: RateLimiter) -> None:
        limiter._mem["k5"] = (999, time.time() - 61)  # pre-fill expired entry
        with patch("app.core.rate_limit.get_valkey_client", side_effect=Exception("no valkey")):
            allowed, remaining, _ = await limiter.check("k5", 5)
        assert allowed is True
        assert remaining == 4

    async def test_reset_at_is_in_future(self, limiter: RateLimiter) -> None:
        with patch("app.core.rate_limit.get_valkey_client", side_effect=Exception("no valkey")):
            _, _, reset_at = await limiter.check("k6", 5)
        assert reset_at > int(time.time())

    async def test_different_keys_are_independent(self, limiter: RateLimiter) -> None:
        with patch("app.core.rate_limit.get_valkey_client", side_effect=Exception("no valkey")):
            for _ in range(6):
                await limiter.check("ka", 5)
            allowed, _, _ = await limiter.check("kb", 5)
        assert allowed is True  # kb counter is independent of ka


# ---------------------------------------------------------------------------
# TestRateLimiterValkey — Valkey backend path
# ---------------------------------------------------------------------------


class TestRateLimiterValkey:
    @pytest.fixture
    def limiter(self) -> RateLimiter:
        return RateLimiter()

    async def test_valkey_allowed(self, limiter: RateLimiter) -> None:
        mock_client = AsyncMock()
        mock_client.eval = AsyncMock(return_value=[3, 45])  # count=3, ttl=45
        with patch("app.core.rate_limit.get_valkey_client", return_value=mock_client):
            allowed, remaining, reset_at = await limiter.check("vk1", 10)
        assert allowed is True
        assert remaining == 7
        assert reset_at >= int(time.time()) + 44  # ttl contributed

    async def test_valkey_rejected(self, limiter: RateLimiter) -> None:
        mock_client = AsyncMock()
        mock_client.eval = AsyncMock(return_value=[11, 30])  # count=11 > limit=10
        with patch("app.core.rate_limit.get_valkey_client", return_value=mock_client):
            allowed, remaining, _ = await limiter.check("vk2", 10)
        assert allowed is False
        assert remaining == 0

    async def test_valkey_error_falls_back_to_memory(self, limiter: RateLimiter) -> None:
        with patch(
            "app.core.rate_limit.get_valkey_client", side_effect=ConnectionError("timeout")
        ):
            allowed, _, _ = await limiter.check("vk3", 5)
        assert allowed is True
        assert "vk3" in limiter._mem


# ---------------------------------------------------------------------------
# TestRateLimitMiddleware — HTTP-level integration via test client
# ---------------------------------------------------------------------------


class TestRateLimitMiddleware:
    async def test_allowed_request_has_ratelimit_headers(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        reset = int(time.time()) + 55
        with patch.object(
            rl_module._rate_limiter, "check", new=AsyncMock(return_value=(True, 250, reset))
        ):
            resp = await client.get("/api/v1/rules", headers=analyst_headers)
        assert "x-ratelimit-limit" in resp.headers
        assert "x-ratelimit-remaining" in resp.headers
        assert "x-ratelimit-reset" in resp.headers

    async def test_allowed_request_remaining_value(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        reset = int(time.time()) + 55
        with patch.object(
            rl_module._rate_limiter, "check", new=AsyncMock(return_value=(True, 250, reset))
        ):
            resp = await client.get("/api/v1/rules", headers=analyst_headers)
        assert resp.headers["x-ratelimit-remaining"] == "250"
        assert resp.headers["x-ratelimit-limit"] == "300"  # read group

    async def test_exceeded_limit_returns_429(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        reset = int(time.time()) + 30
        with patch.object(
            rl_module._rate_limiter, "check", new=AsyncMock(return_value=(False, 0, reset))
        ):
            resp = await client.get("/api/v1/rules", headers=analyst_headers)
        assert resp.status_code == 429

    async def test_429_has_retry_after_header(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        reset = int(time.time()) + 30
        with patch.object(
            rl_module._rate_limiter, "check", new=AsyncMock(return_value=(False, 0, reset))
        ):
            resp = await client.get("/api/v1/rules", headers=analyst_headers)
        assert "retry-after" in resp.headers

    async def test_429_has_ratelimit_remaining_zero(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        reset = int(time.time()) + 30
        with patch.object(
            rl_module._rate_limiter, "check", new=AsyncMock(return_value=(False, 0, reset))
        ):
            resp = await client.get("/api/v1/rules", headers=analyst_headers)
        assert resp.headers["x-ratelimit-remaining"] == "0"
        assert "x-ratelimit-limit" in resp.headers
        assert "x-ratelimit-reset" in resp.headers

    async def test_429_response_body_fields(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        reset = int(time.time()) + 30
        with patch.object(
            rl_module._rate_limiter, "check", new=AsyncMock(return_value=(False, 0, reset))
        ):
            resp = await client.get("/api/v1/rules", headers=analyst_headers)
        data = resp.json()
        assert data["detail"] == "Too Many Requests"
        assert "limit" in data
        assert "retry_after" in data
        assert "group" in data

    async def test_health_probe_skips_rate_limiting(self, client: AsyncClient) -> None:
        resp = await client.get("/health")
        assert "x-ratelimit-limit" not in resp.headers

    async def test_ready_probe_skips_rate_limiting(self, client: AsyncClient) -> None:
        resp = await client.get("/ready")
        assert "x-ratelimit-limit" not in resp.headers

    async def test_metrics_probe_skips_rate_limiting(self, client: AsyncClient) -> None:
        resp = await client.get("/metrics")
        assert "x-ratelimit-limit" not in resp.headers

    async def test_auth_group_limit_is_10(self, client: AsyncClient) -> None:
        """Login path should be classified as 'auth' with limit=10."""
        calls: list[tuple[str, int]] = []

        async def capture_check(key: str, limit: int) -> tuple[bool, int, int]:
            calls.append((key, limit))
            return True, limit - 1, int(time.time()) + 50

        with patch.object(rl_module._rate_limiter, "check", new=capture_check):
            await client.post(
                "/api/v1/auth/login",
                json={"email": "x@x.com", "password": "y"},
            )

        assert len(calls) == 1
        key, limit = calls[0]
        assert "auth" in key
        assert limit == 10

    async def test_write_group_limit_is_60(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        """POST to a non-auth endpoint should be classified as 'write' with limit=60."""
        calls: list[tuple[str, int]] = []

        async def capture_check(key: str, limit: int) -> tuple[bool, int, int]:
            calls.append((key, limit))
            return True, limit - 1, int(time.time()) + 50

        with patch.object(rl_module._rate_limiter, "check", new=capture_check):
            await client.post(
                "/api/v1/rules",
                headers=admin_headers,
                json={},
            )

        assert len(calls) == 1
        _, limit = calls[0]
        assert limit == 60
