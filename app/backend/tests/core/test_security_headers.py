"""Tests for SecurityHeadersMiddleware — feature 33.2.

Coverage:
  SecurityHeadersMiddleware — X-Content-Type-Options: nosniff on regular response
  SecurityHeadersMiddleware — X-Frame-Options: DENY on regular response
  SecurityHeadersMiddleware — X-XSS-Protection: 0 on regular response
  SecurityHeadersMiddleware — Content-Security-Policy present on regular response
  SecurityHeadersMiddleware — Referrer-Policy: strict-origin-when-cross-origin
  SecurityHeadersMiddleware — Permissions-Policy present on regular response
  SecurityHeadersMiddleware — Cache-Control: no-store on regular response
  SecurityHeadersMiddleware — HSTS absent in debug mode (settings.debug=True)
  SecurityHeadersMiddleware — HSTS present in production mode (settings.debug=False)
  SecurityHeadersMiddleware — headers present on error (4xx) responses
  SecurityHeadersMiddleware — headers present on health probe responses
  _STATIC_HEADERS — correct values for all static headers
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from httpx import AsyncClient

from app.core.security_headers import (
    SecurityHeadersMiddleware,
    _HSTS_HEADER,
    _HSTS_VALUE,
    _STATIC_HEADERS,
)


# ---------------------------------------------------------------------------
# Unit tests — static header map
# ---------------------------------------------------------------------------


class TestStaticHeaders:
    def test_x_content_type_options(self) -> None:
        assert _STATIC_HEADERS["X-Content-Type-Options"] == "nosniff"

    def test_x_frame_options(self) -> None:
        assert _STATIC_HEADERS["X-Frame-Options"] == "DENY"

    def test_x_xss_protection(self) -> None:
        assert _STATIC_HEADERS["X-XSS-Protection"] == "0"

    def test_csp_present(self) -> None:
        assert "Content-Security-Policy" in _STATIC_HEADERS
        csp = _STATIC_HEADERS["Content-Security-Policy"]
        assert "default-src 'self'" in csp
        assert "script-src 'self'" in csp

    def test_referrer_policy(self) -> None:
        assert _STATIC_HEADERS["Referrer-Policy"] == "strict-origin-when-cross-origin"

    def test_permissions_policy(self) -> None:
        pp = _STATIC_HEADERS["Permissions-Policy"]
        assert "camera=()" in pp
        assert "microphone=()" in pp
        assert "geolocation=()" in pp

    def test_cache_control(self) -> None:
        assert _STATIC_HEADERS["Cache-Control"] == "no-store"

    def test_hsts_key(self) -> None:
        assert _HSTS_HEADER == "Strict-Transport-Security"

    def test_hsts_value(self) -> None:
        assert "max-age=31536000" in _HSTS_VALUE
        assert "includeSubDomains" in _HSTS_VALUE


# ---------------------------------------------------------------------------
# Integration tests — headers present in HTTP responses via test client
# ---------------------------------------------------------------------------


class TestSecurityHeadersOnResponses:
    """Verify that each security header appears on a regular 200 response."""

    async def test_x_content_type_options(self, client: AsyncClient) -> None:
        resp = await client.get("/health")
        assert resp.headers.get("x-content-type-options") == "nosniff"

    async def test_x_frame_options(self, client: AsyncClient) -> None:
        resp = await client.get("/health")
        assert resp.headers.get("x-frame-options") == "DENY"

    async def test_x_xss_protection(self, client: AsyncClient) -> None:
        resp = await client.get("/health")
        assert resp.headers.get("x-xss-protection") == "0"

    async def test_content_security_policy(self, client: AsyncClient) -> None:
        resp = await client.get("/health")
        csp = resp.headers.get("content-security-policy", "")
        assert "default-src 'self'" in csp

    async def test_referrer_policy(self, client: AsyncClient) -> None:
        resp = await client.get("/health")
        assert resp.headers.get("referrer-policy") == "strict-origin-when-cross-origin"

    async def test_permissions_policy(self, client: AsyncClient) -> None:
        resp = await client.get("/health")
        pp = resp.headers.get("permissions-policy", "")
        assert "camera=()" in pp
        assert "microphone=()" in pp
        assert "geolocation=()" in pp

    async def test_cache_control(self, client: AsyncClient) -> None:
        resp = await client.get("/health")
        assert resp.headers.get("cache-control") == "no-store"

    async def test_hsts_absent_in_debug_mode(self, client: AsyncClient) -> None:
        """HSTS must NOT be sent when settings.debug=True (default in tests)."""
        resp = await client.get("/health")
        assert "strict-transport-security" not in resp.headers

    async def test_hsts_present_in_production_mode(self, client: AsyncClient) -> None:
        """HSTS must be added when settings.debug=False."""
        with patch("app.core.security_headers.settings") as mock_settings:
            mock_settings.debug = False
            resp = await client.get("/health")
        assert "strict-transport-security" in resp.headers
        assert "max-age=31536000" in resp.headers["strict-transport-security"]
        assert "includeSubDomains" in resp.headers["strict-transport-security"]


# ---------------------------------------------------------------------------
# Headers on error and probe responses
# ---------------------------------------------------------------------------


class TestSecurityHeadersOnErrorResponses:
    async def test_headers_on_404(self, client: AsyncClient) -> None:
        resp = await client.get("/api/v1/nonexistent-path-xyz")
        assert resp.headers.get("x-content-type-options") == "nosniff"
        assert resp.headers.get("cache-control") == "no-store"

    async def test_headers_on_health_probe(self, client: AsyncClient) -> None:
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.headers.get("x-frame-options") == "DENY"

    async def test_headers_on_unauthenticated_request(self, client: AsyncClient) -> None:
        """401 responses from protected endpoints must also carry security headers."""
        resp = await client.get("/api/v1/rules")
        assert resp.status_code == 401
        assert resp.headers.get("x-content-type-options") == "nosniff"
        assert resp.headers.get("cache-control") == "no-store"
