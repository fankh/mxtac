"""Tests for app/core/access_log.py — Feature 21.11: Request access log.

The AccessLogMiddleware emits one structured INFO record per HTTP request
containing: method, path, status code, and latency in milliseconds.
High-frequency probe paths (/health, /ready, /metrics) are excluded.

Coverage:
  AccessLogMiddleware — logs INFO on non-skip requests
  AccessLogMiddleware — log message contains method
  AccessLogMiddleware — log message contains path
  AccessLogMiddleware — log message contains status code
  AccessLogMiddleware — log message contains latency_ms field
  AccessLogMiddleware — latency_ms is a non-negative number
  AccessLogMiddleware — /health path is skipped (no log emitted)
  AccessLogMiddleware — /ready path is skipped (no log emitted)
  AccessLogMiddleware — /metrics path is skipped (no log emitted)
  AccessLogMiddleware — response is passed through unchanged
  AccessLogMiddleware — logger name is mxtac.access
  AccessLogMiddleware — POST requests are logged
  AccessLogMiddleware — 4xx responses are logged
  AccessLogMiddleware — 5xx responses are logged
  _SKIP_PATHS — contains /health
  _SKIP_PATHS — contains /ready
  _SKIP_PATHS — contains /metrics
  _SKIP_PATHS — is a frozenset
"""

from __future__ import annotations

import logging
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.requests import Request
from starlette.responses import Response
from starlette.testclient import TestClient
from starlette.applications import Starlette
from starlette.routing import Route

from app.core.access_log import AccessLogMiddleware, _SKIP_PATHS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_request(method: str = "GET", path: str = "/api/v1/rules") -> Request:
    """Build a minimal Starlette Request object for unit-testing dispatch()."""
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "query_string": b"",
        "headers": [],
    }
    return Request(scope)


def _make_response(status_code: int = 200) -> Response:
    return Response(content=b"ok", status_code=status_code)


async def _call_next_factory(status_code: int = 200):
    """Return an async callable that yields a Response with the given status."""
    async def _call_next(request: Request) -> Response:
        return _make_response(status_code)
    return _call_next


# ---------------------------------------------------------------------------
# _SKIP_PATHS constants
# ---------------------------------------------------------------------------


class TestSkipPaths:
    def test_is_frozenset(self) -> None:
        assert isinstance(_SKIP_PATHS, frozenset)

    def test_contains_health(self) -> None:
        assert "/health" in _SKIP_PATHS

    def test_contains_ready(self) -> None:
        assert "/ready" in _SKIP_PATHS

    def test_contains_metrics(self) -> None:
        assert "/metrics" in _SKIP_PATHS


# ---------------------------------------------------------------------------
# AccessLogMiddleware unit tests (dispatch())
# ---------------------------------------------------------------------------


class TestAccessLogMiddlewareDispatch:
    """Unit-test dispatch() directly without a full ASGI stack."""

    @pytest.fixture
    def middleware(self) -> AccessLogMiddleware:
        # BaseHTTPMiddleware requires an 'app' arg but dispatch() never calls it
        app_stub = MagicMock()
        return AccessLogMiddleware(app=app_stub)

    # --- logging behaviour ---

    @pytest.mark.asyncio
    async def test_logs_info_for_normal_request(self, middleware, caplog) -> None:
        request = _make_request("GET", "/api/v1/rules")
        call_next = await _call_next_factory(200)
        with caplog.at_level(logging.INFO, logger="mxtac.access"):
            await middleware.dispatch(request, call_next)
        assert len(caplog.records) == 1

    @pytest.mark.asyncio
    async def test_logger_name_is_mxtac_access(self, middleware, caplog) -> None:
        request = _make_request("GET", "/api/v1/rules")
        call_next = await _call_next_factory(200)
        with caplog.at_level(logging.INFO, logger="mxtac.access"):
            await middleware.dispatch(request, call_next)
        assert caplog.records[0].name == "mxtac.access"

    @pytest.mark.asyncio
    async def test_log_message_contains_method(self, middleware, caplog) -> None:
        request = _make_request("GET", "/api/v1/rules")
        call_next = await _call_next_factory(200)
        with caplog.at_level(logging.INFO, logger="mxtac.access"):
            await middleware.dispatch(request, call_next)
        assert "GET" in caplog.records[0].getMessage()

    @pytest.mark.asyncio
    async def test_log_message_contains_path(self, middleware, caplog) -> None:
        request = _make_request("GET", "/api/v1/rules")
        call_next = await _call_next_factory(200)
        with caplog.at_level(logging.INFO, logger="mxtac.access"):
            await middleware.dispatch(request, call_next)
        assert "/api/v1/rules" in caplog.records[0].getMessage()

    @pytest.mark.asyncio
    async def test_log_message_contains_status_code(self, middleware, caplog) -> None:
        request = _make_request("GET", "/api/v1/rules")
        call_next = await _call_next_factory(200)
        with caplog.at_level(logging.INFO, logger="mxtac.access"):
            await middleware.dispatch(request, call_next)
        assert "200" in caplog.records[0].getMessage()

    @pytest.mark.asyncio
    async def test_log_message_contains_latency_ms_field(self, middleware, caplog) -> None:
        request = _make_request("GET", "/api/v1/rules")
        call_next = await _call_next_factory(200)
        with caplog.at_level(logging.INFO, logger="mxtac.access"):
            await middleware.dispatch(request, call_next)
        assert "latency_ms" in caplog.records[0].getMessage()

    @pytest.mark.asyncio
    async def test_latency_ms_is_non_negative(self, middleware, caplog) -> None:
        import re
        request = _make_request("GET", "/api/v1/rules")
        call_next = await _call_next_factory(200)
        with caplog.at_level(logging.INFO, logger="mxtac.access"):
            await middleware.dispatch(request, call_next)
        msg = caplog.records[0].getMessage()
        match = re.search(r'"latency_ms":([\d.]+)', msg)
        assert match is not None, f"latency_ms not found in: {msg}"
        assert float(match.group(1)) >= 0

    # --- skip behaviour ---

    @pytest.mark.asyncio
    async def test_health_path_is_skipped(self, middleware, caplog) -> None:
        request = _make_request("GET", "/health")
        call_next = await _call_next_factory(200)
        with caplog.at_level(logging.INFO, logger="mxtac.access"):
            await middleware.dispatch(request, call_next)
        assert len(caplog.records) == 0

    @pytest.mark.asyncio
    async def test_ready_path_is_skipped(self, middleware, caplog) -> None:
        request = _make_request("GET", "/ready")
        call_next = await _call_next_factory(200)
        with caplog.at_level(logging.INFO, logger="mxtac.access"):
            await middleware.dispatch(request, call_next)
        assert len(caplog.records) == 0

    @pytest.mark.asyncio
    async def test_metrics_path_is_skipped(self, middleware, caplog) -> None:
        request = _make_request("GET", "/metrics")
        call_next = await _call_next_factory(200)
        with caplog.at_level(logging.INFO, logger="mxtac.access"):
            await middleware.dispatch(request, call_next)
        assert len(caplog.records) == 0

    # --- response pass-through ---

    @pytest.mark.asyncio
    async def test_response_is_passed_through(self, middleware) -> None:
        request = _make_request("GET", "/api/v1/rules")
        call_next = await _call_next_factory(200)
        response = await middleware.dispatch(request, call_next)
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_skip_path_response_is_passed_through(self, middleware) -> None:
        request = _make_request("GET", "/health")
        call_next = await _call_next_factory(200)
        response = await middleware.dispatch(request, call_next)
        assert response.status_code == 200

    # --- various methods and status codes ---

    @pytest.mark.asyncio
    async def test_post_request_is_logged(self, middleware, caplog) -> None:
        request = _make_request("POST", "/api/v1/events/ingest")
        call_next = await _call_next_factory(201)
        with caplog.at_level(logging.INFO, logger="mxtac.access"):
            await middleware.dispatch(request, call_next)
        msg = caplog.records[0].getMessage()
        assert "POST" in msg
        assert "201" in msg

    @pytest.mark.asyncio
    async def test_4xx_response_is_logged(self, middleware, caplog) -> None:
        request = _make_request("GET", "/api/v1/rules/nonexistent")
        call_next = await _call_next_factory(404)
        with caplog.at_level(logging.INFO, logger="mxtac.access"):
            await middleware.dispatch(request, call_next)
        assert "404" in caplog.records[0].getMessage()

    @pytest.mark.asyncio
    async def test_5xx_response_is_logged(self, middleware, caplog) -> None:
        request = _make_request("GET", "/api/v1/rules")
        call_next = await _call_next_factory(500)
        with caplog.at_level(logging.INFO, logger="mxtac.access"):
            await middleware.dispatch(request, call_next)
        assert "500" in caplog.records[0].getMessage()

    @pytest.mark.asyncio
    async def test_delete_request_is_logged(self, middleware, caplog) -> None:
        request = _make_request("DELETE", "/api/v1/rules/123")
        call_next = await _call_next_factory(204)
        with caplog.at_level(logging.INFO, logger="mxtac.access"):
            await middleware.dispatch(request, call_next)
        msg = caplog.records[0].getMessage()
        assert "DELETE" in msg
        assert "204" in msg
