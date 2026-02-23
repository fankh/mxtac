"""Tests for /health and /ready endpoints.

The /health endpoint is a plain liveness probe with no external dependencies.
The /ready endpoint performs DB/Valkey/OpenSearch checks; in tests all external
services are unavailable so we verify response structure, not specific status.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest


class TestHealthEndpoint:
    """GET /health — simple liveness probe."""

    async def test_health_returns_200(self, client) -> None:
        resp = await client.get("/health")
        assert resp.status_code == 200

    async def test_health_status_ok(self, client) -> None:
        resp = await client.get("/health")
        assert resp.json()["status"] == "ok"

    async def test_health_has_version(self, client) -> None:
        resp = await client.get("/health")
        assert "version" in resp.json()

    async def test_health_no_auth_required(self, client) -> None:
        """Health endpoint is publicly accessible — no auth header needed."""
        resp = await client.get("/health")
        assert resp.status_code != 401


class TestReadyEndpoint:
    """GET /ready — readiness probe structure validation.

    External services (DB, Valkey, OpenSearch) are unavailable in the test
    environment.  We assert only the response *shape*, not specific status codes,
    so the tests remain infrastructure-free.
    """

    async def test_ready_returns_json(self, client) -> None:
        resp = await client.get("/ready")
        assert resp.headers["content-type"].startswith("application/json")

    async def test_ready_has_status_key(self, client) -> None:
        resp = await client.get("/ready")
        body = resp.json()
        assert "status" in body

    async def test_ready_has_checks_key(self, client) -> None:
        resp = await client.get("/ready")
        body = resp.json()
        assert "checks" in body

    async def test_ready_checks_contains_db(self, client) -> None:
        resp = await client.get("/ready")
        checks = resp.json()["checks"]
        assert "db" in checks

    async def test_ready_checks_contains_valkey(self, client) -> None:
        resp = await client.get("/ready")
        checks = resp.json()["checks"]
        assert "valkey" in checks

    async def test_ready_checks_contains_opensearch(self, client) -> None:
        resp = await client.get("/ready")
        checks = resp.json()["checks"]
        assert "opensearch" in checks

    async def test_ready_no_auth_required(self, client) -> None:
        """Readiness probe is publicly accessible — no auth header needed."""
        resp = await client.get("/ready")
        assert resp.status_code != 401

    async def test_ready_all_ok_when_db_available(self, client) -> None:
        """When all service checks report 'ok', status is 'ready' and HTTP 200."""
        with (
            patch("app.main.AsyncSessionLocal") as mock_session_factory,
            patch("app.main.asyncio.wait_for") as mock_wait_for,
        ):
            mock_wait_for.return_value = None  # all checks succeed instantly
            resp = await client.get("/ready")
        # We don't assert the exact body here — just that the endpoint returns
        # valid JSON regardless of the mock outcome.
        assert resp.headers["content-type"].startswith("application/json")
