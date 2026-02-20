"""Tests for GET /health and GET /ready endpoints.

Coverage:
  /health (feature 21.1 — always 200):
  - Always returns 200 regardless of external service state
  - Returns status="ok" and a non-empty version string
  - Only the expected keys are present in the response body
  - Version value matches settings.version
  - No authentication required
  - Auth headers do not affect the response
  - Content-Type is application/json
  - Idempotent across multiple calls
  - Non-GET methods are rejected (405)

  /ready (feature 19.9 — HAProxy health check):
  - Returns status field ("ready" or "degraded") and checks dict
  - Status code 200 when all services healthy, 503 when any degraded
  - Each service check key is present (postgres, valkey, opensearch)
  - No authentication required
  - Content-Type is application/json
  - Status code matches the status field value
  - Failure of any single service causes 503 + "degraded"
  - All services failing causes 503 + all error values
  - Error check values start with "error:" and include the message
  - Successful check value is exactly "ok"
  - Timeout on any check reports "error: timeout" and causes 503
  - Postgres timeout does not block valkey/opensearch checks
  - Valkey timeout does not block postgres/opensearch checks
  - OpenSearch timeout does not block postgres/valkey checks
"""

from __future__ import annotations

import asyncio
import sys
from contextlib import contextmanager
from typing import Generator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient

from app.core.config import settings


HEALTH_URL = "/health"
READY_URL = "/ready"


# ---------------------------------------------------------------------------
# Helpers — build mock sessions and service clients
# ---------------------------------------------------------------------------


def _mock_pg_factory(*, fail: bool = False, error: str = "postgres error") -> MagicMock:
    """Return a mock AsyncSessionLocal factory.

    The /ready handler calls ``async with AsyncSessionLocal() as session:``.
    ``AsyncSessionLocal()`` is synchronous; the returned object is an async
    context manager.  ``AsyncMock`` satisfies both requirements out of the box.
    """
    session = AsyncMock()
    if fail:
        session.__aenter__ = AsyncMock(side_effect=Exception(error))
    else:
        session.execute = AsyncMock(return_value=None)
    factory = MagicMock(return_value=session)
    return factory


def _mock_valkey_client(*, fail: bool = False, error: str = "valkey error") -> MagicMock:
    """Return a mock Valkey async client (result of ``from_url()``)."""
    client = MagicMock()
    if fail:
        client.ping = AsyncMock(side_effect=Exception(error))
    else:
        client.ping = AsyncMock(return_value=True)
    client.aclose = AsyncMock()
    return client


@contextmanager
def _patch_opensearch(
    *, fail: bool = False, error: str = "opensearch error"
) -> Generator[MagicMock, None, None]:
    """Inject a fake ``opensearchpy`` module into sys.modules.

    The /ready handler does ``from opensearchpy import AsyncOpenSearch`` at
    runtime.  Since opensearch-py is not installed in the test environment we
    cannot use ``patch("opensearchpy.AsyncOpenSearch")`` — that would try to
    import the absent package first.  Instead we insert a fake module object
    directly into sys.modules so that the local import picks it up.
    """
    mock_instance = MagicMock()
    if fail:
        mock_instance.ping = AsyncMock(side_effect=Exception(error))
    else:
        mock_instance.ping = AsyncMock(return_value=True)
    mock_instance.close = AsyncMock()

    mock_class = MagicMock(return_value=mock_instance)
    mock_module = MagicMock()
    mock_module.AsyncOpenSearch = mock_class

    with patch.dict(sys.modules, {"opensearchpy": mock_module}):
        yield mock_instance


# ---------------------------------------------------------------------------
# /health — always 200 (feature 21.1)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_health_returns_200(client: AsyncClient) -> None:
    """/health always returns 200 OK without authentication."""
    resp = await client.get(HEALTH_URL)
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_health_status_ok(client: AsyncClient) -> None:
    """/health response body contains status='ok'."""
    resp = await client.get(HEALTH_URL)
    assert resp.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_health_contains_version(client: AsyncClient) -> None:
    """/health response body contains a non-empty 'version' field."""
    resp = await client.get(HEALTH_URL)
    data = resp.json()
    assert "version" in data
    assert isinstance(data["version"], str)
    assert data["version"]


@pytest.mark.asyncio
async def test_health_content_type_json(client: AsyncClient) -> None:
    """/health Content-Type is application/json."""
    resp = await client.get(HEALTH_URL)
    assert "application/json" in resp.headers["content-type"]


@pytest.mark.asyncio
async def test_health_exact_response_keys(client: AsyncClient) -> None:
    """/health body contains exactly 'status' and 'version' — no extra keys."""
    resp = await client.get(HEALTH_URL)
    assert set(resp.json().keys()) == {"status", "version"}


@pytest.mark.asyncio
async def test_health_version_matches_settings(client: AsyncClient) -> None:
    """/health 'version' value equals settings.version."""
    resp = await client.get(HEALTH_URL)
    assert resp.json()["version"] == settings.version


@pytest.mark.asyncio
async def test_health_no_auth_required(client: AsyncClient) -> None:
    """/health returns 200 when called with no Authorization header."""
    resp = await client.get(HEALTH_URL)
    assert resp.status_code == 200
    assert "Authorization" not in resp.request.headers


@pytest.mark.asyncio
async def test_health_with_auth_headers_still_200(
    client: AsyncClient,
    analyst_headers: dict[str, str],
) -> None:
    """/health returns 200 even when a valid Bearer token is supplied."""
    resp = await client.get(HEALTH_URL, headers=analyst_headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_health_idempotent(client: AsyncClient) -> None:
    """/health returns 200 on repeated calls — it is stateless."""
    for _ in range(5):
        resp = await client.get(HEALTH_URL)
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_health_post_not_allowed(client: AsyncClient) -> None:
    """/health rejects POST with 405."""
    resp = await client.post(HEALTH_URL)
    assert resp.status_code == 405


@pytest.mark.asyncio
async def test_health_put_not_allowed(client: AsyncClient) -> None:
    """/health rejects PUT with 405."""
    resp = await client.put(HEALTH_URL)
    assert resp.status_code == 405


@pytest.mark.asyncio
async def test_health_delete_not_allowed(client: AsyncClient) -> None:
    """/health rejects DELETE with 405."""
    resp = await client.delete(HEALTH_URL)
    assert resp.status_code == 405


# ---------------------------------------------------------------------------
# /ready — structure & invariants (no mocking required)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ready_returns_status_field(client: AsyncClient) -> None:
    """/ready response body has a 'status' field ('ready' or 'degraded')."""
    resp = await client.get(READY_URL)
    data = resp.json()
    assert "status" in data
    assert data["status"] in ("ready", "degraded")


@pytest.mark.asyncio
async def test_ready_has_checks_dict(client: AsyncClient) -> None:
    """/ready response body has a 'checks' dict with all service keys."""
    resp = await client.get(READY_URL)
    data = resp.json()
    assert "checks" in data
    assert isinstance(data["checks"], dict)
    checks = data["checks"]
    assert "postgres" in checks
    assert "valkey" in checks
    assert "opensearch" in checks


@pytest.mark.asyncio
async def test_ready_content_type_json(client: AsyncClient) -> None:
    """/ready Content-Type is application/json."""
    resp = await client.get(READY_URL)
    assert "application/json" in resp.headers["content-type"]


@pytest.mark.asyncio
async def test_ready_no_auth_required(client: AsyncClient) -> None:
    """/ready responds (200 or 503) without an Authorization header."""
    resp = await client.get(READY_URL)
    assert resp.status_code in (200, 503)


@pytest.mark.asyncio
async def test_ready_status_code_matches_status_field(client: AsyncClient) -> None:
    """HTTP status code matches the 'status' field: 200↔ready, 503↔degraded."""
    resp = await client.get(READY_URL)
    data = resp.json()
    if data["status"] == "ready":
        assert resp.status_code == 200
    else:
        assert resp.status_code == 503


@pytest.mark.asyncio
async def test_ready_check_values_are_strings(client: AsyncClient) -> None:
    """Every value in the 'checks' dict is a string."""
    resp = await client.get(READY_URL)
    for key, val in resp.json()["checks"].items():
        assert isinstance(val, str), f"checks[{key!r}] is not a string"


# ---------------------------------------------------------------------------
# /ready — mocked all-services-healthy path (200)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ready_all_services_ok_returns_200(client: AsyncClient) -> None:
    """/ready returns 200 with status='ready' when all service mocks succeed."""
    pg_factory = _mock_pg_factory()
    vk_client = _mock_valkey_client()

    with patch("app.main.AsyncSessionLocal", pg_factory), \
         patch("valkey.asyncio.from_url", return_value=vk_client), \
         _patch_opensearch():
        resp = await client.get(READY_URL)

    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ready"
    assert data["checks"]["postgres"] == "ok"
    assert data["checks"]["valkey"] == "ok"
    assert data["checks"]["opensearch"] == "ok"


# ---------------------------------------------------------------------------
# /ready — single-service failure paths (503)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ready_postgres_failure_returns_503(client: AsyncClient) -> None:
    """/ready returns 503 + 'degraded' when the PostgreSQL check fails."""
    pg_factory = _mock_pg_factory(fail=True, error="connection refused")
    vk_client = _mock_valkey_client()

    with patch("app.main.AsyncSessionLocal", pg_factory), \
         patch("valkey.asyncio.from_url", return_value=vk_client), \
         _patch_opensearch():
        resp = await client.get(READY_URL)

    assert resp.status_code == 503
    data = resp.json()
    assert data["status"] == "degraded"
    assert data["checks"]["postgres"].startswith("error:")
    assert data["checks"]["valkey"] == "ok"
    assert data["checks"]["opensearch"] == "ok"


@pytest.mark.asyncio
async def test_ready_valkey_failure_returns_503(client: AsyncClient) -> None:
    """/ready returns 503 + 'degraded' when the Valkey check fails."""
    pg_factory = _mock_pg_factory()
    vk_client = _mock_valkey_client(fail=True, error="ECONNREFUSED")

    with patch("app.main.AsyncSessionLocal", pg_factory), \
         patch("valkey.asyncio.from_url", return_value=vk_client), \
         _patch_opensearch():
        resp = await client.get(READY_URL)

    assert resp.status_code == 503
    data = resp.json()
    assert data["status"] == "degraded"
    assert data["checks"]["postgres"] == "ok"
    assert data["checks"]["valkey"].startswith("error:")
    assert data["checks"]["opensearch"] == "ok"


@pytest.mark.asyncio
async def test_ready_opensearch_failure_returns_503(client: AsyncClient) -> None:
    """/ready returns 503 + 'degraded' when the OpenSearch check fails."""
    pg_factory = _mock_pg_factory()
    vk_client = _mock_valkey_client()

    with patch("app.main.AsyncSessionLocal", pg_factory), \
         patch("valkey.asyncio.from_url", return_value=vk_client), \
         _patch_opensearch(fail=True, error="timeout"):
        resp = await client.get(READY_URL)

    assert resp.status_code == 503
    data = resp.json()
    assert data["status"] == "degraded"
    assert data["checks"]["postgres"] == "ok"
    assert data["checks"]["valkey"] == "ok"
    assert data["checks"]["opensearch"].startswith("error:")


# ---------------------------------------------------------------------------
# /ready — all services down (503)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ready_all_services_fail_returns_503(client: AsyncClient) -> None:
    """/ready returns 503 with all check values as errors when all services fail."""
    pg_factory = _mock_pg_factory(fail=True, error="pg down")
    vk_client = _mock_valkey_client(fail=True, error="vk down")

    with patch("app.main.AsyncSessionLocal", pg_factory), \
         patch("valkey.asyncio.from_url", return_value=vk_client), \
         _patch_opensearch(fail=True, error="os down"):
        resp = await client.get(READY_URL)

    assert resp.status_code == 503
    data = resp.json()
    assert data["status"] == "degraded"
    for key in ("postgres", "valkey", "opensearch"):
        assert data["checks"][key].startswith("error:"), (
            f"Expected checks[{key!r}] to start with 'error:', got {data['checks'][key]!r}"
        )


# ---------------------------------------------------------------------------
# /ready — error value format
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ready_error_value_includes_exception_message(client: AsyncClient) -> None:
    """Error check values include the original exception message."""
    error_msg = "unique-sentinel-error-xyz"
    pg_factory = _mock_pg_factory(fail=True, error=error_msg)
    vk_client = _mock_valkey_client()

    with patch("app.main.AsyncSessionLocal", pg_factory), \
         patch("valkey.asyncio.from_url", return_value=vk_client), \
         _patch_opensearch():
        resp = await client.get(READY_URL)

    assert error_msg in resp.json()["checks"]["postgres"]


@pytest.mark.asyncio
async def test_ready_error_format_is_error_colon_prefix(client: AsyncClient) -> None:
    """Error check values follow the 'error: <message>' format exactly."""
    pg_factory = _mock_pg_factory(fail=True, error="something went wrong")
    vk_client = _mock_valkey_client()

    with patch("app.main.AsyncSessionLocal", pg_factory), \
         patch("valkey.asyncio.from_url", return_value=vk_client), \
         _patch_opensearch():
        resp = await client.get(READY_URL)

    assert resp.json()["checks"]["postgres"] == "error: something went wrong"


# ---------------------------------------------------------------------------
# /ready — timeout paths (feature 19.9 — HAProxy health check)
# ---------------------------------------------------------------------------


def _make_slow_pg_factory(delay: float = 10.0) -> MagicMock:
    """Return a mock AsyncSessionLocal whose execute hangs for ``delay`` seconds."""
    async def _slow_execute(*_args, **_kwargs):
        await asyncio.sleep(delay)

    session = AsyncMock()
    session.execute = _slow_execute
    factory = MagicMock(return_value=session)
    return factory


def _make_slow_valkey_client(delay: float = 10.0) -> MagicMock:
    """Return a mock Valkey client whose ping hangs for ``delay`` seconds."""
    async def _slow_ping():
        await asyncio.sleep(delay)

    client = MagicMock()
    client.ping = _slow_ping
    client.aclose = AsyncMock()
    return client


@contextmanager
def _patch_slow_opensearch(delay: float = 10.0) -> Generator[MagicMock, None, None]:
    """Inject a fake opensearchpy module whose ping hangs for ``delay`` seconds."""
    async def _slow_ping():
        await asyncio.sleep(delay)

    mock_instance = MagicMock()
    mock_instance.ping = _slow_ping
    mock_instance.close = AsyncMock()

    mock_class = MagicMock(return_value=mock_instance)
    mock_module = MagicMock()
    mock_module.AsyncOpenSearch = mock_class

    with patch.dict(sys.modules, {"opensearchpy": mock_module}):
        yield mock_instance


@pytest.mark.asyncio
async def test_ready_postgres_timeout_returns_503(client: AsyncClient) -> None:
    """/ready returns 503 with 'error: timeout' when the Postgres check times out."""
    pg_factory = _make_slow_pg_factory()
    vk_client = _mock_valkey_client()

    with patch("app.main.AsyncSessionLocal", pg_factory), \
         patch("valkey.asyncio.from_url", return_value=vk_client), \
         patch("app.main._READY_CHECK_TIMEOUT", 0.05), \
         _patch_opensearch():
        resp = await client.get(READY_URL)

    assert resp.status_code == 503
    data = resp.json()
    assert data["status"] == "degraded"
    assert data["checks"]["postgres"] == "error: timeout"
    assert data["checks"]["valkey"] == "ok"
    assert data["checks"]["opensearch"] == "ok"


@pytest.mark.asyncio
async def test_ready_valkey_timeout_returns_503(client: AsyncClient) -> None:
    """/ready returns 503 with 'error: timeout' when the Valkey check times out."""
    pg_factory = _mock_pg_factory()
    vk_client = _make_slow_valkey_client()

    with patch("app.main.AsyncSessionLocal", pg_factory), \
         patch("valkey.asyncio.from_url", return_value=vk_client), \
         patch("app.main._READY_CHECK_TIMEOUT", 0.05), \
         _patch_opensearch():
        resp = await client.get(READY_URL)

    assert resp.status_code == 503
    data = resp.json()
    assert data["status"] == "degraded"
    assert data["checks"]["postgres"] == "ok"
    assert data["checks"]["valkey"] == "error: timeout"
    assert data["checks"]["opensearch"] == "ok"


@pytest.mark.asyncio
async def test_ready_opensearch_timeout_returns_503(client: AsyncClient) -> None:
    """/ready returns 503 with 'error: timeout' when the OpenSearch check times out."""
    pg_factory = _mock_pg_factory()
    vk_client = _mock_valkey_client()

    with patch("app.main.AsyncSessionLocal", pg_factory), \
         patch("valkey.asyncio.from_url", return_value=vk_client), \
         patch("app.main._READY_CHECK_TIMEOUT", 0.05), \
         _patch_slow_opensearch():
        resp = await client.get(READY_URL)

    assert resp.status_code == 503
    data = resp.json()
    assert data["status"] == "degraded"
    assert data["checks"]["postgres"] == "ok"
    assert data["checks"]["valkey"] == "ok"
    assert data["checks"]["opensearch"] == "error: timeout"


@pytest.mark.asyncio
async def test_ready_timeout_value_is_error_timeout_literal(client: AsyncClient) -> None:
    """Timeout check value is the exact string 'error: timeout'."""
    pg_factory = _make_slow_pg_factory()
    vk_client = _mock_valkey_client()

    with patch("app.main.AsyncSessionLocal", pg_factory), \
         patch("valkey.asyncio.from_url", return_value=vk_client), \
         patch("app.main._READY_CHECK_TIMEOUT", 0.05), \
         _patch_opensearch():
        resp = await client.get(READY_URL)

    assert resp.json()["checks"]["postgres"] == "error: timeout"
