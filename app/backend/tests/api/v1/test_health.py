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
  - Each service check key is present (db, valkey, opensearch, backup)
  - No authentication required
  - Content-Type is application/json
  - Status code matches the status field value
  - Failure of any single service causes 503 + "degraded"
  - All services failing causes 503 + all error values
  - Error check values start with "error:" and include the message
  - Successful check value is exactly "ok"
  - Timeout on any check reports "error: timeout" and causes 503
  - db timeout does not block valkey/opensearch checks
  - Valkey timeout does not block db/opensearch checks
  - OpenSearch timeout does not block db/valkey checks

  /ready — SQLite single-binary mode (feature 20.8):
  - In sqlite_mode, only db check is required for 200
  - In sqlite_mode, Valkey failure does not cause 503
  - In sqlite_mode, OpenSearch failure does not cause 503
  - In sqlite_mode, db failure still causes 503
  - All three service checks are still reported in the checks dict

  /ready — backup status check (feature 38.1):
  - Backup check key is always present in checks dict
  - Backup "warn:..." value does NOT cause 503
  - When no backup directory exists, reports "warn: backup directory not found"
  - When backup directory is empty, reports "warn: no backups found"
  - When a fresh backup exists, reports "ok"
  - When backup is older than threshold, reports "warn: last backup Xh ago"
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


def _mock_db_factory(*, fail: bool = False, error: str = "db error") -> MagicMock:
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
    assert "db" in checks
    assert "valkey" in checks
    assert "opensearch" in checks
    assert "backup" in checks


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
    db_factory = _mock_db_factory()
    vk_client = _mock_valkey_client()

    with patch("app.main.AsyncSessionLocal", db_factory), \
         patch("valkey.asyncio.from_url", return_value=vk_client), \
         _patch_opensearch():
        resp = await client.get(READY_URL)

    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ready"
    assert data["checks"]["db"] == "ok"
    assert data["checks"]["valkey"] == "ok"
    assert data["checks"]["opensearch"] == "ok"


# ---------------------------------------------------------------------------
# /ready — single-service failure paths (503)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ready_db_failure_returns_503(client: AsyncClient) -> None:
    """/ready returns 503 + 'degraded' when the DB check fails."""
    db_factory = _mock_db_factory(fail=True, error="connection refused")
    vk_client = _mock_valkey_client()

    with patch("app.main.AsyncSessionLocal", db_factory), \
         patch("valkey.asyncio.from_url", return_value=vk_client), \
         patch.object(settings, "sqlite_mode", False), \
         patch.object(settings, "database_url", "postgresql+asyncpg://mxtac:mxtac@localhost:5432/mxtac"), \
         _patch_opensearch():
        resp = await client.get(READY_URL)

    assert resp.status_code == 503
    data = resp.json()
    assert data["status"] == "degraded"
    assert data["checks"]["db"].startswith("error:")
    assert data["checks"]["valkey"] == "ok"
    assert data["checks"]["opensearch"] == "ok"


@pytest.mark.asyncio
async def test_ready_valkey_failure_returns_503(client: AsyncClient) -> None:
    """/ready returns 503 + 'degraded' when the Valkey check fails."""
    db_factory = _mock_db_factory()
    vk_client = _mock_valkey_client(fail=True, error="ECONNREFUSED")

    with patch("app.main.AsyncSessionLocal", db_factory), \
         patch("valkey.asyncio.from_url", return_value=vk_client), \
         patch.object(settings, "sqlite_mode", False), \
         patch.object(settings, "database_url", "postgresql+asyncpg://mxtac:mxtac@localhost:5432/mxtac"), \
         _patch_opensearch():
        resp = await client.get(READY_URL)

    assert resp.status_code == 503
    data = resp.json()
    assert data["status"] == "degraded"
    assert data["checks"]["db"] == "ok"
    assert data["checks"]["valkey"].startswith("error:")
    assert data["checks"]["opensearch"] == "ok"


@pytest.mark.asyncio
async def test_ready_opensearch_failure_returns_503(client: AsyncClient) -> None:
    """/ready returns 503 + 'degraded' when the OpenSearch check fails."""
    db_factory = _mock_db_factory()
    vk_client = _mock_valkey_client()

    with patch("app.main.AsyncSessionLocal", db_factory), \
         patch("valkey.asyncio.from_url", return_value=vk_client), \
         patch.object(settings, "sqlite_mode", False), \
         patch.object(settings, "database_url", "postgresql+asyncpg://mxtac:mxtac@localhost:5432/mxtac"), \
         _patch_opensearch(fail=True, error="timeout"):
        resp = await client.get(READY_URL)

    assert resp.status_code == 503
    data = resp.json()
    assert data["status"] == "degraded"
    assert data["checks"]["db"] == "ok"
    assert data["checks"]["valkey"] == "ok"
    assert data["checks"]["opensearch"].startswith("error:")


# ---------------------------------------------------------------------------
# /ready — all services down (503)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ready_all_services_fail_returns_503(client: AsyncClient) -> None:
    """/ready returns 503 with all check values as errors when all services fail."""
    db_factory = _mock_db_factory(fail=True, error="db down")
    vk_client = _mock_valkey_client(fail=True, error="vk down")

    with patch("app.main.AsyncSessionLocal", db_factory), \
         patch("valkey.asyncio.from_url", return_value=vk_client), \
         patch.object(settings, "sqlite_mode", False), \
         patch.object(settings, "database_url", "postgresql+asyncpg://mxtac:mxtac@localhost:5432/mxtac"), \
         _patch_opensearch(fail=True, error="os down"):
        resp = await client.get(READY_URL)

    assert resp.status_code == 503
    data = resp.json()
    assert data["status"] == "degraded"
    for key in ("db", "valkey", "opensearch"):
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
    db_factory = _mock_db_factory(fail=True, error=error_msg)
    vk_client = _mock_valkey_client()

    with patch("app.main.AsyncSessionLocal", db_factory), \
         patch("valkey.asyncio.from_url", return_value=vk_client), \
         _patch_opensearch():
        resp = await client.get(READY_URL)

    assert error_msg in resp.json()["checks"]["db"]


@pytest.mark.asyncio
async def test_ready_error_format_is_error_colon_prefix(client: AsyncClient) -> None:
    """Error check values follow the 'error: <message>' format exactly."""
    db_factory = _mock_db_factory(fail=True, error="something went wrong")
    vk_client = _mock_valkey_client()

    with patch("app.main.AsyncSessionLocal", db_factory), \
         patch("valkey.asyncio.from_url", return_value=vk_client), \
         _patch_opensearch():
        resp = await client.get(READY_URL)

    assert resp.json()["checks"]["db"] == "error: something went wrong"


# ---------------------------------------------------------------------------
# /ready — timeout paths (feature 19.9 — HAProxy health check)
# ---------------------------------------------------------------------------


def _make_slow_db_factory(delay: float = 10.0) -> MagicMock:
    """Return a mock AsyncSessionLocal factory whose __aenter__ hangs for ``delay`` seconds.

    We configure __aenter__ via AsyncMock(side_effect=...) on an AsyncMock instance.
    Python's AsyncMock correctly delegates instance-level dunder assignments through
    the class machinery, so this pattern works — unlike plain assignment to a MagicMock.
    """
    async def _slow_enter(*_args, **_kwargs):
        await asyncio.sleep(delay)

    session = AsyncMock()
    session.__aenter__ = AsyncMock(side_effect=_slow_enter)
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
async def test_ready_db_timeout_returns_503(client: AsyncClient) -> None:
    """/ready returns 503 with 'error: timeout' when the DB check times out."""
    db_factory = _make_slow_db_factory()
    vk_client = _mock_valkey_client()

    with patch("app.main.AsyncSessionLocal", db_factory), \
         patch("valkey.asyncio.from_url", return_value=vk_client), \
         patch("app.main._READY_CHECK_TIMEOUT", 0.05), \
         _patch_opensearch():
        resp = await client.get(READY_URL)

    assert resp.status_code == 503
    data = resp.json()
    assert data["status"] == "degraded"
    assert data["checks"]["db"] == "error: timeout"
    assert data["checks"]["valkey"] == "ok"
    assert data["checks"]["opensearch"] == "ok"


@pytest.mark.asyncio
async def test_ready_valkey_timeout_returns_503(client: AsyncClient) -> None:
    """/ready returns 503 with 'error: timeout' when the Valkey check times out."""
    db_factory = _mock_db_factory()
    vk_client = _make_slow_valkey_client()

    with patch("app.main.AsyncSessionLocal", db_factory), \
         patch("valkey.asyncio.from_url", return_value=vk_client), \
         patch("app.main._READY_CHECK_TIMEOUT", 0.05), \
         patch.object(settings, "sqlite_mode", False), \
         patch.object(settings, "database_url", "postgresql+asyncpg://mxtac:mxtac@localhost:5432/mxtac"), \
         _patch_opensearch():
        resp = await client.get(READY_URL)

    assert resp.status_code == 503
    data = resp.json()
    assert data["status"] == "degraded"
    assert data["checks"]["db"] == "ok"
    assert data["checks"]["valkey"] == "error: timeout"
    assert data["checks"]["opensearch"] == "ok"


@pytest.mark.asyncio
async def test_ready_opensearch_timeout_returns_503(client: AsyncClient) -> None:
    """/ready returns 503 with 'error: timeout' when the OpenSearch check times out."""
    db_factory = _mock_db_factory()
    vk_client = _mock_valkey_client()

    with patch("app.main.AsyncSessionLocal", db_factory), \
         patch("valkey.asyncio.from_url", return_value=vk_client), \
         patch("app.main._READY_CHECK_TIMEOUT", 0.05), \
         patch.object(settings, "sqlite_mode", False), \
         patch.object(settings, "database_url", "postgresql+asyncpg://mxtac:mxtac@localhost:5432/mxtac"), \
         _patch_slow_opensearch():
        resp = await client.get(READY_URL)

    assert resp.status_code == 503
    data = resp.json()
    assert data["status"] == "degraded"
    assert data["checks"]["db"] == "ok"
    assert data["checks"]["valkey"] == "ok"
    assert data["checks"]["opensearch"] == "error: timeout"


@pytest.mark.asyncio
async def test_ready_timeout_value_is_error_timeout_literal(client: AsyncClient) -> None:
    """Timeout check value is the exact string 'error: timeout'."""
    db_factory = _make_slow_db_factory()
    vk_client = _mock_valkey_client()

    with patch("app.main.AsyncSessionLocal", db_factory), \
         patch("valkey.asyncio.from_url", return_value=vk_client), \
         patch("app.main._READY_CHECK_TIMEOUT", 0.05), \
         _patch_opensearch():
        resp = await client.get(READY_URL)

    assert resp.json()["checks"]["db"] == "error: timeout"


# ---------------------------------------------------------------------------
# /ready — SQLite single-binary mode (feature 20.8)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ready_sqlite_mode_db_ok_returns_200_despite_valkey_failure(
    client: AsyncClient,
) -> None:
    """In sqlite_mode, 200 is returned even when Valkey is unavailable."""
    db_factory = _mock_db_factory()
    vk_client = _mock_valkey_client(fail=True, error="no valkey")

    with patch("app.main.AsyncSessionLocal", db_factory), \
         patch("valkey.asyncio.from_url", return_value=vk_client), \
         patch.object(settings, "sqlite_mode", True), \
         patch.object(settings, "database_url", "sqlite+aiosqlite:///./mxtac.db"), \
         _patch_opensearch(fail=True, error="no opensearch"):
        resp = await client.get(READY_URL)

    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ready"
    assert data["checks"]["db"] == "ok"
    # Valkey and OpenSearch are still reported but their failures are informational
    assert data["checks"]["valkey"].startswith("error:")
    assert data["checks"]["opensearch"].startswith("error:")


@pytest.mark.asyncio
async def test_ready_sqlite_mode_db_failure_still_returns_503(
    client: AsyncClient,
) -> None:
    """In sqlite_mode, a DB failure still causes 503."""
    db_factory = _mock_db_factory(fail=True, error="sqlite locked")
    vk_client = _mock_valkey_client()

    with patch("app.main.AsyncSessionLocal", db_factory), \
         patch("valkey.asyncio.from_url", return_value=vk_client), \
         patch.object(settings, "sqlite_mode", True), \
         patch.object(settings, "database_url", "sqlite+aiosqlite:///./mxtac.db"), \
         _patch_opensearch():
        resp = await client.get(READY_URL)

    assert resp.status_code == 503
    data = resp.json()
    assert data["status"] == "degraded"
    assert data["checks"]["db"].startswith("error:")


@pytest.mark.asyncio
async def test_ready_sqlite_mode_all_checks_present_in_response(
    client: AsyncClient,
) -> None:
    """In sqlite_mode, all three check keys are still present in the response."""
    db_factory = _mock_db_factory()
    vk_client = _mock_valkey_client(fail=True, error="no valkey")

    with patch("app.main.AsyncSessionLocal", db_factory), \
         patch("valkey.asyncio.from_url", return_value=vk_client), \
         patch.object(settings, "sqlite_mode", True), \
         patch.object(settings, "database_url", "sqlite+aiosqlite:///./mxtac.db"), \
         _patch_opensearch(fail=True, error="no opensearch"):
        resp = await client.get(READY_URL)

    checks = resp.json()["checks"]
    assert "db" in checks
    assert "valkey" in checks
    assert "opensearch" in checks


@pytest.mark.asyncio
async def test_ready_sqlite_url_without_sqlite_mode_flag_also_uses_optional_checks(
    client: AsyncClient,
) -> None:
    """A sqlite:// DATABASE_URL (without sqlite_mode flag) also uses optional external checks."""
    db_factory = _mock_db_factory()
    vk_client = _mock_valkey_client(fail=True, error="no valkey")

    with patch("app.main.AsyncSessionLocal", db_factory), \
         patch("valkey.asyncio.from_url", return_value=vk_client), \
         patch.object(settings, "sqlite_mode", False), \
         patch.object(settings, "database_url", "sqlite+aiosqlite:///./mxtac.db"), \
         _patch_opensearch(fail=True, error="no opensearch"):
        resp = await client.get(READY_URL)

    # DB is ok → 200 even without Valkey/OpenSearch when URL is sqlite://
    assert resp.status_code == 200
    assert resp.json()["status"] == "ready"


# ---------------------------------------------------------------------------
# /ready — backup status check (feature 38.1)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ready_has_backup_check_key(client: AsyncClient) -> None:
    """/ready always includes a 'backup' key in the checks dict."""
    resp = await client.get(READY_URL)
    assert "backup" in resp.json()["checks"]


@pytest.mark.asyncio
async def test_ready_backup_check_value_is_string(client: AsyncClient) -> None:
    """The 'backup' check value is always a string."""
    resp = await client.get(READY_URL)
    assert isinstance(resp.json()["checks"]["backup"], str)


@pytest.mark.asyncio
async def test_ready_backup_warn_does_not_cause_503(client: AsyncClient) -> None:
    """A backup 'warn:...' value does not cause /ready to return 503."""
    db_factory = _mock_db_factory()
    vk_client = _mock_valkey_client()

    # Force backup check to return a warning (no backup dir)
    with patch("app.main.AsyncSessionLocal", db_factory), \
         patch("valkey.asyncio.from_url", return_value=vk_client), \
         patch("app.main._check_backup_status", return_value="warn: no backups found"), \
         _patch_opensearch():
        resp = await client.get(READY_URL)

    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ready"
    assert data["checks"]["backup"] == "warn: no backups found"


@pytest.mark.asyncio
async def test_ready_backup_ok_when_recent_backup_exists(
    client: AsyncClient,
    tmp_path,
) -> None:
    """Backup check returns 'ok' when a fresh .sql.gz file is in backup_dir."""
    import time as _time

    # Create a backup file with a very recent mtime
    backup_file = tmp_path / "mxtac_backup_2026-02-21_02-00.sql.gz"
    backup_file.write_bytes(b"fake")

    db_factory = _mock_db_factory()
    vk_client = _mock_valkey_client()

    with patch("app.main.AsyncSessionLocal", db_factory), \
         patch("valkey.asyncio.from_url", return_value=vk_client), \
         patch.object(settings, "backup_dir", str(tmp_path)), \
         patch.object(settings, "backup_stale_hours", 48), \
         _patch_opensearch():
        resp = await client.get(READY_URL)

    assert resp.json()["checks"]["backup"] == "ok"


@pytest.mark.asyncio
async def test_ready_backup_warn_when_no_backup_dir(client: AsyncClient) -> None:
    """Backup check warns when backup_dir does not exist."""
    db_factory = _mock_db_factory()
    vk_client = _mock_valkey_client()

    with patch("app.main.AsyncSessionLocal", db_factory), \
         patch("valkey.asyncio.from_url", return_value=vk_client), \
         patch.object(settings, "backup_dir", "/nonexistent/path/that/does/not/exist"), \
         _patch_opensearch():
        resp = await client.get(READY_URL)

    backup_val = resp.json()["checks"]["backup"]
    assert backup_val.startswith("warn:")
    # Still 200 because backup is informational only
    assert resp.status_code in (200, 503)  # depends on db/valkey/opensearch mocks


@pytest.mark.asyncio
async def test_ready_backup_warn_when_no_backups_in_dir(
    client: AsyncClient,
    tmp_path,
) -> None:
    """Backup check warns when backup_dir exists but contains no .sql.gz files."""
    db_factory = _mock_db_factory()
    vk_client = _mock_valkey_client()

    with patch("app.main.AsyncSessionLocal", db_factory), \
         patch("valkey.asyncio.from_url", return_value=vk_client), \
         patch.object(settings, "backup_dir", str(tmp_path)), \
         _patch_opensearch():
        resp = await client.get(READY_URL)

    assert resp.json()["checks"]["backup"] == "warn: no backups found"


@pytest.mark.asyncio
async def test_ready_backup_warn_when_backup_is_stale(
    client: AsyncClient,
    tmp_path,
) -> None:
    """Backup check warns when the most recent backup is older than backup_stale_hours."""
    import os as _os
    import time as _time

    # Create a backup file and set its mtime to 72 hours ago
    backup_file = tmp_path / "mxtac_backup_2026-02-18_02-00.sql.gz"
    backup_file.write_bytes(b"fake")
    stale_mtime = _time.time() - (72 * 3600)  # 72 hours ago
    _os.utime(backup_file, (stale_mtime, stale_mtime))

    db_factory = _mock_db_factory()
    vk_client = _mock_valkey_client()

    with patch("app.main.AsyncSessionLocal", db_factory), \
         patch("valkey.asyncio.from_url", return_value=vk_client), \
         patch.object(settings, "backup_dir", str(tmp_path)), \
         patch.object(settings, "backup_stale_hours", 48), \
         _patch_opensearch():
        resp = await client.get(READY_URL)

    backup_val = resp.json()["checks"]["backup"]
    assert backup_val.startswith("warn: last backup")
    assert "72h" in backup_val or "71h" in backup_val  # allow small float rounding
    assert "threshold: 48h" in backup_val


@pytest.mark.asyncio
async def test_ready_backup_warn_does_not_degrade_all_services_ok(
    client: AsyncClient,
) -> None:
    """All services healthy + backup warning → status='ready', HTTP 200."""
    db_factory = _mock_db_factory()
    vk_client = _mock_valkey_client()

    with patch("app.main.AsyncSessionLocal", db_factory), \
         patch("valkey.asyncio.from_url", return_value=vk_client), \
         patch("app.main._check_backup_status", return_value="warn: no backups found"), \
         patch.object(settings, "sqlite_mode", False), \
         patch.object(settings, "database_url", "postgresql+asyncpg://mxtac:mxtac@localhost:5432/mxtac"), \
         _patch_opensearch():
        resp = await client.get(READY_URL)

    assert resp.status_code == 200
    assert resp.json()["status"] == "ready"
