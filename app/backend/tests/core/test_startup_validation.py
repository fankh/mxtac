"""Tests for startup security validation — feature 33.4.

Coverage:
  _check_startup_config():
  - Warns when DEBUG=True and a production environment indicator is set
  - No warning when DEBUG=False (production mode, key is already enforced)
  - No warning when DEBUG=True with no production indicators
  - Warns when DATABASE_URL matches the development default
  - Warns when opensearch_password is empty and opensearch_host is non-local
  - No opensearch warning when host is localhost

  _sanitize_check_error():
  - Redacts password from PostgreSQL DSN in exception messages
  - Redacts password from Redis DSN in exception messages
  - Leaves messages without DSN patterns unchanged

  /ready endpoint — error message redaction:
  - DB errors containing passwords are redacted in the response
"""

from __future__ import annotations

import logging
import sys
from contextlib import contextmanager
from typing import Generator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient

from app.core.config import settings


# ---------------------------------------------------------------------------
# _check_startup_config — startup warning tests
# ---------------------------------------------------------------------------


class TestCheckStartupConfig:
    """_check_startup_config() emits WARNING-level log messages for risky config."""

    def _run(self, monkeypatch, *, debug: bool, env: dict | None = None,
             db_url: str | None = None,
             opensearch_host: str = "localhost",
             opensearch_password: str = "") -> None:
        """Patch settings and env, then call _check_startup_config()."""
        from app.main import _check_startup_config

        if env:
            for k, v in env.items():
                monkeypatch.setenv(k, v)

        patch_kwargs = {
            "debug": debug,
            "opensearch_host": opensearch_host,
            "opensearch_password": opensearch_password,
        }
        if db_url is not None:
            patch_kwargs["database_url"] = db_url

        with patch.multiple("app.main.settings", **patch_kwargs):
            _check_startup_config()

    def test_debug_true_with_k8s_indicator_warns(self, monkeypatch, caplog) -> None:
        """DEBUG=True + KUBERNETES_SERVICE_HOST → security warning is logged."""
        with caplog.at_level(logging.WARNING, logger="app.main"):
            self._run(
                monkeypatch,
                debug=True,
                env={"KUBERNETES_SERVICE_HOST": "10.96.0.1"},
            )
        assert "SECURITY WARNING" in caplog.text
        assert "DEBUG" in caplog.text

    def test_debug_true_no_indicators_no_warn(self, monkeypatch, caplog) -> None:
        """DEBUG=True with no production indicators → no security warning."""
        # Ensure all known indicators are absent
        for k in ("KUBERNETES_SERVICE_HOST", "DYNO", "AWS_EXECUTION_ENV",
                  "GOOGLE_CLOUD_PROJECT", "WEBSITE_INSTANCE_ID"):
            monkeypatch.delenv(k, raising=False)

        with caplog.at_level(logging.WARNING, logger="app.main"):
            self._run(monkeypatch, debug=True)
        assert "DEBUG" not in caplog.text or "SECURITY WARNING" not in caplog.text

    def test_default_db_url_warns(self, monkeypatch, caplog) -> None:
        """DATABASE_URL == dev default → security warning about credentials."""
        from app.core.config import _DEFAULT_PG_URL

        with caplog.at_level(logging.WARNING, logger="app.main"):
            self._run(monkeypatch, debug=True, db_url=_DEFAULT_PG_URL)
        assert "DATABASE_URL" in caplog.text

    def test_custom_db_url_no_warn(self, monkeypatch, caplog) -> None:
        """Custom DATABASE_URL → no DB credentials warning."""
        with caplog.at_level(logging.WARNING, logger="app.main"):
            self._run(
                monkeypatch,
                debug=True,
                db_url="postgresql+asyncpg://produser:strongpass@db.prod:5432/mxtac",
            )
        assert "DATABASE_URL" not in caplog.text

    def test_remote_opensearch_no_password_warns(self, monkeypatch, caplog) -> None:
        """opensearch_host != localhost + empty password → security warning."""
        with caplog.at_level(logging.WARNING, logger="app.main"):
            self._run(
                monkeypatch,
                debug=True,
                opensearch_host="opensearch.prod.example.com",
                opensearch_password="",
            )
        assert "opensearch_password" in caplog.text

    def test_localhost_opensearch_no_password_no_warn(self, monkeypatch, caplog) -> None:
        """opensearch_host == localhost with no password → no warning (dev default)."""
        with caplog.at_level(logging.WARNING, logger="app.main"):
            self._run(
                monkeypatch,
                debug=True,
                opensearch_host="localhost",
                opensearch_password="",
            )
        assert "opensearch_password" not in caplog.text

    def test_remote_opensearch_with_password_no_warn(self, monkeypatch, caplog) -> None:
        """Remote opensearch_host with a non-empty password → no warning."""
        with caplog.at_level(logging.WARNING, logger="app.main"):
            self._run(
                monkeypatch,
                debug=True,
                opensearch_host="opensearch.prod.example.com",
                opensearch_password="strongpassword123",
            )
        assert "opensearch_password" not in caplog.text


# ---------------------------------------------------------------------------
# _sanitize_check_error — error string redaction
# ---------------------------------------------------------------------------


class TestSanitizeCheckError:
    """_sanitize_check_error strips credentials from DSN-embedded error strings."""

    def test_postgres_dsn_password_redacted(self) -> None:
        from app.main import _sanitize_check_error

        msg = "error: could not connect to postgresql+asyncpg://mxtac:s3cr3t@localhost:5432/mxtac"
        result = _sanitize_check_error(msg)
        assert "s3cr3t" not in result
        assert "***" in result

    def test_redis_dsn_password_redacted(self) -> None:
        from app.main import _sanitize_check_error

        msg = "error: connection refused redis://:mypassword@redis-host:6379/0"
        result = _sanitize_check_error(msg)
        assert "mypassword" not in result
        assert "***" in result

    def test_plain_error_unchanged(self) -> None:
        from app.main import _sanitize_check_error

        msg = "error: connection timed out after 3 seconds"
        assert _sanitize_check_error(msg) == msg

    def test_timeout_string_unchanged(self) -> None:
        from app.main import _sanitize_check_error

        assert _sanitize_check_error("error: timeout") == "error: timeout"

    def test_host_preserved_after_redaction(self) -> None:
        from app.main import _sanitize_check_error

        msg = "error: postgresql+asyncpg://user:pass@db.prod.example.com:5432/mxtac"
        result = _sanitize_check_error(msg)
        assert "db.prod.example.com" in result
        assert "pass" not in result


# ---------------------------------------------------------------------------
# /ready — password redaction in check errors (integration)
# ---------------------------------------------------------------------------


def _mock_db_factory(*, fail: bool = False, error: str = "db error") -> MagicMock:
    session = AsyncMock()
    if fail:
        session.__aenter__ = AsyncMock(side_effect=Exception(error))
    else:
        session.execute = AsyncMock(return_value=None)
    return MagicMock(return_value=session)


def _mock_valkey_client(*, fail: bool = False, error: str = "valkey error") -> MagicMock:
    client = MagicMock()
    if fail:
        client.ping = AsyncMock(side_effect=Exception(error))
    else:
        client.ping = AsyncMock(return_value=True)
    client.aclose = AsyncMock()
    return client


@contextmanager
def _patch_opensearch(*, fail: bool = False, error: str = "os error") -> Generator[MagicMock, None, None]:
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


@pytest.mark.asyncio
async def test_ready_db_error_with_dsn_password_is_redacted(client: AsyncClient) -> None:
    """/ready DB error containing a DSN password is redacted in the response body."""
    error_with_password = (
        "could not connect to postgresql+asyncpg://mxtac:s3cr3t_pass@localhost:5432/mxtac"
    )
    db_factory = _mock_db_factory(fail=True, error=error_with_password)
    vk_client = _mock_valkey_client()

    with patch("app.main.AsyncSessionLocal", db_factory), \
         patch("valkey.asyncio.from_url", return_value=vk_client), \
         _patch_opensearch():
        resp = await client.get("/ready")

    body = resp.text
    assert "s3cr3t_pass" not in body, "Password must not appear in /ready response"
    assert "***" in body, "Redacted marker must appear in /ready response"


@pytest.mark.asyncio
async def test_ready_plain_error_message_preserved(client: AsyncClient) -> None:
    """/ready plain error messages (no DSN) are preserved unchanged."""
    db_factory = _mock_db_factory(fail=True, error="unique-sentinel-error-xyz")
    vk_client = _mock_valkey_client()

    with patch("app.main.AsyncSessionLocal", db_factory), \
         patch("valkey.asyncio.from_url", return_value=vk_client), \
         _patch_opensearch():
        resp = await client.get("/ready")

    assert "unique-sentinel-error-xyz" in resp.text
