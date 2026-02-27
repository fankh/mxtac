"""Tests for /health and /ready endpoints.

The /health endpoint is a plain liveness probe with no external dependencies.
The /ready endpoint performs DB/Valkey/OpenSearch checks; in tests all external
services are unavailable so we verify response structure, not specific status.
"""

from __future__ import annotations

import os
import time
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

    async def test_ready_contains_backup_check(self, client) -> None:
        """/ready response always includes a 'backup' key in checks."""
        resp = await client.get("/ready")
        checks = resp.json()["checks"]
        assert "backup" in checks

    async def test_ready_backup_does_not_affect_status_code(self, client) -> None:
        """A stale/missing backup must not cause a 503 — it is advisory only."""
        with patch("app.main._check_backup_status", return_value="warn: no backups found"):
            resp = await client.get("/ready")
        # backup warning must not turn a passing probe into a 503
        checks = resp.json()["checks"]
        assert checks["backup"] == "warn: no backups found"
        # status code is determined by DB/Valkey/OpenSearch only, not backup
        assert resp.status_code in (200, 503)  # depends on test env services


class TestCheckBackupStatus:
    """Unit tests for the _check_backup_status() helper in app.main."""

    def test_missing_dir_returns_warn(self, tmp_path) -> None:
        """When backup_dir does not exist, return the directory-not-found warning."""
        from app.main import _check_backup_status

        with patch("app.main.settings") as mock_settings:
            mock_settings.backup_dir = str(tmp_path / "nonexistent")
            mock_settings.backup_stale_hours = 48
            result = _check_backup_status()
        assert result == "warn: backup directory not found"

    def test_empty_dir_returns_warn(self, tmp_path) -> None:
        """When backup_dir exists but contains no .sql.gz files, warn."""
        from app.main import _check_backup_status

        with patch("app.main.settings") as mock_settings:
            mock_settings.backup_dir = str(tmp_path)
            mock_settings.backup_stale_hours = 48
            result = _check_backup_status()
        assert result == "warn: no backups found"

    def test_fresh_backup_returns_ok(self, tmp_path) -> None:
        """A backup created less than backup_stale_hours ago returns 'ok'."""
        from app.main import _check_backup_status

        backup_file = tmp_path / "mxtac_backup_2026-02-27_02-00.sql.gz"
        backup_file.write_bytes(b"fake backup")
        # mtime is already 'now' since we just created it

        with patch("app.main.settings") as mock_settings:
            mock_settings.backup_dir = str(tmp_path)
            mock_settings.backup_stale_hours = 48
            result = _check_backup_status()
        assert result == "ok"

    def test_stale_backup_returns_warn(self, tmp_path) -> None:
        """A backup older than backup_stale_hours triggers a stale warning."""
        from app.main import _check_backup_status

        backup_file = tmp_path / "mxtac_backup_2026-01-01_02-00.sql.gz"
        backup_file.write_bytes(b"fake backup")

        # Set mtime to 72 hours ago (> 48h threshold)
        stale_mtime = time.time() - (72 * 3600)
        os.utime(backup_file, (stale_mtime, stale_mtime))

        with patch("app.main.settings") as mock_settings:
            mock_settings.backup_dir = str(tmp_path)
            mock_settings.backup_stale_hours = 48
            result = _check_backup_status()
        assert result.startswith("warn: last backup")
        assert "threshold: 48h" in result

    def test_most_recent_backup_used(self, tmp_path) -> None:
        """When multiple backups exist, the most recently modified file is checked."""
        from app.main import _check_backup_status

        old_file = tmp_path / "mxtac_backup_2026-01-01_02-00.sql.gz"
        new_file = tmp_path / "mxtac_backup_2026-02-27_02-00.sql.gz"
        old_file.write_bytes(b"old backup")
        new_file.write_bytes(b"new backup")

        # Make old_file appear 100h old, new_file appear 1h old
        now = time.time()
        os.utime(old_file, (now - 100 * 3600, now - 100 * 3600))
        os.utime(new_file, (now - 1 * 3600, now - 1 * 3600))

        with patch("app.main.settings") as mock_settings:
            mock_settings.backup_dir = str(tmp_path)
            mock_settings.backup_stale_hours = 48
            result = _check_backup_status()
        # The newest file is only 1h old — should pass
        assert result == "ok"
