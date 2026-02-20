"""Tests for app/db/migrate.py — feature 20.8 SQLite single-binary auto-migration.

Coverage:
  - auto_migrate() calls alembic upgrade head via a thread executor
  - auto_migrate() succeeds silently (returns None) on success
  - auto_migrate() logs INFO on success
  - auto_migrate() swallows exceptions and logs ERROR on failure (does not raise)
  - _run_alembic_upgrade() delegates to alembic.command.upgrade with correct args
  - _ALEMBIC_INI path resolves to the backend/alembic.ini file
"""

from __future__ import annotations

import logging
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.db.migrate import _ALEMBIC_INI, _run_alembic_upgrade, auto_migrate


# ---------------------------------------------------------------------------
# _ALEMBIC_INI path
# ---------------------------------------------------------------------------


class TestAlembicIniPath:
    def test_alembic_ini_path_is_absolute(self) -> None:
        assert _ALEMBIC_INI.is_absolute()

    def test_alembic_ini_path_ends_with_alembic_ini(self) -> None:
        assert _ALEMBIC_INI.name == "alembic.ini"

    def test_alembic_ini_file_exists(self) -> None:
        assert _ALEMBIC_INI.exists(), (
            f"alembic.ini not found at expected path: {_ALEMBIC_INI}"
        )

    def test_alembic_ini_is_in_backend_dir(self) -> None:
        """alembic.ini is expected in the backend/ directory."""
        assert _ALEMBIC_INI.parent.name == "backend"


# ---------------------------------------------------------------------------
# _run_alembic_upgrade
# ---------------------------------------------------------------------------


class TestRunAlembicUpgrade:
    def test_calls_alembic_command_upgrade_head(self) -> None:
        """_run_alembic_upgrade passes 'head' as the revision target.

        The imports are local to the function, so patch the underlying
        alembic.command.upgrade and alembic.config.Config directly.
        """
        with patch("alembic.command.upgrade") as mock_upgrade, \
             patch("alembic.config.Config") as mock_cfg_cls:
            mock_cfg_inst = MagicMock()
            mock_cfg_cls.return_value = mock_cfg_inst
            _run_alembic_upgrade()

        mock_upgrade.assert_called_once_with(mock_cfg_inst, "head")

    def test_creates_config_from_alembic_ini_path(self) -> None:
        """_run_alembic_upgrade passes the full _ALEMBIC_INI path to Config."""
        with patch("alembic.command.upgrade"), \
             patch("alembic.config.Config") as mock_cfg_cls:
            mock_cfg_cls.return_value = MagicMock()
            _run_alembic_upgrade()

        args, _ = mock_cfg_cls.call_args
        assert args[0] == str(_ALEMBIC_INI)


# ---------------------------------------------------------------------------
# auto_migrate — success path
# ---------------------------------------------------------------------------


class TestAutoMigrateSuccess:
    async def test_returns_none_on_success(self) -> None:
        """auto_migrate() returns None when migration succeeds."""
        with patch("app.db.migrate._run_alembic_upgrade"):
            result = await auto_migrate()
        assert result is None

    async def test_logs_info_start_message(self, caplog) -> None:
        """auto_migrate() logs an INFO message before starting the migration."""
        with caplog.at_level(logging.INFO, logger="app.db.migrate"), \
             patch("app.db.migrate._run_alembic_upgrade"):
            await auto_migrate()
        assert any("auto-migration" in msg.lower() for msg in caplog.messages)

    async def test_logs_info_complete_message(self, caplog) -> None:
        """auto_migrate() logs an INFO message after successful completion."""
        with caplog.at_level(logging.INFO, logger="app.db.migrate"), \
             patch("app.db.migrate._run_alembic_upgrade"):
            await auto_migrate()
        assert any("complete" in msg.lower() for msg in caplog.messages)

    async def test_executor_runs_upgrade_function(self) -> None:
        """auto_migrate() executes _run_alembic_upgrade in a thread pool."""
        call_log: list[str] = []

        def _record_call() -> None:
            call_log.append("called")

        with patch("app.db.migrate._run_alembic_upgrade", side_effect=_record_call):
            await auto_migrate()

        assert call_log == ["called"]


# ---------------------------------------------------------------------------
# auto_migrate — failure path (exceptions must not propagate)
# ---------------------------------------------------------------------------


class TestAutoMigrateFailure:
    async def test_does_not_raise_on_exception(self) -> None:
        """auto_migrate() swallows exceptions — startup continues on failure."""
        with patch("app.db.migrate._run_alembic_upgrade",
                   side_effect=RuntimeError("migration failed")):
            # Should NOT raise
            await auto_migrate()

    async def test_logs_error_on_exception(self, caplog) -> None:
        """auto_migrate() logs an ERROR when the migration raises."""
        with caplog.at_level(logging.ERROR, logger="app.db.migrate"), \
             patch("app.db.migrate._run_alembic_upgrade",
                   side_effect=RuntimeError("migration failed")):
            await auto_migrate()
        assert any(r.levelno == logging.ERROR for r in caplog.records)

    async def test_returns_none_on_exception(self) -> None:
        """auto_migrate() returns None even when the migration fails."""
        with patch("app.db.migrate._run_alembic_upgrade",
                   side_effect=Exception("boom")):
            result = await auto_migrate()
        assert result is None
