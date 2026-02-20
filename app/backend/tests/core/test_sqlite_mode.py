"""Tests for sqlite_mode configuration — feature 20.8 SQLite single-binary mode.

Coverage:
  - sqlite_mode=False by default
  - sqlite_mode=True auto-sets database_url to sqlite+aiosqlite:///./mxtac.db
  - sqlite_path overrides the SQLite file location
  - An explicit sqlite:// DATABASE_URL is not overridden by sqlite_mode
  - An explicit postgresql:// DATABASE_URL IS overridden when sqlite_mode=True
  - sqlite_mode can be set via environment variable SQLITE_MODE
  - sqlite_path can be set via environment variable SQLITE_PATH
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.core.config import Settings, _DEFAULT_PG_URL


class TestSqliteModeDefault:
    """sqlite_mode defaults to False; database_url defaults to PostgreSQL."""

    def test_sqlite_mode_default_is_false(self) -> None:
        s = Settings()
        assert s.sqlite_mode is False

    def test_database_url_default_is_postgresql(self) -> None:
        s = Settings()
        assert s.database_url.startswith("postgresql")

    def test_sqlite_path_default(self) -> None:
        s = Settings()
        assert s.sqlite_path == "./mxtac.db"


class TestSqliteModeEnabled:
    """When sqlite_mode=True, database_url is auto-switched to SQLite."""

    def test_sqlite_mode_sets_sqlite_database_url(self) -> None:
        s = Settings(sqlite_mode=True)
        assert s.database_url.startswith("sqlite+aiosqlite://")

    def test_sqlite_mode_default_path_is_mxtac_db(self) -> None:
        s = Settings(sqlite_mode=True)
        assert "mxtac.db" in s.database_url

    def test_sqlite_mode_uses_sqlite_path(self) -> None:
        s = Settings(sqlite_mode=True, sqlite_path="/data/myapp.db")
        assert "/data/myapp.db" in s.database_url

    def test_sqlite_mode_url_has_aiosqlite_driver(self) -> None:
        """The URL must use the aiosqlite async driver."""
        s = Settings(sqlite_mode=True)
        assert "aiosqlite" in s.database_url

    def test_sqlite_mode_relative_path(self) -> None:
        s = Settings(sqlite_mode=True, sqlite_path="./custom.db")
        assert "custom.db" in s.database_url

    def test_sqlite_mode_absolute_path(self) -> None:
        s = Settings(sqlite_mode=True, sqlite_path="/var/lib/mxtac/mxtac.db")
        assert "/var/lib/mxtac/mxtac.db" in s.database_url


class TestSqliteModeWithExplicitUrl:
    """Explicit DATABASE_URL values take precedence over sqlite_mode auto-switch."""

    def test_explicit_sqlite_url_not_overridden(self) -> None:
        """If DATABASE_URL already starts with sqlite, it is not modified."""
        explicit = "sqlite+aiosqlite:///custom-explicit.db"
        s = Settings(sqlite_mode=True, database_url=explicit)
        assert s.database_url == explicit

    def test_explicit_postgresql_url_overridden_by_sqlite_mode(self) -> None:
        """When sqlite_mode=True, a PostgreSQL default URL is replaced with SQLite."""
        s = Settings(sqlite_mode=True, database_url=_DEFAULT_PG_URL)
        assert s.database_url.startswith("sqlite")

    def test_explicit_non_default_postgresql_url_overridden(self) -> None:
        """Custom PostgreSQL URLs are also replaced when sqlite_mode=True."""
        custom_pg = "postgresql+asyncpg://user:pass@myhost:5432/mydb"
        s = Settings(sqlite_mode=True, database_url=custom_pg)
        assert s.database_url.startswith("sqlite")

    def test_sqlite_mode_false_does_not_modify_url(self) -> None:
        """sqlite_mode=False never modifies database_url."""
        s = Settings(sqlite_mode=False)
        assert s.database_url == _DEFAULT_PG_URL


class TestSqliteModeEnvVars:
    """sqlite_mode and sqlite_path are configurable via environment variables."""

    def test_sqlite_mode_env_var_true(self, monkeypatch) -> None:
        monkeypatch.setenv("SQLITE_MODE", "true")
        s = Settings()
        assert s.sqlite_mode is True
        assert s.database_url.startswith("sqlite")

    def test_sqlite_mode_env_var_false(self, monkeypatch) -> None:
        monkeypatch.setenv("SQLITE_MODE", "false")
        s = Settings()
        assert s.sqlite_mode is False
        assert s.database_url.startswith("postgresql")

    def test_sqlite_path_env_var(self, monkeypatch) -> None:
        monkeypatch.setenv("SQLITE_MODE", "true")
        monkeypatch.setenv("SQLITE_PATH", "/tmp/test.db")
        s = Settings()
        assert "/tmp/test.db" in s.database_url

    def test_sqlite_mode_env_var_overrides_explicit_database_url(
        self, monkeypatch
    ) -> None:
        """SQLITE_MODE=true via env var overrides a PostgreSQL DATABASE_URL."""
        monkeypatch.setenv("SQLITE_MODE", "true")
        monkeypatch.setenv("DATABASE_URL", _DEFAULT_PG_URL)
        s = Settings()
        assert s.database_url.startswith("sqlite")
