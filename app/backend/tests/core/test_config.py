"""Tests for secret_key production validation warning — feature 30.3.

The module-level block in app/core/config.py emits a SECURITY WARNING when
``secret_key`` is the development default AND ``debug`` is False.

Coverage:
  scenario 1 — debug=False  + default key  → SECURITY WARNING is logged
  scenario 2 — debug=True   + default key  → no warning (dev mode is fine)
  scenario 3 — debug=False  + custom key   → no warning regardless of debug mode
"""

from __future__ import annotations

import importlib
import logging

import pytest

_DEV_SECRET = "dev-secret-change-in-production"
_CONFIG_LOGGER = "app.core.config"


class TestSecretKeyProductionWarning:
    """Module-level warning fires only when debug=False with the default dev secret."""

    @pytest.fixture(autouse=True)
    def _restore_config(self) -> None:
        """Reload app.core.config with default env after every test so the module
        state does not leak into subsequent tests."""
        yield
        import app.core.config as config_module

        importlib.reload(config_module)

    def _reload(self, monkeypatch, *, secret_key: str, debug: bool) -> None:
        """Set env vars and reload the config module to re-run the module-level check."""
        monkeypatch.setenv("SECRET_KEY", secret_key)
        monkeypatch.setenv("DEBUG", "true" if debug else "false")
        import app.core.config as config_module

        importlib.reload(config_module)

    # ------------------------------------------------------------------
    # Scenario 1 — production mode with the default dev key → warning
    # ------------------------------------------------------------------

    def test_production_default_key_logs_warning(self, monkeypatch, caplog) -> None:
        """debug=False + default secret_key → SECURITY WARNING is logged."""
        with caplog.at_level(logging.WARNING, logger=_CONFIG_LOGGER):
            self._reload(monkeypatch, secret_key=_DEV_SECRET, debug=False)
        assert "SECURITY WARNING" in caplog.text

    def test_production_default_key_warning_message_mentions_secret_key(
        self, monkeypatch, caplog
    ) -> None:
        """Warning message explicitly references SECRET_KEY so operators know how to fix it."""
        with caplog.at_level(logging.WARNING, logger=_CONFIG_LOGGER):
            self._reload(monkeypatch, secret_key=_DEV_SECRET, debug=False)
        assert "SECRET_KEY" in caplog.text

    # ------------------------------------------------------------------
    # Scenario 2 — debug mode with the default key → no warning
    # ------------------------------------------------------------------

    def test_debug_mode_default_key_no_warning(self, monkeypatch, caplog) -> None:
        """debug=True + default secret_key → no warning (dev mode is intentional)."""
        with caplog.at_level(logging.WARNING, logger=_CONFIG_LOGGER):
            self._reload(monkeypatch, secret_key=_DEV_SECRET, debug=True)
        assert "SECURITY WARNING" not in caplog.text

    # ------------------------------------------------------------------
    # Scenario 3 — custom key → no warning regardless of debug flag
    # ------------------------------------------------------------------

    def test_custom_key_production_mode_no_warning(self, monkeypatch, caplog) -> None:
        """Changing secret_key suppresses the warning even when debug=False."""
        with caplog.at_level(logging.WARNING, logger=_CONFIG_LOGGER):
            self._reload(
                monkeypatch,
                secret_key="a-very-strong-unique-production-secret-xyz",
                debug=False,
            )
        assert "SECURITY WARNING" not in caplog.text

    def test_custom_key_debug_mode_no_warning(self, monkeypatch, caplog) -> None:
        """Custom key + debug=True → no warning (redundant guard, confirms no false positives)."""
        with caplog.at_level(logging.WARNING, logger=_CONFIG_LOGGER):
            self._reload(
                monkeypatch,
                secret_key="a-very-strong-unique-production-secret-xyz",
                debug=True,
            )
        assert "SECURITY WARNING" not in caplog.text
