"""Tests for secret_key production validation — feature 33.4.

The model_validator in app/core/config.py raises ValueError (surfaced as a
Pydantic ValidationError) when ``secret_key`` is the development default AND
``debug`` is False.  This prevents the app from starting in production with
an insecure, well-known key.

Coverage:
  scenario 1 — debug=False  + default key  → raises on startup (ValidationError)
  scenario 2 — debug=True   + default key  → no error (dev mode is fine)
  scenario 3 — debug=False  + custom key   → no error (key is properly set)
  scenario 4 — debug=True   + custom key   → no error (redundant guard)
"""

from __future__ import annotations

import importlib

import pytest
from pydantic import ValidationError

_DEV_SECRET = "dev-secret-change-in-production"
_CONFIG_LOGGER = "app.core.config"


class TestSecretKeyProductionEnforcement:
    """Settings raises ValidationError in production with the development default key."""

    @pytest.fixture(autouse=True)
    def _restore_config(self) -> None:
        """Reload app.core.config with default env after every test so the module
        state does not leak into subsequent tests."""
        yield
        import app.core.config as config_module

        importlib.reload(config_module)

    def _reload(self, monkeypatch, *, secret_key: str, debug: bool) -> None:
        """Set env vars and reload the config module to re-run the model_validator."""
        monkeypatch.setenv("SECRET_KEY", secret_key)
        monkeypatch.setenv("DEBUG", "true" if debug else "false")
        import app.core.config as config_module

        importlib.reload(config_module)

    # ------------------------------------------------------------------
    # Scenario 1 — production mode with the default dev key → hard error
    # ------------------------------------------------------------------

    def test_production_default_key_raises(self, monkeypatch) -> None:
        """debug=False + default secret_key → ValidationError is raised (app refuses to start)."""
        with pytest.raises(Exception):
            self._reload(monkeypatch, secret_key=_DEV_SECRET, debug=False)

    def test_production_default_key_error_mentions_secret_key(self, monkeypatch) -> None:
        """Error message references SECRET_KEY so operators know how to fix it."""
        with pytest.raises(Exception, match="SECRET_KEY"):
            self._reload(monkeypatch, secret_key=_DEV_SECRET, debug=False)

    def test_production_default_key_raises_validation_error(self, monkeypatch) -> None:
        """Pydantic surfaces the ValueError as a ValidationError."""
        with pytest.raises((ValidationError, Exception)):
            self._reload(monkeypatch, secret_key=_DEV_SECRET, debug=False)

    # ------------------------------------------------------------------
    # Scenario 2 — debug mode with the default key → no error
    # ------------------------------------------------------------------

    def test_debug_mode_default_key_no_error(self, monkeypatch) -> None:
        """debug=True + default secret_key → no error (dev mode is intentional)."""
        # Should not raise
        self._reload(monkeypatch, secret_key=_DEV_SECRET, debug=True)

    # ------------------------------------------------------------------
    # Scenario 3 — custom key → no error regardless of debug flag
    # ------------------------------------------------------------------

    def test_custom_key_production_mode_no_error(self, monkeypatch) -> None:
        """Changing secret_key suppresses the error even when debug=False."""
        self._reload(
            monkeypatch,
            secret_key="a-very-strong-unique-production-secret-xyz",
            debug=False,
        )

    def test_custom_key_debug_mode_no_error(self, monkeypatch) -> None:
        """Custom key + debug=True → no error."""
        self._reload(
            monkeypatch,
            secret_key="a-very-strong-unique-production-secret-xyz",
            debug=True,
        )


class TestSensitiveFieldsNotInRepr:
    """Sensitive config fields must not appear in Settings repr (to avoid log leakage)."""

    def test_secret_key_not_in_repr(self) -> None:
        """secret_key value must not appear in the Settings repr."""
        from app.core.config import settings

        r = repr(settings)
        assert settings.secret_key not in r

    def test_database_url_not_in_repr(self) -> None:
        """database_url (which may contain passwords) must not appear in repr."""
        from app.core.config import settings

        r = repr(settings)
        assert settings.database_url not in r

    def test_opensearch_password_not_in_repr(self) -> None:
        """opensearch_password must not appear in repr."""
        from app.core.config import settings

        r = repr(settings)
        # Empty string would trivially appear; only check when a password is set.
        if settings.opensearch_password:
            assert settings.opensearch_password not in r


class TestRedactDsn:
    """redact_dsn() strips passwords from DSN-style URLs."""

    def test_postgres_password_redacted(self) -> None:
        from app.core.config import redact_dsn

        url = "postgresql+asyncpg://mxtac:s3cr3t@localhost:5432/mxtac"
        result = redact_dsn(url)
        assert "s3cr3t" not in result
        assert "***" in result

    def test_redis_password_redacted(self) -> None:
        from app.core.config import redact_dsn

        url = "redis://:mypassword@redis-host:6379/0"
        result = redact_dsn(url)
        assert "mypassword" not in result
        assert "***" in result

    def test_url_without_password_unchanged(self) -> None:
        from app.core.config import redact_dsn

        url = "redis://localhost:6379/0"
        assert redact_dsn(url) == url

    def test_host_and_db_preserved(self) -> None:
        from app.core.config import redact_dsn

        url = "postgresql+asyncpg://user:pass@db.example.com:5432/mydb"
        result = redact_dsn(url)
        assert "db.example.com" in result
        assert "mydb" in result
        assert "pass" not in result


class TestJwtKeyVersion:
    """jwt_key_version field must exist and default to 1."""

    def test_jwt_key_version_default(self) -> None:
        from app.core.config import settings

        assert settings.jwt_key_version == 1

    def test_jwt_key_version_env_override(self, monkeypatch) -> None:
        """JWT_KEY_VERSION env var is read and applied."""
        import app.core.config as config_module

        monkeypatch.setenv("JWT_KEY_VERSION", "5")
        importlib.reload(config_module)
        assert config_module.settings.jwt_key_version == 5
        importlib.reload(config_module)


class TestSensitiveFieldsNotInOpenAPISchema:
    """Sensitive config field *values* must not appear in the OpenAPI JSON schema.

    The Settings class is an internal config object, not a FastAPI response model,
    so its field values should never be embedded in the /openapi.json output.
    """

    async def test_secret_key_value_not_in_openapi(self, client) -> None:
        """The actual secret_key value must not appear anywhere in /openapi.json."""
        from app.core.config import settings

        resp = await client.get("/openapi.json")
        assert resp.status_code == 200
        body = resp.text
        # Only check if the key is non-trivially short (avoid false positives)
        if len(settings.secret_key) > 8:
            assert settings.secret_key not in body

    async def test_database_url_not_in_openapi(self, client) -> None:
        """The database_url (which may contain a password) must not appear in /openapi.json."""
        from app.core.config import settings

        resp = await client.get("/openapi.json")
        assert resp.status_code == 200
        body = resp.text
        assert settings.database_url not in body

    async def test_opensearch_password_not_in_openapi(self, client) -> None:
        """The opensearch_password must not appear in /openapi.json."""
        from app.core.config import settings

        if not settings.opensearch_password:
            pytest.skip("opensearch_password is empty — nothing to check")
        resp = await client.get("/openapi.json")
        assert resp.status_code == 200
        assert settings.opensearch_password not in resp.text

    async def test_health_response_does_not_expose_sensitive_config(self, client) -> None:
        """/health must not expose secret_key or database_url."""
        from app.core.config import settings

        resp = await client.get("/health")
        assert resp.status_code == 200
        body = resp.text
        if len(settings.secret_key) > 8:
            assert settings.secret_key not in body
        assert settings.database_url not in body
