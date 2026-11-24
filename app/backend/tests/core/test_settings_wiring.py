"""Settings that used to have no effect are wired up or gone."""

from __future__ import annotations

import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.core import rate_limit
from app.core.config import Settings
from app.services.audit import AuditLogger
from app.services.opensearch_client import OpenSearchService

# ── RATE_LIMIT_PER_MINUTE ────────────────────────────────────────────────────


def test_read_limit_is_the_configured_value() -> None:
    assert rate_limit._LIMITS["read"] == rate_limit.settings.rate_limit_per_minute
    assert rate_limit._classify("GET", "/api/v1/detections") == (
        "read", rate_limit.settings.rate_limit_per_minute,
    )


def test_other_groups_keep_their_fixed_limits() -> None:
    assert rate_limit._classify("POST", "/api/v1/auth/login") == ("auth", 10)
    assert rate_limit._classify("POST", "/api/v1/rules") == ("write", 60)
    assert rate_limit._classify("GET", "/api/v1/events/export") == ("export", 5)


# ── OPENSEARCH_USERNAME / OPENSEARCH_PASSWORD ────────────────────────────────


def test_http_auth_is_none_without_username() -> None:
    assert Settings(opensearch_username="", opensearch_password="ignored").opensearch_http_auth is None


def test_http_auth_is_username_and_password() -> None:
    settings = Settings(opensearch_username="mxtac", opensearch_password="s3cret")
    assert settings.opensearch_http_auth == ("mxtac", "s3cret")


def _opensearch_module() -> MagicMock:
    module = MagicMock()
    module.AsyncOpenSearch.return_value = AsyncMock()
    return module


@pytest.mark.parametrize("http_auth", [("mxtac", "s3cret"), None])
async def test_event_client_passes_credentials(http_auth: tuple[str, str] | None) -> None:
    module = _opensearch_module()
    with (
        patch.dict(sys.modules, {"opensearchpy": module}),
        patch("app.services.opensearch_client.settings") as settings,
    ):
        settings.opensearch_url = "https://search.internal:9200"
        settings.opensearch_http_auth = http_auth
        await OpenSearchService().connect()

    assert module.AsyncOpenSearch.call_args.kwargs["http_auth"] == http_auth


async def test_audit_client_passes_credentials() -> None:
    module = _opensearch_module()
    with (
        patch.dict(sys.modules, {"opensearchpy": module}),
        patch("app.services.audit.settings") as settings,
    ):
        settings.opensearch_url = "https://search.internal:9200"
        settings.opensearch_http_auth = ("mxtac", "s3cret")
        await AuditLogger()._ensure_client()

    assert module.AsyncOpenSearch.call_args.kwargs["http_auth"] == ("mxtac", "s3cret")


# ── Kafka backend removed ────────────────────────────────────────────────────


def test_kafka_settings_are_gone() -> None:
    fields = Settings.model_fields
    assert "kafka_bootstrap_servers" not in fields
    assert "kafka_consumer_group" not in fields
    assert Settings().queue_backend == "memory"
