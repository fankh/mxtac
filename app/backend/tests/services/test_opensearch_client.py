"""Unit tests for OpenSearchService and the filter_to_dsl() helper.

All tests mock the underlying opensearch-py client so no real OpenSearch
cluster is required.
"""

from __future__ import annotations

import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.opensearch_client import (
    OpenSearchService,
    filter_to_dsl,
)


# ---------------------------------------------------------------------------
# filter_to_dsl — DSL clause builder
# ---------------------------------------------------------------------------


def test_filter_to_dsl_eq() -> None:
    clause = filter_to_dsl("severity_id", "eq", 4)
    assert clause == {"term": {"severity_id": 4}}


def test_filter_to_dsl_ne() -> None:
    clause = filter_to_dsl("class_name", "ne", "Network Activity")
    assert clause == {"bool": {"must_not": [{"term": {"class_name": "Network Activity"}}]}}


def test_filter_to_dsl_contains() -> None:
    clause = filter_to_dsl("hostname", "contains", "dc-")
    # hostname maps to src_endpoint.hostname in OS
    assert clause == {"wildcard": {"src_endpoint.hostname": "*dc-*"}}


def test_filter_to_dsl_gt() -> None:
    clause = filter_to_dsl("severity_id", "gt", 3)
    assert clause == {"range": {"severity_id": {"gt": 3}}}


def test_filter_to_dsl_lt() -> None:
    clause = filter_to_dsl("severity_id", "lt", 5)
    assert clause == {"range": {"severity_id": {"lt": 5}}}


def test_filter_to_dsl_gte() -> None:
    clause = filter_to_dsl("severity_id", "gte", 3)
    assert clause == {"range": {"severity_id": {"gte": 3}}}


def test_filter_to_dsl_lte() -> None:
    clause = filter_to_dsl("severity_id", "lte", 4)
    assert clause == {"range": {"severity_id": {"lte": 4}}}


def test_filter_to_dsl_flat_alias_src_ip() -> None:
    """Flat column alias 'src_ip' maps to nested 'src_endpoint.ip'."""
    clause = filter_to_dsl("src_ip", "eq", "192.168.1.1")
    assert clause == {"term": {"src_endpoint.ip": "192.168.1.1"}}


def test_filter_to_dsl_nested_path_passthrough() -> None:
    """Nested OpenSearch paths pass through unchanged."""
    clause = filter_to_dsl("actor_user.name", "eq", "admin")
    assert clause == {"term": {"actor_user.name": "admin"}}


def test_filter_to_dsl_unknown_field_returns_none() -> None:
    """Unknown fields return None so callers can skip them."""
    clause = filter_to_dsl("nonexistent_field", "eq", "value")
    assert clause is None


def test_filter_to_dsl_unsupported_operator_returns_none() -> None:
    """Unsupported operators return None."""
    clause = filter_to_dsl("severity_id", "fuzzy", 3)
    assert clause is None


# ---------------------------------------------------------------------------
# OpenSearchService.is_available
# ---------------------------------------------------------------------------


def test_is_available_false_when_no_client() -> None:
    svc = OpenSearchService()
    assert svc.is_available is False


def test_is_available_true_when_client_set() -> None:
    svc = OpenSearchService()
    svc._client = MagicMock()  # simulate a connected client
    assert svc.is_available is True


# ---------------------------------------------------------------------------
# OpenSearchService.search_events — client unavailable
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_search_events_returns_empty_when_unavailable() -> None:
    """When _client is None, search_events returns an empty hits dict."""
    svc = OpenSearchService()
    result = await svc.search_events(query="mimikatz")
    assert result == {"hits": {"total": {"value": 0}, "hits": []}}


# ---------------------------------------------------------------------------
# OpenSearchService.search_events — with mocked client
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_search_events_delegates_to_client() -> None:
    """search_events builds a bool/must query and delegates to the OS client."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.search = AsyncMock(return_value={
        "hits": {
            "total": {"value": 2},
            "hits": [
                {"_id": "abc", "_source": {"class_name": "Process Activity"}},
                {"_id": "def", "_source": {"class_name": "Network Activity"}},
            ],
        }
    })
    svc._client = mock_client

    result = await svc.search_events(
        query="mimikatz",
        filters=[{"term": {"severity_id": 4}}],
        time_from="now-1h",
        time_to="now",
        size=10,
        from_=0,
    )

    mock_client.search.assert_called_once()
    call_kwargs = mock_client.search.call_args
    body = call_kwargs.kwargs.get("body") or call_kwargs.args[0]
    must_clauses = body["query"]["bool"]["must"]

    # query_string clause for free-text query
    assert any("query_string" in c for c in must_clauses)
    # structured filter clause
    assert {"term": {"severity_id": 4}} in must_clauses
    # time range clause always added
    assert any("range" in c and "time" in c["range"] for c in must_clauses)

    hits = result["hits"]["hits"]
    assert len(hits) == 2


@pytest.mark.asyncio
async def test_search_events_no_query_no_filters() -> None:
    """Without a query or filters, only the time range clause is included."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.search = AsyncMock(return_value={
        "hits": {"total": {"value": 0}, "hits": []}
    })
    svc._client = mock_client

    await svc.search_events()

    body = mock_client.search.call_args.kwargs.get("body") or mock_client.search.call_args.args[0]
    must_clauses = body["query"]["bool"]["must"]
    # Only the time range clause should be present
    assert len(must_clauses) == 1
    assert "range" in must_clauses[0]


@pytest.mark.asyncio
async def test_search_events_exception_returns_empty() -> None:
    """An exception from the OS client is caught; empty hits dict returned."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.search = AsyncMock(side_effect=Exception("connection refused"))
    svc._client = mock_client

    result = await svc.search_events(query="anything")
    assert result == {"hits": {"total": {"value": 0}, "hits": []}}


# ---------------------------------------------------------------------------
# OpenSearchService.index_event
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_index_event_returns_none_when_unavailable() -> None:
    svc = OpenSearchService()
    result = await svc.index_event({"class_name": "Network Activity"})
    assert result is None


@pytest.mark.asyncio
async def test_index_event_uses_doc_id() -> None:
    """When doc_id is provided it is passed to the OS client as the document id."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.index = AsyncMock(return_value={"_id": "pg-uuid-123"})
    svc._client = mock_client

    result = await svc.index_event({"class_name": "Process Activity"}, doc_id="pg-uuid-123")

    assert result == "pg-uuid-123"
    call_kwargs = mock_client.index.call_args.kwargs
    assert call_kwargs.get("id") == "pg-uuid-123"


@pytest.mark.asyncio
async def test_index_event_exception_returns_none() -> None:
    """index_event catches exceptions and returns None."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.index = AsyncMock(side_effect=Exception("timeout"))
    svc._client = mock_client

    result = await svc.index_event({"class_name": "Network Activity"})
    assert result is None


# ---------------------------------------------------------------------------
# OpenSearchService.connect — feature 12.1
# ---------------------------------------------------------------------------
#
# Helper: build a fake opensearchpy module with a mock AsyncOpenSearch class.
# Injected via patch.dict(sys.modules) so the in-function import resolves to
# our mock without requiring the real package to be installed.


def _make_os_module(instance: MagicMock) -> MagicMock:
    """Return a mock module whose AsyncOpenSearch() returns *instance*."""
    mod = MagicMock()
    mod.AsyncOpenSearch.return_value = instance
    return mod


def _make_os_instance(info_return: dict | None = None, info_exc: Exception | None = None) -> MagicMock:
    """Return a mock AsyncOpenSearch instance with a configured .info() coroutine."""
    inst = MagicMock()
    if info_exc is not None:
        inst.info = AsyncMock(side_effect=info_exc)
    else:
        inst.info = AsyncMock(return_value=info_return or {"version": {"number": "2.11.0"}})
    return inst


@pytest.mark.asyncio
async def test_connect_sets_client_on_success() -> None:
    """connect() assigns _client when the OpenSearch handshake succeeds."""
    svc = OpenSearchService()
    inst = _make_os_instance()
    with patch.dict(sys.modules, {"opensearchpy": _make_os_module(inst)}):
        await svc.connect()

    assert svc._client is inst
    assert svc.is_available is True


@pytest.mark.asyncio
async def test_connect_calls_info_to_verify_connectivity() -> None:
    """connect() calls .info() on the created client to confirm a live cluster."""
    svc = OpenSearchService()
    inst = _make_os_instance()
    with patch.dict(sys.modules, {"opensearchpy": _make_os_module(inst)}):
        await svc.connect()

    inst.info.assert_awaited_once()


@pytest.mark.asyncio
async def test_connect_uses_url_from_settings() -> None:
    """connect() passes settings.opensearch_url as the host list."""
    svc = OpenSearchService()
    inst = _make_os_instance()
    mod = _make_os_module(inst)
    custom_url = "http://opensearch.internal:9200"

    with (
        patch.dict(sys.modules, {"opensearchpy": mod}),
        patch("app.services.opensearch_client.settings") as mock_settings,
    ):
        mock_settings.opensearch_url = custom_url
        await svc.connect()

    call_kwargs = mod.AsyncOpenSearch.call_args.kwargs
    assert call_kwargs["hosts"] == [custom_url]


@pytest.mark.asyncio
async def test_connect_uses_default_url_when_setting_absent() -> None:
    """connect() falls back to http://localhost:9200 when opensearch_url is absent."""
    svc = OpenSearchService()
    inst = _make_os_instance()
    mod = _make_os_module(inst)

    # A settings object without opensearch_url; getattr default kicks in.
    class _NoUrlSettings:
        pass

    with (
        patch.dict(sys.modules, {"opensearchpy": mod}),
        patch("app.services.opensearch_client.settings", _NoUrlSettings()),
    ):
        await svc.connect()

    call_kwargs = mod.AsyncOpenSearch.call_args.kwargs
    assert call_kwargs["hosts"] == ["http://localhost:9200"]


@pytest.mark.asyncio
async def test_connect_http_url_disables_ssl() -> None:
    """HTTP scheme must set use_ssl=False."""
    svc = OpenSearchService()
    inst = _make_os_instance()
    mod = _make_os_module(inst)

    with (
        patch.dict(sys.modules, {"opensearchpy": mod}),
        patch("app.services.opensearch_client.settings") as mock_settings,
    ):
        mock_settings.opensearch_url = "http://localhost:9200"
        await svc.connect()

    assert mod.AsyncOpenSearch.call_args.kwargs["use_ssl"] is False


@pytest.mark.asyncio
async def test_connect_https_url_enables_ssl() -> None:
    """HTTPS scheme must set use_ssl=True."""
    svc = OpenSearchService()
    inst = _make_os_instance()
    mod = _make_os_module(inst)

    with (
        patch.dict(sys.modules, {"opensearchpy": mod}),
        patch("app.services.opensearch_client.settings") as mock_settings,
    ):
        mock_settings.opensearch_url = "https://opensearch.example.com:9200"
        await svc.connect()

    assert mod.AsyncOpenSearch.call_args.kwargs["use_ssl"] is True


@pytest.mark.asyncio
async def test_connect_always_sets_http_compress_and_disables_cert_verification() -> None:
    """connect() always enables http_compress and suppresses certificate errors."""
    svc = OpenSearchService()
    inst = _make_os_instance()
    mod = _make_os_module(inst)

    with (
        patch.dict(sys.modules, {"opensearchpy": mod}),
        patch("app.services.opensearch_client.settings") as mock_settings,
    ):
        mock_settings.opensearch_url = "http://localhost:9200"
        await svc.connect()

    kw = mod.AsyncOpenSearch.call_args.kwargs
    assert kw["http_compress"] is True
    assert kw["verify_certs"] is False
    assert kw["ssl_show_warn"] is False


@pytest.mark.asyncio
async def test_connect_import_error_leaves_client_none() -> None:
    """When opensearch-py is not installed, _client stays None (graceful fallback)."""
    svc = OpenSearchService()

    with patch.dict(sys.modules, {"opensearchpy": None}):
        await svc.connect()

    assert svc._client is None
    assert svc.is_available is False


@pytest.mark.asyncio
async def test_connect_info_exception_leaves_client_none() -> None:
    """When .info() raises, connect() catches it and sets _client to None."""
    svc = OpenSearchService()
    inst = _make_os_instance(info_exc=Exception("Connection refused"))
    with patch.dict(sys.modules, {"opensearchpy": _make_os_module(inst)}):
        await svc.connect()

    assert svc._client is None
    assert svc.is_available is False


@pytest.mark.asyncio
async def test_connect_recovers_after_previous_failure() -> None:
    """A successful connect() after a prior failure sets _client correctly."""
    svc = OpenSearchService()

    # First call — info() times out
    inst_fail = _make_os_instance(info_exc=Exception("timeout"))
    mod = _make_os_module(inst_fail)
    with patch.dict(sys.modules, {"opensearchpy": mod}):
        await svc.connect()
    assert svc.is_available is False

    # Second call — info() succeeds
    inst_ok = _make_os_instance()
    mod.AsyncOpenSearch.return_value = inst_ok
    with patch.dict(sys.modules, {"opensearchpy": mod}):
        await svc.connect()

    assert svc._client is inst_ok
    assert svc.is_available is True


@pytest.mark.asyncio
async def test_connect_overwrites_client_on_repeated_calls() -> None:
    """Repeated connect() calls replace _client with the newest instance."""
    svc = OpenSearchService()
    inst1 = _make_os_instance(info_return={"version": {"number": "2.11.0"}})
    inst2 = _make_os_instance(info_return={"version": {"number": "2.12.0"}})
    mod = MagicMock()
    mod.AsyncOpenSearch.side_effect = [inst1, inst2]

    with patch.dict(sys.modules, {"opensearchpy": mod}):
        await svc.connect()
        assert svc._client is inst1

        await svc.connect()
        assert svc._client is inst2

    assert svc.is_available is True


@pytest.mark.asyncio
async def test_connect_logs_version_on_success(caplog: pytest.LogCaptureFixture) -> None:
    """connect() logs the cluster version number at INFO level on success."""
    import logging

    svc = OpenSearchService()
    inst = _make_os_instance(info_return={"version": {"number": "2.11.1"}})
    with (
        patch.dict(sys.modules, {"opensearchpy": _make_os_module(inst)}),
        caplog.at_level(logging.INFO),
    ):
        await svc.connect()

    assert "2.11.1" in caplog.text


@pytest.mark.asyncio
async def test_connect_logs_warning_on_import_error(caplog: pytest.LogCaptureFixture) -> None:
    """connect() logs a warning when opensearch-py is not installed."""
    import logging

    svc = OpenSearchService()
    with (
        patch.dict(sys.modules, {"opensearchpy": None}),
        caplog.at_level(logging.WARNING),
    ):
        await svc.connect()

    assert "not installed" in caplog.text.lower() or "opensearch" in caplog.text.lower()


@pytest.mark.asyncio
async def test_connect_logs_warning_on_connection_failure(caplog: pytest.LogCaptureFixture) -> None:
    """connect() logs a warning when the cluster is unreachable."""
    import logging

    svc = OpenSearchService()
    inst = _make_os_instance(info_exc=Exception("cluster not ready"))
    with (
        patch.dict(sys.modules, {"opensearchpy": _make_os_module(inst)}),
        caplog.at_level(logging.WARNING),
    ):
        await svc.connect()

    assert "cluster not ready" in caplog.text
