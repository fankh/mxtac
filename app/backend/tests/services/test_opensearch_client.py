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
    _daily_index,
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
# _daily_index helper — feature 12.3 (daily rotation naming)
# ---------------------------------------------------------------------------


def test_daily_index_returns_base_with_date_suffix() -> None:
    """_daily_index(base) appends today's UTC date in YYYY.MM.DD format."""
    from datetime import datetime, timezone

    result = _daily_index("mxtac-events")
    today = datetime.now(timezone.utc).strftime("%Y.%m.%d")
    assert result == f"mxtac-events-{today}"


def test_daily_index_frozen_date() -> None:
    """_daily_index() uses UTC time — verifiable by freezing datetime.now."""
    from datetime import datetime, timezone

    fixed_dt = datetime(2026, 2, 20, 12, 0, 0, tzinfo=timezone.utc)
    with patch("app.services.opensearch_client.datetime") as mock_dt:
        mock_dt.now.return_value = fixed_dt
        result = _daily_index("mxtac-events")

    assert result == "mxtac-events-2026.02.20"


def test_daily_index_uses_dot_separated_date() -> None:
    """The date portion uses dots (YYYY.MM.DD) not dashes, per OpenSearch conventions."""
    result = _daily_index("mxtac-events")
    suffix = result.replace("mxtac-events-", "")
    parts = suffix.split(".")
    assert len(parts) == 3, f"Expected YYYY.MM.DD, got {suffix!r}"
    assert all(p.isdigit() for p in parts), f"Non-digit part in {suffix!r}"


def test_daily_index_works_for_alerts_base() -> None:
    """_daily_index is reusable — produces the correct name for the alerts base."""
    from datetime import datetime, timezone

    result = _daily_index("mxtac-alerts")
    today = datetime.now(timezone.utc).strftime("%Y.%m.%d")
    assert result == f"mxtac-alerts-{today}"


# ---------------------------------------------------------------------------
# OpenSearchService.index_event — feature 12.3 (daily rotation)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_index_event_targets_mxtac_events_index() -> None:
    """index_event() writes to a mxtac-events-* index, not mxtac-alerts or mxtac-rules."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.index = AsyncMock(return_value={"_id": "x"})
    svc._client = mock_client

    await svc.index_event({"class_name": "Network Activity"})

    idx = mock_client.index.call_args.kwargs["index"]
    assert idx.startswith("mxtac-events-")


@pytest.mark.asyncio
async def test_index_event_index_name_matches_daily_pattern() -> None:
    """The index name follows the YYYY.MM.DD daily-rollover pattern."""
    import re

    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.index = AsyncMock(return_value={"_id": "x"})
    svc._client = mock_client

    await svc.index_event({"class_name": "Network Activity"})

    idx = mock_client.index.call_args.kwargs["index"]
    assert re.fullmatch(r"mxtac-events-\d{4}\.\d{2}\.\d{2}", idx), (
        f"Expected mxtac-events-YYYY.MM.DD, got {idx!r}"
    )


@pytest.mark.asyncio
async def test_index_event_index_name_uses_utc_today() -> None:
    """The daily index suffix reflects today's UTC date, not local time."""
    from datetime import datetime, timezone

    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.index = AsyncMock(return_value={"_id": "x"})
    svc._client = mock_client

    await svc.index_event({"class_name": "Process Activity"})

    idx = mock_client.index.call_args.kwargs["index"]
    today = datetime.now(timezone.utc).strftime("%Y.%m.%d")
    assert idx == f"mxtac-events-{today}"


@pytest.mark.asyncio
async def test_index_event_index_name_frozen_date() -> None:
    """index_event() uses the UTC date at call time — verifiable with frozen datetime."""
    from datetime import datetime, timezone

    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.index = AsyncMock(return_value={"_id": "x"})
    svc._client = mock_client

    fixed_dt = datetime(2026, 2, 20, 12, 0, 0, tzinfo=timezone.utc)
    with patch("app.services.opensearch_client.datetime") as mock_dt:
        mock_dt.now.return_value = fixed_dt
        await svc.index_event({"class_name": "Process Activity"})

    idx = mock_client.index.call_args.kwargs["index"]
    assert idx == "mxtac-events-2026.02.20"


@pytest.mark.asyncio
async def test_index_event_passes_event_as_body() -> None:
    """The event dict is passed verbatim as the document body."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.index = AsyncMock(return_value={"_id": "abc"})
    svc._client = mock_client

    event = {
        "class_name": "Network Activity",
        "severity_id": 4,
        "src_endpoint": {"ip": "10.0.0.1"},
    }
    await svc.index_event(event)

    body = mock_client.index.call_args.kwargs["body"]
    assert body is event


@pytest.mark.asyncio
async def test_index_event_passes_refresh_false() -> None:
    """index_event() uses refresh='false' to avoid write-amplification on every call."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.index = AsyncMock(return_value={"_id": "abc"})
    svc._client = mock_client

    await svc.index_event({"class_name": "Network Activity"})

    kw = mock_client.index.call_args.kwargs
    assert kw.get("refresh") == "false"


@pytest.mark.asyncio
async def test_index_event_without_doc_id_passes_none_as_id() -> None:
    """When doc_id is omitted, id=None is passed so OpenSearch auto-generates the _id."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.index = AsyncMock(return_value={"_id": "OS-autogenerated"})
    svc._client = mock_client

    result = await svc.index_event({"class_name": "Network Activity"})

    kw = mock_client.index.call_args.kwargs
    assert kw.get("id") is None
    assert result == "OS-autogenerated"


@pytest.mark.asyncio
async def test_index_event_returns_id_from_response() -> None:
    """index_event() returns the _id value from the OpenSearch index response."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.index = AsyncMock(
        return_value={"_id": "returned-uuid", "_index": "mxtac-events-2026.02.20", "result": "created"}
    )
    svc._client = mock_client

    result = await svc.index_event({"class_name": "Network Activity"})

    assert result == "returned-uuid"


@pytest.mark.asyncio
async def test_index_event_returns_none_when_response_missing_id() -> None:
    """If the OS response dict has no _id key, index_event() returns None."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.index = AsyncMock(return_value={"result": "created"})  # _id absent
    svc._client = mock_client

    result = await svc.index_event({"class_name": "Network Activity"})

    assert result is None


@pytest.mark.asyncio
async def test_index_event_logs_error_on_exception(caplog: pytest.LogCaptureFixture) -> None:
    """index_event() logs an ERROR-level message containing the exception text."""
    import logging

    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.index = AsyncMock(side_effect=Exception("cluster unavailable"))
    svc._client = mock_client

    with caplog.at_level(logging.ERROR):
        result = await svc.index_event({"class_name": "Network Activity"})

    assert result is None
    assert "cluster unavailable" in caplog.text


@pytest.mark.asyncio
async def test_index_event_with_full_ocsf_event() -> None:
    """A fully-populated OCSF event is forwarded to OpenSearch without transformation."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.index = AsyncMock(return_value={"_id": "full-ocsf-id"})
    svc._client = mock_client

    ocsf_event = {
        "metadata_uid": "evt-001",
        "time": "2026-02-20T12:00:00Z",
        "class_name": "Network Activity",
        "class_uid": 4001,
        "severity_id": 4,
        "metadata_product": "wazuh",
        "metadata_version": "1.0.0",
        "src_endpoint": {
            "ip": "192.168.1.10",
            "hostname": "workstation-01",
            "port": 54321,
        },
        "dst_endpoint": {
            "ip": "10.0.0.1",
            "hostname": "server-01",
            "port": 443,
        },
        "actor_user": {"name": "jsmith", "uid": "S-1-5-21-001", "domain": "CORP"},
        "process": {
            "pid": 1234,
            "name": "powershell.exe",
            "cmd_line": "powershell.exe -enc JABXAG...",
        },
        "unmapped": {"raw_field": "raw_value"},
    }
    result = await svc.index_event(ocsf_event, doc_id="full-ocsf-id")

    assert result == "full-ocsf-id"
    call_kw = mock_client.index.call_args.kwargs
    assert call_kw["body"] is ocsf_event
    assert call_kw["id"] == "full-ocsf-id"
    assert call_kw["refresh"] == "false"
    assert call_kw["index"].startswith("mxtac-events-")


@pytest.mark.asyncio
async def test_index_event_with_empty_event_dict() -> None:
    """index_event() accepts an empty event dict without raising."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.index = AsyncMock(return_value={"_id": "empty-id"})
    svc._client = mock_client

    result = await svc.index_event({})

    assert result == "empty-id"
    body = mock_client.index.call_args.kwargs["body"]
    assert body == {}


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


# ---------------------------------------------------------------------------
# OpenSearchService.ensure_indices — feature 12.2
# ---------------------------------------------------------------------------


def _make_indices_client(*, rules_exist: bool = False) -> MagicMock:
    """Return a mock IndicesClient with all relevant methods mocked async."""
    idx = MagicMock()
    idx.put_index_template = AsyncMock(return_value={"acknowledged": True})
    idx.exists = AsyncMock(return_value=rules_exist)
    idx.create = AsyncMock(return_value={"acknowledged": True})
    return idx


@pytest.mark.asyncio
async def test_ensure_indices_noop_when_unavailable() -> None:
    """ensure_indices() is a no-op when no client is connected."""
    svc = OpenSearchService()
    # _client is None — should not raise and not call anything
    await svc.ensure_indices()


@pytest.mark.asyncio
async def test_ensure_indices_creates_events_template() -> None:
    """ensure_indices() calls put_index_template for the events template."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.indices = _make_indices_client(rules_exist=True)
    svc._client = mock_client

    await svc.ensure_indices()

    names_called = [
        c.kwargs.get("name") or (c.args[0] if c.args else None)
        for c in mock_client.indices.put_index_template.call_args_list
    ]
    assert "mxtac-events-template" in names_called


@pytest.mark.asyncio
async def test_ensure_indices_events_template_uses_correct_index_pattern() -> None:
    """The events template must target the mxtac-events-* index pattern."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.indices = _make_indices_client(rules_exist=True)
    svc._client = mock_client

    await svc.ensure_indices()

    calls = {
        c.kwargs.get("name"): c.kwargs.get("body")
        for c in mock_client.indices.put_index_template.call_args_list
    }
    body = calls.get("mxtac-events-template", {})
    assert body.get("index_patterns") == ["mxtac-events-*"]


@pytest.mark.asyncio
async def test_ensure_indices_creates_alerts_template() -> None:
    """ensure_indices() calls put_index_template for the alerts template."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.indices = _make_indices_client(rules_exist=True)
    svc._client = mock_client

    await svc.ensure_indices()

    names_called = [
        c.kwargs.get("name") or (c.args[0] if c.args else None)
        for c in mock_client.indices.put_index_template.call_args_list
    ]
    assert "mxtac-alerts-template" in names_called


@pytest.mark.asyncio
async def test_ensure_indices_alerts_template_uses_correct_index_pattern() -> None:
    """The alerts template must target the mxtac-alerts-* index pattern."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.indices = _make_indices_client(rules_exist=True)
    svc._client = mock_client

    await svc.ensure_indices()

    calls = {
        c.kwargs.get("name"): c.kwargs.get("body")
        for c in mock_client.indices.put_index_template.call_args_list
    }
    body = calls.get("mxtac-alerts-template", {})
    assert body.get("index_patterns") == ["mxtac-alerts-*"]


@pytest.mark.asyncio
async def test_ensure_indices_creates_rules_index_when_absent() -> None:
    """ensure_indices() creates mxtac-rules when the index does not exist."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.indices = _make_indices_client(rules_exist=False)
    svc._client = mock_client

    await svc.ensure_indices()

    mock_client.indices.exists.assert_awaited_once_with(index="mxtac-rules")
    mock_client.indices.create.assert_awaited_once()
    create_kwargs = mock_client.indices.create.call_args.kwargs
    assert create_kwargs.get("index") == "mxtac-rules"


@pytest.mark.asyncio
async def test_ensure_indices_skips_rules_create_when_already_exists() -> None:
    """ensure_indices() skips creating mxtac-rules if it already exists."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.indices = _make_indices_client(rules_exist=True)
    svc._client = mock_client

    await svc.ensure_indices()

    mock_client.indices.exists.assert_awaited_once_with(index="mxtac-rules")
    mock_client.indices.create.assert_not_awaited()


@pytest.mark.asyncio
async def test_ensure_indices_events_template_has_time_date_field() -> None:
    """Events template must map 'time' as a date field."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.indices = _make_indices_client(rules_exist=True)
    svc._client = mock_client

    await svc.ensure_indices()

    calls = {
        c.kwargs.get("name"): c.kwargs.get("body")
        for c in mock_client.indices.put_index_template.call_args_list
    }
    props = calls["mxtac-events-template"]["template"]["mappings"]["properties"]
    assert props["time"] == {"type": "date"}
    assert props["severity_id"] == {"type": "integer"}
    assert props["src_endpoint"]["properties"]["ip"] == {"type": "ip"}


@pytest.mark.asyncio
async def test_ensure_indices_alerts_template_has_alert_fields() -> None:
    """Alerts template must include alert-specific fields like risk_score."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.indices = _make_indices_client(rules_exist=True)
    svc._client = mock_client

    await svc.ensure_indices()

    calls = {
        c.kwargs.get("name"): c.kwargs.get("body")
        for c in mock_client.indices.put_index_template.call_args_list
    }
    props = calls["mxtac-alerts-template"]["template"]["mappings"]["properties"]
    assert props["rule_id"] == {"type": "keyword"}
    assert props["risk_score"] == {"type": "float"}
    assert props["status"] == {"type": "keyword"}


@pytest.mark.asyncio
async def test_ensure_indices_events_template_exception_does_not_crash() -> None:
    """An exception from put_index_template for events is caught; method continues."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.indices = _make_indices_client(rules_exist=True)
    mock_client.indices.put_index_template = AsyncMock(side_effect=Exception("OS error"))
    svc._client = mock_client

    # Must not raise
    await svc.ensure_indices()


@pytest.mark.asyncio
async def test_ensure_indices_rules_exception_does_not_crash() -> None:
    """An exception from indices.exists is caught; method completes without raising."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.indices = _make_indices_client()
    mock_client.indices.exists = AsyncMock(side_effect=Exception("cluster unavailable"))
    svc._client = mock_client

    # Must not raise
    await svc.ensure_indices()


@pytest.mark.asyncio
async def test_ensure_indices_logs_success(caplog: pytest.LogCaptureFixture) -> None:
    """ensure_indices() logs INFO messages on success."""
    import logging

    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.indices = _make_indices_client(rules_exist=False)
    svc._client = mock_client

    with caplog.at_level(logging.INFO):
        await svc.ensure_indices()

    assert "mxtac-events-template" in caplog.text
    assert "mxtac-alerts-template" in caplog.text
    assert "mxtac-rules" in caplog.text
