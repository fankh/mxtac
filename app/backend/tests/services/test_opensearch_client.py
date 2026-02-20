"""Unit tests for OpenSearchService and the filter_to_dsl() helper.

All tests mock the underlying opensearch-py client so no real OpenSearch
cluster is required.
"""

from __future__ import annotations

import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.opensearch_client import (
    ALERTS_INDEX_TEMPLATE,
    EVENTS_INDEX_TEMPLATE,
    ILM_POLICY_NAME,
    ILM_RETENTION_DAYS,
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
# OpenSearchService.index_alert — feature 12.4 (daily rotation)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_index_alert_returns_none_when_client_not_set() -> None:
    """index_alert() short-circuits with None when _client is not initialised."""
    svc = OpenSearchService()
    # _client is None by default — no mock needed
    result = await svc.index_alert({"rule_name": "Suspicious PowerShell"})
    assert result is None


@pytest.mark.asyncio
async def test_index_alert_targets_mxtac_alerts_index() -> None:
    """index_alert() writes to a mxtac-alerts-* index, not mxtac-events or mxtac-rules."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.index = AsyncMock(return_value={"_id": "a1"})
    svc._client = mock_client

    await svc.index_alert({"rule_name": "Suspicious PowerShell"})

    idx = mock_client.index.call_args.kwargs["index"]
    assert idx.startswith("mxtac-alerts-")


@pytest.mark.asyncio
async def test_index_alert_index_name_matches_daily_pattern() -> None:
    """The index name follows the YYYY.MM.DD daily-rollover pattern."""
    import re

    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.index = AsyncMock(return_value={"_id": "a1"})
    svc._client = mock_client

    await svc.index_alert({"rule_name": "Suspicious PowerShell"})

    idx = mock_client.index.call_args.kwargs["index"]
    assert re.fullmatch(r"mxtac-alerts-\d{4}\.\d{2}\.\d{2}", idx), (
        f"Expected mxtac-alerts-YYYY.MM.DD, got {idx!r}"
    )


@pytest.mark.asyncio
async def test_index_alert_index_name_uses_utc_today() -> None:
    """The daily index suffix reflects today's UTC date, not local time."""
    from datetime import datetime, timezone

    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.index = AsyncMock(return_value={"_id": "a1"})
    svc._client = mock_client

    await svc.index_alert({"rule_name": "Suspicious PowerShell"})

    idx = mock_client.index.call_args.kwargs["index"]
    today = datetime.now(timezone.utc).strftime("%Y.%m.%d")
    assert idx == f"mxtac-alerts-{today}"


@pytest.mark.asyncio
async def test_index_alert_index_name_frozen_date() -> None:
    """index_alert() uses the UTC date at call time — verifiable with frozen datetime."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.index = AsyncMock(return_value={"_id": "a1"})
    svc._client = mock_client

    from datetime import datetime, timezone

    fixed_dt = datetime(2026, 2, 20, 12, 0, 0, tzinfo=timezone.utc)
    with patch("app.services.opensearch_client.datetime") as mock_dt:
        mock_dt.now.return_value = fixed_dt
        await svc.index_alert({"rule_name": "Suspicious PowerShell"})

    idx = mock_client.index.call_args.kwargs["index"]
    assert idx == "mxtac-alerts-2026.02.20"


@pytest.mark.asyncio
async def test_index_alert_passes_alert_as_body() -> None:
    """The alert dict is passed verbatim as the document body."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.index = AsyncMock(return_value={"_id": "abc"})
    svc._client = mock_client

    alert = {
        "rule_name": "Suspicious PowerShell",
        "severity_name": "High",
        "risk_score": 85,
    }
    await svc.index_alert(alert)

    body = mock_client.index.call_args.kwargs["body"]
    assert body is alert


@pytest.mark.asyncio
async def test_index_alert_passes_refresh_true() -> None:
    """index_alert() uses refresh='true' so alerts are immediately visible for queries."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.index = AsyncMock(return_value={"_id": "abc"})
    svc._client = mock_client

    await svc.index_alert({"rule_name": "Suspicious PowerShell"})

    kw = mock_client.index.call_args.kwargs
    assert kw.get("refresh") == "true"


@pytest.mark.asyncio
async def test_index_alert_returns_id_from_response() -> None:
    """index_alert() returns the _id value from the OpenSearch index response."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.index = AsyncMock(
        return_value={"_id": "alert-uuid-999", "_index": "mxtac-alerts-2026.02.20", "result": "created"}
    )
    svc._client = mock_client

    result = await svc.index_alert({"rule_name": "Suspicious PowerShell"})

    assert result == "alert-uuid-999"


@pytest.mark.asyncio
async def test_index_alert_returns_none_when_response_missing_id() -> None:
    """If the OS response dict has no _id key, index_alert() returns None."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.index = AsyncMock(return_value={"result": "created"})  # _id absent
    svc._client = mock_client

    result = await svc.index_alert({"rule_name": "Suspicious PowerShell"})

    assert result is None


@pytest.mark.asyncio
async def test_index_alert_returns_none_on_exception() -> None:
    """index_alert() returns None when the OpenSearch client raises."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.index = AsyncMock(side_effect=ConnectionError("connection refused"))
    svc._client = mock_client

    result = await svc.index_alert({"rule_name": "Suspicious PowerShell"})

    assert result is None


@pytest.mark.asyncio
async def test_index_alert_logs_error_on_exception(caplog: pytest.LogCaptureFixture) -> None:
    """index_alert() logs an ERROR-level message containing the exception text."""
    import logging

    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.index = AsyncMock(side_effect=Exception("cluster unavailable"))
    svc._client = mock_client

    with caplog.at_level(logging.ERROR):
        result = await svc.index_alert({"rule_name": "Suspicious PowerShell"})

    assert result is None
    assert "cluster unavailable" in caplog.text


@pytest.mark.asyncio
async def test_index_alert_with_full_alert_structure() -> None:
    """A fully-populated enriched alert is forwarded to OpenSearch without transformation."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.index = AsyncMock(return_value={"_id": "full-alert-id"})
    svc._client = mock_client

    alert = {
        "alert_id": "full-alert-id",
        "time": "2026-02-20T12:00:00Z",
        "rule_name": "PowerShell Encoded Command",
        "rule_id": "sigma-psh-enc-001",
        "severity_name": "High",
        "severity_id": 4,
        "risk_score": 85,
        "mitre_attack": {"tactic": "Execution", "technique": "T1059.001"},
        "src_endpoint": {"ip": "192.168.1.10", "hostname": "workstation-01"},
        "actor_user": {"name": "jsmith", "domain": "CORP"},
        "process": {"name": "powershell.exe", "cmd_line": "powershell.exe -enc JABXAG..."},
        "matched_event_ids": ["evt-001", "evt-002"],
        "status": "open",
    }
    result = await svc.index_alert(alert)

    assert result == "full-alert-id"
    call_kw = mock_client.index.call_args.kwargs
    assert call_kw["body"] is alert
    assert call_kw["refresh"] == "true"
    assert call_kw["index"].startswith("mxtac-alerts-")


@pytest.mark.asyncio
async def test_index_alert_does_not_accept_doc_id() -> None:
    """index_alert() does NOT forward a caller-supplied id — OpenSearch auto-generates _id."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.index = AsyncMock(return_value={"_id": "OS-autogenerated"})
    svc._client = mock_client

    await svc.index_alert({"rule_name": "Suspicious PowerShell"})

    kw = mock_client.index.call_args.kwargs
    # The call must not include an explicit 'id' kwarg
    assert "id" not in kw


@pytest.mark.asyncio
async def test_index_alert_does_not_write_to_events_index() -> None:
    """index_alert() must never write to the events index — wrong index would corrupt event data."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.index = AsyncMock(return_value={"_id": "a1"})
    svc._client = mock_client

    await svc.index_alert({"rule_name": "Suspicious PowerShell"})

    idx = mock_client.index.call_args.kwargs["index"]
    assert not idx.startswith("mxtac-events-"), (
        f"index_alert() must not write to the events index, got {idx!r}"
    )


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


# ---------------------------------------------------------------------------
# feature 12.5 — search_events() bool query with filters — query construction
# ---------------------------------------------------------------------------


def _make_search_client(hits: list[dict] | None = None, total: int = 0) -> MagicMock:
    """Return a mock client whose .search() returns a standard hits envelope."""
    mock_client = MagicMock()
    mock_client.search = AsyncMock(return_value={
        "hits": {
            "total": {"value": total},
            "hits": hits or [],
        }
    })
    return mock_client


def _get_search_body(mock_client: MagicMock) -> dict:
    """Extract the body kwarg from the most recent .search() call."""
    call = mock_client.search.call_args
    return call.kwargs.get("body") or call.args[0]


@pytest.mark.asyncio
async def test_search_events_query_string_value_matches_input() -> None:
    """The query_string clause carries the exact query text passed in."""
    svc = OpenSearchService()
    svc._client = _make_search_client()

    await svc.search_events(query="mimikatz lsass")

    body = _get_search_body(svc._client)
    must = body["query"]["bool"]["must"]
    qs_clauses = [c for c in must if "query_string" in c]
    assert len(qs_clauses) == 1
    assert qs_clauses[0]["query_string"]["query"] == "mimikatz lsass"


@pytest.mark.asyncio
async def test_search_events_query_only_has_two_must_clauses() -> None:
    """With a query but no filters, must has exactly: query_string + time range."""
    svc = OpenSearchService()
    svc._client = _make_search_client()

    await svc.search_events(query="powershell")

    body = _get_search_body(svc._client)
    must = body["query"]["bool"]["must"]
    assert len(must) == 2
    assert any("query_string" in c for c in must)
    assert any("range" in c for c in must)


@pytest.mark.asyncio
async def test_search_events_filters_only_no_query_string_clause() -> None:
    """With filters but no query, must has no query_string clause."""
    svc = OpenSearchService()
    svc._client = _make_search_client()

    await svc.search_events(filters=[{"term": {"severity_id": 4}}])

    body = _get_search_body(svc._client)
    must = body["query"]["bool"]["must"]
    assert not any("query_string" in c for c in must)
    assert {"term": {"severity_id": 4}} in must


@pytest.mark.asyncio
async def test_search_events_multiple_filters_all_in_must() -> None:
    """Each filter dict is appended as a separate must clause."""
    svc = OpenSearchService()
    svc._client = _make_search_client()

    filters = [
        {"term": {"severity_id": 4}},
        {"term": {"class_name": "Process Activity"}},
        {"wildcard": {"src_endpoint.hostname": "*dc-*"}},
    ]
    await svc.search_events(filters=filters)

    body = _get_search_body(svc._client)
    must = body["query"]["bool"]["must"]
    for f in filters:
        assert f in must, f"Expected filter clause {f!r} in must"


@pytest.mark.asyncio
async def test_search_events_empty_string_query_not_added() -> None:
    """An empty string query is falsy — no query_string clause is added."""
    svc = OpenSearchService()
    svc._client = _make_search_client()

    await svc.search_events(query="")

    body = _get_search_body(svc._client)
    must = body["query"]["bool"]["must"]
    assert not any("query_string" in c for c in must)


@pytest.mark.asyncio
async def test_search_events_empty_filters_list_not_added() -> None:
    """An empty filters list is falsy — no extra clauses are added to must."""
    svc = OpenSearchService()
    svc._client = _make_search_client()

    await svc.search_events(filters=[])

    body = _get_search_body(svc._client)
    must = body["query"]["bool"]["must"]
    # Only the time range clause should be present
    assert len(must) == 1
    assert "range" in must[0]


# ---------------------------------------------------------------------------
# feature 12.5 — search_events() — request body structure
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_search_events_sort_is_time_descending() -> None:
    """The sort field is time in descending order (newest-first)."""
    svc = OpenSearchService()
    svc._client = _make_search_client()

    await svc.search_events()

    body = _get_search_body(svc._client)
    assert body["sort"] == [{"time": {"order": "desc"}}]


@pytest.mark.asyncio
async def test_search_events_size_forwarded_to_body() -> None:
    """The size parameter is included in the OpenSearch request body."""
    svc = OpenSearchService()
    svc._client = _make_search_client()

    await svc.search_events(size=25)

    body = _get_search_body(svc._client)
    assert body["size"] == 25


@pytest.mark.asyncio
async def test_search_events_from_forwarded_to_body() -> None:
    """The from_ parameter is included in the OpenSearch request body as 'from'."""
    svc = OpenSearchService()
    svc._client = _make_search_client()

    await svc.search_events(from_=50)

    body = _get_search_body(svc._client)
    assert body["from"] == 50


@pytest.mark.asyncio
async def test_search_events_default_size_is_100() -> None:
    """Default size is 100 when not specified."""
    svc = OpenSearchService()
    svc._client = _make_search_client()

    await svc.search_events()

    body = _get_search_body(svc._client)
    assert body["size"] == 100


@pytest.mark.asyncio
async def test_search_events_default_from_is_0() -> None:
    """Default from_ is 0 when not specified."""
    svc = OpenSearchService()
    svc._client = _make_search_client()

    await svc.search_events()

    body = _get_search_body(svc._client)
    assert body["from"] == 0


@pytest.mark.asyncio
async def test_search_events_time_range_uses_gte_and_lte() -> None:
    """The time range clause uses 'gte' / 'lte' (inclusive), not 'gt' / 'lt'."""
    svc = OpenSearchService()
    svc._client = _make_search_client()

    await svc.search_events(time_from="now-24h", time_to="now")

    body = _get_search_body(svc._client)
    must = body["query"]["bool"]["must"]
    range_clauses = [c for c in must if "range" in c and "time" in c.get("range", {})]
    assert len(range_clauses) == 1
    time_range = range_clauses[0]["range"]["time"]
    assert "gte" in time_range, "time range must use 'gte', not 'gt'"
    assert "lte" in time_range, "time range must use 'lte', not 'lt'"
    assert "gt" not in time_range
    assert "lt" not in time_range


@pytest.mark.asyncio
async def test_search_events_time_range_values_match_params() -> None:
    """The gte/lte values match the time_from/time_to arguments exactly."""
    svc = OpenSearchService()
    svc._client = _make_search_client()

    await svc.search_events(time_from="now-6h", time_to="2026-02-20T23:59:59Z")

    body = _get_search_body(svc._client)
    must = body["query"]["bool"]["must"]
    time_range = next(
        c["range"]["time"]
        for c in must
        if "range" in c and "time" in c.get("range", {})
    )
    assert time_range["gte"] == "now-6h"
    assert time_range["lte"] == "2026-02-20T23:59:59Z"


@pytest.mark.asyncio
async def test_search_events_default_time_from_is_now_minus_7d() -> None:
    """Default time_from is 'now-7d' when not specified."""
    svc = OpenSearchService()
    svc._client = _make_search_client()

    await svc.search_events()

    body = _get_search_body(svc._client)
    must = body["query"]["bool"]["must"]
    time_range = next(
        c["range"]["time"]
        for c in must
        if "range" in c and "time" in c.get("range", {})
    )
    assert time_range["gte"] == "now-7d"
    assert time_range["lte"] == "now"


# ---------------------------------------------------------------------------
# feature 12.5 — search_events() — index targeting
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_search_events_targets_events_wildcard_index() -> None:
    """search_events() searches across mxtac-events-* (all daily indices)."""
    svc = OpenSearchService()
    svc._client = _make_search_client()

    await svc.search_events()

    call = svc._client.search.call_args
    index_arg = call.kwargs.get("index") or call.args[0]
    assert index_arg == "mxtac-events-*"


@pytest.mark.asyncio
async def test_search_events_does_not_target_alerts_index() -> None:
    """search_events() must never search the alerts index."""
    svc = OpenSearchService()
    svc._client = _make_search_client()

    await svc.search_events()

    call = svc._client.search.call_args
    index_arg = call.kwargs.get("index") or call.args[0]
    assert "alerts" not in index_arg, (
        f"search_events() must not target alerts index, got {index_arg!r}"
    )


# ---------------------------------------------------------------------------
# feature 12.5 — search_events() — result passthrough and logging
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_search_events_returns_full_response_verbatim() -> None:
    """The raw OpenSearch response dict is returned as-is, without transformation."""
    os_response = {
        "hits": {
            "total": {"value": 3, "relation": "eq"},
            "hits": [
                {"_id": "a", "_score": 1.5, "_source": {"class_name": "Network Activity"}},
                {"_id": "b", "_score": 1.2, "_source": {"class_name": "Process Activity"}},
                {"_id": "c", "_score": 0.8, "_source": {"class_name": "Authentication"}},
            ],
        },
        "_shards": {"total": 3, "successful": 3, "failed": 0},
        "timed_out": False,
        "took": 12,
    }
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.search = AsyncMock(return_value=os_response)
    svc._client = mock_client

    result = await svc.search_events(query="test")

    assert result is os_response


@pytest.mark.asyncio
async def test_search_events_logs_error_on_exception(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """An exception from OS search is logged at ERROR level with exception text."""
    import logging

    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.search = AsyncMock(side_effect=Exception("cluster not reachable"))
    svc._client = mock_client

    with caplog.at_level(logging.ERROR):
        result = await svc.search_events(query="anything")

    assert result == {"hits": {"total": {"value": 0}, "hits": []}}
    assert "cluster not reachable" in caplog.text


@pytest.mark.asyncio
async def test_search_events_combined_query_and_multiple_filters() -> None:
    """With query + 2 filters, must has: query_string + 2 filters + time range = 4 clauses."""
    svc = OpenSearchService()
    svc._client = _make_search_client()

    filters = [
        {"term": {"severity_id": 5}},
        {"wildcard": {"src_endpoint.hostname": "*dc*"}},
    ]
    await svc.search_events(query="lsass", filters=filters)

    body = _get_search_body(svc._client)
    must = body["query"]["bool"]["must"]
    assert len(must) == 4  # query_string + 2 filters + time range
    assert any("query_string" in c for c in must)
    assert {"term": {"severity_id": 5}} in must
    assert {"wildcard": {"src_endpoint.hostname": "*dc*"}} in must
    assert any("range" in c and "time" in c["range"] for c in must)


# ---------------------------------------------------------------------------
# feature 12.5 — filter_to_dsl() — additional field mapping coverage
# ---------------------------------------------------------------------------


def test_filter_to_dsl_dst_ip_maps_to_nested_field() -> None:
    """'dst_ip' flat alias maps to 'dst_endpoint.ip' in OpenSearch."""
    clause = filter_to_dsl("dst_ip", "eq", "10.0.0.1")
    assert clause == {"term": {"dst_endpoint.ip": "10.0.0.1"}}


def test_filter_to_dsl_username_maps_to_actor_user_name() -> None:
    """'username' flat alias maps to 'actor_user.name'."""
    clause = filter_to_dsl("username", "eq", "CORP\\admin")
    assert clause == {"term": {"actor_user.name": "CORP\\admin"}}


def test_filter_to_dsl_process_hash_maps_to_hash_sha256() -> None:
    """'process_hash' flat alias maps to 'process.hash_sha256'."""
    clause = filter_to_dsl("process_hash", "eq", "abc123def456")
    assert clause == {"term": {"process.hash_sha256": "abc123def456"}}


def test_filter_to_dsl_source_maps_to_metadata_product() -> None:
    """'source' flat alias maps to 'metadata_product'."""
    clause = filter_to_dsl("source", "eq", "wazuh")
    assert clause == {"term": {"metadata_product": "wazuh"}}


def test_filter_to_dsl_class_uid_maps_to_itself() -> None:
    """'class_uid' maps to 'class_uid' (no renaming)."""
    clause = filter_to_dsl("class_uid", "eq", 4001)
    assert clause == {"term": {"class_uid": 4001}}


def test_filter_to_dsl_dst_endpoint_hostname_passthrough() -> None:
    """'dst_endpoint.hostname' nested path passes through unchanged."""
    clause = filter_to_dsl("dst_endpoint.hostname", "eq", "server-01")
    assert clause == {"term": {"dst_endpoint.hostname": "server-01"}}


def test_filter_to_dsl_dst_endpoint_ip_passthrough() -> None:
    """'dst_endpoint.ip' nested path passes through unchanged."""
    clause = filter_to_dsl("dst_endpoint.ip", "eq", "172.16.0.1")
    assert clause == {"term": {"dst_endpoint.ip": "172.16.0.1"}}


def test_filter_to_dsl_process_hash_sha256_passthrough() -> None:
    """'process.hash_sha256' nested path passes through unchanged."""
    clause = filter_to_dsl("process.hash_sha256", "eq", "deadbeef")
    assert clause == {"term": {"process.hash_sha256": "deadbeef"}}


def test_filter_to_dsl_contains_wraps_value_with_wildcards() -> None:
    """'contains' operator wraps the value with leading and trailing wildcards."""
    clause = filter_to_dsl("username", "contains", "admin")
    assert clause is not None
    wc_field, wc_pattern = next(iter(clause["wildcard"].items()))
    assert wc_pattern.startswith("*"), "wildcard pattern must start with *"
    assert wc_pattern.endswith("*"), "wildcard pattern must end with *"
    assert "admin" in wc_pattern


def test_filter_to_dsl_ne_generates_bool_must_not_structure() -> None:
    """'ne' operator produces a bool/must_not clause (not a simple term)."""
    clause = filter_to_dsl("severity_id", "ne", 1)
    assert clause is not None
    assert "bool" in clause
    assert "must_not" in clause["bool"]
    inner = clause["bool"]["must_not"]
    assert isinstance(inner, list) and len(inner) == 1
    assert inner[0] == {"term": {"severity_id": 1}}


def test_filter_to_dsl_ne_with_nested_field() -> None:
    """'ne' with a nested-path field generates a correct bool/must_not."""
    clause = filter_to_dsl("actor_user.name", "ne", "SYSTEM")
    assert clause == {"bool": {"must_not": [{"term": {"actor_user.name": "SYSTEM"}}]}}


def test_filter_to_dsl_range_operators_with_string_value() -> None:
    """Range operators (gt, lt, gte, lte) work with string values (e.g. dates)."""
    date_str = "2026-02-20T00:00:00Z"
    assert filter_to_dsl("severity_id", "gt", date_str) == {"range": {"severity_id": {"gt": date_str}}}
    assert filter_to_dsl("severity_id", "lt", date_str) == {"range": {"severity_id": {"lt": date_str}}}
    assert filter_to_dsl("severity_id", "gte", date_str) == {"range": {"severity_id": {"gte": date_str}}}
    assert filter_to_dsl("severity_id", "lte", date_str) == {"range": {"severity_id": {"lte": date_str}}}


def test_filter_to_dsl_src_endpoint_ip_passthrough() -> None:
    """'src_endpoint.ip' nested path passes through unchanged."""
    clause = filter_to_dsl("src_endpoint.ip", "eq", "192.168.1.1")
    assert clause == {"term": {"src_endpoint.ip": "192.168.1.1"}}


# ---------------------------------------------------------------------------
# feature 12.6 — OpenSearchService.get_event() — fetch by _id
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_event_returns_none_when_client_unavailable() -> None:
    """get_event() returns None when no OpenSearch connection is established."""
    svc = OpenSearchService()
    # _client is None by default — short-circuit path
    result = await svc.get_event("some-event-id")
    assert result is None


@pytest.mark.asyncio
async def test_get_event_returns_source_on_success() -> None:
    """get_event() returns the _source dict from the OpenSearch get response."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    source_data = {"class_name": "Process Activity", "severity_id": 4}
    mock_client.get = AsyncMock(return_value={"_id": "pg-uuid-123", "_source": source_data})
    svc._client = mock_client

    result = await svc.get_event("pg-uuid-123")
    assert result == source_data


@pytest.mark.asyncio
async def test_get_event_passes_id_to_client() -> None:
    """get_event() passes the event_id as the 'id' keyword argument to the OS client."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.get = AsyncMock(return_value={"_source": {}})
    svc._client = mock_client

    await svc.get_event("test-event-uuid")

    call_kwargs = mock_client.get.call_args.kwargs
    assert call_kwargs.get("id") == "test-event-uuid"


@pytest.mark.asyncio
async def test_get_event_default_index_is_wildcard_events() -> None:
    """When no index is specified, get_event() searches across mxtac-events-*."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.get = AsyncMock(return_value={"_source": {}})
    svc._client = mock_client

    await svc.get_event("some-id")

    call_kwargs = mock_client.get.call_args.kwargs
    assert call_kwargs.get("index") == "mxtac-events-*"


@pytest.mark.asyncio
async def test_get_event_custom_index_overrides_default() -> None:
    """When an index is provided, get_event() uses it instead of the wildcard default."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.get = AsyncMock(return_value={"_source": {}})
    svc._client = mock_client

    await svc.get_event("some-id", index="mxtac-events-2026.02.20")

    call_kwargs = mock_client.get.call_args.kwargs
    assert call_kwargs.get("index") == "mxtac-events-2026.02.20"


@pytest.mark.asyncio
async def test_get_event_exception_returns_none() -> None:
    """get_event() catches any exception from the OS client and returns None."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.get = AsyncMock(side_effect=Exception("cluster error"))
    svc._client = mock_client

    result = await svc.get_event("some-id")
    assert result is None


@pytest.mark.asyncio
async def test_get_event_not_found_exception_returns_none() -> None:
    """A document-not-found exception is caught — None is returned, not raised."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    # Simulate opensearch-py NotFoundError (HTTP 404 from OS cluster)
    mock_client.get = AsyncMock(side_effect=Exception("NotFound: 404 Not Found"))
    svc._client = mock_client

    result = await svc.get_event("nonexistent-id")
    assert result is None


@pytest.mark.asyncio
async def test_get_event_empty_source_returns_empty_dict() -> None:
    """When _source is an empty dict, get_event() returns {} (not None)."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.get = AsyncMock(return_value={"_id": "x", "_source": {}})
    svc._client = mock_client

    result = await svc.get_event("x")
    assert result == {}


@pytest.mark.asyncio
async def test_get_event_source_missing_returns_none() -> None:
    """When the response has no _source key, get_event() returns None."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    # Response without _source — dict.get("_source") returns None
    mock_client.get = AsyncMock(return_value={"_id": "x", "_index": "mxtac-events-2026.02.20"})
    svc._client = mock_client

    result = await svc.get_event("x")
    assert result is None


@pytest.mark.asyncio
async def test_get_event_returns_full_ocsf_source_unchanged() -> None:
    """get_event() returns the complete _source payload without any transformation."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    ocsf_source = {
        "id": "pg-uuid-999",
        "class_name": "Network Activity",
        "class_uid": 4001,
        "severity_id": 4,
        "time": "2026-02-20T12:00:00Z",
        "metadata_product": "wazuh",
        "src_endpoint": {"ip": "192.168.1.10", "hostname": "workstation-01"},
        "dst_endpoint": {"ip": "10.0.0.1", "port": 443},
        "actor_user": {"name": "jsmith", "domain": "CORP"},
    }
    mock_client.get = AsyncMock(
        return_value={"_id": "pg-uuid-999", "_source": ocsf_source}
    )
    svc._client = mock_client

    result = await svc.get_event("pg-uuid-999")
    assert result is ocsf_source


@pytest.mark.asyncio
async def test_get_event_called_once_per_invocation() -> None:
    """get_event() makes exactly one call to the underlying OS client per invocation."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.get = AsyncMock(return_value={"_source": {"class_name": "Authentication"}})
    svc._client = mock_client

    await svc.get_event("event-abc")

    mock_client.get.assert_awaited_once()


@pytest.mark.asyncio
async def test_get_event_wildcard_index_not_an_alerts_index() -> None:
    """The default index pattern used by get_event() must not target alerts indices."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.get = AsyncMock(return_value={"_source": {}})
    svc._client = mock_client

    await svc.get_event("some-id")

    index_arg = mock_client.get.call_args.kwargs.get("index")
    assert "alerts" not in index_arg, (
        f"get_event() must not search alerts index, got {index_arg!r}"
    )


# ---------------------------------------------------------------------------
# OpenSearchService.aggregate — feature 12.7
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_aggregate_terms_returns_empty_when_unavailable() -> None:
    """aggregate() returns [] when no client is connected."""
    svc = OpenSearchService()
    result = await svc.aggregate("terms", field="severity_id")
    assert result == []


@pytest.mark.asyncio
async def test_aggregate_date_histogram_returns_empty_when_unavailable() -> None:
    """aggregate(date_histogram) returns [] when no client is connected."""
    svc = OpenSearchService()
    result = await svc.aggregate("date_histogram", interval="1h")
    assert result == []


@pytest.mark.asyncio
async def test_aggregate_terms_unknown_field_returns_empty() -> None:
    """aggregate(terms) with an unknown field skips the query and returns []."""
    svc = OpenSearchService()
    svc._client = MagicMock()  # client is present but should not be called
    svc._client.search = AsyncMock(side_effect=AssertionError("should not be called"))

    result = await svc.aggregate("terms", field="nonexistent_field")
    assert result == []


@pytest.mark.asyncio
async def test_aggregate_date_histogram_unknown_interval_returns_empty() -> None:
    """aggregate(date_histogram) with an unknown interval returns [] without calling OS."""
    svc = OpenSearchService()
    svc._client = MagicMock()
    svc._client.search = AsyncMock(side_effect=AssertionError("should not be called"))

    result = await svc.aggregate("date_histogram", interval="99x")
    assert result == []


@pytest.mark.asyncio
async def test_aggregate_unsupported_agg_type_returns_empty() -> None:
    """aggregate() with an unknown agg_type returns [] without calling OS."""
    svc = OpenSearchService()
    svc._client = MagicMock()
    svc._client.search = AsyncMock(side_effect=AssertionError("should not be called"))

    result = await svc.aggregate("percentiles", field="severity_id")
    assert result == []


@pytest.mark.asyncio
async def test_aggregate_terms_builds_correct_dsl() -> None:
    """aggregate(terms) sends a terms aggregation DSL with the mapped field name."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.search = AsyncMock(return_value={
        "aggregations": {
            "terms_agg": {
                "buckets": [
                    {"key": 5, "doc_count": 42},
                    {"key": 3, "doc_count": 15},
                ]
            }
        }
    })
    svc._client = mock_client

    result = await svc.aggregate(
        "terms",
        field="severity_id",
        time_from="now-7d",
        time_to="now",
        size=10,
    )

    mock_client.search.assert_called_once()
    body = mock_client.search.call_args.kwargs.get("body") or mock_client.search.call_args.args[0]

    # size=0 means no hits are returned, only aggregation buckets
    assert body["size"] == 0
    # Time range filter is always present
    assert body["query"]["range"]["time"] == {"gte": "now-7d", "lte": "now"}
    # Terms agg uses the correct (mapped) field
    terms_agg = body["aggs"]["terms_agg"]["terms"]
    assert terms_agg["field"] == "severity_id"
    assert terms_agg["size"] == 10

    # Response is normalized to {"key": str, "count": int}
    assert result == [{"key": "5", "count": 42}, {"key": "3", "count": 15}]


@pytest.mark.asyncio
async def test_aggregate_terms_maps_flat_alias_to_os_field() -> None:
    """aggregate(terms) on 'src_ip' maps to 'src_endpoint.ip' in the DSL."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.search = AsyncMock(return_value={
        "aggregations": {"terms_agg": {"buckets": []}}
    })
    svc._client = mock_client

    await svc.aggregate("terms", field="src_ip", size=5)

    body = mock_client.search.call_args.kwargs.get("body") or mock_client.search.call_args.args[0]
    assert body["aggs"]["terms_agg"]["terms"]["field"] == "src_endpoint.ip"


@pytest.mark.asyncio
async def test_aggregate_terms_result_keys_are_strings() -> None:
    """aggregate(terms) coerces all bucket keys to strings."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.search = AsyncMock(return_value={
        "aggregations": {
            "terms_agg": {
                "buckets": [
                    {"key": 4, "doc_count": 10},   # integer key
                    {"key": "critical", "doc_count": 5},  # string key
                ]
            }
        }
    })
    svc._client = mock_client

    result = await svc.aggregate("terms", field="severity_id")
    assert all(isinstance(b["key"], str) for b in result)
    assert result[0]["key"] == "4"
    assert result[1]["key"] == "critical"


@pytest.mark.asyncio
async def test_aggregate_terms_exception_returns_empty() -> None:
    """An exception from the OS client is caught; [] is returned."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.search = AsyncMock(side_effect=Exception("connection refused"))
    svc._client = mock_client

    result = await svc.aggregate("terms", field="class_name")
    assert result == []


@pytest.mark.asyncio
async def test_aggregate_date_histogram_builds_correct_dsl() -> None:
    """aggregate(date_histogram) sends a date_histogram DSL with calendar_interval."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.search = AsyncMock(return_value={
        "aggregations": {
            "histogram_agg": {
                "buckets": [
                    {"key_as_string": "2026-02-20T12:00:00.000Z", "doc_count": 8},
                    {"key_as_string": "2026-02-20T13:00:00.000Z", "doc_count": 5},
                ]
            }
        }
    })
    svc._client = mock_client

    result = await svc.aggregate(
        "date_histogram",
        interval="1h",
        time_from="now-24h",
        time_to="now",
    )

    body = mock_client.search.call_args.kwargs.get("body") or mock_client.search.call_args.args[0]
    assert body["size"] == 0
    assert body["query"]["range"]["time"] == {"gte": "now-24h", "lte": "now"}

    hist_agg = body["aggs"]["histogram_agg"]["date_histogram"]
    assert hist_agg["field"] == "time"
    assert hist_agg["calendar_interval"] == "hour"
    assert hist_agg["min_doc_count"] == 1

    # Response is normalized to {"key": key_as_string, "count": int}
    assert result == [
        {"key": "2026-02-20T12:00:00.000Z", "count": 8},
        {"key": "2026-02-20T13:00:00.000Z", "count": 5},
    ]


@pytest.mark.parametrize("interval,expected_cal", [
    ("1m",     "minute"),
    ("minute", "minute"),
    ("1h",     "hour"),
    ("hour",   "hour"),
    ("1d",     "day"),
    ("24h",    "day"),
    ("day",    "day"),
    ("1w",     "week"),
    ("week",   "week"),
    ("1M",     "month"),
    ("month",  "month"),
])
@pytest.mark.asyncio
async def test_aggregate_date_histogram_interval_mapping(interval: str, expected_cal: str) -> None:
    """All supported interval aliases map to the correct OpenSearch calendar_interval."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.search = AsyncMock(return_value={
        "aggregations": {"histogram_agg": {"buckets": []}}
    })
    svc._client = mock_client

    await svc.aggregate("date_histogram", interval=interval)

    body = mock_client.search.call_args.kwargs.get("body") or mock_client.search.call_args.args[0]
    assert body["aggs"]["histogram_agg"]["date_histogram"]["calendar_interval"] == expected_cal


@pytest.mark.asyncio
async def test_aggregate_date_histogram_exception_returns_empty() -> None:
    """An exception from the OS client during date_histogram is caught; [] returned."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.search = AsyncMock(side_effect=Exception("timeout"))
    svc._client = mock_client

    result = await svc.aggregate("date_histogram", interval="1h")
    assert result == []


@pytest.mark.asyncio
async def test_aggregate_terms_empty_buckets() -> None:
    """aggregate(terms) on an index with no matching docs returns []."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.search = AsyncMock(return_value={
        "aggregations": {"terms_agg": {"buckets": []}}
    })
    svc._client = mock_client

    result = await svc.aggregate("terms", field="severity_id")
    assert result == []


@pytest.mark.asyncio
async def test_aggregate_queries_events_index_wildcard() -> None:
    """aggregate() always targets the mxtac-events-* wildcard, not alerts or rules."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.search = AsyncMock(return_value={
        "aggregations": {"terms_agg": {"buckets": []}}
    })
    svc._client = mock_client

    await svc.aggregate("terms", field="class_name")

    index_arg = mock_client.search.call_args.kwargs.get("index")
    assert index_arg == "mxtac-events-*"
    assert "alerts" not in index_arg


# ---------------------------------------------------------------------------
# OpenSearchService.ensure_ilm_policy — feature 12.9 (90-day retention)
# ---------------------------------------------------------------------------


def _make_transport_mock(*, exc: Exception | None = None) -> MagicMock:
    """Return a mock transport with perform_request mocked as async."""
    transport = MagicMock()
    if exc is not None:
        transport.perform_request = AsyncMock(side_effect=exc)
    else:
        transport.perform_request = AsyncMock(return_value={"_id": ILM_POLICY_NAME, "policy": {}})
    return transport


@pytest.mark.asyncio
async def test_ensure_ilm_policy_noop_when_unavailable() -> None:
    """ensure_ilm_policy() is a no-op when no client is connected."""
    svc = OpenSearchService()
    # _client is None — must not raise
    await svc.ensure_ilm_policy()


@pytest.mark.asyncio
async def test_ensure_ilm_policy_calls_put_via_transport() -> None:
    """ensure_ilm_policy() calls transport.perform_request with PUT method."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.transport = _make_transport_mock()
    svc._client = mock_client

    await svc.ensure_ilm_policy()

    mock_client.transport.perform_request.assert_awaited_once()
    call_args = mock_client.transport.perform_request.call_args
    method = call_args.args[0] if call_args.args else call_args.kwargs.get("method")
    assert method == "PUT"


@pytest.mark.asyncio
async def test_ensure_ilm_policy_targets_correct_ism_endpoint() -> None:
    """ensure_ilm_policy() targets the ISM policies API endpoint."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.transport = _make_transport_mock()
    svc._client = mock_client

    await svc.ensure_ilm_policy()

    call_args = mock_client.transport.perform_request.call_args
    url = call_args.args[1] if len(call_args.args) > 1 else call_args.kwargs.get("url")
    assert ILM_POLICY_NAME in url
    assert "_ism" in url or "_plugins" in url


@pytest.mark.asyncio
async def test_ensure_ilm_policy_body_has_correct_policy_name() -> None:
    """ensure_ilm_policy() sends the canonical policy name in the ISM path."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.transport = _make_transport_mock()
    svc._client = mock_client

    await svc.ensure_ilm_policy()

    assert ILM_POLICY_NAME == "mxtac-90day-retention"


@pytest.mark.asyncio
async def test_ensure_ilm_policy_body_has_ingest_and_delete_states() -> None:
    """Policy body contains 'ingest' and 'delete' states."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.transport = _make_transport_mock()
    svc._client = mock_client

    await svc.ensure_ilm_policy()

    call_args = mock_client.transport.perform_request.call_args
    body = call_args.kwargs.get("body") or (call_args.args[2] if len(call_args.args) > 2 else None)
    assert body is not None
    state_names = {s["name"] for s in body["policy"]["states"]}
    assert "ingest" in state_names
    assert "delete" in state_names


@pytest.mark.asyncio
async def test_ensure_ilm_policy_retention_is_90_days() -> None:
    """Policy transition uses 'min_index_age' of 90d."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.transport = _make_transport_mock()
    svc._client = mock_client

    await svc.ensure_ilm_policy()

    call_args = mock_client.transport.perform_request.call_args
    body = call_args.kwargs.get("body") or (call_args.args[2] if len(call_args.args) > 2 else None)
    ingest_state = next(s for s in body["policy"]["states"] if s["name"] == "ingest")
    transition = ingest_state["transitions"][0]
    assert transition["state_name"] == "delete"
    assert transition["conditions"]["min_index_age"] == f"{ILM_RETENTION_DAYS}d"
    assert ILM_RETENTION_DAYS == 90


@pytest.mark.asyncio
async def test_ensure_ilm_policy_delete_state_has_delete_action() -> None:
    """Policy 'delete' state includes the delete action."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.transport = _make_transport_mock()
    svc._client = mock_client

    await svc.ensure_ilm_policy()

    call_args = mock_client.transport.perform_request.call_args
    body = call_args.kwargs.get("body") or (call_args.args[2] if len(call_args.args) > 2 else None)
    delete_state = next(s for s in body["policy"]["states"] if s["name"] == "delete")
    assert {"delete": {}} in delete_state["actions"]
    assert delete_state["transitions"] == []


@pytest.mark.asyncio
async def test_ensure_ilm_policy_ism_template_covers_events_index() -> None:
    """ISM template in the policy covers mxtac-events-* pattern."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.transport = _make_transport_mock()
    svc._client = mock_client

    await svc.ensure_ilm_policy()

    call_args = mock_client.transport.perform_request.call_args
    body = call_args.kwargs.get("body") or (call_args.args[2] if len(call_args.args) > 2 else None)
    ism_patterns = body["policy"]["ism_template"][0]["index_patterns"]
    assert f"{EVENTS_INDEX_TEMPLATE}-*" in ism_patterns


@pytest.mark.asyncio
async def test_ensure_ilm_policy_ism_template_covers_alerts_index() -> None:
    """ISM template in the policy covers mxtac-alerts-* pattern."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.transport = _make_transport_mock()
    svc._client = mock_client

    await svc.ensure_ilm_policy()

    call_args = mock_client.transport.perform_request.call_args
    body = call_args.kwargs.get("body") or (call_args.args[2] if len(call_args.args) > 2 else None)
    ism_patterns = body["policy"]["ism_template"][0]["index_patterns"]
    assert f"{ALERTS_INDEX_TEMPLATE}-*" in ism_patterns


@pytest.mark.asyncio
async def test_ensure_ilm_policy_ism_template_priority_is_100() -> None:
    """ISM template priority is 100 so it wins over lower-priority templates."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.transport = _make_transport_mock()
    svc._client = mock_client

    await svc.ensure_ilm_policy()

    call_args = mock_client.transport.perform_request.call_args
    body = call_args.kwargs.get("body") or (call_args.args[2] if len(call_args.args) > 2 else None)
    priority = body["policy"]["ism_template"][0]["priority"]
    assert priority == 100


@pytest.mark.asyncio
async def test_ensure_ilm_policy_exception_does_not_crash() -> None:
    """An exception from the transport is caught; method returns without raising."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.transport = _make_transport_mock(exc=Exception("ISM plugin unavailable"))
    svc._client = mock_client

    # Must not raise
    await svc.ensure_ilm_policy()


@pytest.mark.asyncio
async def test_ensure_ilm_policy_exception_logs_warning(caplog: pytest.LogCaptureFixture) -> None:
    """A transport exception is logged at WARNING level."""
    import logging

    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.transport = _make_transport_mock(exc=Exception("ISM plugin unavailable"))
    svc._client = mock_client

    with caplog.at_level(logging.WARNING):
        await svc.ensure_ilm_policy()

    assert "ISM plugin unavailable" in caplog.text


@pytest.mark.asyncio
async def test_ensure_ilm_policy_logs_success_on_apply(caplog: pytest.LogCaptureFixture) -> None:
    """ensure_ilm_policy() logs INFO on successful policy application."""
    import logging

    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.transport = _make_transport_mock()
    svc._client = mock_client

    with caplog.at_level(logging.INFO):
        await svc.ensure_ilm_policy()

    assert ILM_POLICY_NAME in caplog.text


# ---------------------------------------------------------------------------
# ensure_indices — ISM policy_id embedded in template settings (feature 12.9)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ensure_indices_events_template_has_ism_policy_id() -> None:
    """Events template settings include the ISM policy_id for 90-day retention."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.indices = _make_indices_client(rules_exist=True)
    mock_client.transport = _make_transport_mock()
    svc._client = mock_client

    await svc.ensure_indices()

    calls = {
        c.kwargs.get("name"): c.kwargs.get("body")
        for c in mock_client.indices.put_index_template.call_args_list
    }
    events_body = calls.get("mxtac-events-template")
    assert events_body is not None
    settings = events_body["template"]["settings"]
    assert settings.get("plugins.index_state_management.policy_id") == ILM_POLICY_NAME


@pytest.mark.asyncio
async def test_ensure_indices_alerts_template_has_ism_policy_id() -> None:
    """Alerts template settings include the ISM policy_id for 90-day retention."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.indices = _make_indices_client(rules_exist=True)
    mock_client.transport = _make_transport_mock()
    svc._client = mock_client

    await svc.ensure_indices()

    calls = {
        c.kwargs.get("name"): c.kwargs.get("body")
        for c in mock_client.indices.put_index_template.call_args_list
    }
    alerts_body = calls.get("mxtac-alerts-template")
    assert alerts_body is not None
    settings = alerts_body["template"]["settings"]
    assert settings.get("plugins.index_state_management.policy_id") == ILM_POLICY_NAME
