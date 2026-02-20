"""Unit tests for OpenSearchService and the filter_to_dsl() helper.

All tests mock the underlying opensearch-py client so no real OpenSearch
cluster is required.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

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
