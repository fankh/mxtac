"""Tests for /api/v1/events endpoints.

RBAC:
  events:search → hunter, engineer, admin
"""

from __future__ import annotations

import pytest


_BASE = "/api/v1/events"


class TestSearchEventsRBAC:
    """POST /events/search — access control."""

    _payload = {
        "query": None,
        "filters": [],
        "time_from": "now-1h",
        "time_to": "now",
        "size": 10,
    }

    async def test_hunter_can_search(self, client, hunter_headers) -> None:
        resp = await client.post(f"{_BASE}/search", json=self._payload, headers=hunter_headers)
        assert resp.status_code == 200

    async def test_engineer_can_search(self, client, engineer_headers) -> None:
        resp = await client.post(f"{_BASE}/search", json=self._payload, headers=engineer_headers)
        assert resp.status_code == 200

    async def test_admin_can_search(self, client, admin_headers) -> None:
        resp = await client.post(f"{_BASE}/search", json=self._payload, headers=admin_headers)
        assert resp.status_code == 200

    async def test_analyst_cannot_search(self, client, analyst_headers) -> None:
        resp = await client.post(f"{_BASE}/search", json=self._payload, headers=analyst_headers)
        assert resp.status_code == 403

    async def test_viewer_cannot_search(self, client, viewer_headers) -> None:
        resp = await client.post(f"{_BASE}/search", json=self._payload, headers=viewer_headers)
        assert resp.status_code == 403

    async def test_unauthenticated_cannot_search(self, client) -> None:
        resp = await client.post(f"{_BASE}/search", json=self._payload)
        assert resp.status_code == 401


class TestSearchEventsResponse:
    """POST /events/search — response shape (PostgreSQL fallback when OS/DuckDB unavailable)."""

    _payload = {
        "query": None,
        "filters": [],
        "time_from": "now-1h",
        "time_to": "now",
        "size": 10,
    }

    async def test_response_has_total(self, client, hunter_headers) -> None:
        resp = await client.post(f"{_BASE}/search", json=self._payload, headers=hunter_headers)
        body = resp.json()
        assert "total" in body

    async def test_response_has_items(self, client, hunter_headers) -> None:
        resp = await client.post(f"{_BASE}/search", json=self._payload, headers=hunter_headers)
        body = resp.json()
        assert "items" in body
        assert isinstance(body["items"], list)

    async def test_response_has_backend(self, client, hunter_headers) -> None:
        resp = await client.post(f"{_BASE}/search", json=self._payload, headers=hunter_headers)
        body = resp.json()
        # Fallback to postgres when OpenSearch + DuckDB are not available
        assert body.get("backend") in ("opensearch", "duckdb", "postgres")

    async def test_empty_results_when_no_events(self, client, hunter_headers) -> None:
        resp = await client.post(f"{_BASE}/search", json=self._payload, headers=hunter_headers)
        body = resp.json()
        assert body["total"] == 0
        assert body["items"] == []


class TestSearchEventsValidation:
    """POST /events/search — request validation."""

    async def test_invalid_filter_field_returns_422(self, client, hunter_headers) -> None:
        resp = await client.post(
            f"{_BASE}/search",
            json={
                "filters": [{"field": "not_an_allowed_field", "operator": "eq", "value": "x"}],
            },
            headers=hunter_headers,
        )
        assert resp.status_code == 422

    async def test_size_too_large_returns_422(self, client, hunter_headers) -> None:
        resp = await client.post(
            f"{_BASE}/search",
            json={"size": 9999},  # max is 1000
            headers=hunter_headers,
        )
        assert resp.status_code == 422


class TestAggregateEvents:
    """POST /events/aggregate — event aggregation."""

    async def test_hunter_can_aggregate(self, client, hunter_headers) -> None:
        resp = await client.post(
            f"{_BASE}/aggregate",
            json={"agg_type": "terms", "field": "hostname", "size": 10},
            headers=hunter_headers,
        )
        assert resp.status_code == 200

    async def test_analyst_cannot_aggregate(self, client, analyst_headers) -> None:
        resp = await client.post(
            f"{_BASE}/aggregate",
            json={"agg_type": "terms", "field": "hostname"},
            headers=analyst_headers,
        )
        assert resp.status_code == 403


class TestBuildQueryDSL:
    """POST /events/query-dsl — Lucene DSL translation (pure logic, no DB)."""

    async def test_hunter_gets_lucene_string(self, client, hunter_headers) -> None:
        resp = await client.post(
            f"{_BASE}/query-dsl",
            json={"query": "failed login", "filters": []},
            headers=hunter_headers,
        )
        assert resp.status_code == 200
        assert "lucene" in resp.json()

    async def test_viewer_cannot_get_dsl(self, client, viewer_headers) -> None:
        resp = await client.post(
            f"{_BASE}/query-dsl",
            json={"query": "test"},
            headers=viewer_headers,
        )
        assert resp.status_code == 403


class TestGetEventById:
    """GET /events/{id} — retrieve a specific event by UUID."""

    async def test_nonexistent_event_returns_404(self, client, hunter_headers) -> None:
        resp = await client.get(
            f"{_BASE}/00000000-0000-0000-0000-000000000000",
            headers=hunter_headers,
        )
        assert resp.status_code == 404
