"""Tests for /api/v1/detections endpoints.

RBAC:
  detections:read   → viewer, analyst, hunter, engineer, admin
  detections:write  → analyst, hunter, engineer, admin
  detections:delete → admin
"""

from __future__ import annotations

import pytest


_BASE = "/api/v1/detections"


class TestListDetectionsRBAC:
    """GET /detections — access control (all authenticated roles allowed)."""

    async def test_viewer_can_list(self, client, viewer_headers) -> None:
        resp = await client.get(_BASE, headers=viewer_headers)
        assert resp.status_code == 200

    async def test_analyst_can_list(self, client, analyst_headers) -> None:
        resp = await client.get(_BASE, headers=analyst_headers)
        assert resp.status_code == 200

    async def test_hunter_can_list(self, client, hunter_headers) -> None:
        resp = await client.get(_BASE, headers=hunter_headers)
        assert resp.status_code == 200

    async def test_engineer_can_list(self, client, engineer_headers) -> None:
        resp = await client.get(_BASE, headers=engineer_headers)
        assert resp.status_code == 200

    async def test_admin_can_list(self, client, admin_headers) -> None:
        resp = await client.get(_BASE, headers=admin_headers)
        assert resp.status_code == 200

    async def test_unauthenticated_cannot_list(self, client) -> None:
        resp = await client.get(_BASE)
        assert resp.status_code == 401


class TestListDetectionsResponse:
    """GET /detections — response shape with pagination."""

    async def test_response_has_items(self, client, analyst_headers) -> None:
        resp = await client.get(_BASE, headers=analyst_headers)
        body = resp.json()
        assert "items" in body

    async def test_response_has_pagination(self, client, analyst_headers) -> None:
        resp = await client.get(_BASE, headers=analyst_headers)
        body = resp.json()
        assert "pagination" in body

    async def test_items_is_list(self, client, analyst_headers) -> None:
        resp = await client.get(_BASE, headers=analyst_headers)
        body = resp.json()
        assert isinstance(body["items"], list)

    async def test_empty_items_when_no_detections(self, client, analyst_headers) -> None:
        resp = await client.get(_BASE, headers=analyst_headers)
        body = resp.json()
        assert body["items"] == []

    async def test_pagination_has_page(self, client, analyst_headers) -> None:
        resp = await client.get(_BASE, headers=analyst_headers)
        pagination = resp.json()["pagination"]
        assert "page" in pagination

    async def test_pagination_has_total(self, client, analyst_headers) -> None:
        resp = await client.get(_BASE, headers=analyst_headers)
        pagination = resp.json()["pagination"]
        assert "total" in pagination


class TestListDetectionsQueryParams:
    """GET /detections — query parameter filtering."""

    async def test_filter_by_severity(self, client, analyst_headers) -> None:
        resp = await client.get(f"{_BASE}?severity=critical", headers=analyst_headers)
        assert resp.status_code == 200

    async def test_filter_by_status(self, client, analyst_headers) -> None:
        # Valid DetectionStatus values: active, investigating, resolved, false_positive
        resp = await client.get(f"{_BASE}?status=active", headers=analyst_headers)
        assert resp.status_code == 200

    async def test_filter_by_page(self, client, analyst_headers) -> None:
        resp = await client.get(f"{_BASE}?page=1&page_size=10", headers=analyst_headers)
        assert resp.status_code == 200

    async def test_invalid_page_zero_returns_422(self, client, analyst_headers) -> None:
        resp = await client.get(f"{_BASE}?page=0", headers=analyst_headers)
        assert resp.status_code == 422

    async def test_page_size_exceeds_max_returns_422(self, client, analyst_headers) -> None:
        resp = await client.get(f"{_BASE}?page_size=999", headers=analyst_headers)
        assert resp.status_code == 422


class TestGetDetectionById:
    """GET /detections/{id} — retrieve a single detection."""

    async def test_nonexistent_detection_returns_404(self, client, analyst_headers) -> None:
        resp = await client.get(
            f"{_BASE}/00000000-0000-0000-0000-000000000000",
            headers=analyst_headers,
        )
        assert resp.status_code == 404


class TestUpdateDetectionRBAC:
    """PATCH /detections/{id} — access control for status update."""

    async def test_viewer_cannot_update(self, client, viewer_headers) -> None:
        resp = await client.patch(
            f"{_BASE}/00000000-0000-0000-0000-000000000000",
            json={"status": "acknowledged"},
            headers=viewer_headers,
        )
        assert resp.status_code == 403

    async def test_analyst_can_attempt_update(self, client, analyst_headers) -> None:
        """Analyst has detections:write — 404 for non-existent item, not 403."""
        resp = await client.patch(
            f"{_BASE}/00000000-0000-0000-0000-000000000000",
            json={"status": "investigating"},  # valid DetectionStatus value
            headers=analyst_headers,
        )
        assert resp.status_code == 404


class TestDeleteDetectionRBAC:
    """DELETE /detections/{id} — admin-only."""

    async def test_analyst_cannot_delete(self, client, analyst_headers) -> None:
        resp = await client.delete(
            f"{_BASE}/00000000-0000-0000-0000-000000000000",
            headers=analyst_headers,
        )
        assert resp.status_code == 403

    async def test_admin_can_attempt_delete(self, client, admin_headers) -> None:
        """Admin has detections:delete — 404 for non-existent item, not 403."""
        resp = await client.delete(
            f"{_BASE}/00000000-0000-0000-0000-000000000000",
            headers=admin_headers,
        )
        assert resp.status_code == 404
