"""Tests for Feature 3.4 — viewer: read-only dashboards + alerts.

Verifies that the viewer role:
  - Can access all overview (dashboard) endpoints (GET /api/v1/overview/*)
  - Can list and view detections (alerts) (GET /api/v1/detections)
  - Can list and view incidents (GET /api/v1/incidents)
  - Is denied on all write/mutate operations (PATCH detections, POST/PATCH incidents)

Also verifies that unauthenticated requests to dashboard endpoints return 401.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_OVERVIEW_READ_ENDPOINTS = [
    "/api/v1/overview/kpis",
    "/api/v1/overview/timeline",
    "/api/v1/overview/tactics",
    "/api/v1/overview/coverage/heatmap",
    "/api/v1/overview/coverage/tactic-labels",
    "/api/v1/overview/integrations",
    "/api/v1/overview/recent-detections",
]


# ---------------------------------------------------------------------------
# Dashboard (overview) — viewer access
# ---------------------------------------------------------------------------


class TestViewerDashboardAccess:
    """Viewer can read all overview/dashboard endpoints."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("url", _OVERVIEW_READ_ENDPOINTS)
    async def test_viewer_can_access_overview_endpoint(
        self, client: AsyncClient, viewer_headers: dict, url: str
    ) -> None:
        resp = await client.get(url, headers=viewer_headers)
        assert resp.status_code == 200, (
            f"Viewer should be able to GET {url}, got {resp.status_code}"
        )

    @pytest.mark.asyncio
    @pytest.mark.parametrize("url", _OVERVIEW_READ_ENDPOINTS)
    async def test_unauthenticated_overview_returns_401(
        self, client: AsyncClient, url: str
    ) -> None:
        resp = await client.get(url)
        assert resp.status_code == 401, (
            f"Unauthenticated request to {url} should return 401, got {resp.status_code}"
        )


class TestViewerDashboardKpis:
    """Viewer receives valid KPI data from the overview dashboard."""

    @pytest.mark.asyncio
    async def test_viewer_kpis_response_shape(
        self, client: AsyncClient, viewer_headers: dict
    ) -> None:
        resp = await client.get("/api/v1/overview/kpis", headers=viewer_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "total_detections" in data
        assert "critical_alerts" in data
        assert "attack_covered" in data
        assert "sigma_rules_active" in data

    @pytest.mark.asyncio
    async def test_viewer_timeline_response_shape(
        self, client: AsyncClient, viewer_headers: dict
    ) -> None:
        resp = await client.get("/api/v1/overview/timeline", headers=viewer_headers)
        assert resp.status_code == 200
        items = resp.json()
        assert isinstance(items, list)
        assert len(items) > 0
        assert "date" in items[0]
        assert "total" in items[0]

    @pytest.mark.asyncio
    async def test_viewer_tactics_response_shape(
        self, client: AsyncClient, viewer_headers: dict
    ) -> None:
        resp = await client.get("/api/v1/overview/tactics", headers=viewer_headers)
        assert resp.status_code == 200
        items = resp.json()
        assert isinstance(items, list)
        assert len(items) > 0
        assert "tactic" in items[0]
        assert "count" in items[0]

    @pytest.mark.asyncio
    async def test_viewer_heatmap_response_shape(
        self, client: AsyncClient, viewer_headers: dict
    ) -> None:
        resp = await client.get("/api/v1/overview/coverage/heatmap", headers=viewer_headers)
        assert resp.status_code == 200
        rows = resp.json()
        assert isinstance(rows, list)
        assert "row" in rows[0]
        assert "cells" in rows[0]

    @pytest.mark.asyncio
    async def test_viewer_integrations_response_shape(
        self, client: AsyncClient, viewer_headers: dict
    ) -> None:
        resp = await client.get("/api/v1/overview/integrations", headers=viewer_headers)
        assert resp.status_code == 200
        items = resp.json()
        assert isinstance(items, list)
        assert "name" in items[0]
        assert "status" in items[0]

    @pytest.mark.asyncio
    async def test_viewer_recent_detections_response_shape(
        self, client: AsyncClient, viewer_headers: dict
    ) -> None:
        resp = await client.get("/api/v1/overview/recent-detections", headers=viewer_headers)
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)


# ---------------------------------------------------------------------------
# All roles can access dashboard endpoints
# ---------------------------------------------------------------------------


class TestAllRolesDashboardAccess:
    """All authenticated roles can access dashboard (overview) endpoints."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("headers_fixture", [
        "viewer_headers", "analyst_headers", "hunter_headers",
        "engineer_headers", "admin_headers",
    ])
    async def test_all_roles_can_access_kpis(
        self, request, client: AsyncClient, headers_fixture: str
    ) -> None:
        headers = request.getfixturevalue(headers_fixture)
        resp = await client.get("/api/v1/overview/kpis", headers=headers)
        assert resp.status_code == 200, (
            f"Role '{headers_fixture.replace('_headers', '')}' should access /overview/kpis"
        )

    @pytest.mark.asyncio
    @pytest.mark.parametrize("headers_fixture", [
        "viewer_headers", "analyst_headers", "hunter_headers",
        "engineer_headers", "admin_headers",
    ])
    async def test_all_roles_can_access_recent_detections(
        self, request, client: AsyncClient, headers_fixture: str
    ) -> None:
        headers = request.getfixturevalue(headers_fixture)
        resp = await client.get("/api/v1/overview/recent-detections", headers=headers)
        assert resp.status_code == 200, (
            f"Role '{headers_fixture.replace('_headers', '')}' should access /overview/recent-detections"
        )


# ---------------------------------------------------------------------------
# Alerts (detections) — viewer read access
# ---------------------------------------------------------------------------


class TestViewerAlertsAccess:
    """Viewer can read detections (alerts) but cannot modify them."""

    @pytest.mark.asyncio
    async def test_viewer_can_list_detections(
        self, client: AsyncClient, viewer_headers: dict
    ) -> None:
        resp = await client.get("/api/v1/detections", headers=viewer_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        assert "pagination" in data

    @pytest.mark.asyncio
    async def test_viewer_cannot_patch_detection(
        self, client: AsyncClient, viewer_headers: dict
    ) -> None:
        resp = await client.patch(
            "/api/v1/detections/DET-2026-00001",
            headers=viewer_headers,
            json={"status": "investigating"},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_viewer_patch_forbidden_has_detail(
        self, client: AsyncClient, viewer_headers: dict
    ) -> None:
        resp = await client.patch(
            "/api/v1/detections/DET-2026-00001",
            headers=viewer_headers,
            json={"status": "resolved"},
        )
        assert resp.status_code == 403
        body = resp.json()
        assert "detail" in body
        assert "viewer" in body["detail"]

    @pytest.mark.asyncio
    async def test_viewer_patch_forbidden_precedes_404(
        self, client: AsyncClient, viewer_headers: dict
    ) -> None:
        """RBAC check runs before DB lookup — viewer gets 403, not 404, for nonexistent IDs."""
        resp = await client.patch(
            "/api/v1/detections/nonexistent-id",
            headers=viewer_headers,
            json={"status": "investigating"},
        )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Incidents — viewer read access
# ---------------------------------------------------------------------------


class TestViewerIncidentsAccess:
    """Viewer can read incidents but cannot create or modify them."""

    @pytest.mark.asyncio
    async def test_viewer_can_list_incidents(
        self, client: AsyncClient, viewer_headers: dict
    ) -> None:
        resp = await client.get("/api/v1/incidents", headers=viewer_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        assert "pagination" in data

    @pytest.mark.asyncio
    async def test_viewer_cannot_create_incident(
        self, client: AsyncClient, viewer_headers: dict
    ) -> None:
        resp = await client.post(
            "/api/v1/incidents",
            headers=viewer_headers,
            json={
                "title": "Test Incident",
                "description": "Attempted by viewer",
                "severity": "high",
                "detection_ids": [],
            },
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_viewer_cannot_patch_incident(
        self, client: AsyncClient, viewer_headers: dict
    ) -> None:
        resp = await client.patch(
            "/api/v1/incidents/1",
            headers=viewer_headers,
            json={"status": "investigating"},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_viewer_create_incident_forbidden_has_detail(
        self, client: AsyncClient, viewer_headers: dict
    ) -> None:
        resp = await client.post(
            "/api/v1/incidents",
            headers=viewer_headers,
            json={"title": "X", "severity": "low", "detection_ids": []},
        )
        assert resp.status_code == 403
        body = resp.json()
        assert "detail" in body
        assert "viewer" in body["detail"]


# ---------------------------------------------------------------------------
# Unauthenticated access to detections and incidents
# ---------------------------------------------------------------------------


class TestUnauthenticatedAccess:
    """Unauthenticated requests to protected endpoints return 401."""

    @pytest.mark.asyncio
    async def test_unauthenticated_detections_returns_401(
        self, client: AsyncClient
    ) -> None:
        resp = await client.get("/api/v1/detections")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_unauthenticated_incidents_returns_401(
        self, client: AsyncClient
    ) -> None:
        resp = await client.get("/api/v1/incidents")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    @pytest.mark.parametrize("url", _OVERVIEW_READ_ENDPOINTS)
    async def test_unauthenticated_overview_returns_401(
        self, client: AsyncClient, url: str
    ) -> None:
        resp = await client.get(url)
        assert resp.status_code == 401
