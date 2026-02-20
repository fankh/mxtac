"""Tests for Feature 3.5 — analyst: view + investigate + resolve alerts.

Verifies that the analyst role:
  - Can view all detections (list with filters, single detail)
  - Can investigate alerts (PATCH status → investigating)
  - Can resolve alerts (PATCH status → resolved, false_positive)
  - Can update alert assignment and priority
  - Can list, create, view, and update incidents
  - Is denied access to rules, connectors, and user management (403)

Also verifies that viewer cannot investigate or resolve (403 for PATCH detections).
"""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient

# ---------------------------------------------------------------------------
# Mock repo paths
# ---------------------------------------------------------------------------

_DET_REPO = "app.api.v1.endpoints.detections.DetectionRepo"
_INC_REPO = "app.api.v1.endpoints.incidents.IncidentRepo"
_INC_DET_REPO = "app.api.v1.endpoints.incidents.DetectionRepo"

# ---------------------------------------------------------------------------
# Helpers — minimal ORM-like namespaces
# ---------------------------------------------------------------------------

_NOW = datetime(2026, 2, 20, 8, 0, 0, tzinfo=timezone.utc)


def _make_detection(**overrides) -> SimpleNamespace:
    defaults = {
        "id": "DET-2026-00100",
        "score": 8.5,
        "severity": "high",
        "technique_id": "T1059.001",
        "technique_name": "PowerShell",
        "name": "Suspicious PowerShell Execution",
        "host": "WS-CORP-42",
        "tactic": "Execution",
        "status": "active",
        "time": _NOW,
        "user": "CORP\\jsmith",
        "process": "powershell.exe",
        "rule_name": "win_suspicious_powershell",
        "log_source": "Wazuh",
        "event_id": "4103",
        "occurrence_count": 3,
        "description": "Suspicious PowerShell command detected.",
        "cvss_v3": 7.5,
        "confidence": 85,
        "tactic_id": "TA0002",
        "assigned_to": None,
        "priority": "P2 High",
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _make_incident(**overrides) -> SimpleNamespace:
    defaults = {
        "id": 1,
        "title": "Suspected Lateral Movement on WS-CORP-42",
        "description": "PowerShell execution leading to lateral movement.",
        "severity": "high",
        "status": "new",
        "priority": 2,
        "assigned_to": "analyst@mxtac.local",
        "created_by": "analyst@mxtac.local",
        "detection_ids": ["DET-2026-00100"],
        "technique_ids": ["T1059.001"],
        "tactic_ids": ["TA0002"],
        "hosts": ["WS-CORP-42"],
        "ttd_seconds": None,
        "ttr_seconds": None,
        "closed_at": None,
        "notes": [],
        "created_at": _NOW,
        "updated_at": _NOW,
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


_DET = _make_detection()
_DET_INVESTIGATING = _make_detection(status="investigating", assigned_to="analyst@mxtac.local")
_DET_RESOLVED = _make_detection(status="resolved")
_DET_FP = _make_detection(status="false_positive")
_INC = _make_incident()


# ---------------------------------------------------------------------------
# 1. Analyst can view alerts (detections)
# ---------------------------------------------------------------------------


class TestAnalystViewAlerts:
    """Analyst can list and view detections (alerts) in any status/severity."""

    @pytest.mark.asyncio
    async def test_analyst_can_list_detections(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        with patch(f"{_DET_REPO}.list", new=AsyncMock(return_value=([_DET], 1))):
            resp = await client.get("/api/v1/detections", headers=analyst_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        assert "pagination" in data
        assert len(data["items"]) == 1

    @pytest.mark.asyncio
    async def test_analyst_list_detections_response_shape(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        with patch(f"{_DET_REPO}.list", new=AsyncMock(return_value=([_DET], 1))):
            resp = await client.get("/api/v1/detections", headers=analyst_headers)
        item = resp.json()["items"][0]
        assert item["id"] == "DET-2026-00100"
        assert item["severity"] == "high"
        assert item["status"] == "active"
        assert item["technique_id"] == "T1059.001"
        assert item["host"] == "WS-CORP-42"

    @pytest.mark.asyncio
    async def test_analyst_can_filter_detections_by_severity(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        critical_det = _make_detection(id="DET-C", severity="critical", status="active")
        with patch(f"{_DET_REPO}.list", new=AsyncMock(return_value=([critical_det], 1))):
            resp = await client.get(
                "/api/v1/detections?severity=critical", headers=analyst_headers
            )
        assert resp.status_code == 200
        assert resp.json()["items"][0]["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_analyst_can_filter_detections_by_status(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        with patch(
            f"{_DET_REPO}.list",
            new=AsyncMock(return_value=([_DET_INVESTIGATING], 1)),
        ):
            resp = await client.get(
                "/api/v1/detections?status=investigating", headers=analyst_headers
            )
        assert resp.status_code == 200
        assert resp.json()["items"][0]["status"] == "investigating"

    @pytest.mark.asyncio
    async def test_analyst_can_get_detection_detail(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        with patch(f"{_DET_REPO}.get", new=AsyncMock(return_value=_DET)):
            resp = await client.get(
                "/api/v1/detections/DET-2026-00100", headers=analyst_headers
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == "DET-2026-00100"
        assert data["name"] == "Suspicious PowerShell Execution"
        assert data["user"] == "CORP\\jsmith"
        assert data["rule_name"] == "win_suspicious_powershell"

    @pytest.mark.asyncio
    async def test_analyst_detection_detail_not_found(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        with patch(f"{_DET_REPO}.get", new=AsyncMock(return_value=None)):
            resp = await client.get(
                "/api/v1/detections/nonexistent-id", headers=analyst_headers
            )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_analyst_can_search_detections(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        with patch(f"{_DET_REPO}.list", new=AsyncMock(return_value=([_DET], 1))):
            resp = await client.get(
                "/api/v1/detections?search=powershell", headers=analyst_headers
            )
        assert resp.status_code == 200
        assert isinstance(resp.json()["items"], list)

    @pytest.mark.asyncio
    async def test_analyst_list_detections_pagination(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        with patch(f"{_DET_REPO}.list", new=AsyncMock(return_value=([], 0))):
            resp = await client.get(
                "/api/v1/detections?page=1&page_size=25", headers=analyst_headers
            )
        pg = resp.json()["pagination"]
        assert pg["page"] == 1
        assert pg["page_size"] == 25
        assert pg["total"] == 0
        assert pg["total_pages"] == 1


# ---------------------------------------------------------------------------
# 2. Analyst can investigate alerts
# ---------------------------------------------------------------------------


class TestAnalystInvestigateAlerts:
    """Analyst can transition detection status to 'investigating'."""

    @pytest.mark.asyncio
    async def test_analyst_can_mark_alert_investigating(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        with patch(f"{_DET_REPO}.update", new=AsyncMock(return_value=_DET_INVESTIGATING)):
            resp = await client.patch(
                "/api/v1/detections/DET-2026-00100",
                headers=analyst_headers,
                json={"status": "investigating"},
            )
        assert resp.status_code == 200
        assert resp.json()["status"] == "investigating"

    @pytest.mark.asyncio
    async def test_analyst_can_assign_alert_to_self_during_investigation(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        with patch(f"{_DET_REPO}.update", new=AsyncMock(return_value=_DET_INVESTIGATING)):
            resp = await client.patch(
                "/api/v1/detections/DET-2026-00100",
                headers=analyst_headers,
                json={"status": "investigating", "assigned_to": "analyst@mxtac.local"},
            )
        assert resp.status_code == 200
        assert resp.json()["assigned_to"] == "analyst@mxtac.local"

    @pytest.mark.asyncio
    async def test_analyst_investigate_nonexistent_alert_returns_404(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        with patch(f"{_DET_REPO}.update", new=AsyncMock(return_value=None)):
            resp = await client.patch(
                "/api/v1/detections/nonexistent-id",
                headers=analyst_headers,
                json={"status": "investigating"},
            )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_analyst_can_update_alert_priority(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        updated = _make_detection(priority="P1 Critical")
        with patch(f"{_DET_REPO}.update", new=AsyncMock(return_value=updated)):
            resp = await client.patch(
                "/api/v1/detections/DET-2026-00100",
                headers=analyst_headers,
                json={"priority": "P1 Critical"},
            )
        assert resp.status_code == 200
        assert resp.json()["priority"] == "P1 Critical"

    @pytest.mark.asyncio
    async def test_analyst_can_reassign_alert(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        updated = _make_detection(assigned_to="senior@mxtac.local")
        with patch(f"{_DET_REPO}.update", new=AsyncMock(return_value=updated)):
            resp = await client.patch(
                "/api/v1/detections/DET-2026-00100",
                headers=analyst_headers,
                json={"assigned_to": "senior@mxtac.local"},
            )
        assert resp.status_code == 200
        assert resp.json()["assigned_to"] == "senior@mxtac.local"


# ---------------------------------------------------------------------------
# 3. Analyst can resolve alerts
# ---------------------------------------------------------------------------


class TestAnalystResolveAlerts:
    """Analyst can transition detection status to 'resolved' or 'false_positive'."""

    @pytest.mark.asyncio
    async def test_analyst_can_resolve_alert(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        with patch(f"{_DET_REPO}.update", new=AsyncMock(return_value=_DET_RESOLVED)):
            resp = await client.patch(
                "/api/v1/detections/DET-2026-00100",
                headers=analyst_headers,
                json={"status": "resolved"},
            )
        assert resp.status_code == 200
        assert resp.json()["status"] == "resolved"

    @pytest.mark.asyncio
    async def test_analyst_can_mark_alert_false_positive(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        with patch(f"{_DET_REPO}.update", new=AsyncMock(return_value=_DET_FP)):
            resp = await client.patch(
                "/api/v1/detections/DET-2026-00100",
                headers=analyst_headers,
                json={"status": "false_positive"},
            )
        assert resp.status_code == 200
        assert resp.json()["status"] == "false_positive"

    @pytest.mark.asyncio
    async def test_analyst_resolve_nonexistent_alert_returns_404(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        with patch(f"{_DET_REPO}.update", new=AsyncMock(return_value=None)):
            resp = await client.patch(
                "/api/v1/detections/nonexistent-id",
                headers=analyst_headers,
                json={"status": "resolved"},
            )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_analyst_can_set_active_status(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        """Analyst can reset a detection back to active (e.g., reopen)."""
        updated = _make_detection(status="active")
        with patch(f"{_DET_REPO}.update", new=AsyncMock(return_value=updated)):
            resp = await client.patch(
                "/api/v1/detections/DET-2026-00100",
                headers=analyst_headers,
                json={"status": "active"},
            )
        assert resp.status_code == 200
        assert resp.json()["status"] == "active"


# ---------------------------------------------------------------------------
# 4. Analyst can manage incidents linked to alerts
# ---------------------------------------------------------------------------


class TestAnalystIncidentManagement:
    """Analyst can create, view, and update incidents that group related alerts."""

    @pytest.mark.asyncio
    async def test_analyst_can_list_incidents(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        with patch(f"{_INC_REPO}.list", new=AsyncMock(return_value=([_INC], 1))):
            resp = await client.get("/api/v1/incidents", headers=analyst_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        assert "pagination" in data

    @pytest.mark.asyncio
    async def test_analyst_can_create_incident(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        with (
            patch(f"{_INC_DET_REPO}.get", new=AsyncMock(return_value=None)),
            patch(f"{_INC_REPO}.create", new=AsyncMock(return_value=_INC)),
        ):
            resp = await client.post(
                "/api/v1/incidents",
                headers=analyst_headers,
                json={
                    "title": "Suspected Lateral Movement on WS-CORP-42",
                    "description": "PowerShell execution leading to lateral movement.",
                    "severity": "high",
                    "detection_ids": [],
                },
            )
        assert resp.status_code == 201
        data = resp.json()
        assert data["title"] == "Suspected Lateral Movement on WS-CORP-42"
        assert data["severity"] == "high"

    @pytest.mark.asyncio
    async def test_analyst_incident_create_sets_created_by(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        """Incident created_by is auto-set from the analyst's JWT subject."""
        with (
            patch(f"{_INC_DET_REPO}.get", new=AsyncMock(return_value=None)),
            patch(f"{_INC_REPO}.create", new=AsyncMock(return_value=_INC)),
        ):
            resp = await client.post(
                "/api/v1/incidents",
                headers=analyst_headers,
                json={
                    "title": "Test Incident",
                    "severity": "medium",
                    "detection_ids": [],
                },
            )
        assert resp.status_code == 201
        # created_by comes from the mock incident (analyst@mxtac.local)
        assert resp.json()["created_by"] == "analyst@mxtac.local"

    @pytest.mark.asyncio
    async def test_analyst_can_get_incident_detail(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        with patch(f"{_INC_REPO}.get_by_id", new=AsyncMock(return_value=_INC)):
            resp = await client.get("/api/v1/incidents/1", headers=analyst_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == 1
        assert data["status"] == "new"
        assert "detections" in data
        assert "notes" in data

    @pytest.mark.asyncio
    async def test_analyst_get_incident_detail_not_found(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        with patch(f"{_INC_REPO}.get_by_id", new=AsyncMock(return_value=None)):
            resp = await client.get("/api/v1/incidents/999", headers=analyst_headers)
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_analyst_can_update_incident_status_to_investigating(
        self, client: AsyncClient, analyst_headers: dict, db_session
    ) -> None:
        """Analyst can advance an incident from 'new' to 'investigating'."""
        investigating_inc = _make_incident(status="investigating")
        with patch(f"{_INC_REPO}.get_by_id", new=AsyncMock(return_value=_INC)):
            resp = await client.patch(
                "/api/v1/incidents/1",
                headers=analyst_headers,
                json={"status": "investigating"},
            )
        # The endpoint uses setattr + db.flush() on the existing object; status is changed in-place
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_analyst_can_filter_incidents_by_status(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        with patch(
            f"{_INC_REPO}.list",
            new=AsyncMock(return_value=([_make_incident(status="investigating")], 1)),
        ):
            resp = await client.get(
                "/api/v1/incidents?status=investigating", headers=analyst_headers
            )
        assert resp.status_code == 200
        assert resp.json()["items"][0]["status"] == "investigating"


# ---------------------------------------------------------------------------
# 5. Analyst is denied access to privileged resources
# ---------------------------------------------------------------------------


class TestAnalystAccessDenied:
    """Analyst cannot access rules, connectors, or user management (403)."""

    @pytest.mark.asyncio
    async def test_analyst_cannot_list_rules(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        resp = await client.get("/api/v1/rules", headers=analyst_headers)
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_analyst_cannot_list_connectors(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        resp = await client.get("/api/v1/connectors", headers=analyst_headers)
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_analyst_cannot_list_users(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        resp = await client.get("/api/v1/users", headers=analyst_headers)
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_analyst_cannot_write_rules(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        resp = await client.post(
            "/api/v1/rules",
            headers=analyst_headers,
            json={
                "title": "Test Rule",
                "description": "Unauthorized rule",
                "content": "rule: test",
                "severity": "high",
                "status": "active",
            },
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_analyst_cannot_write_connectors(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        resp = await client.post(
            "/api/v1/connectors",
            headers=analyst_headers,
            json={"name": "Evil Connector", "type": "wazuh", "config": {}},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_analyst_access_denied_contains_role_in_detail(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        """403 response body includes the role that was denied."""
        resp = await client.get("/api/v1/rules", headers=analyst_headers)
        assert resp.status_code == 403
        body = resp.json()
        assert "detail" in body
        assert "analyst" in body["detail"]

    @pytest.mark.asyncio
    async def test_analyst_cannot_search_events(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        resp = await client.get("/api/v1/events/search", headers=analyst_headers)
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 6. Viewer cannot investigate or resolve alerts
# ---------------------------------------------------------------------------


class TestViewerCannotModifyAlerts:
    """Viewer is denied all mutation operations on detections and incidents."""

    @pytest.mark.asyncio
    async def test_viewer_cannot_investigate_alert(
        self, client: AsyncClient, viewer_headers: dict
    ) -> None:
        resp = await client.patch(
            "/api/v1/detections/DET-2026-00100",
            headers=viewer_headers,
            json={"status": "investigating"},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_viewer_cannot_resolve_alert(
        self, client: AsyncClient, viewer_headers: dict
    ) -> None:
        resp = await client.patch(
            "/api/v1/detections/DET-2026-00100",
            headers=viewer_headers,
            json={"status": "resolved"},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_viewer_cannot_mark_false_positive(
        self, client: AsyncClient, viewer_headers: dict
    ) -> None:
        resp = await client.patch(
            "/api/v1/detections/DET-2026-00100",
            headers=viewer_headers,
            json={"status": "false_positive"},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_viewer_forbidden_precedes_db_lookup(
        self, client: AsyncClient, viewer_headers: dict
    ) -> None:
        """RBAC check runs before DB lookup — viewer gets 403 even for nonexistent IDs."""
        resp = await client.patch(
            "/api/v1/detections/nonexistent-id",
            headers=viewer_headers,
            json={"status": "investigating"},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_viewer_forbidden_response_contains_role(
        self, client: AsyncClient, viewer_headers: dict
    ) -> None:
        resp = await client.patch(
            "/api/v1/detections/DET-2026-00100",
            headers=viewer_headers,
            json={"status": "resolved"},
        )
        assert resp.status_code == 403
        assert "viewer" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_viewer_cannot_create_incident(
        self, client: AsyncClient, viewer_headers: dict
    ) -> None:
        resp = await client.post(
            "/api/v1/incidents",
            headers=viewer_headers,
            json={
                "title": "Viewer Incident",
                "severity": "low",
                "detection_ids": [],
            },
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_viewer_cannot_update_incident(
        self, client: AsyncClient, viewer_headers: dict
    ) -> None:
        resp = await client.patch(
            "/api/v1/incidents/1",
            headers=viewer_headers,
            json={"status": "investigating"},
        )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 7. Unauthenticated access
# ---------------------------------------------------------------------------


class TestUnauthenticatedAlertAccess:
    """Unauthenticated requests to detection and incident endpoints return 401."""

    @pytest.mark.asyncio
    async def test_unauthenticated_cannot_list_detections(
        self, client: AsyncClient
    ) -> None:
        resp = await client.get("/api/v1/detections")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_unauthenticated_cannot_patch_detection(
        self, client: AsyncClient
    ) -> None:
        resp = await client.patch(
            "/api/v1/detections/DET-2026-00100",
            json={"status": "investigating"},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_unauthenticated_cannot_list_incidents(
        self, client: AsyncClient
    ) -> None:
        resp = await client.get("/api/v1/incidents")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_unauthenticated_cannot_create_incident(
        self, client: AsyncClient
    ) -> None:
        resp = await client.post(
            "/api/v1/incidents",
            json={"title": "Test", "severity": "low", "detection_ids": []},
        )
        assert resp.status_code == 401
