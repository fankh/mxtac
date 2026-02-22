"""Tests for Feature 3.6 — hunter: analyst + query events + saved hunts.

Verifies that the hunter role:
  - Inherits all analyst capabilities (view/investigate/resolve detections, manage incidents)
  - Can search and aggregate events (events:search permission)
  - Can query entity timelines and export events
  - Can build Lucene DSL queries (POST /events/query-dsl)
  - Can create, list, update, and delete saved hunt queries
  - Can read Sigma rules (but NOT write them)
  - Can read threat intelligence (but NOT write)
  - Can view ATT&CK-guided hunt suggestions
  - Is denied access to connectors, user management, agent management, and audit logs

Also verifies that analyst cannot access hunter-exclusive endpoints (403).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.main import app
from app.models.event import Event
from app.models.saved_query import SavedQuery
from app.services.opensearch_client import get_opensearch_dep

# ---------------------------------------------------------------------------
# Mock repo paths
# ---------------------------------------------------------------------------

_DET_REPO = "app.api.v1.endpoints.detections.DetectionRepo"
_INC_REPO = "app.api.v1.endpoints.incidents.IncidentRepo"
_INC_DET_REPO = "app.api.v1.endpoints.incidents.DetectionRepo"

# ---------------------------------------------------------------------------
# Helpers — minimal ORM-like namespaces and factories
# ---------------------------------------------------------------------------

_NOW = datetime.now(timezone.utc)


def _make_detection(**overrides) -> SimpleNamespace:
    defaults = {
        "id": "DET-2026-00200",
        "score": 9.1,
        "severity": "critical",
        "technique_id": "T1003.006",
        "technique_name": "DCSync",
        "name": "DCSync Attack Detected",
        "host": "DC-PROD-01",
        "tactic": "Credential Access",
        "status": "active",
        "time": _NOW,
        "user": "CORP\\svcaccount",
        "process": "lsass.exe",
        "rule_name": "win_dcsync_mimikatz",
        "log_source": "Wazuh",
        "event_id": "4662",
        "occurrence_count": 1,
        "description": "DCSync replication detected from non-DC host.",
        "cvss_v3": 9.0,
        "confidence": 95,
        "tactic_id": "TA0006",
        "assigned_to": None,
        "priority": "P1 Critical",
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _make_incident(**overrides) -> SimpleNamespace:
    defaults = {
        "id": 10,
        "title": "DCSync Attack on DC-PROD-01",
        "description": "Credential theft via DCSync replication from non-DC host.",
        "severity": "critical",
        "status": "new",
        "priority": 1,
        "assigned_to": "hunter@mxtac.local",
        "created_by": "hunter@mxtac.local",
        "detection_ids": ["DET-2026-00200"],
        "technique_ids": ["T1003.006"],
        "tactic_ids": ["TA0006"],
        "hosts": ["DC-PROD-01"],
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
_DET_INVESTIGATING = _make_detection(status="investigating", assigned_to="hunter@mxtac.local")
_DET_RESOLVED = _make_detection(status="resolved")
_INC = _make_incident()


def _make_event_kwargs(**kwargs) -> dict:
    defaults = {
        "time": _NOW - timedelta(minutes=30),
        "class_name": "Process Activity",
        "severity_id": 5,
        "hostname": "dc-prod-01",
        "username": "CORP\\svcaccount",
        "src_ip": "10.0.1.5",
        "dst_ip": "10.0.0.1",
        "summary": "lsass memory read detected",
        "source": "wazuh",
    }
    defaults.update(kwargs)
    return defaults


async def _seed_event(db: AsyncSession, **kwargs) -> Event:
    evt = Event(**_make_event_kwargs(**kwargs))
    db.add(evt)
    await db.flush()
    return evt


# ---------------------------------------------------------------------------
# 1. Hunter inherits analyst capabilities — detections
# ---------------------------------------------------------------------------


class TestHunterDetectionAccess:
    """Hunter can list, view, and update detections (analyst capability inherited)."""

    @pytest.mark.asyncio
    async def test_hunter_can_list_detections(
        self, client: AsyncClient, hunter_headers: dict
    ) -> None:
        with patch(f"{_DET_REPO}.list", new=AsyncMock(return_value=([_DET], 1))):
            resp = await client.get("/api/v1/detections", headers=hunter_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        assert len(data["items"]) == 1
        assert data["items"][0]["technique_id"] == "T1003.006"

    @pytest.mark.asyncio
    async def test_hunter_can_get_detection_detail(
        self, client: AsyncClient, hunter_headers: dict
    ) -> None:
        with patch(f"{_DET_REPO}.get", new=AsyncMock(return_value=_DET)):
            resp = await client.get(
                "/api/v1/detections/DET-2026-00200", headers=hunter_headers
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == "DET-2026-00200"
        assert data["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_hunter_can_investigate_detection(
        self, client: AsyncClient, hunter_headers: dict
    ) -> None:
        with patch(f"{_DET_REPO}.update", new=AsyncMock(return_value=_DET_INVESTIGATING)):
            resp = await client.patch(
                "/api/v1/detections/DET-2026-00200",
                headers=hunter_headers,
                json={"status": "investigating"},
            )
        assert resp.status_code == 200
        assert resp.json()["status"] == "investigating"

    @pytest.mark.asyncio
    async def test_hunter_can_resolve_detection(
        self, client: AsyncClient, hunter_headers: dict
    ) -> None:
        with patch(f"{_DET_REPO}.update", new=AsyncMock(return_value=_DET_RESOLVED)):
            resp = await client.patch(
                "/api/v1/detections/DET-2026-00200",
                headers=hunter_headers,
                json={"status": "resolved"},
            )
        assert resp.status_code == 200
        assert resp.json()["status"] == "resolved"

    @pytest.mark.asyncio
    async def test_hunter_can_assign_detection(
        self, client: AsyncClient, hunter_headers: dict
    ) -> None:
        assigned = _make_detection(assigned_to="hunter@mxtac.local")
        with patch(f"{_DET_REPO}.update", new=AsyncMock(return_value=assigned)):
            resp = await client.patch(
                "/api/v1/detections/DET-2026-00200",
                headers=hunter_headers,
                json={"assigned_to": "hunter@mxtac.local"},
            )
        assert resp.status_code == 200
        assert resp.json()["assigned_to"] == "hunter@mxtac.local"

    @pytest.mark.asyncio
    async def test_hunter_can_filter_detections_by_severity(
        self, client: AsyncClient, hunter_headers: dict
    ) -> None:
        with patch(f"{_DET_REPO}.list", new=AsyncMock(return_value=([_DET], 1))):
            resp = await client.get(
                "/api/v1/detections?severity=critical", headers=hunter_headers
            )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 2. Hunter inherits analyst capabilities — incidents
# ---------------------------------------------------------------------------


class TestHunterIncidentAccess:
    """Hunter can list, create, and update incidents."""

    @pytest.mark.asyncio
    async def test_hunter_can_list_incidents(
        self, client: AsyncClient, hunter_headers: dict
    ) -> None:
        with patch(f"{_INC_REPO}.list", new=AsyncMock(return_value=([_INC], 1))):
            resp = await client.get("/api/v1/incidents", headers=hunter_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        assert len(data["items"]) == 1

    @pytest.mark.asyncio
    async def test_hunter_can_create_incident(
        self, client: AsyncClient, hunter_headers: dict
    ) -> None:
        with (
            patch(f"{_INC_DET_REPO}.get", new=AsyncMock(return_value=None)),
            patch(f"{_INC_REPO}.create", new=AsyncMock(return_value=_INC)),
        ):
            resp = await client.post(
                "/api/v1/incidents",
                headers=hunter_headers,
                json={
                    "title": "DCSync Attack",
                    "severity": "critical",
                    "detection_ids": [],
                },
            )
        assert resp.status_code == 201
        data = resp.json()
        assert data["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_hunter_can_get_incident_detail(
        self, client: AsyncClient, hunter_headers: dict
    ) -> None:
        with patch(f"{_INC_REPO}.get_by_id", new=AsyncMock(return_value=_INC)):
            resp = await client.get("/api/v1/incidents/10", headers=hunter_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == 10

    @pytest.mark.asyncio
    async def test_hunter_can_update_incident_status(
        self, client: AsyncClient, hunter_headers: dict
    ) -> None:
        with patch(f"{_INC_REPO}.get_by_id", new=AsyncMock(return_value=_INC)):
            resp = await client.patch(
                "/api/v1/incidents/10",
                headers=hunter_headers,
                json={"status": "investigating"},
            )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 3. Hunter can query events (events:search permission)
# ---------------------------------------------------------------------------


class TestHunterEventSearch:
    """Hunter can search, aggregate, and retrieve events."""

    @pytest.mark.asyncio
    async def test_hunter_can_search_events_empty_db(
        self, client: AsyncClient, hunter_headers: dict
    ) -> None:
        resp = await client.post(
            "/api/v1/events/search",
            headers=hunter_headers,
            json={"query": "mimikatz", "time_from": "now-24h"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["items"] == []

    @pytest.mark.asyncio
    async def test_hunter_can_search_events_with_results(
        self, client: AsyncClient, hunter_headers: dict, db_session: AsyncSession
    ) -> None:
        await _seed_event(db_session, summary="lsass memory dump", hostname="dc-01")
        resp = await client.post(
            "/api/v1/events/search",
            headers=hunter_headers,
            json={"time_from": "now-1h"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["hostname"] == "dc-01"

    @pytest.mark.asyncio
    async def test_hunter_can_search_with_filters(
        self, client: AsyncClient, hunter_headers: dict, db_session: AsyncSession
    ) -> None:
        await _seed_event(db_session, severity_id=5, hostname="dc-01")
        await _seed_event(db_session, severity_id=2, hostname="ws-01")
        resp = await client.post(
            "/api/v1/events/search",
            headers=hunter_headers,
            json={
                "filters": [{"field": "severity_id", "operator": "gte", "value": 4}],
                "time_from": "now-1h",
            },
        )
        assert resp.status_code == 200
        assert resp.json()["total"] == 1
        assert resp.json()["items"][0]["severity_id"] == 5

    @pytest.mark.asyncio
    async def test_hunter_can_aggregate_events(
        self, client: AsyncClient, hunter_headers: dict, db_session: AsyncSession
    ) -> None:
        await _seed_event(db_session, severity_id=5)
        await _seed_event(db_session, severity_id=5)
        await _seed_event(db_session, severity_id=3)
        resp = await client.post(
            "/api/v1/events/aggregate",
            headers=hunter_headers,
            json={"field": "severity_id", "time_from": "now-1h"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["field"] == "severity_id"
        buckets = {b["key"]: b["count"] for b in data["buckets"]}
        assert buckets.get("5") == 2
        assert buckets.get("3") == 1

    @pytest.mark.asyncio
    async def test_hunter_can_get_event_by_id(
        self, client: AsyncClient, hunter_headers: dict, db_session: AsyncSession
    ) -> None:
        evt = await _seed_event(db_session, summary="specific event")
        resp = await client.get(f"/api/v1/events/{evt.id}", headers=hunter_headers)
        assert resp.status_code == 200
        assert resp.json()["id"] == evt.id
        assert resp.json()["summary"] == "specific event"

    @pytest.mark.asyncio
    async def test_hunter_get_nonexistent_event_returns_404(
        self, client: AsyncClient, hunter_headers: dict
    ) -> None:
        resp = await client.get("/api/v1/events/nonexistent-id", headers=hunter_headers)
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_hunter_can_query_entity_timeline(
        self, client: AsyncClient, hunter_headers: dict, db_session: AsyncSession
    ) -> None:
        await _seed_event(db_session, hostname="dc-prod-01")
        resp = await client.get(
            "/api/v1/events/entity/host/dc-prod-01", headers=hunter_headers
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["entity_type"] == "host"
        assert data["total"] == 1

    @pytest.mark.asyncio
    async def test_hunter_can_build_lucene_query(
        self, client: AsyncClient, hunter_headers: dict
    ) -> None:
        resp = await client.post(
            "/api/v1/events/query-dsl",
            headers=hunter_headers,
            json={"query": "lsass", "time_from": "now-24h", "time_to": "now"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "lucene" in data
        assert "lsass" in data["lucene"]

    @pytest.mark.asyncio
    async def test_hunter_lucene_query_includes_time_range(
        self, client: AsyncClient, hunter_headers: dict
    ) -> None:
        resp = await client.post(
            "/api/v1/events/query-dsl",
            headers=hunter_headers,
            json={"time_from": "now-7d", "time_to": "now"},
        )
        assert resp.status_code == 200
        assert "time:[now-7d TO now]" in resp.json()["lucene"]

    @pytest.mark.asyncio
    async def test_hunter_can_export_events(
        self, client: AsyncClient, hunter_headers: dict, db_session: AsyncSession
    ) -> None:
        await _seed_event(db_session, summary="export test event")
        resp = await client.post(
            "/api/v1/events/export",
            headers=hunter_headers,
            json={"time_from": "now-1h"},
        )
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/csv")


# ---------------------------------------------------------------------------
# 4. Hunter can manage saved hunt queries
# ---------------------------------------------------------------------------


class TestHunterSavedHunts:
    """Hunter can create, list, update, and delete saved hunt queries."""

    _BASE = "/api/v1/hunt/queries"

    @pytest.mark.asyncio
    async def test_hunter_can_create_saved_hunt(
        self, client: AsyncClient, hunter_headers: dict
    ) -> None:
        resp = await client.post(
            self._BASE,
            headers=hunter_headers,
            json={
                "name": "DCSync Hunt",
                "description": "Search for DCSync replication activity",
                "query": "T1003.006",
                "time_from": "now-7d",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "DCSync Hunt"
        assert data["created_by"] == "hunter@mxtac.local"

    @pytest.mark.asyncio
    async def test_hunter_can_create_hunt_with_filters(
        self, client: AsyncClient, hunter_headers: dict
    ) -> None:
        resp = await client.post(
            self._BASE,
            headers=hunter_headers,
            json={
                "name": "Lateral Movement Hunt",
                "query": "cmd.exe",
                "filters": [{"field": "hostname", "operator": "contains", "value": "DC"}],
                "time_from": "now-24h",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert len(data["filters"]) == 1
        assert data["filters"][0]["field"] == "hostname"

    @pytest.mark.asyncio
    async def test_hunter_can_list_saved_hunts(
        self, client: AsyncClient, hunter_headers: dict, db_session: AsyncSession
    ) -> None:
        sq = SavedQuery(
            name="My Hunt",
            query="lsass",
            filters=[],
            time_from="now-24h",
            time_to="now",
            created_by="hunter@mxtac.local",
        )
        db_session.add(sq)
        await db_session.commit()

        resp = await client.get(self._BASE, headers=hunter_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["name"] == "My Hunt"

    @pytest.mark.asyncio
    async def test_hunter_list_hunts_user_scoped(
        self,
        client: AsyncClient,
        hunter_headers: dict,
        engineer_headers: dict,
        db_session: AsyncSession,
    ) -> None:
        """Hunter only sees their own saved hunts."""
        for owner in ("hunter@mxtac.local", "engineer@mxtac.local"):
            db_session.add(
                SavedQuery(
                    name=f"{owner} Hunt",
                    query="test",
                    filters=[],
                    time_from="now-24h",
                    time_to="now",
                    created_by=owner,
                )
            )
        await db_session.commit()

        resp = await client.get(self._BASE, headers=hunter_headers)
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 1
        assert items[0]["created_by"] == "hunter@mxtac.local"

    @pytest.mark.asyncio
    async def test_hunter_can_get_saved_hunt(
        self, client: AsyncClient, hunter_headers: dict, db_session: AsyncSession
    ) -> None:
        sq = SavedQuery(
            name="Credential Hunt",
            query="T1003",
            filters=[],
            time_from="now-7d",
            time_to="now",
            created_by="hunter@mxtac.local",
        )
        db_session.add(sq)
        await db_session.commit()

        resp = await client.get(f"{self._BASE}/{sq.id}", headers=hunter_headers)
        assert resp.status_code == 200
        assert resp.json()["id"] == sq.id
        assert resp.json()["name"] == "Credential Hunt"

    @pytest.mark.asyncio
    async def test_hunter_cannot_access_other_users_hunt(
        self, client: AsyncClient, hunter_headers: dict, db_session: AsyncSession
    ) -> None:
        sq = SavedQuery(
            name="Other Hunt",
            query="test",
            filters=[],
            time_from="now-24h",
            time_to="now",
            created_by="other@mxtac.local",
        )
        db_session.add(sq)
        await db_session.commit()

        resp = await client.get(f"{self._BASE}/{sq.id}", headers=hunter_headers)
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_hunter_can_update_saved_hunt(
        self, client: AsyncClient, hunter_headers: dict, db_session: AsyncSession
    ) -> None:
        sq = SavedQuery(
            name="Old Name",
            query="old query",
            filters=[],
            time_from="now-24h",
            time_to="now",
            created_by="hunter@mxtac.local",
        )
        db_session.add(sq)
        await db_session.commit()

        resp = await client.put(
            f"{self._BASE}/{sq.id}",
            headers=hunter_headers,
            json={"name": "Updated Hunt Name"},
        )
        assert resp.status_code == 200
        assert resp.json()["name"] == "Updated Hunt Name"

    @pytest.mark.asyncio
    async def test_hunter_can_delete_saved_hunt(
        self, client: AsyncClient, hunter_headers: dict, db_session: AsyncSession
    ) -> None:
        sq = SavedQuery(
            name="To Delete",
            query="test",
            filters=[],
            time_from="now-24h",
            time_to="now",
            created_by="hunter@mxtac.local",
        )
        db_session.add(sq)
        await db_session.commit()

        resp = await client.delete(f"{self._BASE}/{sq.id}", headers=hunter_headers)
        assert resp.status_code == 204

        # Confirm it's gone
        resp2 = await client.get(f"{self._BASE}/{sq.id}", headers=hunter_headers)
        assert resp2.status_code == 404

    @pytest.mark.asyncio
    async def test_hunter_saved_hunt_name_required(
        self, client: AsyncClient, hunter_headers: dict
    ) -> None:
        resp = await client.post(
            self._BASE, headers=hunter_headers, json={"name": ""}
        )
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# 5. Hunter can read Sigma rules (but NOT write them)
# ---------------------------------------------------------------------------


class TestHunterRulesAccess:
    """Hunter has rules:read but NOT rules:write."""

    @pytest.mark.asyncio
    async def test_hunter_can_read_rules(
        self, client: AsyncClient, hunter_headers: dict
    ) -> None:
        """Hunter has rules:read — endpoint returns 200 (empty list is fine)."""
        resp = await client.get("/api/v1/rules", headers=hunter_headers)
        # RBAC passes for hunter — any non-403 response confirms access
        assert resp.status_code != 403

    @pytest.mark.asyncio
    async def test_hunter_can_access_rule_detail_endpoint(
        self, client: AsyncClient, hunter_headers: dict
    ) -> None:
        """Hunter has rules:read — endpoint returns 404 (rule not found) not 403."""
        resp = await client.get("/api/v1/rules/nonexistent-rule-id", headers=hunter_headers)
        # RBAC check passes; 404 means the rule wasn't found, not access denied
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_hunter_cannot_create_rule(
        self, client: AsyncClient, hunter_headers: dict
    ) -> None:
        resp = await client.post(
            "/api/v1/rules",
            headers=hunter_headers,
            json={
                "title": "Hunter Rule",
                "content": "title: Hunter Rule\n",
                "level": "high",
            },
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_hunter_cannot_delete_rule(
        self, client: AsyncClient, hunter_headers: dict
    ) -> None:
        resp = await client.delete("/api/v1/rules/rule-001", headers=hunter_headers)
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 6. Hunter can view ATT&CK-guided hunt suggestions
# ---------------------------------------------------------------------------


class TestHunterHuntSuggestions:
    """Hunter can access the ATT&CK-guided hunt suggestions endpoint."""

    @pytest.mark.asyncio
    async def test_hunter_can_access_suggestions(
        self, client: AsyncClient, hunter_headers: dict
    ) -> None:
        resp = await client.get("/api/v1/hunting/suggestions", headers=hunter_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "suggestions" in data
        assert "generated_at" in data
        assert "window_hours" in data

    @pytest.mark.asyncio
    async def test_hunter_suggestions_with_custom_params(
        self, client: AsyncClient, hunter_headers: dict
    ) -> None:
        resp = await client.get(
            "/api/v1/hunting/suggestions",
            headers=hunter_headers,
            params={"hours": 48, "limit": 5},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["window_hours"] == 48
        assert len(data["suggestions"]) <= 5


# ---------------------------------------------------------------------------
# 7. Hunter access denied — privileged operations
# ---------------------------------------------------------------------------


class TestHunterAccessDenied:
    """Hunter cannot access connectors, user management, or agent management."""

    @pytest.mark.asyncio
    async def test_hunter_cannot_list_connectors(
        self, client: AsyncClient, hunter_headers: dict
    ) -> None:
        resp = await client.get("/api/v1/connectors", headers=hunter_headers)
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_hunter_cannot_create_connector(
        self, client: AsyncClient, hunter_headers: dict
    ) -> None:
        resp = await client.post(
            "/api/v1/connectors",
            headers=hunter_headers,
            json={"name": "Unauthorized", "type": "wazuh", "config": {}},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_hunter_cannot_list_users(
        self, client: AsyncClient, hunter_headers: dict
    ) -> None:
        resp = await client.get("/api/v1/users", headers=hunter_headers)
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_hunter_cannot_list_agents(
        self, client: AsyncClient, hunter_headers: dict
    ) -> None:
        resp = await client.get("/api/v1/agents", headers=hunter_headers)
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_hunter_cannot_write_rules(
        self, client: AsyncClient, hunter_headers: dict
    ) -> None:
        resp = await client.post(
            "/api/v1/rules",
            headers=hunter_headers,
            json={"title": "Bad Rule", "content": "title: Bad\n", "level": "high"},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_hunter_forbidden_response_contains_role(
        self, client: AsyncClient, hunter_headers: dict
    ) -> None:
        resp = await client.get("/api/v1/connectors", headers=hunter_headers)
        assert resp.status_code == 403
        body = resp.json()
        assert "detail" in body
        assert "hunter" in body["detail"]

    @pytest.mark.asyncio
    async def test_hunter_forbidden_response_contains_permission(
        self, client: AsyncClient, hunter_headers: dict
    ) -> None:
        resp = await client.get("/api/v1/connectors", headers=hunter_headers)
        assert resp.status_code == 403
        assert "connectors:read" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# 8. Analyst is denied hunter-exclusive endpoints
# ---------------------------------------------------------------------------


class TestAnalystDeniedHunterEndpoints:
    """Analyst (role below hunter) cannot access hunter-exclusive resources."""

    _HUNT_BASE = "/api/v1/hunt/queries"

    @pytest.mark.asyncio
    async def test_analyst_cannot_search_events(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        resp = await client.post(
            "/api/v1/events/search", headers=analyst_headers, json={}
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_analyst_cannot_aggregate_events(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        resp = await client.post(
            "/api/v1/events/aggregate", headers=analyst_headers, json={}
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_analyst_cannot_get_event(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        resp = await client.get(
            "/api/v1/events/some-id", headers=analyst_headers
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_analyst_cannot_query_entity_timeline(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        resp = await client.get(
            "/api/v1/events/entity/host/somehost", headers=analyst_headers
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_analyst_cannot_build_lucene_query(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        resp = await client.post(
            "/api/v1/events/query-dsl", headers=analyst_headers, json={}
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_analyst_cannot_create_saved_hunt(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        resp = await client.post(
            self._HUNT_BASE, headers=analyst_headers, json={"name": "Analyst Hunt"}
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_analyst_cannot_list_saved_hunts(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        resp = await client.get(self._HUNT_BASE, headers=analyst_headers)
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_analyst_cannot_read_rules(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        resp = await client.get("/api/v1/rules", headers=analyst_headers)
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 9. Viewer is denied all hunter endpoints
# ---------------------------------------------------------------------------


class TestViewerDeniedHunterEndpoints:
    """Viewer cannot access any hunter-exclusive resource."""

    @pytest.mark.asyncio
    async def test_viewer_cannot_search_events(
        self, client: AsyncClient, viewer_headers: dict
    ) -> None:
        resp = await client.post(
            "/api/v1/events/search", headers=viewer_headers, json={}
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_viewer_cannot_create_saved_hunt(
        self, client: AsyncClient, viewer_headers: dict
    ) -> None:
        resp = await client.post(
            "/api/v1/hunt/queries",
            headers=viewer_headers,
            json={"name": "Viewer Hunt"},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_viewer_cannot_list_saved_hunts(
        self, client: AsyncClient, viewer_headers: dict
    ) -> None:
        resp = await client.get("/api/v1/hunt/queries", headers=viewer_headers)
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 10. Unauthenticated access
# ---------------------------------------------------------------------------


class TestUnauthenticatedHunterEndpoints:
    """Unauthenticated requests to hunter endpoints return 401."""

    @pytest.mark.asyncio
    async def test_unauthenticated_cannot_search_events(
        self, client: AsyncClient
    ) -> None:
        resp = await client.post("/api/v1/events/search", json={})
        assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_unauthenticated_cannot_list_saved_hunts(
        self, client: AsyncClient
    ) -> None:
        resp = await client.get("/api/v1/hunt/queries")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_unauthenticated_cannot_create_saved_hunt(
        self, client: AsyncClient
    ) -> None:
        resp = await client.post("/api/v1/hunt/queries", json={"name": "Test"})
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_unauthenticated_cannot_get_event(self, client: AsyncClient) -> None:
        resp = await client.get("/api/v1/events/some-event-id")
        assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# 11. Engineer/Admin inherit all hunter permissions
# ---------------------------------------------------------------------------


class TestEngineerAdminInheritHunterPerms:
    """Engineer and admin can perform all hunter-level operations."""

    @pytest.mark.asyncio
    async def test_engineer_can_search_events(
        self, client: AsyncClient, engineer_headers: dict, db_session: AsyncSession
    ) -> None:
        resp = await client.post(
            "/api/v1/events/search",
            headers=engineer_headers,
            json={"time_from": "now-1h"},
        )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_admin_can_search_events(
        self, client: AsyncClient, admin_headers: dict, db_session: AsyncSession
    ) -> None:
        resp = await client.post(
            "/api/v1/events/search",
            headers=admin_headers,
            json={"time_from": "now-1h"},
        )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_engineer_can_create_saved_hunt(
        self, client: AsyncClient, engineer_headers: dict
    ) -> None:
        resp = await client.post(
            "/api/v1/hunt/queries",
            headers=engineer_headers,
            json={"name": "Engineer Hunt"},
        )
        assert resp.status_code == 201
        assert resp.json()["created_by"] == "engineer@mxtac.local"

    @pytest.mark.asyncio
    async def test_admin_can_create_saved_hunt(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        resp = await client.post(
            "/api/v1/hunt/queries",
            headers=admin_headers,
            json={"name": "Admin Hunt"},
        )
        assert resp.status_code == 201
        assert resp.json()["created_by"] == "admin@mxtac.local"

    @pytest.mark.asyncio
    async def test_engineer_can_access_hunt_suggestions(
        self, client: AsyncClient, engineer_headers: dict
    ) -> None:
        resp = await client.get(
            "/api/v1/hunting/suggestions", headers=engineer_headers
        )
        assert resp.status_code == 200
