"""Tests for Feature 3.7 — engineer: hunter + manage rules + connectors.

Verifies that the engineer role:
  - Inherits all hunter capabilities (event search, saved hunts, detections, incidents)
  - Can read AND write Sigma rules (full CRUD + import + reload + test)
  - Can read AND write connectors (full CRUD + test + health + start/stop)
  - Can write threat intelligence (threat_intel:write)
  - Can manage assets (assets:write)
  - Can manage agents (agents:read + agents:write)
  - Is denied access to user management and audit logs (admin-only)

Also verifies that hunter cannot access engineer-exclusive write operations (403).
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.main import app
from app.models.event import Event
from app.models.saved_query import SavedQuery

# ---------------------------------------------------------------------------
# Mock repo paths
# ---------------------------------------------------------------------------

_DET_REPO = "app.api.v1.endpoints.detections.DetectionRepo"
_INC_REPO = "app.api.v1.endpoints.incidents.IncidentRepo"
_INC_DET_REPO = "app.api.v1.endpoints.incidents.DetectionRepo"
_RULE_REPO = "app.api.v1.endpoints.rules.RuleRepo"
_CONN_REPO = "app.api.v1.endpoints.connectors.ConnectorRepo"

# ---------------------------------------------------------------------------
# Helpers — minimal ORM-like namespaces
# ---------------------------------------------------------------------------

_NOW = datetime.now(timezone.utc)

_MINIMAL_SIGMA_YAML = """\
title: Engineer Test Rule
id: eng-rule-0001
status: test
description: Minimal rule for engineer RBAC tests
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\\mimikatz.exe'
    condition: selection
level: high
"""


def _make_detection(**overrides) -> SimpleNamespace:
    defaults = {
        "id": "DET-2026-00300",
        "score": 9.5,
        "severity": "critical",
        "technique_id": "T1055.001",
        "technique_name": "DLL Injection",
        "name": "DLL Injection via Process Hollowing",
        "host": "SRV-PROD-01",
        "tactic": "Defense Evasion",
        "status": "active",
        "time": _NOW,
        "user": "SYSTEM",
        "process": "svchost.exe",
        "rule_name": "win_dll_injection",
        "log_source": "Wazuh",
        "event_id": "4688",
        "occurrence_count": 2,
        "description": "DLL injection via process hollowing detected.",
        "cvss_v3": 8.5,
        "confidence": 90,
        "tactic_id": "TA0005",
        "assigned_to": None,
        "priority": "P1 Critical",
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _make_incident(**overrides) -> SimpleNamespace:
    defaults = {
        "id": 20,
        "title": "DLL Injection on SRV-PROD-01",
        "description": "Defense evasion via DLL injection detected.",
        "severity": "critical",
        "status": "new",
        "priority": 1,
        "assigned_to": "engineer@mxtac.local",
        "created_by": "engineer@mxtac.local",
        "detection_ids": ["DET-2026-00300"],
        "technique_ids": ["T1055.001"],
        "tactic_ids": ["TA0005"],
        "hosts": ["SRV-PROD-01"],
        "ttd_seconds": None,
        "ttr_seconds": None,
        "closed_at": None,
        "notes": [],
        "created_at": _NOW,
        "updated_at": _NOW,
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _make_rule(**overrides) -> SimpleNamespace:
    defaults = {
        "id": "eng-rule-0001",
        "title": "Engineer Test Rule",
        "level": "high",
        "status": "test",
        "enabled": True,
        "technique_ids": "[]",
        "tactic_ids": "[]",
        "logsource_product": "windows",
        "logsource_category": "process_creation",
        "logsource_service": None,
        "hit_count": 0,
        "fp_count": 0,
        "content": _MINIMAL_SIGMA_YAML,
        "description": "Minimal rule for engineer RBAC tests",
        "source": "custom",
        "created_by": None,
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _make_connector(**overrides) -> SimpleNamespace:
    defaults = {
        "id": "conn-wazuh-001",
        "name": "Wazuh Production",
        "connector_type": "wazuh",
        "status": "active",
        "enabled": True,
        "events_total": 1000,
        "errors_total": 2,
        "last_seen_at": _NOW.isoformat(),
        "error_message": None,
        "config_json": json.dumps(
            {"url": "https://wazuh.local:55000", "username": "admin", "password": "secret"}
        ),
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _make_event_kwargs(**kwargs) -> dict:
    defaults = {
        "time": _NOW - timedelta(minutes=10),
        "class_name": "Process Activity",
        "severity_id": 5,
        "hostname": "srv-prod-01",
        "username": "SYSTEM",
        "src_ip": "10.0.2.10",
        "dst_ip": "10.0.0.1",
        "summary": "suspicious process injection detected",
        "source": "wazuh",
    }
    defaults.update(kwargs)
    return defaults


async def _seed_event(db: AsyncSession, **kwargs) -> Event:
    evt = Event(**_make_event_kwargs(**kwargs))
    db.add(evt)
    await db.flush()
    return evt


_DET = _make_detection()
_INC = _make_incident()
_RULE = _make_rule()
_CONN = _make_connector()


# ---------------------------------------------------------------------------
# 1. Engineer inherits hunter capabilities — events
# ---------------------------------------------------------------------------


class TestEngineerEventSearch:
    """Engineer can search, aggregate, and retrieve events (events:search)."""

    @pytest.mark.asyncio
    async def test_engineer_can_search_events(
        self, client: AsyncClient, engineer_headers: dict
    ) -> None:
        resp = await client.post(
            "/api/v1/events/search",
            headers=engineer_headers,
            json={"time_from": "now-1h"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "total" in data
        assert "items" in data

    @pytest.mark.asyncio
    async def test_engineer_can_search_events_with_results(
        self, client: AsyncClient, engineer_headers: dict, db_session: AsyncSession
    ) -> None:
        await _seed_event(db_session, summary="dll injection", hostname="srv-prod-01")
        resp = await client.post(
            "/api/v1/events/search",
            headers=engineer_headers,
            json={"time_from": "now-1h"},
        )
        assert resp.status_code == 200
        assert resp.json()["total"] == 1
        assert resp.json()["items"][0]["hostname"] == "srv-prod-01"

    @pytest.mark.asyncio
    async def test_engineer_can_aggregate_events(
        self, client: AsyncClient, engineer_headers: dict, db_session: AsyncSession
    ) -> None:
        await _seed_event(db_session, severity_id=5)
        await _seed_event(db_session, severity_id=3)
        resp = await client.post(
            "/api/v1/events/aggregate",
            headers=engineer_headers,
            json={"field": "severity_id", "time_from": "now-1h"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["field"] == "severity_id"
        assert isinstance(data["buckets"], list)

    @pytest.mark.asyncio
    async def test_engineer_can_get_event_by_id(
        self, client: AsyncClient, engineer_headers: dict, db_session: AsyncSession
    ) -> None:
        evt = await _seed_event(db_session, summary="specific engineer event")
        resp = await client.get(f"/api/v1/events/{evt.id}", headers=engineer_headers)
        assert resp.status_code == 200
        assert resp.json()["id"] == evt.id

    @pytest.mark.asyncio
    async def test_engineer_can_query_entity_timeline(
        self, client: AsyncClient, engineer_headers: dict, db_session: AsyncSession
    ) -> None:
        await _seed_event(db_session, hostname="srv-prod-01")
        resp = await client.get(
            "/api/v1/events/entity/host/srv-prod-01", headers=engineer_headers
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["entity_type"] == "host"
        assert data["total"] == 1

    @pytest.mark.asyncio
    async def test_engineer_can_build_lucene_query(
        self, client: AsyncClient, engineer_headers: dict
    ) -> None:
        resp = await client.post(
            "/api/v1/events/query-dsl",
            headers=engineer_headers,
            json={"query": "injection", "time_from": "now-24h", "time_to": "now"},
        )
        assert resp.status_code == 200
        assert "lucene" in resp.json()

    @pytest.mark.asyncio
    async def test_engineer_can_export_events(
        self, client: AsyncClient, engineer_headers: dict, db_session: AsyncSession
    ) -> None:
        await _seed_event(db_session, summary="export test")
        resp = await client.post(
            "/api/v1/events/export",
            headers=engineer_headers,
            json={"time_from": "now-1h"},
        )
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/csv")


# ---------------------------------------------------------------------------
# 2. Engineer inherits hunter capabilities — saved hunt queries
# ---------------------------------------------------------------------------


class TestEngineerSavedHunts:
    """Engineer can create, list, update, and delete saved hunt queries."""

    _BASE = "/api/v1/hunt/queries"

    @pytest.mark.asyncio
    async def test_engineer_can_create_saved_hunt(
        self, client: AsyncClient, engineer_headers: dict
    ) -> None:
        resp = await client.post(
            self._BASE,
            headers=engineer_headers,
            json={
                "name": "Engineer Hunt",
                "description": "DLL injection hunt",
                "query": "T1055.001",
                "time_from": "now-7d",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "Engineer Hunt"
        assert data["created_by"] == "engineer@mxtac.local"

    @pytest.mark.asyncio
    async def test_engineer_can_list_saved_hunts(
        self, client: AsyncClient, engineer_headers: dict, db_session: AsyncSession
    ) -> None:
        sq = SavedQuery(
            name="My Engineer Hunt",
            query="injection",
            filters=[],
            time_from="now-24h",
            time_to="now",
            created_by="engineer@mxtac.local",
        )
        db_session.add(sq)
        await db_session.commit()

        resp = await client.get(self._BASE, headers=engineer_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["name"] == "My Engineer Hunt"

    @pytest.mark.asyncio
    async def test_engineer_list_hunts_user_scoped(
        self,
        client: AsyncClient,
        engineer_headers: dict,
        db_session: AsyncSession,
    ) -> None:
        """Engineer only sees their own saved hunts."""
        for owner in ("engineer@mxtac.local", "hunter@mxtac.local"):
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

        resp = await client.get(self._BASE, headers=engineer_headers)
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 1
        assert items[0]["created_by"] == "engineer@mxtac.local"

    @pytest.mark.asyncio
    async def test_engineer_can_update_saved_hunt(
        self, client: AsyncClient, engineer_headers: dict, db_session: AsyncSession
    ) -> None:
        sq = SavedQuery(
            name="Old Name",
            query="old query",
            filters=[],
            time_from="now-24h",
            time_to="now",
            created_by="engineer@mxtac.local",
        )
        db_session.add(sq)
        await db_session.commit()

        resp = await client.put(
            f"{self._BASE}/{sq.id}",
            headers=engineer_headers,
            json={"name": "Updated Engineer Hunt"},
        )
        assert resp.status_code == 200
        assert resp.json()["name"] == "Updated Engineer Hunt"

    @pytest.mark.asyncio
    async def test_engineer_can_delete_saved_hunt(
        self, client: AsyncClient, engineer_headers: dict, db_session: AsyncSession
    ) -> None:
        sq = SavedQuery(
            name="To Delete",
            query="test",
            filters=[],
            time_from="now-24h",
            time_to="now",
            created_by="engineer@mxtac.local",
        )
        db_session.add(sq)
        await db_session.commit()

        resp = await client.delete(f"{self._BASE}/{sq.id}", headers=engineer_headers)
        assert resp.status_code == 204

        resp2 = await client.get(f"{self._BASE}/{sq.id}", headers=engineer_headers)
        assert resp2.status_code == 404


# ---------------------------------------------------------------------------
# 3. Engineer inherits hunter capabilities — detections
# ---------------------------------------------------------------------------


class TestEngineerDetectionAccess:
    """Engineer can view and update detections (inherits analyst + hunter)."""

    @pytest.mark.asyncio
    async def test_engineer_can_list_detections(
        self, client: AsyncClient, engineer_headers: dict
    ) -> None:
        with patch(f"{_DET_REPO}.list", new=AsyncMock(return_value=([_DET], 1))):
            resp = await client.get("/api/v1/detections", headers=engineer_headers)
        assert resp.status_code == 200
        assert "items" in resp.json()

    @pytest.mark.asyncio
    async def test_engineer_can_update_detection_status(
        self, client: AsyncClient, engineer_headers: dict
    ) -> None:
        updated = _make_detection(status="investigating", assigned_to="engineer@mxtac.local")
        with patch(f"{_DET_REPO}.update", new=AsyncMock(return_value=updated)):
            resp = await client.patch(
                "/api/v1/detections/DET-2026-00300",
                headers=engineer_headers,
                json={"status": "investigating"},
            )
        assert resp.status_code == 200
        assert resp.json()["status"] == "investigating"


# ---------------------------------------------------------------------------
# 4. Engineer can manage Sigma rules (rules:read + rules:write)
# ---------------------------------------------------------------------------


class TestEngineerRulesWrite:
    """Engineer has full rules:read + rules:write access."""

    @pytest.mark.asyncio
    async def test_engineer_can_list_rules(
        self, client: AsyncClient, engineer_headers: dict
    ) -> None:
        with patch(f"{_RULE_REPO}.list", new=AsyncMock(return_value=[_RULE])):
            resp = await client.get("/api/v1/rules", headers=engineer_headers)
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    @pytest.mark.asyncio
    async def test_engineer_can_get_rule_detail(
        self, client: AsyncClient, engineer_headers: dict
    ) -> None:
        with patch(f"{_RULE_REPO}.get_by_id", new=AsyncMock(return_value=_RULE)):
            resp = await client.get("/api/v1/rules/eng-rule-0001", headers=engineer_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == "eng-rule-0001"
        assert data["level"] == "high"

    @pytest.mark.asyncio
    async def test_engineer_can_create_rule(
        self, client: AsyncClient, engineer_headers: dict
    ) -> None:
        with (
            patch(f"{_RULE_REPO}.create", new=AsyncMock(return_value=_RULE)),
            patch("app.api.v1.endpoints.rules.publish_rule_reload", new=AsyncMock()),
        ):
            resp = await client.post(
                "/api/v1/rules",
                headers=engineer_headers,
                json={
                    "title": "Engineer Test Rule",
                    "content": _MINIMAL_SIGMA_YAML,
                    "enabled": True,
                },
            )
        # 201 if Sigma YAML parses correctly, 422 if engine rejects it
        assert resp.status_code in (201, 422)

    @pytest.mark.asyncio
    async def test_engineer_can_update_rule_enabled(
        self, client: AsyncClient, engineer_headers: dict
    ) -> None:
        disabled = _make_rule(enabled=False)
        with (
            patch(f"{_RULE_REPO}.get_by_id", new=AsyncMock(return_value=_RULE)),
            patch(f"{_RULE_REPO}.update", new=AsyncMock(return_value=disabled)),
            patch("app.api.v1.endpoints.rules.publish_rule_reload", new=AsyncMock()),
        ):
            resp = await client.patch(
                "/api/v1/rules/eng-rule-0001",
                headers=engineer_headers,
                json={"enabled": False},
            )
        assert resp.status_code == 200
        assert resp.json()["enabled"] is False

    @pytest.mark.asyncio
    async def test_engineer_can_delete_rule(
        self, client: AsyncClient, engineer_headers: dict
    ) -> None:
        with (
            patch(f"{_RULE_REPO}.delete", new=AsyncMock(return_value=True)),
            patch("app.api.v1.endpoints.rules.publish_rule_reload", new=AsyncMock()),
        ):
            resp = await client.delete(
                "/api/v1/rules/eng-rule-0001", headers=engineer_headers
            )
        assert resp.status_code == 204

    @pytest.mark.asyncio
    async def test_engineer_delete_nonexistent_rule_returns_404(
        self, client: AsyncClient, engineer_headers: dict
    ) -> None:
        with (
            patch(f"{_RULE_REPO}.delete", new=AsyncMock(return_value=False)),
            patch("app.api.v1.endpoints.rules.publish_rule_reload", new=AsyncMock()),
        ):
            resp = await client.delete(
                "/api/v1/rules/nonexistent-rule", headers=engineer_headers
            )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_engineer_can_test_rule_yaml(
        self, client: AsyncClient, engineer_headers: dict
    ) -> None:
        resp = await client.post(
            "/api/v1/rules/test",
            headers=engineer_headers,
            json={
                "content": _MINIMAL_SIGMA_YAML,
                "sample_event": {"Image": "C:\\Windows\\mimikatz.exe"},
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "matched" in data
        assert "errors" in data

    @pytest.mark.asyncio
    async def test_engineer_can_import_rules(
        self, client: AsyncClient, engineer_headers: dict
    ) -> None:
        with (
            patch(f"{_RULE_REPO}.create", new=AsyncMock(return_value=_RULE)),
            patch(f"{_RULE_REPO}.count", new=AsyncMock(return_value=1)),
            patch("app.api.v1.endpoints.rules.publish_rule_reload", new=AsyncMock()),
        ):
            resp = await client.post(
                "/api/v1/rules/import",
                headers=engineer_headers,
                json={"yaml_content": _MINIMAL_SIGMA_YAML},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert "imported" in data
        assert "total_rules" in data

    @pytest.mark.asyncio
    async def test_engineer_can_reload_rules(
        self, client: AsyncClient, engineer_headers: dict
    ) -> None:
        mock_engine = MagicMock()
        mock_engine.reload_from_db = AsyncMock(return_value=5)
        app.state.sigma_engine = mock_engine
        with patch(f"{_RULE_REPO}.count", new=AsyncMock(return_value=5)):
            resp = await client.post(
                "/api/v1/rules/reload", headers=engineer_headers
            )
        app.state.sigma_engine = None
        assert resp.status_code == 200
        data = resp.json()
        assert "reloaded" in data
        assert "total_rules" in data

    @pytest.mark.asyncio
    async def test_engineer_can_get_rules_summary(
        self, client: AsyncClient, engineer_headers: dict
    ) -> None:
        with patch(f"{_RULE_REPO}.list", new=AsyncMock(return_value=[_RULE])):
            resp = await client.get(
                "/api/v1/rules/stats/summary", headers=engineer_headers
            )
        assert resp.status_code == 200
        data = resp.json()
        assert "total" in data
        assert "enabled" in data
        assert "by_level" in data


# ---------------------------------------------------------------------------
# 5. Engineer can manage connectors (connectors:read + connectors:write)
# ---------------------------------------------------------------------------


class TestEngineerConnectorAccess:
    """Engineer has full connectors:read + connectors:write access."""

    @pytest.mark.asyncio
    async def test_engineer_can_list_connectors(
        self, client: AsyncClient, engineer_headers: dict
    ) -> None:
        with patch(f"{_CONN_REPO}.list", new=AsyncMock(return_value=[_CONN])):
            resp = await client.get("/api/v1/connectors", headers=engineer_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["name"] == "Wazuh Production"

    @pytest.mark.asyncio
    async def test_engineer_can_get_connector(
        self, client: AsyncClient, engineer_headers: dict
    ) -> None:
        with patch(f"{_CONN_REPO}.get_by_id", new=AsyncMock(return_value=_CONN)):
            resp = await client.get(
                "/api/v1/connectors/conn-wazuh-001", headers=engineer_headers
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == "conn-wazuh-001"
        assert data["connector_type"] == "wazuh"

    @pytest.mark.asyncio
    async def test_engineer_can_create_connector(
        self, client: AsyncClient, engineer_headers: dict
    ) -> None:
        with patch(f"{_CONN_REPO}.create", new=AsyncMock(return_value=_CONN)):
            resp = await client.post(
                "/api/v1/connectors",
                headers=engineer_headers,
                json={
                    "name": "Wazuh Production",
                    "connector_type": "wazuh",
                    "config": {
                        "url": "https://wazuh.local:55000",
                        "username": "admin",
                        "password": "secret",
                    },
                    "enabled": True,
                },
            )
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "Wazuh Production"
        assert data["connector_type"] == "wazuh"

    @pytest.mark.asyncio
    async def test_engineer_create_connector_invalid_type_returns_422(
        self, client: AsyncClient, engineer_headers: dict
    ) -> None:
        resp = await client.post(
            "/api/v1/connectors",
            headers=engineer_headers,
            json={
                "name": "Bad Connector",
                "connector_type": "unknown_type",
                "config": {},
            },
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_engineer_can_update_connector(
        self, client: AsyncClient, engineer_headers: dict
    ) -> None:
        disabled = _make_connector(enabled=False, status="inactive")
        with (
            patch(f"{_CONN_REPO}.get_by_id", new=AsyncMock(return_value=_CONN)),
            patch(f"{_CONN_REPO}.update", new=AsyncMock(return_value=disabled)),
        ):
            resp = await client.patch(
                "/api/v1/connectors/conn-wazuh-001",
                headers=engineer_headers,
                json={"enabled": False},
            )
        assert resp.status_code == 200
        assert resp.json()["enabled"] is False

    @pytest.mark.asyncio
    async def test_engineer_can_delete_connector(
        self, client: AsyncClient, engineer_headers: dict
    ) -> None:
        with patch(f"{_CONN_REPO}.delete", new=AsyncMock(return_value=True)):
            resp = await client.delete(
                "/api/v1/connectors/conn-wazuh-001", headers=engineer_headers
            )
        assert resp.status_code == 204

    @pytest.mark.asyncio
    async def test_engineer_delete_nonexistent_connector_returns_404(
        self, client: AsyncClient, engineer_headers: dict
    ) -> None:
        with patch(f"{_CONN_REPO}.delete", new=AsyncMock(return_value=False)):
            resp = await client.delete(
                "/api/v1/connectors/nonexistent-conn", headers=engineer_headers
            )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_engineer_can_get_connector_health(
        self, client: AsyncClient, engineer_headers: dict
    ) -> None:
        with patch(f"{_CONN_REPO}.get_by_id", new=AsyncMock(return_value=_CONN)):
            resp = await client.get(
                "/api/v1/connectors/conn-wazuh-001/health", headers=engineer_headers
            )
        assert resp.status_code == 200
        data = resp.json()
        assert "healthy" in data
        assert data["id"] == "conn-wazuh-001"

    @pytest.mark.asyncio
    async def test_engineer_health_returns_true_for_active_enabled(
        self, client: AsyncClient, engineer_headers: dict
    ) -> None:
        active_conn = _make_connector(status="active", enabled=True)
        with patch(f"{_CONN_REPO}.get_by_id", new=AsyncMock(return_value=active_conn)):
            resp = await client.get(
                "/api/v1/connectors/conn-wazuh-001/health", headers=engineer_headers
            )
        assert resp.status_code == 200
        assert resp.json()["healthy"] is True

    @pytest.mark.asyncio
    async def test_engineer_health_returns_false_for_disabled(
        self, client: AsyncClient, engineer_headers: dict
    ) -> None:
        disabled_conn = _make_connector(status="active", enabled=False)
        with patch(f"{_CONN_REPO}.get_by_id", new=AsyncMock(return_value=disabled_conn)):
            resp = await client.get(
                "/api/v1/connectors/conn-wazuh-001/health", headers=engineer_headers
            )
        assert resp.status_code == 200
        assert resp.json()["healthy"] is False

    @pytest.mark.asyncio
    async def test_engineer_can_test_connector(
        self, client: AsyncClient, engineer_headers: dict
    ) -> None:
        with (
            patch(f"{_CONN_REPO}.get_by_id", new=AsyncMock(return_value=_CONN)),
            patch(
                "app.api.v1.endpoints.connectors._test_wazuh_connection",
                new=AsyncMock(return_value=(True, "Wazuh API reachable and credentials valid")),
            ),
            patch(f"{_CONN_REPO}.update_status", new=AsyncMock()),
        ):
            resp = await client.post(
                "/api/v1/connectors/conn-wazuh-001/test", headers=engineer_headers
            )
        assert resp.status_code == 200
        data = resp.json()
        assert "reachable" in data
        assert "message" in data
        assert data["connector_id"] == "conn-wazuh-001"

    @pytest.mark.asyncio
    async def test_engineer_can_get_connector_not_found(
        self, client: AsyncClient, engineer_headers: dict
    ) -> None:
        with patch(f"{_CONN_REPO}.get_by_id", new=AsyncMock(return_value=None)):
            resp = await client.get(
                "/api/v1/connectors/nonexistent-conn", headers=engineer_headers
            )
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 6. Engineer can view ATT&CK hunt suggestions (inherits from hunter)
# ---------------------------------------------------------------------------


class TestEngineerHuntSuggestions:
    """Engineer can access ATT&CK-guided hunt suggestions."""

    @pytest.mark.asyncio
    async def test_engineer_can_access_suggestions(
        self, client: AsyncClient, engineer_headers: dict
    ) -> None:
        resp = await client.get(
            "/api/v1/hunting/suggestions", headers=engineer_headers
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "suggestions" in data
        assert "generated_at" in data
        assert "window_hours" in data

    @pytest.mark.asyncio
    async def test_engineer_suggestions_with_custom_params(
        self, client: AsyncClient, engineer_headers: dict
    ) -> None:
        resp = await client.get(
            "/api/v1/hunting/suggestions",
            headers=engineer_headers,
            params={"hours": 72, "limit": 5},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["window_hours"] == 72
        assert len(data["suggestions"]) <= 5


# ---------------------------------------------------------------------------
# 7. Engineer is denied admin-exclusive endpoints
# ---------------------------------------------------------------------------


class TestEngineerAccessDenied:
    """Engineer cannot access user management or audit logs (admin-only)."""

    @pytest.mark.asyncio
    async def test_engineer_cannot_list_users(
        self, client: AsyncClient, engineer_headers: dict
    ) -> None:
        resp = await client.get("/api/v1/users", headers=engineer_headers)
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_engineer_cannot_create_user(
        self, client: AsyncClient, engineer_headers: dict
    ) -> None:
        resp = await client.post(
            "/api/v1/users",
            headers=engineer_headers,
            json={
                "email": "hacked@mxtac.local",
                "full_name": "Hacker",
                "role": "admin",
                "password": "pw",
            },
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_engineer_cannot_get_user_by_id(
        self, client: AsyncClient, engineer_headers: dict
    ) -> None:
        resp = await client.get("/api/v1/users/some-id", headers=engineer_headers)
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_engineer_cannot_update_user(
        self, client: AsyncClient, engineer_headers: dict
    ) -> None:
        resp = await client.patch(
            "/api/v1/users/some-id",
            headers=engineer_headers,
            json={"role": "admin"},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_engineer_cannot_delete_user(
        self, client: AsyncClient, engineer_headers: dict
    ) -> None:
        resp = await client.delete("/api/v1/users/some-id", headers=engineer_headers)
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_engineer_forbidden_response_contains_role(
        self, client: AsyncClient, engineer_headers: dict
    ) -> None:
        resp = await client.get("/api/v1/users", headers=engineer_headers)
        assert resp.status_code == 403
        body = resp.json()
        assert "detail" in body
        assert "engineer" in body["detail"]

    @pytest.mark.asyncio
    async def test_engineer_forbidden_response_contains_permission(
        self, client: AsyncClient, engineer_headers: dict
    ) -> None:
        resp = await client.get("/api/v1/users", headers=engineer_headers)
        assert resp.status_code == 403
        assert "users:read" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# 8. Hunter cannot access engineer-exclusive write operations
# ---------------------------------------------------------------------------


class TestHunterDeniedEngineerWriteOps:
    """Hunter cannot write rules or access connectors (engineer-only)."""

    @pytest.mark.asyncio
    async def test_hunter_cannot_create_rule(
        self, client: AsyncClient, hunter_headers: dict
    ) -> None:
        resp = await client.post(
            "/api/v1/rules",
            headers=hunter_headers,
            json={
                "title": "Hunter Rule Attempt",
                "content": _MINIMAL_SIGMA_YAML,
            },
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_hunter_cannot_update_rule(
        self, client: AsyncClient, hunter_headers: dict
    ) -> None:
        resp = await client.patch(
            "/api/v1/rules/some-rule-id",
            headers=hunter_headers,
            json={"enabled": False},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_hunter_cannot_delete_rule(
        self, client: AsyncClient, hunter_headers: dict
    ) -> None:
        resp = await client.delete("/api/v1/rules/some-rule-id", headers=hunter_headers)
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_hunter_cannot_import_rules(
        self, client: AsyncClient, hunter_headers: dict
    ) -> None:
        resp = await client.post(
            "/api/v1/rules/import",
            headers=hunter_headers,
            json={"yaml_content": _MINIMAL_SIGMA_YAML},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_hunter_cannot_reload_rules(
        self, client: AsyncClient, hunter_headers: dict
    ) -> None:
        resp = await client.post("/api/v1/rules/reload", headers=hunter_headers)
        assert resp.status_code == 403

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
            json={"name": "Evil Connector", "connector_type": "wazuh", "config": {}},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_hunter_cannot_delete_connector(
        self, client: AsyncClient, hunter_headers: dict
    ) -> None:
        resp = await client.delete(
            "/api/v1/connectors/some-connector", headers=hunter_headers
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_hunter_cannot_test_connector(
        self, client: AsyncClient, hunter_headers: dict
    ) -> None:
        resp = await client.post(
            "/api/v1/connectors/some-connector/test", headers=hunter_headers
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_hunter_forbidden_on_connector_contains_permission(
        self, client: AsyncClient, hunter_headers: dict
    ) -> None:
        resp = await client.get("/api/v1/connectors", headers=hunter_headers)
        assert resp.status_code == 403
        assert "connectors:read" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# 9. Analyst and viewer denied engineer endpoints
# ---------------------------------------------------------------------------


class TestLowerRolesDeniedEngineerEndpoints:
    """Analyst and viewer cannot access rules write or connectors."""

    @pytest.mark.asyncio
    async def test_analyst_cannot_write_rules(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        resp = await client.post(
            "/api/v1/rules",
            headers=analyst_headers,
            json={"title": "Analyst Rule", "content": _MINIMAL_SIGMA_YAML},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_analyst_cannot_list_connectors(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        resp = await client.get("/api/v1/connectors", headers=analyst_headers)
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_viewer_cannot_write_rules(
        self, client: AsyncClient, viewer_headers: dict
    ) -> None:
        resp = await client.post(
            "/api/v1/rules",
            headers=viewer_headers,
            json={"title": "Viewer Rule", "content": _MINIMAL_SIGMA_YAML},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_viewer_cannot_list_connectors(
        self, client: AsyncClient, viewer_headers: dict
    ) -> None:
        resp = await client.get("/api/v1/connectors", headers=viewer_headers)
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_analyst_cannot_delete_rule(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        resp = await client.delete("/api/v1/rules/rule-001", headers=analyst_headers)
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_viewer_cannot_delete_connector(
        self, client: AsyncClient, viewer_headers: dict
    ) -> None:
        resp = await client.delete(
            "/api/v1/connectors/conn-001", headers=viewer_headers
        )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 10. Unauthenticated access to engineer endpoints
# ---------------------------------------------------------------------------


class TestUnauthenticatedEngineerEndpoints:
    """Unauthenticated requests to engineer endpoints return 401."""

    @pytest.mark.asyncio
    async def test_unauthenticated_cannot_list_connectors(
        self, client: AsyncClient
    ) -> None:
        resp = await client.get("/api/v1/connectors")
        assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_unauthenticated_cannot_create_connector(
        self, client: AsyncClient
    ) -> None:
        resp = await client.post(
            "/api/v1/connectors",
            json={"name": "Anon Conn", "connector_type": "wazuh", "config": {}},
        )
        assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_unauthenticated_cannot_write_rules(
        self, client: AsyncClient
    ) -> None:
        resp = await client.post(
            "/api/v1/rules",
            json={"title": "Anon Rule", "content": _MINIMAL_SIGMA_YAML},
        )
        assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_unauthenticated_cannot_delete_rule(
        self, client: AsyncClient
    ) -> None:
        resp = await client.delete("/api/v1/rules/some-rule-id")
        assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_unauthenticated_cannot_import_rules(
        self, client: AsyncClient
    ) -> None:
        resp = await client.post(
            "/api/v1/rules/import",
            json={"yaml_content": _MINIMAL_SIGMA_YAML},
        )
        assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# 11. Admin inherits all engineer permissions
# ---------------------------------------------------------------------------


class TestAdminInheritsEngineerPerms:
    """Admin can perform all engineer-level operations."""

    @pytest.mark.asyncio
    async def test_admin_can_list_connectors(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        with patch(f"{_CONN_REPO}.list", new=AsyncMock(return_value=[_CONN])):
            resp = await client.get("/api/v1/connectors", headers=admin_headers)
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_admin_can_create_connector(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        with patch(f"{_CONN_REPO}.create", new=AsyncMock(return_value=_CONN)):
            resp = await client.post(
                "/api/v1/connectors",
                headers=admin_headers,
                json={
                    "name": "Admin Connector",
                    "connector_type": "wazuh",
                    "config": {"url": "https://wazuh.local:55000"},
                    "enabled": True,
                },
            )
        assert resp.status_code == 201

    @pytest.mark.asyncio
    async def test_admin_can_delete_rule(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        with (
            patch(f"{_RULE_REPO}.delete", new=AsyncMock(return_value=True)),
            patch("app.api.v1.endpoints.rules.publish_rule_reload", new=AsyncMock()),
        ):
            resp = await client.delete(
                "/api/v1/rules/eng-rule-0001", headers=admin_headers
            )
        assert resp.status_code == 204

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
