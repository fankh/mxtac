"""Tests for /api/v1/assets endpoints — Feature 30.3.

Coverage:
  - GET  /assets                  — paginated list, filters (type/criticality/active/search)
  - GET  /assets/stats            — aggregate counts
  - POST /assets/bulk             — bulk import, deduplication
  - GET  /assets/{id}             — detail, 404
  - POST /assets                  — create single asset (201), 409 duplicate
  - PATCH /assets/{id}            — update fields, 404
  - DELETE /assets/{id}           — soft deactivate, 404
  - GET  /assets/{id}/detections  — detections for asset, 404
  - GET  /assets/{id}/incidents   — incidents for asset, 404
  - RBAC: analyst+ for read, engineer+ for write
  - Unauthenticated → 401/403
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient

from app.core.security import create_access_token

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MOCK_REPO = "app.api.v1.endpoints.assets.AssetRepo"
MOCK_LIST_DETECTIONS = "app.api.v1.endpoints.assets._list_asset_detections"
MOCK_LIST_INCIDENTS = "app.api.v1.endpoints.assets._list_asset_incidents"
BASE = "/api/v1/assets"
_NOW = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _asset(**overrides) -> SimpleNamespace:
    """Build a minimal ORM-like Asset namespace for use as a mock return."""
    defaults = {
        "id": 1,
        "hostname": "web-server-01",
        "ip_addresses": ["10.0.1.5"],
        "os": "Ubuntu 22.04",
        "os_family": "linux",
        "asset_type": "server",
        "criticality": 4,
        "owner": "ops-team",
        "department": "Engineering",
        "location": "us-east-1",
        "tags": ["web", "prod"],
        "is_active": True,
        "last_seen_at": _NOW,
        "agent_id": "agent-abc123",
        "detection_count": 3,
        "incident_count": 1,
        "created_at": _NOW,
        "updated_at": _NOW,
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _detection(**overrides) -> SimpleNamespace:
    defaults = {
        "id": "det-001",
        "name": "Suspicious Process",
        "severity": "high",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "execution",
        "status": "active",
        "host": "web-server-01",
        "time": _NOW,
        "created_at": _NOW,
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _incident(**overrides) -> SimpleNamespace:
    defaults = {
        "id": 1,
        "title": "Lateral movement detected",
        "severity": "high",
        "status": "new",
        "priority": 2,
        "assigned_to": None,
        "hosts": ["web-server-01"],
        "created_at": _NOW,
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _token_headers(role: str) -> dict[str, str]:
    token = create_access_token(
        {"sub": f"{role}@mxtac.local", "role": role},
        expires_delta=timedelta(hours=1),
    )
    return {"Authorization": f"Bearer {token}"}


_ASSET = _asset()

_CREATE_BODY = {
    "hostname": "web-server-01",
    "ip_addresses": ["10.0.1.5"],
    "os": "Ubuntu 22.04",
    "os_family": "linux",
    "asset_type": "server",
    "criticality": 4,
    "owner": "ops-team",
    "department": "Engineering",
    "location": "us-east-1",
    "tags": ["web", "prod"],
}

_STATS = {
    "total": 50,
    "by_type": {"server": 30, "workstation": 15, "network": 5},
    "by_criticality": {"3": 20, "4": 25, "5": 5},
    "by_os_family": {"linux": 35, "windows": 15},
}


# ---------------------------------------------------------------------------
# GET /assets — list
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_assets_returns_200(client: AsyncClient) -> None:
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([_ASSET], 1))):
        resp = await client.get(BASE, headers=_token_headers("analyst"))
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "pagination" in data
    assert len(data["items"]) == 1


@pytest.mark.asyncio
async def test_list_assets_pagination_fields(client: AsyncClient) -> None:
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([_ASSET], 1))):
        resp = await client.get(BASE, headers=_token_headers("analyst"))
    pg = resp.json()["pagination"]
    assert pg["page"] == 1
    assert pg["page_size"] == 25
    assert pg["total"] == 1
    assert pg["total_pages"] == 1


@pytest.mark.asyncio
async def test_list_assets_empty(client: AsyncClient) -> None:
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([], 0))):
        resp = await client.get(BASE, headers=_token_headers("analyst"))
    assert resp.status_code == 200
    data = resp.json()
    assert data["items"] == []
    assert data["pagination"]["total"] == 0
    assert data["pagination"]["total_pages"] == 1


@pytest.mark.asyncio
async def test_list_assets_filter_asset_type_forwarded(client: AsyncClient) -> None:
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        await client.get(f"{BASE}?asset_type=server", headers=_token_headers("analyst"))
    assert mock_list.call_args.kwargs.get("asset_type") == "server"


@pytest.mark.asyncio
async def test_list_assets_filter_criticality_forwarded(client: AsyncClient) -> None:
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        await client.get(f"{BASE}?criticality=4", headers=_token_headers("analyst"))
    assert mock_list.call_args.kwargs.get("criticality") == 4


@pytest.mark.asyncio
async def test_list_assets_filter_is_active_forwarded(client: AsyncClient) -> None:
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        await client.get(f"{BASE}?is_active=true", headers=_token_headers("analyst"))
    assert mock_list.call_args.kwargs.get("is_active") is True


@pytest.mark.asyncio
async def test_list_assets_filter_search_forwarded(client: AsyncClient) -> None:
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        await client.get(f"{BASE}?search=web", headers=_token_headers("analyst"))
    assert mock_list.call_args.kwargs.get("search") == "web"


@pytest.mark.asyncio
async def test_list_assets_item_fields(client: AsyncClient) -> None:
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([_ASSET], 1))):
        resp = await client.get(BASE, headers=_token_headers("analyst"))
    item = resp.json()["items"][0]
    for field in (
        "id", "hostname", "ip_addresses", "os", "os_family", "asset_type",
        "criticality", "is_active", "detection_count", "incident_count", "tags",
    ):
        assert field in item, f"Missing field: {field}"


# ---------------------------------------------------------------------------
# GET /assets/stats — aggregate counts
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stats_returns_200(client: AsyncClient) -> None:
    with patch(f"{MOCK_REPO}.stats", new=AsyncMock(return_value=_STATS)):
        resp = await client.get(f"{BASE}/stats", headers=_token_headers("analyst"))
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_stats_fields(client: AsyncClient) -> None:
    with patch(f"{MOCK_REPO}.stats", new=AsyncMock(return_value=_STATS)):
        resp = await client.get(f"{BASE}/stats", headers=_token_headers("analyst"))
    data = resp.json()
    assert data["total"] == 50
    assert data["by_type"]["server"] == 30
    assert data["by_criticality"]["4"] == 25
    assert data["by_os_family"]["linux"] == 35


@pytest.mark.asyncio
async def test_stats_empty_db(client: AsyncClient) -> None:
    empty = {"total": 0, "by_type": {}, "by_criticality": {}, "by_os_family": {}}
    with patch(f"{MOCK_REPO}.stats", new=AsyncMock(return_value=empty)):
        resp = await client.get(f"{BASE}/stats", headers=_token_headers("analyst"))
    assert resp.status_code == 200
    assert resp.json()["total"] == 0


# ---------------------------------------------------------------------------
# POST /assets/bulk — bulk import
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bulk_import_returns_created_skipped(client: AsyncClient) -> None:
    with (
        patch(f"{MOCK_REPO}.get_by_hostname", new=AsyncMock(return_value=None)),
        patch(f"{MOCK_REPO}.create", new=AsyncMock(return_value=_ASSET)),
    ):
        resp = await client.post(
            f"{BASE}/bulk",
            headers=_token_headers("engineer"),
            json=[_CREATE_BODY],
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["created"] == 1
    assert data["skipped"] == 0


@pytest.mark.asyncio
async def test_bulk_import_skips_existing(client: AsyncClient) -> None:
    with patch(f"{MOCK_REPO}.get_by_hostname", new=AsyncMock(return_value=_ASSET)):
        resp = await client.post(
            f"{BASE}/bulk",
            headers=_token_headers("engineer"),
            json=[_CREATE_BODY],
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["created"] == 0
    assert data["skipped"] == 1


@pytest.mark.asyncio
async def test_bulk_import_empty_list(client: AsyncClient) -> None:
    resp = await client.post(
        f"{BASE}/bulk",
        headers=_token_headers("engineer"),
        json=[],
    )
    assert resp.status_code == 200
    assert resp.json() == {"created": 0, "skipped": 0}


# ---------------------------------------------------------------------------
# GET /assets/{id} — detail
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_asset_returns_200(client: AsyncClient) -> None:
    with patch(f"{MOCK_REPO}.get_by_id", new=AsyncMock(return_value=_ASSET)):
        resp = await client.get(f"{BASE}/1", headers=_token_headers("analyst"))
    assert resp.status_code == 200
    assert resp.json()["id"] == 1
    assert resp.json()["hostname"] == "web-server-01"


@pytest.mark.asyncio
async def test_get_asset_not_found(client: AsyncClient) -> None:
    with patch(f"{MOCK_REPO}.get_by_id", new=AsyncMock(return_value=None)):
        resp = await client.get(f"{BASE}/999", headers=_token_headers("analyst"))
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_get_asset_includes_counts(client: AsyncClient) -> None:
    a = _asset(detection_count=5, incident_count=2)
    with patch(f"{MOCK_REPO}.get_by_id", new=AsyncMock(return_value=a)):
        resp = await client.get(f"{BASE}/1", headers=_token_headers("analyst"))
    data = resp.json()
    assert data["detection_count"] == 5
    assert data["incident_count"] == 2


# ---------------------------------------------------------------------------
# POST /assets — create
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_asset_returns_201(client: AsyncClient) -> None:
    with (
        patch(f"{MOCK_REPO}.get_by_hostname", new=AsyncMock(return_value=None)),
        patch(f"{MOCK_REPO}.create", new=AsyncMock(return_value=_ASSET)),
    ):
        resp = await client.post(
            BASE,
            headers=_token_headers("engineer"),
            json=_CREATE_BODY,
        )
    assert resp.status_code == 201
    assert resp.json()["hostname"] == "web-server-01"


@pytest.mark.asyncio
async def test_create_asset_duplicate_returns_409(client: AsyncClient) -> None:
    with patch(f"{MOCK_REPO}.get_by_hostname", new=AsyncMock(return_value=_ASSET)):
        resp = await client.post(
            BASE,
            headers=_token_headers("engineer"),
            json=_CREATE_BODY,
        )
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_create_asset_missing_required_field(client: AsyncClient) -> None:
    body = {k: v for k, v in _CREATE_BODY.items() if k != "asset_type"}
    resp = await client.post(
        BASE,
        headers=_token_headers("engineer"),
        json=body,
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_asset_invalid_criticality(client: AsyncClient) -> None:
    body = {**_CREATE_BODY, "criticality": 10}
    resp = await client.post(
        BASE,
        headers=_token_headers("engineer"),
        json=body,
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# PATCH /assets/{id} — update
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_update_asset_returns_updated(client: AsyncClient) -> None:
    updated = _asset(criticality=5, owner="security-team")
    with patch(f"{MOCK_REPO}.update", new=AsyncMock(return_value=updated)):
        resp = await client.patch(
            f"{BASE}/1",
            headers=_token_headers("engineer"),
            json={"criticality": 5, "owner": "security-team"},
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["criticality"] == 5
    assert data["owner"] == "security-team"


@pytest.mark.asyncio
async def test_update_asset_not_found(client: AsyncClient) -> None:
    with patch(f"{MOCK_REPO}.update", new=AsyncMock(return_value=None)):
        resp = await client.patch(
            f"{BASE}/999",
            headers=_token_headers("engineer"),
            json={"criticality": 3},
        )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# DELETE /assets/{id} — soft deactivate
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_deactivate_asset_returns_200_with_asset(client: AsyncClient) -> None:
    deactivated = _asset(is_active=False)
    with patch(f"{MOCK_REPO}.update", new=AsyncMock(return_value=deactivated)):
        resp = await client.delete(f"{BASE}/1", headers=_token_headers("engineer"))
    assert resp.status_code == 200
    assert resp.json()["is_active"] is False


@pytest.mark.asyncio
async def test_deactivate_asset_calls_update_with_is_active_false(
    client: AsyncClient,
) -> None:
    mock_update = AsyncMock(return_value=_asset(is_active=False))
    with patch(f"{MOCK_REPO}.update", new=mock_update):
        await client.delete(f"{BASE}/1", headers=_token_headers("engineer"))
    kwargs = mock_update.call_args.kwargs
    assert kwargs.get("is_active") is False


@pytest.mark.asyncio
async def test_deactivate_asset_not_found(client: AsyncClient) -> None:
    with patch(f"{MOCK_REPO}.update", new=AsyncMock(return_value=None)):
        resp = await client.delete(f"{BASE}/999", headers=_token_headers("engineer"))
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# GET /assets/{id}/detections
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_asset_detections_returns_200(client: AsyncClient) -> None:
    det = _detection()
    with (
        patch(f"{MOCK_REPO}.get_by_id", new=AsyncMock(return_value=_ASSET)),
        patch(MOCK_LIST_DETECTIONS, new=AsyncMock(return_value=([det], 1))),
    ):
        resp = await client.get(f"{BASE}/1/detections", headers=_token_headers("analyst"))
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["items"]) == 1
    assert data["items"][0]["technique_id"] == "T1059"


@pytest.mark.asyncio
async def test_list_asset_detections_asset_not_found(client: AsyncClient) -> None:
    with patch(f"{MOCK_REPO}.get_by_id", new=AsyncMock(return_value=None)):
        resp = await client.get(f"{BASE}/999/detections", headers=_token_headers("analyst"))
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_list_asset_detections_empty(client: AsyncClient) -> None:
    with (
        patch(f"{MOCK_REPO}.get_by_id", new=AsyncMock(return_value=_ASSET)),
        patch(MOCK_LIST_DETECTIONS, new=AsyncMock(return_value=([], 0))),
    ):
        resp = await client.get(f"{BASE}/1/detections", headers=_token_headers("analyst"))
    assert resp.status_code == 200
    assert resp.json()["items"] == []
    assert resp.json()["pagination"]["total"] == 0


# ---------------------------------------------------------------------------
# GET /assets/{id}/incidents
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_asset_incidents_returns_200(client: AsyncClient) -> None:
    inc = _incident()
    with (
        patch(f"{MOCK_REPO}.get_by_id", new=AsyncMock(return_value=_ASSET)),
        patch(MOCK_LIST_INCIDENTS, new=AsyncMock(return_value=([inc], 1))),
    ):
        resp = await client.get(f"{BASE}/1/incidents", headers=_token_headers("analyst"))
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["items"]) == 1
    assert data["items"][0]["title"] == "Lateral movement detected"


@pytest.mark.asyncio
async def test_list_asset_incidents_asset_not_found(client: AsyncClient) -> None:
    with patch(f"{MOCK_REPO}.get_by_id", new=AsyncMock(return_value=None)):
        resp = await client.get(f"{BASE}/999/incidents", headers=_token_headers("analyst"))
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_list_asset_incidents_empty(client: AsyncClient) -> None:
    with (
        patch(f"{MOCK_REPO}.get_by_id", new=AsyncMock(return_value=_ASSET)),
        patch(MOCK_LIST_INCIDENTS, new=AsyncMock(return_value=([], 0))),
    ):
        resp = await client.get(f"{BASE}/1/incidents", headers=_token_headers("analyst"))
    assert resp.status_code == 200
    assert resp.json()["items"] == []


# ---------------------------------------------------------------------------
# RBAC — read (analyst+)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_viewer_cannot_read_assets(client: AsyncClient) -> None:
    resp = await client.get(BASE, headers=_token_headers("viewer"))
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_analyst_can_read_assets(client: AsyncClient) -> None:
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([], 0))):
        resp = await client.get(BASE, headers=_token_headers("analyst"))
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_hunter_can_read_assets(client: AsyncClient) -> None:
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([], 0))):
        resp = await client.get(BASE, headers=_token_headers("hunter"))
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_engineer_can_read_assets(client: AsyncClient) -> None:
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([], 0))):
        resp = await client.get(BASE, headers=_token_headers("engineer"))
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_admin_can_read_assets(client: AsyncClient) -> None:
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([], 0))):
        resp = await client.get(BASE, headers=_token_headers("admin"))
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# RBAC — write (engineer+)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_analyst_cannot_create_asset(client: AsyncClient) -> None:
    resp = await client.post(BASE, headers=_token_headers("analyst"), json=_CREATE_BODY)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_hunter_cannot_create_asset(client: AsyncClient) -> None:
    resp = await client.post(BASE, headers=_token_headers("hunter"), json=_CREATE_BODY)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_engineer_can_create_asset(client: AsyncClient) -> None:
    with (
        patch(f"{MOCK_REPO}.get_by_hostname", new=AsyncMock(return_value=None)),
        patch(f"{MOCK_REPO}.create", new=AsyncMock(return_value=_ASSET)),
    ):
        resp = await client.post(
            BASE, headers=_token_headers("engineer"), json=_CREATE_BODY
        )
    assert resp.status_code == 201


@pytest.mark.asyncio
async def test_admin_can_create_asset(client: AsyncClient) -> None:
    with (
        patch(f"{MOCK_REPO}.get_by_hostname", new=AsyncMock(return_value=None)),
        patch(f"{MOCK_REPO}.create", new=AsyncMock(return_value=_ASSET)),
    ):
        resp = await client.post(
            BASE, headers=_token_headers("admin"), json=_CREATE_BODY
        )
    assert resp.status_code == 201


@pytest.mark.asyncio
async def test_analyst_cannot_delete_asset(client: AsyncClient) -> None:
    resp = await client.delete(f"{BASE}/1", headers=_token_headers("analyst"))
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_hunter_cannot_bulk_import(client: AsyncClient) -> None:
    resp = await client.post(
        f"{BASE}/bulk", headers=_token_headers("hunter"), json=[_CREATE_BODY]
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_analyst_cannot_update_asset(client: AsyncClient) -> None:
    resp = await client.patch(
        f"{BASE}/1", headers=_token_headers("analyst"), json={"criticality": 3}
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Unauthenticated
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unauthenticated_list(client: AsyncClient) -> None:
    resp = await client.get(BASE)
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_unauthenticated_create(client: AsyncClient) -> None:
    resp = await client.post(BASE, json=_CREATE_BODY)
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_unauthenticated_stats(client: AsyncClient) -> None:
    resp = await client.get(f"{BASE}/stats")
    assert resp.status_code in (401, 403)
