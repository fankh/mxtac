"""Tests for /api/v1/threat-intel endpoints — Feature 29.4.

Coverage:
  - GET  /threat-intel/iocs          — paginated list, filters (type/source/active/search)
  - GET  /threat-intel/iocs/{id}     — detail, 404
  - POST /threat-intel/iocs          — create single IOC (201)
  - POST /threat-intel/iocs/bulk     — bulk import, deduplication
  - POST /threat-intel/iocs/lookup   — exact lookup, 404 miss
  - PATCH /threat-intel/iocs/{id}    — update fields, 404
  - DELETE /threat-intel/iocs/{id}   — soft deactivate, 404
  - GET  /threat-intel/stats         — aggregate counts
  - RBAC: hunter+ for read, engineer+ for write
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

MOCK_REPO = "app.api.v1.endpoints.threat_intel.IOCRepo"
BASE = "/api/v1/threat-intel"
_NOW = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ioc(**overrides) -> SimpleNamespace:
    """Build a minimal ORM-like IOC namespace for use as a mock return."""
    defaults = {
        "id": 1,
        "ioc_type": "ip",
        "value": "203.0.113.42",
        "source": "manual",
        "confidence": 80,
        "severity": "high",
        "description": "Known C2 server",
        "tags": ["apt28", "c2"],
        "first_seen": _NOW,
        "last_seen": _NOW,
        "expires_at": None,
        "is_active": True,
        "hit_count": 3,
        "last_hit_at": _NOW,
        "created_at": _NOW,
        "updated_at": _NOW,
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _token_headers(role: str) -> dict[str, str]:
    token = create_access_token(
        {"sub": f"{role}@mxtac.local", "role": role},
        expires_delta=timedelta(hours=1),
    )
    return {"Authorization": f"Bearer {token}"}


_IOC = _ioc()

_CREATE_BODY = {
    "ioc_type": "ip",
    "value": "203.0.113.42",
    "source": "manual",
    "confidence": 80,
    "severity": "high",
    "description": "Known C2 server",
    "tags": ["apt28"],
    "first_seen": _NOW.isoformat(),
    "last_seen": _NOW.isoformat(),
}


# ---------------------------------------------------------------------------
# GET /threat-intel/iocs — list
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_iocs_returns_200(client: AsyncClient) -> None:
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([_IOC], 1))):
        resp = await client.get(f"{BASE}/iocs", headers=_token_headers("hunter"))
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "pagination" in data
    assert len(data["items"]) == 1


@pytest.mark.asyncio
async def test_list_iocs_pagination_fields(client: AsyncClient) -> None:
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([_IOC], 1))):
        resp = await client.get(f"{BASE}/iocs", headers=_token_headers("hunter"))
    pg = resp.json()["pagination"]
    assert pg["page"] == 1
    assert pg["page_size"] == 25
    assert pg["total"] == 1
    assert pg["total_pages"] == 1


@pytest.mark.asyncio
async def test_list_iocs_empty(client: AsyncClient) -> None:
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([], 0))):
        resp = await client.get(f"{BASE}/iocs", headers=_token_headers("hunter"))
    assert resp.status_code == 200
    data = resp.json()
    assert data["items"] == []
    assert data["pagination"]["total"] == 0
    assert data["pagination"]["total_pages"] == 1


@pytest.mark.asyncio
async def test_list_iocs_filter_type_forwarded(client: AsyncClient) -> None:
    """?ioc_type=ip is forwarded to the repo."""
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        await client.get(f"{BASE}/iocs?ioc_type=ip", headers=_token_headers("hunter"))
    assert mock_list.call_args.kwargs.get("ioc_type") == "ip"


@pytest.mark.asyncio
async def test_list_iocs_filter_source_forwarded(client: AsyncClient) -> None:
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        await client.get(f"{BASE}/iocs?source=opencti", headers=_token_headers("hunter"))
    assert mock_list.call_args.kwargs.get("source") == "opencti"


@pytest.mark.asyncio
async def test_list_iocs_filter_active_forwarded(client: AsyncClient) -> None:
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        await client.get(f"{BASE}/iocs?is_active=true", headers=_token_headers("hunter"))
    assert mock_list.call_args.kwargs.get("is_active") is True


@pytest.mark.asyncio
async def test_list_iocs_filter_search_forwarded(client: AsyncClient) -> None:
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        await client.get(f"{BASE}/iocs?search=apt28", headers=_token_headers("hunter"))
    assert mock_list.call_args.kwargs.get("search") == "apt28"


@pytest.mark.asyncio
async def test_list_iocs_item_fields(client: AsyncClient) -> None:
    """Response items include all required IOCResponse fields."""
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([_IOC], 1))):
        resp = await client.get(f"{BASE}/iocs", headers=_token_headers("hunter"))
    item = resp.json()["items"][0]
    for field in ("id", "ioc_type", "value", "source", "confidence", "severity",
                  "is_active", "hit_count", "tags", "first_seen", "last_seen"):
        assert field in item, f"Missing field: {field}"


# ---------------------------------------------------------------------------
# GET /threat-intel/iocs/{id} — detail
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_ioc_returns_200(client: AsyncClient) -> None:
    with patch(f"{MOCK_REPO}.get_by_id", new=AsyncMock(return_value=_IOC)):
        resp = await client.get(f"{BASE}/iocs/1", headers=_token_headers("hunter"))
    assert resp.status_code == 200
    assert resp.json()["id"] == 1


@pytest.mark.asyncio
async def test_get_ioc_not_found(client: AsyncClient) -> None:
    with patch(f"{MOCK_REPO}.get_by_id", new=AsyncMock(return_value=None)):
        resp = await client.get(f"{BASE}/iocs/999", headers=_token_headers("hunter"))
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# POST /threat-intel/iocs — create
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_ioc_returns_201(client: AsyncClient) -> None:
    with patch(f"{MOCK_REPO}.create", new=AsyncMock(return_value=_IOC)):
        resp = await client.post(
            f"{BASE}/iocs",
            headers=_token_headers("engineer"),
            json=_CREATE_BODY,
        )
    assert resp.status_code == 201
    assert resp.json()["ioc_type"] == "ip"


@pytest.mark.asyncio
async def test_create_ioc_missing_required_field(client: AsyncClient) -> None:
    body = {k: v for k, v in _CREATE_BODY.items() if k != "ioc_type"}
    resp = await client.post(
        f"{BASE}/iocs",
        headers=_token_headers("engineer"),
        json=body,
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_ioc_invalid_type(client: AsyncClient) -> None:
    body = {**_CREATE_BODY, "ioc_type": "invalid_type"}
    resp = await client.post(
        f"{BASE}/iocs",
        headers=_token_headers("engineer"),
        json=body,
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# POST /threat-intel/iocs/bulk — bulk import
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bulk_import_returns_created_skipped(client: AsyncClient) -> None:
    with patch(f"{MOCK_REPO}.bulk_create", new=AsyncMock(return_value=(2, 1))):
        resp = await client.post(
            f"{BASE}/iocs/bulk",
            headers=_token_headers("engineer"),
            json=[_CREATE_BODY, _CREATE_BODY, _CREATE_BODY],
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["created"] == 2
    assert data["skipped"] == 1


@pytest.mark.asyncio
async def test_bulk_import_empty_list(client: AsyncClient) -> None:
    with patch(f"{MOCK_REPO}.bulk_create", new=AsyncMock(return_value=(0, 0))):
        resp = await client.post(
            f"{BASE}/iocs/bulk",
            headers=_token_headers("engineer"),
            json=[],
        )
    assert resp.status_code == 200
    assert resp.json() == {"created": 0, "skipped": 0}


# ---------------------------------------------------------------------------
# POST /threat-intel/iocs/lookup — exact lookup
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_lookup_ioc_found(client: AsyncClient) -> None:
    with patch(f"{MOCK_REPO}.lookup", new=AsyncMock(return_value=_IOC)):
        resp = await client.post(
            f"{BASE}/iocs/lookup",
            headers=_token_headers("hunter"),
            json={"ioc_type": "ip", "value": "203.0.113.42"},
        )
    assert resp.status_code == 200
    assert resp.json()["value"] == "203.0.113.42"


@pytest.mark.asyncio
async def test_lookup_ioc_not_found(client: AsyncClient) -> None:
    with patch(f"{MOCK_REPO}.lookup", new=AsyncMock(return_value=None)):
        resp = await client.post(
            f"{BASE}/iocs/lookup",
            headers=_token_headers("hunter"),
            json={"ioc_type": "ip", "value": "1.2.3.4"},
        )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# PATCH /threat-intel/iocs/{id} — update
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_update_ioc_returns_updated(client: AsyncClient) -> None:
    updated = _ioc(confidence=95, severity="critical")
    with patch(f"{MOCK_REPO}.update", new=AsyncMock(return_value=updated)):
        resp = await client.patch(
            f"{BASE}/iocs/1",
            headers=_token_headers("engineer"),
            json={"confidence": 95, "severity": "critical"},
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["confidence"] == 95
    assert data["severity"] == "critical"


@pytest.mark.asyncio
async def test_update_ioc_not_found(client: AsyncClient) -> None:
    with patch(f"{MOCK_REPO}.update", new=AsyncMock(return_value=None)):
        resp = await client.patch(
            f"{BASE}/iocs/999",
            headers=_token_headers("engineer"),
            json={"confidence": 50},
        )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# DELETE /threat-intel/iocs/{id} — soft deactivate
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_deactivate_ioc_returns_200_with_ioc(client: AsyncClient) -> None:
    """DELETE deactivates (is_active=False) and returns the updated IOC."""
    deactivated = _ioc(is_active=False)
    with patch(f"{MOCK_REPO}.update", new=AsyncMock(return_value=deactivated)):
        resp = await client.delete(
            f"{BASE}/iocs/1",
            headers=_token_headers("engineer"),
        )
    assert resp.status_code == 200
    assert resp.json()["is_active"] is False


@pytest.mark.asyncio
async def test_deactivate_ioc_calls_update_with_is_active_false(client: AsyncClient) -> None:
    """DELETE passes is_active=False to the repo (not IOCRepo.delete)."""
    mock_update = AsyncMock(return_value=_ioc(is_active=False))
    with patch(f"{MOCK_REPO}.update", new=mock_update):
        await client.delete(f"{BASE}/iocs/1", headers=_token_headers("engineer"))
    kwargs = mock_update.call_args.kwargs
    assert kwargs.get("is_active") is False


@pytest.mark.asyncio
async def test_deactivate_ioc_not_found(client: AsyncClient) -> None:
    with patch(f"{MOCK_REPO}.update", new=AsyncMock(return_value=None)):
        resp = await client.delete(
            f"{BASE}/iocs/999",
            headers=_token_headers("engineer"),
        )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# GET /threat-intel/stats
# ---------------------------------------------------------------------------


_STATS = {
    "total": 100,
    "by_type": {"ip": 60, "domain": 30, "hash_sha256": 10},
    "by_source": {"manual": 40, "opencti": 60},
    "active": 90,
    "expired": 10,
}


@pytest.mark.asyncio
async def test_stats_returns_200(client: AsyncClient) -> None:
    with patch(f"{MOCK_REPO}.stats", new=AsyncMock(return_value=_STATS)):
        resp = await client.get(f"{BASE}/stats", headers=_token_headers("hunter"))
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_stats_fields(client: AsyncClient) -> None:
    with patch(f"{MOCK_REPO}.stats", new=AsyncMock(return_value=_STATS)):
        resp = await client.get(f"{BASE}/stats", headers=_token_headers("hunter"))
    data = resp.json()
    assert data["total"] == 100
    assert data["active"] == 90
    assert data["expired"] == 10
    assert data["by_type"]["ip"] == 60
    assert data["by_source"]["opencti"] == 60


@pytest.mark.asyncio
async def test_stats_empty_db(client: AsyncClient) -> None:
    empty = {"total": 0, "by_type": {}, "by_source": {}, "active": 0, "expired": 0}
    with patch(f"{MOCK_REPO}.stats", new=AsyncMock(return_value=empty)):
        resp = await client.get(f"{BASE}/stats", headers=_token_headers("hunter"))
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 0
    assert data["by_type"] == {}


# ---------------------------------------------------------------------------
# RBAC — read (hunter+)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_viewer_cannot_read_iocs(client: AsyncClient) -> None:
    resp = await client.get(f"{BASE}/iocs", headers=_token_headers("viewer"))
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_analyst_cannot_read_iocs(client: AsyncClient) -> None:
    resp = await client.get(f"{BASE}/iocs", headers=_token_headers("analyst"))
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_hunter_can_read_iocs(client: AsyncClient) -> None:
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([], 0))):
        resp = await client.get(f"{BASE}/iocs", headers=_token_headers("hunter"))
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_engineer_can_read_iocs(client: AsyncClient) -> None:
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([], 0))):
        resp = await client.get(f"{BASE}/iocs", headers=_token_headers("engineer"))
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_admin_can_read_iocs(client: AsyncClient) -> None:
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([], 0))):
        resp = await client.get(f"{BASE}/iocs", headers=_token_headers("admin"))
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# RBAC — write (engineer+)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_hunter_cannot_create_ioc(client: AsyncClient) -> None:
    resp = await client.post(
        f"{BASE}/iocs",
        headers=_token_headers("hunter"),
        json=_CREATE_BODY,
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_engineer_can_create_ioc(client: AsyncClient) -> None:
    with patch(f"{MOCK_REPO}.create", new=AsyncMock(return_value=_IOC)):
        resp = await client.post(
            f"{BASE}/iocs",
            headers=_token_headers("engineer"),
            json=_CREATE_BODY,
        )
    assert resp.status_code == 201


@pytest.mark.asyncio
async def test_admin_can_create_ioc(client: AsyncClient) -> None:
    with patch(f"{MOCK_REPO}.create", new=AsyncMock(return_value=_IOC)):
        resp = await client.post(
            f"{BASE}/iocs",
            headers=_token_headers("admin"),
            json=_CREATE_BODY,
        )
    assert resp.status_code == 201


@pytest.mark.asyncio
async def test_hunter_cannot_delete_ioc(client: AsyncClient) -> None:
    resp = await client.delete(f"{BASE}/iocs/1", headers=_token_headers("hunter"))
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_hunter_cannot_bulk_import(client: AsyncClient) -> None:
    resp = await client.post(
        f"{BASE}/iocs/bulk",
        headers=_token_headers("hunter"),
        json=[_CREATE_BODY],
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Unauthenticated
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unauthenticated_list(client: AsyncClient) -> None:
    resp = await client.get(f"{BASE}/iocs")
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_unauthenticated_create(client: AsyncClient) -> None:
    resp = await client.post(f"{BASE}/iocs", json=_CREATE_BODY)
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_unauthenticated_stats(client: AsyncClient) -> None:
    resp = await client.get(f"{BASE}/stats")
    assert resp.status_code in (401, 403)
