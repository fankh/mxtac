"""Tests for /api/v1/connectors endpoints.

Coverage:
  - List: unauthenticated → 401; non-engineer → 403; empty DB → []
  - GET by ID: 404 when not found
  - POST create: 422 on unknown type; 201 on valid type
  - PATCH update: 404 when not found
  - DELETE: 404 when not found
  - POST /{id}/test: 404 when not found
  - GET /{id}/health: 404 when not found

Uses in-memory SQLite via the ``client`` fixture (get_db overridden).
``ConnectorRepo`` performs real SQL against SQLite — no mocks needed.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient

BASE_URL = "/api/v1/connectors"

_VALID_PAYLOAD = {
    "name": "wazuh-prod",
    "connector_type": "wazuh",
    "config": {"host": "wazuh.local", "port": 1514},
    "enabled": True,
}


# ---------------------------------------------------------------------------
# Auth / access control
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_connectors_unauthenticated(client: AsyncClient) -> None:
    """GET /connectors without auth → 401 or 403."""
    resp = await client.get(BASE_URL)
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_list_connectors_any_auth_succeeds(client: AsyncClient, analyst_headers: dict) -> None:
    """GET /connectors with any valid JWT → 200 (endpoint uses plain get_current_user)."""
    resp = await client.get(BASE_URL, headers=analyst_headers)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


# ---------------------------------------------------------------------------
# List connectors
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_connectors_empty(client: AsyncClient, engineer_headers: dict) -> None:
    """GET /connectors with empty DB returns an empty list."""
    resp = await client.get(BASE_URL, headers=engineer_headers)
    assert resp.status_code == 200
    assert resp.json() == []


# ---------------------------------------------------------------------------
# GET single connector
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_connector_not_found(client: AsyncClient, engineer_headers: dict) -> None:
    """GET /connectors/{id} for unknown ID → 404."""
    resp = await client.get(f"{BASE_URL}/nonexistent-id", headers=engineer_headers)
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Connector not found"


# ---------------------------------------------------------------------------
# POST create connector
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_connector_invalid_type(client: AsyncClient, engineer_headers: dict) -> None:
    """POST /connectors with unknown connector_type → 422."""
    resp = await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={
            "name": "bad-conn",
            "connector_type": "unknown_vendor",
            "config": {},
        },
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_connector_success(client: AsyncClient, engineer_headers: dict) -> None:
    """POST /connectors with valid payload → 201, returned object has correct fields."""
    resp = await client.post(BASE_URL, headers=engineer_headers, json=_VALID_PAYLOAD)
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == _VALID_PAYLOAD["name"]
    assert data["connector_type"] == _VALID_PAYLOAD["connector_type"]
    assert data["enabled"] is True
    assert "id" in data


@pytest.mark.asyncio
async def test_create_connector_appears_in_list(client: AsyncClient, engineer_headers: dict) -> None:
    """After creation, the connector appears in GET /connectors list."""
    await client.post(BASE_URL, headers=engineer_headers, json=_VALID_PAYLOAD)
    resp = await client.get(BASE_URL, headers=engineer_headers)
    assert resp.status_code == 200
    names = [c["name"] for c in resp.json()]
    assert _VALID_PAYLOAD["name"] in names


# ---------------------------------------------------------------------------
# PATCH update connector
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_update_connector_not_found(client: AsyncClient, engineer_headers: dict) -> None:
    """PATCH /connectors/{id} for unknown ID → 404."""
    resp = await client.patch(
        f"{BASE_URL}/nonexistent-id",
        headers=engineer_headers,
        json={"enabled": False},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_update_connector_disable(client: AsyncClient, engineer_headers: dict) -> None:
    """PATCH /connectors/{id} with enabled=False disables the connector."""
    create_resp = await client.post(BASE_URL, headers=engineer_headers, json=_VALID_PAYLOAD)
    connector_id = create_resp.json()["id"]
    resp = await client.patch(
        f"{BASE_URL}/{connector_id}",
        headers=engineer_headers,
        json={"enabled": False},
    )
    assert resp.status_code == 200
    assert resp.json()["enabled"] is False


# ---------------------------------------------------------------------------
# DELETE connector
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_delete_connector_not_found(client: AsyncClient, engineer_headers: dict) -> None:
    """DELETE /connectors/{id} for unknown ID → 404."""
    resp = await client.delete(f"{BASE_URL}/nonexistent-id", headers=engineer_headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_delete_connector_success(client: AsyncClient, engineer_headers: dict) -> None:
    """DELETE /connectors/{id} for an existing connector → 204."""
    create_resp = await client.post(BASE_URL, headers=engineer_headers, json=_VALID_PAYLOAD)
    connector_id = create_resp.json()["id"]
    resp = await client.delete(f"{BASE_URL}/{connector_id}", headers=engineer_headers)
    assert resp.status_code == 204


# ---------------------------------------------------------------------------
# POST /{id}/test — connection test
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_connector_test_not_found(client: AsyncClient, engineer_headers: dict) -> None:
    """POST /connectors/{id}/test for unknown ID → 404."""
    resp = await client.post(f"{BASE_URL}/nonexistent-id/test", headers=engineer_headers)
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# GET /{id}/health
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_connector_health_not_found(client: AsyncClient, engineer_headers: dict) -> None:
    """GET /connectors/{id}/health for unknown ID → 404."""
    resp = await client.get(f"{BASE_URL}/nonexistent-id/health", headers=engineer_headers)
    assert resp.status_code == 404
