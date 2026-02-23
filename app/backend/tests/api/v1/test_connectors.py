"""Tests for /api/v1/connectors endpoints.

RBAC:
  connectors:read  → engineer, admin
  connectors:write → engineer, admin
"""

from __future__ import annotations

import pytest


_BASE = "/api/v1/connectors"


class TestListConnectorsRBAC:
    """GET /connectors — access control."""

    async def test_engineer_can_list(self, client, engineer_headers) -> None:
        resp = await client.get(_BASE, headers=engineer_headers)
        assert resp.status_code == 200

    async def test_admin_can_list(self, client, admin_headers) -> None:
        resp = await client.get(_BASE, headers=admin_headers)
        assert resp.status_code == 200

    async def test_analyst_cannot_list(self, client, analyst_headers) -> None:
        resp = await client.get(_BASE, headers=analyst_headers)
        assert resp.status_code == 403

    async def test_hunter_cannot_list(self, client, hunter_headers) -> None:
        resp = await client.get(_BASE, headers=hunter_headers)
        assert resp.status_code == 403

    async def test_viewer_cannot_list(self, client, viewer_headers) -> None:
        resp = await client.get(_BASE, headers=viewer_headers)
        assert resp.status_code == 403

    async def test_unauthenticated_cannot_list(self, client) -> None:
        resp = await client.get(_BASE)
        assert resp.status_code == 401


class TestListConnectorsResponse:
    """GET /connectors — response shape."""

    async def test_returns_list(self, client, engineer_headers) -> None:
        resp = await client.get(_BASE, headers=engineer_headers)
        assert isinstance(resp.json(), list)

    async def test_empty_list_when_no_connectors(self, client, engineer_headers) -> None:
        resp = await client.get(_BASE, headers=engineer_headers)
        assert resp.json() == []


class TestCreateConnectorRBAC:
    """POST /connectors — access control."""

    _payload = {
        "name": "Test Wazuh",
        "connector_type": "wazuh",
        "config": {"url": "http://localhost:55000", "username": "admin", "password": "pass"},
        "enabled": False,
    }

    async def test_engineer_can_create(self, client, engineer_headers) -> None:
        resp = await client.post(_BASE, json=self._payload, headers=engineer_headers)
        # 200/201 for success or 409 if duplicate; 4xx for auth errors
        assert resp.status_code not in (401, 403)

    async def test_admin_can_create(self, client, admin_headers) -> None:
        resp = await client.post(_BASE, json=self._payload, headers=admin_headers)
        assert resp.status_code not in (401, 403)

    async def test_analyst_cannot_create(self, client, analyst_headers) -> None:
        resp = await client.post(_BASE, json=self._payload, headers=analyst_headers)
        assert resp.status_code == 403

    async def test_hunter_cannot_create(self, client, hunter_headers) -> None:
        resp = await client.post(_BASE, json=self._payload, headers=hunter_headers)
        assert resp.status_code == 403


class TestCreateConnectorValidation:
    """POST /connectors — request validation."""

    async def test_invalid_connector_type_returns_422(self, client, engineer_headers) -> None:
        resp = await client.post(
            _BASE,
            json={
                "name": "Bad Connector",
                "connector_type": "not_a_real_type",
                "config": {},
            },
            headers=engineer_headers,
        )
        assert resp.status_code == 422

    async def test_missing_name_returns_422(self, client, engineer_headers) -> None:
        resp = await client.post(
            _BASE,
            json={"connector_type": "wazuh", "config": {}},
            headers=engineer_headers,
        )
        assert resp.status_code == 422

    async def test_missing_config_returns_422(self, client, engineer_headers) -> None:
        resp = await client.post(
            _BASE,
            json={"name": "No Config Conn", "connector_type": "wazuh"},
            headers=engineer_headers,
        )
        assert resp.status_code == 422


class TestConnectorNotFound:
    """GET/PATCH/DELETE /connectors/{id} — 404 for missing resources."""

    async def test_get_nonexistent_returns_404(self, client, engineer_headers) -> None:
        resp = await client.get(
            f"{_BASE}/00000000-0000-0000-0000-000000000000",
            headers=engineer_headers,
        )
        assert resp.status_code == 404

    async def test_delete_nonexistent_returns_404(self, client, engineer_headers) -> None:
        resp = await client.delete(
            f"{_BASE}/00000000-0000-0000-0000-000000000000",
            headers=engineer_headers,
        )
        assert resp.status_code == 404
