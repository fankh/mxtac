"""Tests for Feature 6.8 — Health check endpoint `POST /connectors/{id}/test`.

Verifies the real (non-stub) implementation of the connection test endpoint:

Coverage:
  Wazuh connection test
    - reachable=True when Wazuh API returns HTTP 200
    - reachable=False + message when API returns HTTP 401
    - reachable=False + message on network connection error
    - reachable=False when required 'url' config key is missing

  Zeek connection test
    - reachable=True when configured log directory exists
    - reachable=False when log directory does not exist

  Suricata connection test
    - reachable=True when configured EVE file exists
    - reachable=False when EVE file does not exist

  Unsupported connector type
    - reachable=False with 'not supported' message for velociraptor, osquery, generic, etc.

  Database persistence
    - status set to 'active' in DB after successful connection test
    - status set to 'error' in DB after failed connection test
    - error_message persisted in DB when test fails
    - error_message cleared in DB when test succeeds
    - last_seen_at updated after every test (both success and failure)

  RBAC
    - viewer cannot trigger test (403)
    - engineer can trigger test (200)
    - admin can trigger test (200)

  Error handling
    - 404 when connector_id does not exist

Uses in-memory SQLite via the ``client`` fixture (get_db overridden).
External HTTP and filesystem calls are mocked to test both success and failure
paths deterministically.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from httpx import AsyncClient

from app.repositories.connector_repo import ConnectorRepo

BASE_URL = "/api/v1/connectors"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_WAZUH_PAYLOAD = {
    "name": "wazuh-test",
    "connector_type": "wazuh",
    "config": {
        "url": "https://wazuh.example.com:55000",
        "username": "admin",
        "password": "s3cr3t",
        "verify_ssl": False,
    },
    "enabled": True,
}

_ZEEK_PAYLOAD = {
    "name": "zeek-test",
    "connector_type": "zeek",
    "config": {"log_dir": "/opt/zeek/logs/current"},
    "enabled": True,
}

_SURICATA_PAYLOAD = {
    "name": "suricata-test",
    "connector_type": "suricata",
    "config": {"eve_file": "/var/log/suricata/eve.json"},
    "enabled": True,
}

_PROWLER_PAYLOAD = {
    "name": "prowler-test",
    "connector_type": "prowler",
    "config": {},
    "enabled": True,
}


async def _create(client: AsyncClient, headers: dict, payload: dict) -> dict:
    resp = await client.post(BASE_URL, headers=headers, json=payload)
    assert resp.status_code == 201
    return resp.json()


def _make_httpx_response(status_code: int) -> MagicMock:
    """Build a minimal httpx.Response mock with a given status code."""
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    return resp


# ---------------------------------------------------------------------------
# Wazuh connection test — success path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_wazuh_test_reachable_when_api_returns_200(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """POST /connectors/{id}/test → reachable=True when Wazuh API returns 200."""
    conn = await _create(client, engineer_headers, _WAZUH_PAYLOAD)

    mock_resp = _make_httpx_response(200)
    mock_async_client = AsyncMock()
    mock_async_client.__aenter__ = AsyncMock(return_value=mock_async_client)
    mock_async_client.__aexit__ = AsyncMock(return_value=False)
    mock_async_client.get = AsyncMock(return_value=mock_resp)

    with patch("app.api.v1.endpoints.connectors.httpx.AsyncClient", return_value=mock_async_client):
        resp = await client.post(f"{BASE_URL}/{conn['id']}/test", headers=engineer_headers)

    assert resp.status_code == 200
    data = resp.json()
    assert data["reachable"] is True
    assert data["connector_id"] == conn["id"]
    assert "Wazuh API reachable" in data["message"]


# ---------------------------------------------------------------------------
# Wazuh connection test — auth failure path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_wazuh_test_not_reachable_on_401(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """POST /connectors/{id}/test → reachable=False when Wazuh API returns 401."""
    conn = await _create(client, engineer_headers, _WAZUH_PAYLOAD)

    mock_resp = _make_httpx_response(401)
    mock_async_client = AsyncMock()
    mock_async_client.__aenter__ = AsyncMock(return_value=mock_async_client)
    mock_async_client.__aexit__ = AsyncMock(return_value=False)
    mock_async_client.get = AsyncMock(return_value=mock_resp)

    with patch("app.api.v1.endpoints.connectors.httpx.AsyncClient", return_value=mock_async_client):
        resp = await client.post(f"{BASE_URL}/{conn['id']}/test", headers=engineer_headers)

    data = resp.json()
    assert data["reachable"] is False
    assert "credentials" in data["message"].lower()


# ---------------------------------------------------------------------------
# Wazuh connection test — network error path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_wazuh_test_not_reachable_on_connect_error(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """POST /connectors/{id}/test → reachable=False on network connection failure."""
    conn = await _create(client, engineer_headers, _WAZUH_PAYLOAD)

    mock_async_client = AsyncMock()
    mock_async_client.__aenter__ = AsyncMock(return_value=mock_async_client)
    mock_async_client.__aexit__ = AsyncMock(return_value=False)
    mock_async_client.get = AsyncMock(
        side_effect=httpx.ConnectError("Connection refused")
    )

    with patch("app.api.v1.endpoints.connectors.httpx.AsyncClient", return_value=mock_async_client):
        resp = await client.post(f"{BASE_URL}/{conn['id']}/test", headers=engineer_headers)

    data = resp.json()
    assert data["reachable"] is False
    assert "Cannot connect" in data["message"] or "connect" in data["message"].lower()


# ---------------------------------------------------------------------------
# Wazuh connection test — missing url config
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_wazuh_test_not_reachable_when_url_missing(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """POST /connectors/{id}/test → reachable=False when 'url' config is absent."""
    payload = {**_WAZUH_PAYLOAD, "config": {"username": "admin", "password": "pass"}}
    conn = await _create(client, engineer_headers, payload)

    resp = await client.post(f"{BASE_URL}/{conn['id']}/test", headers=engineer_headers)

    data = resp.json()
    assert data["reachable"] is False
    assert "url" in data["message"].lower()


# ---------------------------------------------------------------------------
# Zeek connection test
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_zeek_test_reachable_when_log_dir_exists(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """POST /connectors/{id}/test → reachable=True when Zeek log directory exists."""
    conn = await _create(client, engineer_headers, _ZEEK_PAYLOAD)

    with patch("app.api.v1.endpoints.connectors.os.path.isdir", return_value=True):
        resp = await client.post(f"{BASE_URL}/{conn['id']}/test", headers=engineer_headers)

    data = resp.json()
    assert data["reachable"] is True
    assert "accessible" in data["message"].lower()


@pytest.mark.asyncio
async def test_zeek_test_not_reachable_when_log_dir_missing(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """POST /connectors/{id}/test → reachable=False when Zeek log directory absent."""
    conn = await _create(client, engineer_headers, _ZEEK_PAYLOAD)

    with patch("app.api.v1.endpoints.connectors.os.path.isdir", return_value=False):
        resp = await client.post(f"{BASE_URL}/{conn['id']}/test", headers=engineer_headers)

    data = resp.json()
    assert data["reachable"] is False
    assert "not found" in data["message"].lower()


# ---------------------------------------------------------------------------
# Suricata connection test
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_suricata_test_reachable_when_eve_file_exists(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """POST /connectors/{id}/test → reachable=True when Suricata EVE file exists."""
    conn = await _create(client, engineer_headers, _SURICATA_PAYLOAD)

    with patch("app.api.v1.endpoints.connectors.os.path.isfile", return_value=True):
        resp = await client.post(f"{BASE_URL}/{conn['id']}/test", headers=engineer_headers)

    data = resp.json()
    assert data["reachable"] is True
    assert "accessible" in data["message"].lower()


@pytest.mark.asyncio
async def test_suricata_test_not_reachable_when_eve_file_missing(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """POST /connectors/{id}/test → reachable=False when Suricata EVE file absent."""
    conn = await _create(client, engineer_headers, _SURICATA_PAYLOAD)

    with patch("app.api.v1.endpoints.connectors.os.path.isfile", return_value=False):
        resp = await client.post(f"{BASE_URL}/{conn['id']}/test", headers=engineer_headers)

    data = resp.json()
    assert data["reachable"] is False
    assert "not found" in data["message"].lower()


# ---------------------------------------------------------------------------
# Unsupported connector types
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("connector_type", ["osquery", "generic"])
async def test_unsupported_type_returns_not_reachable(
    client: AsyncClient, engineer_headers: dict, connector_type: str
) -> None:
    """POST /connectors/{id}/test → reachable=False for connector types with no tester."""
    payload = {
        "name": f"{connector_type}-conn",
        "connector_type": connector_type,
        "config": {},
        "enabled": True,
    }
    conn = await _create(client, engineer_headers, payload)

    resp = await client.post(f"{BASE_URL}/{conn['id']}/test", headers=engineer_headers)

    assert resp.status_code == 200
    data = resp.json()
    assert data["reachable"] is False
    assert "not supported" in data["message"].lower()


# ---------------------------------------------------------------------------
# Database persistence — status update
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_db_status_set_to_active_on_success(
    client: AsyncClient, engineer_headers: dict, db_session
) -> None:
    """After a successful connection test, DB status is updated to 'active'."""
    conn = await _create(client, engineer_headers, _WAZUH_PAYLOAD)

    mock_resp = _make_httpx_response(200)
    mock_async_client = AsyncMock()
    mock_async_client.__aenter__ = AsyncMock(return_value=mock_async_client)
    mock_async_client.__aexit__ = AsyncMock(return_value=False)
    mock_async_client.get = AsyncMock(return_value=mock_resp)

    with patch("app.api.v1.endpoints.connectors.httpx.AsyncClient", return_value=mock_async_client):
        await client.post(f"{BASE_URL}/{conn['id']}/test", headers=engineer_headers)

    db_conn = await ConnectorRepo.get_by_id(db_session, conn["id"])
    assert db_conn is not None
    assert db_conn.status == "active"


@pytest.mark.asyncio
async def test_db_status_set_to_error_on_failure(
    client: AsyncClient, engineer_headers: dict, db_session
) -> None:
    """After a failed connection test, DB status is updated to 'error'."""
    conn = await _create(client, engineer_headers, _WAZUH_PAYLOAD)

    mock_async_client = AsyncMock()
    mock_async_client.__aenter__ = AsyncMock(return_value=mock_async_client)
    mock_async_client.__aexit__ = AsyncMock(return_value=False)
    mock_async_client.get = AsyncMock(
        side_effect=httpx.ConnectError("refused")
    )

    with patch("app.api.v1.endpoints.connectors.httpx.AsyncClient", return_value=mock_async_client):
        await client.post(f"{BASE_URL}/{conn['id']}/test", headers=engineer_headers)

    db_conn = await ConnectorRepo.get_by_id(db_session, conn["id"])
    assert db_conn is not None
    assert db_conn.status == "error"


@pytest.mark.asyncio
async def test_db_error_message_persisted_on_failure(
    client: AsyncClient, engineer_headers: dict, db_session
) -> None:
    """After a failed test, error_message is stored in the DB."""
    conn = await _create(client, engineer_headers, _WAZUH_PAYLOAD)

    mock_async_client = AsyncMock()
    mock_async_client.__aenter__ = AsyncMock(return_value=mock_async_client)
    mock_async_client.__aexit__ = AsyncMock(return_value=False)
    mock_async_client.get = AsyncMock(
        side_effect=httpx.ConnectError("refused")
    )

    with patch("app.api.v1.endpoints.connectors.httpx.AsyncClient", return_value=mock_async_client):
        await client.post(f"{BASE_URL}/{conn['id']}/test", headers=engineer_headers)

    db_conn = await ConnectorRepo.get_by_id(db_session, conn["id"])
    assert db_conn.error_message is not None
    assert len(db_conn.error_message) > 0


@pytest.mark.asyncio
async def test_db_error_message_cleared_on_success(
    client: AsyncClient, engineer_headers: dict, db_session
) -> None:
    """After a successful test, error_message is cleared to None in the DB."""
    conn = await _create(client, engineer_headers, _WAZUH_PAYLOAD)

    mock_resp = _make_httpx_response(200)
    mock_async_client = AsyncMock()
    mock_async_client.__aenter__ = AsyncMock(return_value=mock_async_client)
    mock_async_client.__aexit__ = AsyncMock(return_value=False)
    mock_async_client.get = AsyncMock(return_value=mock_resp)

    with patch("app.api.v1.endpoints.connectors.httpx.AsyncClient", return_value=mock_async_client):
        await client.post(f"{BASE_URL}/{conn['id']}/test", headers=engineer_headers)

    db_conn = await ConnectorRepo.get_by_id(db_session, conn["id"])
    assert db_conn.error_message is None


@pytest.mark.asyncio
async def test_db_last_seen_at_updated_on_success(
    client: AsyncClient, engineer_headers: dict, db_session
) -> None:
    """After a successful test, last_seen_at is populated in the DB."""
    conn = await _create(client, engineer_headers, _WAZUH_PAYLOAD)

    # Verify initial state: last_seen_at is None
    db_conn = await ConnectorRepo.get_by_id(db_session, conn["id"])
    assert db_conn.last_seen_at is None

    mock_resp = _make_httpx_response(200)
    mock_async_client = AsyncMock()
    mock_async_client.__aenter__ = AsyncMock(return_value=mock_async_client)
    mock_async_client.__aexit__ = AsyncMock(return_value=False)
    mock_async_client.get = AsyncMock(return_value=mock_resp)

    with patch("app.api.v1.endpoints.connectors.httpx.AsyncClient", return_value=mock_async_client):
        await client.post(f"{BASE_URL}/{conn['id']}/test", headers=engineer_headers)

    db_conn = await ConnectorRepo.get_by_id(db_session, conn["id"])
    assert db_conn.last_seen_at is not None


@pytest.mark.asyncio
async def test_db_last_seen_at_updated_on_failure(
    client: AsyncClient, engineer_headers: dict, db_session
) -> None:
    """After a failed test, last_seen_at is also updated in the DB."""
    conn = await _create(client, engineer_headers, _WAZUH_PAYLOAD)

    mock_async_client = AsyncMock()
    mock_async_client.__aenter__ = AsyncMock(return_value=mock_async_client)
    mock_async_client.__aexit__ = AsyncMock(return_value=False)
    mock_async_client.get = AsyncMock(
        side_effect=httpx.ConnectError("refused")
    )

    with patch("app.api.v1.endpoints.connectors.httpx.AsyncClient", return_value=mock_async_client):
        await client.post(f"{BASE_URL}/{conn['id']}/test", headers=engineer_headers)

    db_conn = await ConnectorRepo.get_by_id(db_session, conn["id"])
    assert db_conn.last_seen_at is not None


# ---------------------------------------------------------------------------
# Response shape
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_response_contains_required_fields(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """POST /connectors/{id}/test response always contains connector_id, reachable, message."""
    conn = await _create(client, engineer_headers, _PROWLER_PAYLOAD)

    resp = await client.post(f"{BASE_URL}/{conn['id']}/test", headers=engineer_headers)

    assert resp.status_code == 200
    data = resp.json()
    assert "connector_id" in data
    assert "reachable" in data
    assert "message" in data
    assert isinstance(data["connector_id"], str)
    assert isinstance(data["reachable"], bool)
    assert isinstance(data["message"], str)


@pytest.mark.asyncio
async def test_response_connector_id_matches(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """connector_id in the response matches the requested connector's ID."""
    conn = await _create(client, engineer_headers, _PROWLER_PAYLOAD)

    resp = await client.post(f"{BASE_URL}/{conn['id']}/test", headers=engineer_headers)

    assert resp.json()["connector_id"] == conn["id"]


# ---------------------------------------------------------------------------
# 404 — unknown connector
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_returns_404_for_unknown_connector(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """POST /connectors/nonexistent/test → 404."""
    resp = await client.post(f"{BASE_URL}/nonexistent-id/test", headers=engineer_headers)
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Connector not found"


# ---------------------------------------------------------------------------
# RBAC
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_viewer_cannot_trigger_test(
    client: AsyncClient, engineer_headers: dict, viewer_headers: dict
) -> None:
    """Viewer role is denied POST /connectors/{id}/test (requires connectors:write)."""
    conn = await _create(client, engineer_headers, _PROWLER_PAYLOAD)
    resp = await client.post(f"{BASE_URL}/{conn['id']}/test", headers=viewer_headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_engineer_can_trigger_test(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """Engineer role can POST /connectors/{id}/test."""
    conn = await _create(client, engineer_headers, _PROWLER_PAYLOAD)
    resp = await client.post(f"{BASE_URL}/{conn['id']}/test", headers=engineer_headers)
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_admin_can_trigger_test(
    client: AsyncClient, admin_headers: dict
) -> None:
    """Admin role can POST /connectors/{id}/test."""
    conn = await _create(client, admin_headers, _PROWLER_PAYLOAD)
    resp = await client.post(f"{BASE_URL}/{conn['id']}/test", headers=admin_headers)
    assert resp.status_code == 200
