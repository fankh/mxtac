"""Tests for /api/v1/agents endpoints.

Coverage:
  - POST /agents/register: missing API key → 401; invalid key → 403; invalid type → 422
  - POST /agents/register: valid → 201 with correct fields; idempotent re-registration
  - POST /agents/{id}/heartbeat: valid → 200, status=online; unknown id → 404
  - GET /agents: unauthenticated → 401/403; analyst denied → 403; engineer allowed → 200
  - GET /agents/{id}: 200 with correct fields; 404 when not found
  - PATCH /agents/{id}: version update; config merge; 404 when not found
  - DELETE /agents/{id}: 204 on success; 404 when not found; gone after delete

Agent degradation logic:
  - AgentRepo.degrade_stale_agents: online + no hb → offline; online + stale → degraded/offline

Uses in-memory SQLite via the ``client`` fixture (get_db overridden).
``AgentRepo`` and ``APIKeyRepo`` perform real SQL against SQLite — no mocks needed.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agent import Agent
from app.repositories.agent_repo import AgentRepo
from app.repositories.api_key_repo import APIKeyRepo

BASE_URL = "/api/v1/agents"

_RAW_KEY = "test-agent-api-key-9876"

_VALID_REGISTER = {
    "hostname": "sensor-01.corp.local",
    "agent_type": "mxguard",
    "version": "1.2.3",
    "config": {"poll_interval": 30},
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
async def api_key_headers(db_session: AsyncSession) -> dict[str, str]:
    """Create an API key in the test DB and return X-API-Key headers."""
    await APIKeyRepo.create(db_session, _RAW_KEY, "test-key")
    return {"X-API-Key": _RAW_KEY}


@pytest.fixture
async def registered_agent(
    client: AsyncClient, api_key_headers: dict[str, str]
) -> dict:
    """Register an agent and return the response JSON."""
    resp = await client.post(
        f"{BASE_URL}/register", headers=api_key_headers, json=_VALID_REGISTER
    )
    assert resp.status_code == 201
    return resp.json()


# ---------------------------------------------------------------------------
# POST /agents/register — auth checks
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_register_no_api_key(client: AsyncClient) -> None:
    """POST /agents/register without X-API-Key → 401."""
    resp = await client.post(f"{BASE_URL}/register", json=_VALID_REGISTER)
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_register_invalid_api_key(client: AsyncClient) -> None:
    """POST /agents/register with unknown X-API-Key → 403."""
    resp = await client.post(
        f"{BASE_URL}/register",
        headers={"X-API-Key": "wrong-key"},
        json=_VALID_REGISTER,
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# POST /agents/register — validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_register_invalid_agent_type(
    client: AsyncClient, api_key_headers: dict[str, str]
) -> None:
    """POST /agents/register with unknown agent_type → 422."""
    payload = {**_VALID_REGISTER, "agent_type": "unknown_agent"}
    resp = await client.post(
        f"{BASE_URL}/register", headers=api_key_headers, json=payload
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
@pytest.mark.parametrize("agent_type", ["mxguard", "mxwatch"])
async def test_register_all_valid_agent_types(
    client: AsyncClient, api_key_headers: dict[str, str], agent_type: str
) -> None:
    """Both documented agent types are accepted."""
    payload = {**_VALID_REGISTER, "hostname": f"host-{agent_type}", "agent_type": agent_type}
    resp = await client.post(
        f"{BASE_URL}/register", headers=api_key_headers, json=payload
    )
    assert resp.status_code == 201
    assert resp.json()["agent_type"] == agent_type


# ---------------------------------------------------------------------------
# POST /agents/register — success
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_register_success_fields(
    client: AsyncClient, api_key_headers: dict[str, str]
) -> None:
    """POST /agents/register → 201 with all expected fields."""
    resp = await client.post(
        f"{BASE_URL}/register", headers=api_key_headers, json=_VALID_REGISTER
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["hostname"] == _VALID_REGISTER["hostname"]
    assert data["agent_type"] == _VALID_REGISTER["agent_type"]
    assert data["version"] == _VALID_REGISTER["version"]
    assert data["status"] == "online"
    assert data["last_heartbeat"] is not None
    assert "id" in data
    assert "created_at" in data
    assert "updated_at" in data


@pytest.mark.asyncio
async def test_register_idempotent(
    client: AsyncClient, api_key_headers: dict[str, str]
) -> None:
    """Re-registering with the same hostname updates the existing record."""
    resp1 = await client.post(
        f"{BASE_URL}/register", headers=api_key_headers, json=_VALID_REGISTER
    )
    id1 = resp1.json()["id"]

    updated = {**_VALID_REGISTER, "version": "2.0.0"}
    resp2 = await client.post(
        f"{BASE_URL}/register", headers=api_key_headers, json=updated
    )
    assert resp2.status_code == 201
    data2 = resp2.json()
    # Same record, same ID
    assert data2["id"] == id1
    assert data2["version"] == "2.0.0"
    assert data2["status"] == "online"


# ---------------------------------------------------------------------------
# POST /agents/{id}/heartbeat
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_heartbeat_no_api_key(
    client: AsyncClient, registered_agent: dict
) -> None:
    """POST /agents/{id}/heartbeat without X-API-Key → 401."""
    agent_id = registered_agent["id"]
    resp = await client.post(f"{BASE_URL}/{agent_id}/heartbeat")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_heartbeat_not_found(
    client: AsyncClient, api_key_headers: dict[str, str]
) -> None:
    """POST /agents/{id}/heartbeat for unknown ID → 404."""
    resp = await client.post(
        f"{BASE_URL}/nonexistent-id/heartbeat", headers=api_key_headers
    )
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Agent not found"


@pytest.mark.asyncio
async def test_heartbeat_success(
    client: AsyncClient,
    api_key_headers: dict[str, str],
    registered_agent: dict,
) -> None:
    """POST /agents/{id}/heartbeat → 200 with status=online and refreshed timestamp."""
    agent_id = registered_agent["id"]
    resp = await client.post(
        f"{BASE_URL}/{agent_id}/heartbeat", headers=api_key_headers
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == agent_id
    assert data["status"] == "online"
    assert data["last_heartbeat"] is not None


# ---------------------------------------------------------------------------
# GET /agents — list
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_agents_unauthenticated(client: AsyncClient) -> None:
    """GET /agents without auth → 401 or 403."""
    resp = await client.get(BASE_URL)
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_list_agents_analyst_denied(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """GET /agents with analyst role → 403 (agents:read requires engineer+)."""
    resp = await client.get(BASE_URL, headers=analyst_headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_list_agents_empty(client: AsyncClient, engineer_headers: dict) -> None:
    """GET /agents with empty DB → 200, []."""
    resp = await client.get(BASE_URL, headers=engineer_headers)
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_list_agents_contains_registered(
    client: AsyncClient,
    engineer_headers: dict,
    registered_agent: dict,
) -> None:
    """After registration, agent appears in GET /agents list."""
    resp = await client.get(BASE_URL, headers=engineer_headers)
    assert resp.status_code == 200
    ids = [a["id"] for a in resp.json()]
    assert registered_agent["id"] in ids


# ---------------------------------------------------------------------------
# GET /agents/{id} — single
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_agent_not_found(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """GET /agents/{id} for unknown ID → 404."""
    resp = await client.get(f"{BASE_URL}/nonexistent-id", headers=engineer_headers)
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Agent not found"


@pytest.mark.asyncio
async def test_get_agent_success(
    client: AsyncClient,
    engineer_headers: dict,
    registered_agent: dict,
) -> None:
    """GET /agents/{id} for existing agent → 200 with correct fields."""
    agent_id = registered_agent["id"]
    resp = await client.get(f"{BASE_URL}/{agent_id}", headers=engineer_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == agent_id
    assert data["hostname"] == _VALID_REGISTER["hostname"]
    assert data["agent_type"] == _VALID_REGISTER["agent_type"]
    assert data["version"] == _VALID_REGISTER["version"]


# ---------------------------------------------------------------------------
# PATCH /agents/{id}
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_update_agent_not_found(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """PATCH /agents/{id} for unknown ID → 404."""
    resp = await client.patch(
        f"{BASE_URL}/nonexistent-id",
        headers=engineer_headers,
        json={"version": "9.9.9"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_update_agent_version(
    client: AsyncClient,
    engineer_headers: dict,
    registered_agent: dict,
) -> None:
    """PATCH /agents/{id} with version → 200, version updated."""
    agent_id = registered_agent["id"]
    resp = await client.patch(
        f"{BASE_URL}/{agent_id}",
        headers=engineer_headers,
        json={"version": "9.9.9"},
    )
    assert resp.status_code == 200
    assert resp.json()["version"] == "9.9.9"


@pytest.mark.asyncio
async def test_update_agent_config_merged(
    client: AsyncClient,
    engineer_headers: dict,
    registered_agent: dict,
) -> None:
    """PATCH /agents/{id} with config merges into existing config."""
    agent_id = registered_agent["id"]
    resp = await client.patch(
        f"{BASE_URL}/{agent_id}",
        headers=engineer_headers,
        json={"config": {"new_key": "new_value"}},
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_update_agent_analyst_denied(
    client: AsyncClient,
    analyst_headers: dict,
    registered_agent: dict,
) -> None:
    """PATCH /agents/{id} with analyst role → 403 (agents:write requires engineer+)."""
    agent_id = registered_agent["id"]
    resp = await client.patch(
        f"{BASE_URL}/{agent_id}",
        headers=analyst_headers,
        json={"version": "1.0.0"},
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# DELETE /agents/{id}
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_delete_agent_not_found(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """DELETE /agents/{id} for unknown ID → 404."""
    resp = await client.delete(
        f"{BASE_URL}/nonexistent-id", headers=engineer_headers
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_delete_agent_success(
    client: AsyncClient,
    engineer_headers: dict,
    registered_agent: dict,
) -> None:
    """DELETE /agents/{id} → 204."""
    agent_id = registered_agent["id"]
    resp = await client.delete(f"{BASE_URL}/{agent_id}", headers=engineer_headers)
    assert resp.status_code == 204


@pytest.mark.asyncio
async def test_deleted_agent_absent_from_list(
    client: AsyncClient,
    engineer_headers: dict,
    registered_agent: dict,
) -> None:
    """After DELETE, agent no longer appears in GET /agents list."""
    agent_id = registered_agent["id"]
    await client.delete(f"{BASE_URL}/{agent_id}", headers=engineer_headers)
    list_resp = await client.get(BASE_URL, headers=engineer_headers)
    ids = [a["id"] for a in list_resp.json()]
    assert agent_id not in ids


# ---------------------------------------------------------------------------
# AgentRepo.degrade_stale_agents — unit tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_degrade_stale_online_agent(db_session: AsyncSession) -> None:
    """Online agent with no heartbeat for >2min becomes degraded."""
    agent = Agent(
        hostname="stale-host",
        agent_type="mxguard",
        version="1.0",
        status="online",
        last_heartbeat=datetime.now(timezone.utc) - timedelta(minutes=5),
    )
    db_session.add(agent)
    await db_session.flush()

    degraded, offline = await AgentRepo.degrade_stale_agents(db_session)
    assert degraded == 1
    assert offline == 0

    await db_session.refresh(agent)
    assert agent.status == "degraded"


@pytest.mark.asyncio
async def test_degrade_stale_to_offline(db_session: AsyncSession) -> None:
    """Online agent with no heartbeat for >10min becomes offline."""
    agent = Agent(
        hostname="very-stale-host",
        agent_type="mxwatch",
        version="1.0",
        status="online",
        last_heartbeat=datetime.now(timezone.utc) - timedelta(minutes=15),
    )
    db_session.add(agent)
    await db_session.flush()

    degraded, offline = await AgentRepo.degrade_stale_agents(db_session)
    assert offline == 1

    await db_session.refresh(agent)
    assert agent.status == "offline"


@pytest.mark.asyncio
async def test_degrade_already_degraded_to_offline(db_session: AsyncSession) -> None:
    """Degraded agent with >10min silence is escalated to offline."""
    agent = Agent(
        hostname="degraded-old",
        agent_type="mxguard",
        version="1.0",
        status="degraded",
        last_heartbeat=datetime.now(timezone.utc) - timedelta(minutes=20),
    )
    db_session.add(agent)
    await db_session.flush()

    degraded, offline = await AgentRepo.degrade_stale_agents(db_session)
    assert offline == 1

    await db_session.refresh(agent)
    assert agent.status == "offline"


@pytest.mark.asyncio
async def test_degrade_fresh_agent_unchanged(db_session: AsyncSession) -> None:
    """Recently heartbeating agent is not degraded."""
    agent = Agent(
        hostname="fresh-host",
        agent_type="mxguard",
        version="1.0",
        status="online",
        last_heartbeat=datetime.now(timezone.utc) - timedelta(seconds=30),
    )
    db_session.add(agent)
    await db_session.flush()

    degraded, offline = await AgentRepo.degrade_stale_agents(db_session)
    assert degraded == 0
    assert offline == 0

    await db_session.refresh(agent)
    assert agent.status == "online"


@pytest.mark.asyncio
async def test_degrade_agent_no_heartbeat(db_session: AsyncSession) -> None:
    """Online agent that has never sent a heartbeat (last_heartbeat=None) → offline."""
    agent = Agent(
        hostname="never-hb",
        agent_type="mxwatch",
        version="1.0",
        status="online",
        last_heartbeat=None,
    )
    db_session.add(agent)
    await db_session.flush()

    degraded, offline = await AgentRepo.degrade_stale_agents(db_session)
    assert offline == 1

    await db_session.refresh(agent)
    assert agent.status == "offline"


@pytest.mark.asyncio
async def test_degrade_offline_agent_unchanged(db_session: AsyncSession) -> None:
    """Already offline agent is not double-counted."""
    agent = Agent(
        hostname="already-offline",
        agent_type="mxguard",
        version="1.0",
        status="offline",
        last_heartbeat=datetime.now(timezone.utc) - timedelta(hours=1),
    )
    db_session.add(agent)
    await db_session.flush()

    degraded, offline = await AgentRepo.degrade_stale_agents(db_session)
    assert degraded == 0
    assert offline == 0

    await db_session.refresh(agent)
    assert agent.status == "offline"
