"""Tests for Feature 11.7 — Save and name hunt queries.

Covers the /api/v1/hunt/queries endpoints:
    POST   /hunt/queries           create
    GET    /hunt/queries           list
    GET    /hunt/queries/{id}      get one
    PUT    /hunt/queries/{id}      update
    DELETE /hunt/queries/{id}      delete
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.saved_query import SavedQuery

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

BASE = "/api/v1/hunt/queries"


def _make_body(**overrides) -> dict:
    """Return a minimal valid create payload."""
    defaults = {
        "name": "Test Hunt",
        "query": "mimikatz",
        "filters": [],
        "time_from": "now-24h",
        "time_to": "now",
    }
    defaults.update(overrides)
    return defaults


async def _create_in_db(
    db: AsyncSession,
    *,
    name: str = "Seeded Query",
    created_by: str = "hunter@mxtac.local",
) -> SavedQuery:
    sq = SavedQuery(
        name=name,
        query="test query",
        filters=[],
        time_from="now-7d",
        time_to="now",
        created_by=created_by,
    )
    db.add(sq)
    await db.flush()
    return sq


# ---------------------------------------------------------------------------
# Auth / permission checks
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_requires_hunter_role(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Analysts (below hunter) must be rejected."""
    resp = await client.post(BASE, headers=analyst_headers, json=_make_body())
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_list_requires_hunter_role(
    client: AsyncClient, analyst_headers: dict
) -> None:
    resp = await client.get(BASE, headers=analyst_headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_unauthenticated_rejected(client: AsyncClient) -> None:
    resp = await client.get(BASE)
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Create
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_minimal(
    client: AsyncClient, hunter_headers: dict
) -> None:
    """Create with only required fields."""
    resp = await client.post(BASE, headers=hunter_headers, json={"name": "My Hunt"})
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "My Hunt"
    assert data["filters"] == []
    assert data["time_from"] == "now-24h"
    assert data["created_by"] == "hunter@mxtac.local"
    assert "id" in data


@pytest.mark.asyncio
async def test_create_full(
    client: AsyncClient, hunter_headers: dict
) -> None:
    """Create with all fields including filters."""
    body = _make_body(
        name="Lateral Movement Hunt",
        description="Detect lateral movement from internal subnets",
        query="cmd.exe /c",
        filters=[{"field": "hostname", "operator": "contains", "value": "WIN"}],
        time_from="now-7d",
        time_to="now",
    )
    resp = await client.post(BASE, headers=hunter_headers, json=body)
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "Lateral Movement Hunt"
    assert data["description"] == "Detect lateral movement from internal subnets"
    assert data["query"] == "cmd.exe /c"
    assert len(data["filters"]) == 1
    assert data["filters"][0]["field"] == "hostname"
    assert data["time_from"] == "now-7d"


@pytest.mark.asyncio
async def test_create_validates_name_required(
    client: AsyncClient, hunter_headers: dict
) -> None:
    resp = await client.post(BASE, headers=hunter_headers, json={"name": ""})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_admin_also_works(
    client: AsyncClient, admin_headers: dict
) -> None:
    resp = await client.post(BASE, headers=admin_headers, json={"name": "Admin Hunt"})
    assert resp.status_code == 201
    assert resp.json()["created_by"] == "admin@mxtac.local"


# ---------------------------------------------------------------------------
# List
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_empty(
    client: AsyncClient, hunter_headers: dict
) -> None:
    resp = await client.get(BASE, headers=hunter_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["items"] == []
    assert body["total"] == 0


@pytest.mark.asyncio
async def test_list_returns_own_queries_only(
    client: AsyncClient,
    hunter_headers: dict,
    engineer_headers: dict,
    db_session: AsyncSession,
) -> None:
    """Each user only sees their own saved queries."""
    await _create_in_db(db_session, name="Hunter Q", created_by="hunter@mxtac.local")
    await _create_in_db(db_session, name="Engineer Q", created_by="engineer@mxtac.local")
    await db_session.commit()

    hunter_resp = await client.get(BASE, headers=hunter_headers)
    assert hunter_resp.status_code == 200
    hunter_items = hunter_resp.json()["items"]
    assert len(hunter_items) == 1
    assert hunter_items[0]["name"] == "Hunter Q"

    eng_resp = await client.get(BASE, headers=engineer_headers)
    assert eng_resp.status_code == 200
    eng_items = eng_resp.json()["items"]
    assert len(eng_items) == 1
    assert eng_items[0]["name"] == "Engineer Q"


@pytest.mark.asyncio
async def test_list_returns_multiple_queries(
    client: AsyncClient, hunter_headers: dict, db_session: AsyncSession
) -> None:
    """List returns all queries belonging to the user."""
    await _create_in_db(db_session, name="First")
    await _create_in_db(db_session, name="Second")
    await db_session.commit()

    resp = await client.get(BASE, headers=hunter_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 2
    names = {item["name"] for item in body["items"]}
    assert names == {"First", "Second"}


# ---------------------------------------------------------------------------
# Get one
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_own_query(
    client: AsyncClient, hunter_headers: dict, db_session: AsyncSession
) -> None:
    sq = await _create_in_db(db_session)
    await db_session.commit()

    resp = await client.get(f"{BASE}/{sq.id}", headers=hunter_headers)
    assert resp.status_code == 200
    assert resp.json()["id"] == sq.id


@pytest.mark.asyncio
async def test_get_other_users_query_returns_404(
    client: AsyncClient, hunter_headers: dict, db_session: AsyncSession
) -> None:
    sq = await _create_in_db(db_session, created_by="other@mxtac.local")
    await db_session.commit()

    resp = await client.get(f"{BASE}/{sq.id}", headers=hunter_headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_get_nonexistent_returns_404(
    client: AsyncClient, hunter_headers: dict
) -> None:
    resp = await client.get(f"{BASE}/does-not-exist", headers=hunter_headers)
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Update
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_update_name(
    client: AsyncClient, hunter_headers: dict, db_session: AsyncSession
) -> None:
    sq = await _create_in_db(db_session, name="Old Name")
    await db_session.commit()

    resp = await client.put(
        f"{BASE}/{sq.id}", headers=hunter_headers, json={"name": "New Name"}
    )
    assert resp.status_code == 200
    assert resp.json()["name"] == "New Name"


@pytest.mark.asyncio
async def test_update_filters(
    client: AsyncClient, hunter_headers: dict, db_session: AsyncSession
) -> None:
    sq = await _create_in_db(db_session)
    await db_session.commit()

    new_filters = [{"field": "src_ip", "operator": "eq", "value": "10.0.0.1"}]
    resp = await client.put(
        f"{BASE}/{sq.id}",
        headers=hunter_headers,
        json={"name": sq.name, "filters": new_filters},
    )
    assert resp.status_code == 200
    assert len(resp.json()["filters"]) == 1
    assert resp.json()["filters"][0]["field"] == "src_ip"


@pytest.mark.asyncio
async def test_update_other_users_query_returns_404(
    client: AsyncClient, hunter_headers: dict, db_session: AsyncSession
) -> None:
    sq = await _create_in_db(db_session, created_by="other@mxtac.local")
    await db_session.commit()

    resp = await client.put(
        f"{BASE}/{sq.id}", headers=hunter_headers, json={"name": "Hijack"}
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Delete
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_delete_own_query(
    client: AsyncClient, hunter_headers: dict, db_session: AsyncSession
) -> None:
    sq = await _create_in_db(db_session)
    await db_session.commit()

    resp = await client.delete(f"{BASE}/{sq.id}", headers=hunter_headers)
    assert resp.status_code == 204

    # Confirm it's gone
    resp2 = await client.get(f"{BASE}/{sq.id}", headers=hunter_headers)
    assert resp2.status_code == 404


@pytest.mark.asyncio
async def test_delete_other_users_query_returns_404(
    client: AsyncClient, hunter_headers: dict, db_session: AsyncSession
) -> None:
    sq = await _create_in_db(db_session, created_by="other@mxtac.local")
    await db_session.commit()

    resp = await client.delete(f"{BASE}/{sq.id}", headers=hunter_headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_delete_nonexistent_returns_404(
    client: AsyncClient, hunter_headers: dict
) -> None:
    resp = await client.delete(f"{BASE}/ghost-id", headers=hunter_headers)
    assert resp.status_code == 404
