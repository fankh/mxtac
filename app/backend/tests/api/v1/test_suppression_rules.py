"""API tests for suppression rules endpoints (feature 9.11).

Coverage:
  - GET  /suppression-rules — returns paginated list (engineer)
  - GET  /suppression-rules — returns 403 for viewer role
  - GET  /suppression-rules — returns 401 without auth
  - POST /suppression-rules — creates rule (engineer), returns 201
  - POST /suppression-rules — returns 403 for analyst role
  - POST /suppression-rules — returns 422 when no match field provided
  - GET  /suppression-rules/{id} — found → 200
  - GET  /suppression-rules/{id} — not found → 404
  - PATCH /suppression-rules/{id} — updates rule → 200
  - PATCH /suppression-rules/{id} — not found → 404
  - DELETE /suppression-rules/{id} — deletes rule → 204
  - DELETE /suppression-rules/{id} — not found → 404
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.repositories.suppression_repo import SuppressionRepo


pytestmark = pytest.mark.asyncio


async def _create_rule(db: AsyncSession, **kwargs):
    defaults = {
        "name": "test-rule",
        "rule_id": "sigma-001",
        "created_by": "engineer@mxtac.local",
    }
    defaults.update(kwargs)
    rule = await SuppressionRepo.create(db, **defaults)
    await db.commit()
    return rule


# ---------------------------------------------------------------------------
# GET /suppression-rules
# ---------------------------------------------------------------------------


async def test_list_suppression_rules_ok(client: AsyncClient, engineer_headers, db_session):
    await _create_rule(db_session, name="rule-a", rule_id="r-a")
    await _create_rule(db_session, name="rule-b", host="win-*")

    resp = await client.get("/api/v1/suppression-rules", headers=engineer_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "pagination" in data
    assert data["pagination"]["total"] == 2


async def test_list_suppression_rules_viewer_forbidden(client: AsyncClient, viewer_headers):
    resp = await client.get("/api/v1/suppression-rules", headers=viewer_headers)
    assert resp.status_code == 403


async def test_list_suppression_rules_unauthenticated(client: AsyncClient):
    resp = await client.get("/api/v1/suppression-rules")
    assert resp.status_code == 401


async def test_list_suppression_rules_filter_active(
    client: AsyncClient, engineer_headers, db_session
):
    await _create_rule(db_session, name="active-rule", rule_id="r-active", is_active=True)
    await _create_rule(db_session, name="inactive-rule", rule_id="r-inactive", is_active=False)

    resp = await client.get(
        "/api/v1/suppression-rules", params={"is_active": "true"}, headers=engineer_headers
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["pagination"]["total"] == 1
    assert data["items"][0]["name"] == "active-rule"


# ---------------------------------------------------------------------------
# POST /suppression-rules
# ---------------------------------------------------------------------------


async def test_create_suppression_rule_ok(client: AsyncClient, engineer_headers):
    payload = {
        "name": "suppress-low-win",
        "host": "win-*",
        "severity": "low",
        "reason": "Low-severity Windows alerts are noisy",
    }
    resp = await client.post("/api/v1/suppression-rules", json=payload, headers=engineer_headers)
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "suppress-low-win"
    assert data["host"] == "win-*"
    assert data["severity"] == "low"
    assert data["is_active"] is True
    assert data["hit_count"] == 0


async def test_create_suppression_rule_analyst_forbidden(client: AsyncClient, analyst_headers):
    payload = {"name": "test", "rule_id": "sigma-999"}
    resp = await client.post("/api/v1/suppression-rules", json=payload, headers=analyst_headers)
    assert resp.status_code == 403


async def test_create_suppression_rule_no_match_field(client: AsyncClient, engineer_headers):
    """At least one match field is required."""
    payload = {"name": "no-match-fields", "reason": "will fail"}
    resp = await client.post("/api/v1/suppression-rules", json=payload, headers=engineer_headers)
    assert resp.status_code == 422


async def test_create_suppression_rule_with_rule_id(client: AsyncClient, engineer_headers):
    payload = {"name": "by-rule-id", "rule_id": "sigma-lsass-dump"}
    resp = await client.post("/api/v1/suppression-rules", json=payload, headers=engineer_headers)
    assert resp.status_code == 201
    assert resp.json()["rule_id"] == "sigma-lsass-dump"


async def test_create_suppression_rule_with_technique(client: AsyncClient, engineer_headers):
    payload = {"name": "by-technique", "technique_id": "T1059.001"}
    resp = await client.post("/api/v1/suppression-rules", json=payload, headers=engineer_headers)
    assert resp.status_code == 201
    assert resp.json()["technique_id"] == "T1059.001"


# ---------------------------------------------------------------------------
# GET /suppression-rules/{id}
# ---------------------------------------------------------------------------


async def test_get_suppression_rule_found(client: AsyncClient, engineer_headers, db_session):
    rule = await _create_rule(db_session, name="found-rule", severity="critical")
    resp = await client.get(f"/api/v1/suppression-rules/{rule.id}", headers=engineer_headers)
    assert resp.status_code == 200
    assert resp.json()["id"] == rule.id


async def test_get_suppression_rule_not_found(client: AsyncClient, engineer_headers):
    resp = await client.get("/api/v1/suppression-rules/99999", headers=engineer_headers)
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# PATCH /suppression-rules/{id}
# ---------------------------------------------------------------------------


async def test_patch_suppression_rule_ok(client: AsyncClient, engineer_headers, db_session):
    rule = await _create_rule(db_session, name="patch-me", rule_id="r1")
    resp = await client.patch(
        f"/api/v1/suppression-rules/{rule.id}",
        json={"is_active": False, "reason": "no longer needed"},
        headers=engineer_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_active"] is False
    assert data["reason"] == "no longer needed"


async def test_patch_suppression_rule_not_found(client: AsyncClient, engineer_headers):
    resp = await client.patch(
        "/api/v1/suppression-rules/99999",
        json={"is_active": False},
        headers=engineer_headers,
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# DELETE /suppression-rules/{id}
# ---------------------------------------------------------------------------


async def test_delete_suppression_rule_ok(client: AsyncClient, engineer_headers, db_session):
    rule = await _create_rule(db_session, name="delete-me", host="lin-*")
    resp = await client.delete(f"/api/v1/suppression-rules/{rule.id}", headers=engineer_headers)
    assert resp.status_code == 204

    # Confirm gone
    resp2 = await client.get(f"/api/v1/suppression-rules/{rule.id}", headers=engineer_headers)
    assert resp2.status_code == 404


async def test_delete_suppression_rule_not_found(client: AsyncClient, engineer_headers):
    resp = await client.delete("/api/v1/suppression-rules/99999", headers=engineer_headers)
    assert resp.status_code == 404
