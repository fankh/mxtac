"""Tests for Feature 8.20 — Rule performance tracking: hit_count and fp_count.

Coverage:

  POST /rules/{rule_id}/mark_fp:
  - 401 when Authorization header is absent
  - 403 when role lacks detections:write (hunter_headers only has rules:read,
    but analyst has detections:write — use viewer_headers for 403)
  - 404 when rule_id does not exist in the database
  - 200 with valid request and existing rule (analyst role)
  - Response body contains "rule_id" key
  - Response body "rule_id" matches the requested rule_id
  - Response body contains "status" key
  - Response body "status" is "marked"
  - fp_count is incremented by 1 in the database after mark_fp
  - hit_count is NOT affected by mark_fp
  - hunter role can mark FP (detections:write permission)
  - engineer role can mark FP (detections:write permission)
  - admin role can mark FP (detections:write permission)
  - viewer role cannot mark FP (lacks detections:write) → 403
  - Repeated mark_fp calls accumulate fp_count (idempotent endpoint, not idempotent count)

  Rule API response fields:
  - GET /rules response includes hit_count (int, default 0)
  - GET /rules response includes fp_count (int, default 0)
  - GET /rules/{id} response includes hit_count and fp_count
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.repositories.rule_repo import RuleRepo

BASE = "/api/v1/rules"

# ---------------------------------------------------------------------------
# Minimal Sigma YAML for a rule usable in tests
# ---------------------------------------------------------------------------

_RULE_YAML = """\
title: Test FP Tracking Rule
id: fp-test-rule-001
status: experimental
level: medium
description: Used to test false-positive tracking.
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    name: suspicious.exe
  condition: selection
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _create_rule(db: AsyncSession, rule_id: str = "fp-test-rule-001") -> object:
    """Persist a minimal rule and return the ORM object."""
    return await RuleRepo.create(
        db,
        id=rule_id,
        title="Test FP Tracking Rule",
        content=_RULE_YAML,
        level="medium",
        status="experimental",
        rule_type="sigma",
    )


# ---------------------------------------------------------------------------
# Auth / RBAC
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mark_fp_no_auth(client: AsyncClient) -> None:
    """Missing Authorization header → 401."""
    resp = await client.post(f"{BASE}/fp-test-rule-001/mark_fp")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_mark_fp_viewer_forbidden(
    client: AsyncClient, viewer_headers: dict, db_session: AsyncSession
) -> None:
    """viewer role lacks detections:write → 403."""
    await _create_rule(db_session)
    resp = await client.post(
        f"{BASE}/fp-test-rule-001/mark_fp",
        headers=viewer_headers,
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 404 — rule not found
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mark_fp_rule_not_found(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Non-existent rule_id → 404."""
    resp = await client.post(
        f"{BASE}/does-not-exist/mark_fp",
        headers=analyst_headers,
    )
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# 200 — happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mark_fp_returns_200(
    client: AsyncClient, analyst_headers: dict, db_session: AsyncSession
) -> None:
    """Valid request with existing rule → 200."""
    await _create_rule(db_session)
    resp = await client.post(
        f"{BASE}/fp-test-rule-001/mark_fp",
        headers=analyst_headers,
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_mark_fp_response_has_rule_id(
    client: AsyncClient, analyst_headers: dict, db_session: AsyncSession
) -> None:
    """Response body contains 'rule_id'."""
    await _create_rule(db_session)
    resp = await client.post(
        f"{BASE}/fp-test-rule-001/mark_fp",
        headers=analyst_headers,
    )
    assert "rule_id" in resp.json()


@pytest.mark.asyncio
async def test_mark_fp_response_rule_id_matches(
    client: AsyncClient, analyst_headers: dict, db_session: AsyncSession
) -> None:
    """Response 'rule_id' matches the requested rule_id."""
    await _create_rule(db_session)
    resp = await client.post(
        f"{BASE}/fp-test-rule-001/mark_fp",
        headers=analyst_headers,
    )
    assert resp.json()["rule_id"] == "fp-test-rule-001"


@pytest.mark.asyncio
async def test_mark_fp_response_has_status(
    client: AsyncClient, analyst_headers: dict, db_session: AsyncSession
) -> None:
    """Response body contains 'status'."""
    await _create_rule(db_session)
    resp = await client.post(
        f"{BASE}/fp-test-rule-001/mark_fp",
        headers=analyst_headers,
    )
    assert "status" in resp.json()


@pytest.mark.asyncio
async def test_mark_fp_response_status_is_marked(
    client: AsyncClient, analyst_headers: dict, db_session: AsyncSession
) -> None:
    """Response 'status' is 'marked'."""
    await _create_rule(db_session)
    resp = await client.post(
        f"{BASE}/fp-test-rule-001/mark_fp",
        headers=analyst_headers,
    )
    assert resp.json()["status"] == "marked"


# ---------------------------------------------------------------------------
# DB state after mark_fp
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mark_fp_increments_fp_count(
    client: AsyncClient, analyst_headers: dict, db_session: AsyncSession
) -> None:
    """fp_count is incremented by 1 after a single mark_fp call."""
    rule = await _create_rule(db_session)
    initial_fp = rule.fp_count  # default 0

    await client.post(
        f"{BASE}/fp-test-rule-001/mark_fp",
        headers=analyst_headers,
    )

    # Re-fetch from DB
    await db_session.refresh(rule)
    assert rule.fp_count == initial_fp + 1


@pytest.mark.asyncio
async def test_mark_fp_does_not_change_hit_count(
    client: AsyncClient, analyst_headers: dict, db_session: AsyncSession
) -> None:
    """hit_count is unaffected by mark_fp."""
    rule = await _create_rule(db_session)
    initial_hit = rule.hit_count  # default 0

    await client.post(
        f"{BASE}/fp-test-rule-001/mark_fp",
        headers=analyst_headers,
    )

    await db_session.refresh(rule)
    assert rule.hit_count == initial_hit


@pytest.mark.asyncio
async def test_mark_fp_twice_increments_fp_count_by_two(
    client: AsyncClient, analyst_headers: dict, db_session: AsyncSession
) -> None:
    """Two mark_fp calls accumulate: fp_count increases by 2."""
    rule = await _create_rule(db_session)

    await client.post(f"{BASE}/fp-test-rule-001/mark_fp", headers=analyst_headers)
    await client.post(f"{BASE}/fp-test-rule-001/mark_fp", headers=analyst_headers)

    await db_session.refresh(rule)
    assert rule.fp_count == 2


# ---------------------------------------------------------------------------
# RBAC — roles with detections:write
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mark_fp_analyst_allowed(
    client: AsyncClient, analyst_headers: dict, db_session: AsyncSession
) -> None:
    """analyst role has detections:write → 200."""
    await _create_rule(db_session)
    resp = await client.post(
        f"{BASE}/fp-test-rule-001/mark_fp",
        headers=analyst_headers,
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_mark_fp_hunter_allowed(
    client: AsyncClient, hunter_headers: dict, db_session: AsyncSession
) -> None:
    """hunter role has detections:write → 200."""
    await _create_rule(db_session)
    resp = await client.post(
        f"{BASE}/fp-test-rule-001/mark_fp",
        headers=hunter_headers,
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_mark_fp_engineer_allowed(
    client: AsyncClient, engineer_headers: dict, db_session: AsyncSession
) -> None:
    """engineer role has detections:write → 200."""
    await _create_rule(db_session)
    resp = await client.post(
        f"{BASE}/fp-test-rule-001/mark_fp",
        headers=engineer_headers,
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_mark_fp_admin_allowed(
    client: AsyncClient, admin_headers: dict, db_session: AsyncSession
) -> None:
    """admin role has detections:write → 200."""
    await _create_rule(db_session)
    resp = await client.post(
        f"{BASE}/fp-test-rule-001/mark_fp",
        headers=admin_headers,
    )
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Rule list response fields (hit_count / fp_count always present)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_rules_response_includes_hit_count(
    client: AsyncClient, hunter_headers: dict, db_session: AsyncSession
) -> None:
    """GET /rules response items include hit_count as an integer."""
    await _create_rule(db_session)
    resp = await client.get(BASE, headers=hunter_headers)
    assert resp.status_code == 200
    items = resp.json()
    assert len(items) >= 1
    for item in items:
        assert "hit_count" in item
        assert isinstance(item["hit_count"], int)


@pytest.mark.asyncio
async def test_list_rules_response_includes_fp_count(
    client: AsyncClient, hunter_headers: dict, db_session: AsyncSession
) -> None:
    """GET /rules response items include fp_count as an integer."""
    await _create_rule(db_session)
    resp = await client.get(BASE, headers=hunter_headers)
    assert resp.status_code == 200
    items = resp.json()
    assert len(items) >= 1
    for item in items:
        assert "fp_count" in item
        assert isinstance(item["fp_count"], int)


@pytest.mark.asyncio
async def test_get_rule_response_includes_hit_count(
    client: AsyncClient, hunter_headers: dict, db_session: AsyncSession
) -> None:
    """GET /rules/{id} detail response includes hit_count."""
    await _create_rule(db_session)
    resp = await client.get(f"{BASE}/fp-test-rule-001", headers=hunter_headers)
    assert resp.status_code == 200
    assert "hit_count" in resp.json()
    assert isinstance(resp.json()["hit_count"], int)


@pytest.mark.asyncio
async def test_get_rule_response_includes_fp_count(
    client: AsyncClient, hunter_headers: dict, db_session: AsyncSession
) -> None:
    """GET /rules/{id} detail response includes fp_count."""
    await _create_rule(db_session)
    resp = await client.get(f"{BASE}/fp-test-rule-001", headers=hunter_headers)
    assert resp.status_code == 200
    assert "fp_count" in resp.json()
    assert isinstance(resp.json()["fp_count"], int)


@pytest.mark.asyncio
async def test_new_rule_has_zero_hit_count(
    client: AsyncClient, hunter_headers: dict, db_session: AsyncSession
) -> None:
    """Newly created rule starts with hit_count=0."""
    await _create_rule(db_session)
    resp = await client.get(f"{BASE}/fp-test-rule-001", headers=hunter_headers)
    assert resp.status_code == 200
    assert resp.json()["hit_count"] == 0


@pytest.mark.asyncio
async def test_new_rule_has_zero_fp_count(
    client: AsyncClient, hunter_headers: dict, db_session: AsyncSession
) -> None:
    """Newly created rule starts with fp_count=0."""
    await _create_rule(db_session)
    resp = await client.get(f"{BASE}/fp-test-rule-001", headers=hunter_headers)
    assert resp.status_code == 200
    assert resp.json()["fp_count"] == 0
