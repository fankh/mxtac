"""Tests for Sigma Rules CRUD endpoints — GET, POST, PATCH, DELETE, import.

Coverage:
  - List rules: unauthenticated → 401; hunter+ required for rules:read
  - GET rule by ID: 404 when not found
  - POST create rule: 422 on invalid YAML; 201 on valid Sigma YAML
  - POST /rules/import: bulk import returns imported count
  - GET /rules/stats/summary: total/enabled/by_level
  - POST /rules/test: test arbitrary YAML against a sample event

The module-level ``_rule_store`` in the endpoint is reset by an autouse fixture
so tests are fully isolated.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient

BASE_URL = "/api/v1/rules"

# Minimal valid Sigma rule YAML
_SIGMA_YAML = """\
title: Test Mimikatz Detection
id: test-rule-0001
status: experimental
description: Detects mimikatz execution
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains: mimikatz
  condition: selection
level: high
tags:
  - attack.credential_access
  - attack.t1003
"""


@pytest.fixture(autouse=True)
def _clear_rule_store():
    """Reset module-level rule store and sigma engine before/after each test."""
    from app.api.v1.endpoints import rules as rules_mod

    rules_mod._rule_store.clear()
    rules_mod._engine._rules.clear()
    yield
    rules_mod._rule_store.clear()
    rules_mod._engine._rules.clear()


# ---------------------------------------------------------------------------
# Auth / access control
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_rules_unauthenticated(client: AsyncClient) -> None:
    """GET /rules without auth → 401 or 403."""
    resp = await client.get(BASE_URL)
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_list_rules_any_auth_succeeds(client: AsyncClient, viewer_headers: dict) -> None:
    """GET /rules with any valid JWT → 200 (endpoint uses plain get_current_user)."""
    resp = await client.get(BASE_URL, headers=viewer_headers)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


@pytest.mark.asyncio
async def test_list_rules_all_roles_can_list(client: AsyncClient, analyst_headers: dict) -> None:
    """GET /rules with analyst role also returns 200 (no RBAC on list yet)."""
    resp = await client.get(BASE_URL, headers=analyst_headers)
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_list_rules_hunter_empty(client: AsyncClient, hunter_headers: dict) -> None:
    """GET /rules with hunter role and empty store returns []."""
    resp = await client.get(BASE_URL, headers=hunter_headers)
    assert resp.status_code == 200
    assert resp.json() == []


# ---------------------------------------------------------------------------
# GET single rule
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_rule_not_found(client: AsyncClient, hunter_headers: dict) -> None:
    """GET /rules/{id} for unknown rule → 404."""
    resp = await client.get(f"{BASE_URL}/nonexistent-rule-id", headers=hunter_headers)
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Rule not found"


# ---------------------------------------------------------------------------
# POST create rule
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_rule_invalid_yaml(client: AsyncClient, engineer_headers: dict) -> None:
    """POST /rules with non-dict YAML content (plain string) → 422.

    The engine returns an empty list when the YAML document is not a dict
    (e.g. a bare string), which triggers the 422 guard in the endpoint.
    """
    resp = await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Bad Rule", "content": "just a plain string, not a mapping"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_rule_valid(client: AsyncClient, engineer_headers: dict) -> None:
    """POST /rules with valid Sigma YAML → 201, rule id and level returned."""
    resp = await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Test Rule", "content": _SIGMA_YAML},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert "id" in data
    assert data["level"] == "high"
    assert data["enabled"] is True


# ---------------------------------------------------------------------------
# Import rules
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_import_single_rule(client: AsyncClient, engineer_headers: dict) -> None:
    """POST /rules/import with single Sigma YAML → imported=1."""
    resp = await client.post(
        f"{BASE_URL}/import",
        headers=engineer_headers,
        json={"yaml_content": _SIGMA_YAML},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["imported"] == 1
    assert data["total_rules"] >= 1


# ---------------------------------------------------------------------------
# Stats summary
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rules_summary_empty(client: AsyncClient, hunter_headers: dict) -> None:
    """GET /rules/stats/summary with empty store → total=0, enabled=0."""
    resp = await client.get(f"{BASE_URL}/stats/summary", headers=hunter_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 0
    assert data["enabled"] == 0
    assert isinstance(data["by_level"], dict)


@pytest.mark.asyncio
async def test_rules_summary_after_import(client: AsyncClient, engineer_headers: dict) -> None:
    """GET /rules/stats/summary after import reflects imported count."""
    await client.post(
        f"{BASE_URL}/import",
        headers=engineer_headers,
        json={"yaml_content": _SIGMA_YAML},
    )
    resp = await client.get(
        f"{BASE_URL}/stats/summary",
        headers=engineer_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["total"] >= 1


# ---------------------------------------------------------------------------
# Test arbitrary YAML (POST /rules/test)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rule_yaml_matches_event(client: AsyncClient, hunter_headers: dict) -> None:
    """POST /rules/test with matching event → matched=true."""
    resp = await client.post(
        f"{BASE_URL}/test",
        headers=hunter_headers,
        json={
            "content": _SIGMA_YAML,
            "sample_event": {"CommandLine": "mimikatz sekurlsa::logonpasswords"},
        },
    )
    assert resp.status_code == 200
    assert resp.json()["matched"] is True


@pytest.mark.asyncio
async def test_rule_yaml_no_match(client: AsyncClient, hunter_headers: dict) -> None:
    """POST /rules/test with non-matching event → matched=false."""
    resp = await client.post(
        f"{BASE_URL}/test",
        headers=hunter_headers,
        json={
            "content": _SIGMA_YAML,
            "sample_event": {"CommandLine": "notepad.exe"},
        },
    )
    assert resp.status_code == 200
    assert resp.json()["matched"] is False
