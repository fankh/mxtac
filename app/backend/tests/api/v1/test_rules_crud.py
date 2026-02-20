"""Tests for Sigma Rules CRUD endpoints — GET, POST, PATCH, DELETE, import.

Coverage:
  - List rules: unauthenticated → 401/403; viewer/analyst → 403 (rules:read requires hunter+)
  - GET rule by ID: 404 when not found (hunter+)
  - Feature 13.1 — GET /rules with level/enabled filters (DB-backed)
  - Feature 28.8 — RBAC: engineer can create rules
      viewer / analyst / hunter → 403 on POST /rules (rules:write requires engineer+)
      engineer → 201 on POST /rules with valid Sigma YAML
      admin → 201 on POST /rules with valid Sigma YAML
      unauthenticated → 401 or 403 on POST /rules
      invalid YAML → 422
  - POST /rules/import: bulk import returns imported count (engineer+)
  - GET /rules/stats/summary: total/enabled/by_level (hunter+)
  - POST /rules/test: test arbitrary YAML against a sample event (hunter+)
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

_SIGMA_YAML_LOW = """\
title: Low Severity Rule
id: test-rule-0002
status: experimental
description: Low severity test rule
logsource:
  category: network_connection
  product: linux
detection:
  selection:
    dst_port: 8080
  condition: selection
level: low
"""


# ---------------------------------------------------------------------------
# GET /rules — access control (rules:read requires hunter+)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_rules_unauthenticated(client: AsyncClient) -> None:
    """GET /rules without auth → 401 or 403."""
    resp = await client.get(BASE_URL)
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_list_rules_viewer_forbidden(client: AsyncClient, viewer_headers: dict) -> None:
    """GET /rules with viewer role → 403 (rules:read requires hunter+)."""
    resp = await client.get(BASE_URL, headers=viewer_headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_list_rules_analyst_forbidden(client: AsyncClient, analyst_headers: dict) -> None:
    """GET /rules with analyst role → 403 (rules:read requires hunter+)."""
    resp = await client.get(BASE_URL, headers=analyst_headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_list_rules_hunter_empty(client: AsyncClient, hunter_headers: dict) -> None:
    """GET /rules with hunter role and empty DB returns []."""
    resp = await client.get(BASE_URL, headers=hunter_headers)
    assert resp.status_code == 200
    assert resp.json() == []


# ---------------------------------------------------------------------------
# Feature 13.1 — GET /rules with level / enabled filters (DB-backed)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_rules_returns_created_rule(
    client: AsyncClient, hunter_headers: dict, engineer_headers: dict
) -> None:
    """POST then GET /rules — created rule appears in listing."""
    await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Mimikatz", "content": _SIGMA_YAML},
    )
    resp = await client.get(BASE_URL, headers=hunter_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["id"] == "test-rule-0001"
    assert data[0]["level"] == "high"
    assert data[0]["enabled"] is True


@pytest.mark.asyncio
async def test_list_rules_filter_by_level(
    client: AsyncClient, hunter_headers: dict, engineer_headers: dict
) -> None:
    """GET /rules?level=high returns only high-level rules."""
    # Create one high and one low rule
    await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "High Rule", "content": _SIGMA_YAML},
    )
    await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Low Rule", "content": _SIGMA_YAML_LOW},
    )

    resp = await client.get(f"{BASE_URL}?level=high", headers=hunter_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["level"] == "high"

    resp_low = await client.get(f"{BASE_URL}?level=low", headers=hunter_headers)
    assert resp_low.status_code == 200
    assert len(resp_low.json()) == 1
    assert resp_low.json()[0]["level"] == "low"


@pytest.mark.asyncio
async def test_list_rules_filter_by_enabled(
    client: AsyncClient, hunter_headers: dict, engineer_headers: dict
) -> None:
    """GET /rules?enabled=true / false returns only matching rules."""
    # Create one enabled and one disabled rule
    await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Enabled Rule", "content": _SIGMA_YAML, "enabled": True},
    )
    await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Disabled Rule", "content": _SIGMA_YAML_LOW, "enabled": False},
    )

    resp_enabled = await client.get(f"{BASE_URL}?enabled=true", headers=hunter_headers)
    assert resp_enabled.status_code == 200
    enabled_rules = resp_enabled.json()
    assert len(enabled_rules) == 1
    assert enabled_rules[0]["enabled"] is True

    resp_disabled = await client.get(f"{BASE_URL}?enabled=false", headers=hunter_headers)
    assert resp_disabled.status_code == 200
    disabled_rules = resp_disabled.json()
    assert len(disabled_rules) == 1
    assert disabled_rules[0]["enabled"] is False


@pytest.mark.asyncio
async def test_list_rules_response_schema(
    client: AsyncClient, hunter_headers: dict, engineer_headers: dict
) -> None:
    """GET /rules response items have all required RuleResponse fields."""
    await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Schema Test", "content": _SIGMA_YAML},
    )
    resp = await client.get(BASE_URL, headers=hunter_headers)
    assert resp.status_code == 200
    item = resp.json()[0]
    assert "id" in item
    assert "title" in item
    assert "level" in item
    assert "status" in item
    assert "enabled" in item
    assert "technique_ids" in item
    assert "tactic_ids" in item
    assert "logsource" in item
    assert "hit_count" in item
    assert "fp_count" in item
    # ATT&CK tags should be parsed
    assert "T1003" in item["technique_ids"]
    assert item["logsource"]["product"] == "windows"
    assert item["logsource"]["category"] == "process_creation"


# ---------------------------------------------------------------------------
# GET /rules/{id} — access control (rules:read requires hunter+)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_rule_not_found(client: AsyncClient, hunter_headers: dict) -> None:
    """GET /rules/{id} for unknown rule → 404."""
    resp = await client.get(f"{BASE_URL}/nonexistent-rule-id", headers=hunter_headers)
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Rule not found"


# ---------------------------------------------------------------------------
# Feature 13.2 — GET /rules/{id} — detail + YAML content
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_rule_detail_returns_yaml_content(
    client: AsyncClient, hunter_headers: dict, engineer_headers: dict
) -> None:
    """GET /rules/{id} returns raw YAML content field."""
    await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Mimikatz", "content": _SIGMA_YAML},
    )
    resp = await client.get(f"{BASE_URL}/test-rule-0001", headers=hunter_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "content" in data
    assert "mimikatz" in data["content"].lower()


@pytest.mark.asyncio
async def test_get_rule_detail_schema(
    client: AsyncClient, hunter_headers: dict, engineer_headers: dict
) -> None:
    """GET /rules/{id} response includes all RuleDetailResponse fields."""
    await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Mimikatz", "content": _SIGMA_YAML},
    )
    resp = await client.get(f"{BASE_URL}/test-rule-0001", headers=hunter_headers)
    assert resp.status_code == 200
    data = resp.json()
    # Base fields
    assert data["id"] == "test-rule-0001"
    assert data["title"] == "Test Mimikatz Detection"
    assert data["level"] == "high"
    assert data["status"] == "experimental"
    assert data["enabled"] is True
    assert isinstance(data["technique_ids"], list)
    assert isinstance(data["tactic_ids"], list)
    assert isinstance(data["logsource"], dict)
    assert isinstance(data["hit_count"], int)
    assert isinstance(data["fp_count"], int)
    # Detail-only fields
    assert "content" in data
    assert isinstance(data["content"], str)
    assert len(data["content"]) > 0
    assert "description" in data
    assert "source" in data


@pytest.mark.asyncio
async def test_get_rule_detail_viewer_forbidden(
    client: AsyncClient, viewer_headers: dict
) -> None:
    """GET /rules/{id} with viewer role → 403."""
    resp = await client.get(f"{BASE_URL}/any-rule-id", headers=viewer_headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_get_rule_detail_analyst_forbidden(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """GET /rules/{id} with analyst role → 403 (rules:read requires hunter+)."""
    resp = await client.get(f"{BASE_URL}/any-rule-id", headers=analyst_headers)
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Feature 28.8 — RBAC: engineer can create rules (POST /rules)
# rules:write is granted to engineer and admin only
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_rule_unauthenticated(client: AsyncClient) -> None:
    """POST /rules without auth → 401 or 403."""
    resp = await client.post(
        BASE_URL,
        json={"title": "Test Rule", "content": _SIGMA_YAML},
    )
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_create_rule_viewer_forbidden(client: AsyncClient, viewer_headers: dict) -> None:
    """POST /rules with viewer role → 403 (rules:write requires engineer+)."""
    resp = await client.post(
        BASE_URL,
        headers=viewer_headers,
        json={"title": "Test Rule", "content": _SIGMA_YAML},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_create_rule_analyst_forbidden(client: AsyncClient, analyst_headers: dict) -> None:
    """POST /rules with analyst role → 403 (rules:write requires engineer+)."""
    resp = await client.post(
        BASE_URL,
        headers=analyst_headers,
        json={"title": "Test Rule", "content": _SIGMA_YAML},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_create_rule_hunter_forbidden(client: AsyncClient, hunter_headers: dict) -> None:
    """POST /rules with hunter role → 403.

    Hunter has rules:read but NOT rules:write; create is blocked.
    """
    resp = await client.post(
        BASE_URL,
        headers=hunter_headers,
        json={"title": "Test Rule", "content": _SIGMA_YAML},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_create_rule_engineer_valid(client: AsyncClient, engineer_headers: dict) -> None:
    """POST /rules with engineer role and valid Sigma YAML → 201.

    Confirms engineer has rules:write permission and the rule is created.
    """
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


@pytest.mark.asyncio
async def test_create_rule_admin_valid(client: AsyncClient, admin_headers: dict) -> None:
    """POST /rules with admin role and valid Sigma YAML → 201."""
    resp = await client.post(
        BASE_URL,
        headers=admin_headers,
        json={"title": "Test Rule", "content": _SIGMA_YAML},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert "id" in data
    assert data["level"] == "high"


@pytest.mark.asyncio
async def test_create_rule_engineer_invalid_yaml(client: AsyncClient, engineer_headers: dict) -> None:
    """POST /rules with engineer role but non-dict YAML content → 422.

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
async def test_create_rule_engineer_disabled(client: AsyncClient, engineer_headers: dict) -> None:
    """POST /rules with enabled=False → 201, rule created with enabled=False."""
    resp = await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Disabled Rule", "content": _SIGMA_YAML, "enabled": False},
    )
    assert resp.status_code == 201
    assert resp.json()["enabled"] is False


# ---------------------------------------------------------------------------
# POST /rules/import — bulk import (engineer+)
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
# GET /rules/stats/summary (hunter+)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rules_summary_empty(client: AsyncClient, hunter_headers: dict) -> None:
    """GET /rules/stats/summary with empty DB → total=0, enabled=0."""
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
# POST /rules/test — test arbitrary YAML against event (hunter+)
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
