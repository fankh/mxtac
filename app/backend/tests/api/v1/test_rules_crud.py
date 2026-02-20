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
  - Feature 13.5 — DELETE /rules/{id} — remove rule
      unauthenticated → 401 or 403
      viewer / analyst / hunter → 403 (rules:write requires engineer+)
      engineer → 204 on success
      admin → 204 on success
      404 when rule not found
      rule absent from GET after deletion
      double delete → 404
      stats summary decrements after delete
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


# ---------------------------------------------------------------------------
# Feature 13.4 — PATCH /rules/{id} — enable / disable / update
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_patch_rule_disable(
    client: AsyncClient, hunter_headers: dict, engineer_headers: dict
) -> None:
    """PATCH /rules/{id} with enabled=False disables the rule."""
    await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Mimikatz", "content": _SIGMA_YAML},
    )
    resp = await client.patch(
        f"{BASE_URL}/test-rule-0001",
        headers=engineer_headers,
        json={"enabled": False},
    )
    assert resp.status_code == 200
    assert resp.json()["enabled"] is False

    # Verify persistence: GET returns disabled state
    detail = await client.get(f"{BASE_URL}/test-rule-0001", headers=hunter_headers)
    assert detail.json()["enabled"] is False


@pytest.mark.asyncio
async def test_patch_rule_enable(
    client: AsyncClient, hunter_headers: dict, engineer_headers: dict
) -> None:
    """PATCH /rules/{id} with enabled=True re-enables a disabled rule."""
    await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Mimikatz", "content": _SIGMA_YAML, "enabled": False},
    )
    resp = await client.patch(
        f"{BASE_URL}/test-rule-0001",
        headers=engineer_headers,
        json={"enabled": True},
    )
    assert resp.status_code == 200
    assert resp.json()["enabled"] is True


@pytest.mark.asyncio
async def test_patch_rule_content_update(
    client: AsyncClient, hunter_headers: dict, engineer_headers: dict
) -> None:
    """PATCH /rules/{id} with new content re-parses and updates derived fields."""
    await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Mimikatz", "content": _SIGMA_YAML},
    )
    # Replace with a low-severity rule that has same ID
    updated_yaml = _SIGMA_YAML.replace("level: high", "level: low")
    resp = await client.patch(
        f"{BASE_URL}/test-rule-0001",
        headers=engineer_headers,
        json={"content": updated_yaml},
    )
    assert resp.status_code == 200
    assert resp.json()["level"] == "low"

    # Verify persistence via GET detail
    detail = await client.get(f"{BASE_URL}/test-rule-0001", headers=hunter_headers)
    assert detail.json()["level"] == "low"
    assert "level: low" in detail.json()["content"]


@pytest.mark.asyncio
async def test_patch_rule_both_fields(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """PATCH /rules/{id} updating both enabled and content applies both changes."""
    await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Mimikatz", "content": _SIGMA_YAML},
    )
    updated_yaml = _SIGMA_YAML.replace("level: high", "level: medium")
    resp = await client.patch(
        f"{BASE_URL}/test-rule-0001",
        headers=engineer_headers,
        json={"enabled": False, "content": updated_yaml},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["enabled"] is False
    assert data["level"] == "medium"


@pytest.mark.asyncio
async def test_patch_rule_not_found(client: AsyncClient, engineer_headers: dict) -> None:
    """PATCH /rules/{id} for unknown rule → 404."""
    resp = await client.patch(
        f"{BASE_URL}/nonexistent-rule-id",
        headers=engineer_headers,
        json={"enabled": False},
    )
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Rule not found"


@pytest.mark.asyncio
async def test_patch_rule_invalid_yaml(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """PATCH /rules/{id} with invalid Sigma YAML content → 422."""
    await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Mimikatz", "content": _SIGMA_YAML},
    )
    resp = await client.patch(
        f"{BASE_URL}/test-rule-0001",
        headers=engineer_headers,
        json={"content": "just a plain string, not a mapping"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_patch_rule_no_op_returns_rule(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """PATCH /rules/{id} with empty body returns current rule unchanged."""
    await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Mimikatz", "content": _SIGMA_YAML},
    )
    resp = await client.patch(
        f"{BASE_URL}/test-rule-0001",
        headers=engineer_headers,
        json={},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == "test-rule-0001"
    assert data["enabled"] is True


@pytest.mark.asyncio
async def test_patch_rule_response_schema(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """PATCH /rules/{id} response includes all RuleResponse fields."""
    await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Mimikatz", "content": _SIGMA_YAML},
    )
    resp = await client.patch(
        f"{BASE_URL}/test-rule-0001",
        headers=engineer_headers,
        json={"enabled": False},
    )
    assert resp.status_code == 200
    data = resp.json()
    for field in ("id", "title", "level", "status", "enabled",
                  "technique_ids", "tactic_ids", "logsource",
                  "hit_count", "fp_count"):
        assert field in data, f"Missing field: {field}"


# ---------------------------------------------------------------------------
# Feature 13.5 — DELETE /rules/{id} — remove rule
# rules:write is required (engineer and admin only)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_delete_rule_unauthenticated(client: AsyncClient) -> None:
    """DELETE /rules/{id} without auth → 401 or 403."""
    resp = await client.delete(f"{BASE_URL}/any-rule-id")
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_delete_rule_viewer_forbidden(client: AsyncClient, viewer_headers: dict) -> None:
    """DELETE /rules/{id} with viewer role → 403 (rules:write requires engineer+)."""
    resp = await client.delete(f"{BASE_URL}/any-rule-id", headers=viewer_headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_delete_rule_analyst_forbidden(client: AsyncClient, analyst_headers: dict) -> None:
    """DELETE /rules/{id} with analyst role → 403 (rules:write requires engineer+)."""
    resp = await client.delete(f"{BASE_URL}/any-rule-id", headers=analyst_headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_delete_rule_hunter_forbidden(client: AsyncClient, hunter_headers: dict) -> None:
    """DELETE /rules/{id} with hunter role → 403.

    Hunter has rules:read but NOT rules:write; delete is blocked.
    """
    resp = await client.delete(f"{BASE_URL}/any-rule-id", headers=hunter_headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_delete_rule_not_found(client: AsyncClient, engineer_headers: dict) -> None:
    """DELETE /rules/{id} for nonexistent rule → 404."""
    resp = await client.delete(f"{BASE_URL}/nonexistent-rule-id", headers=engineer_headers)
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Rule not found"


@pytest.mark.asyncio
async def test_delete_rule_engineer_success(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """DELETE /rules/{id} with engineer role → 204 No Content."""
    await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Mimikatz", "content": _SIGMA_YAML},
    )
    resp = await client.delete(f"{BASE_URL}/test-rule-0001", headers=engineer_headers)
    assert resp.status_code == 204
    assert resp.content == b""


@pytest.mark.asyncio
async def test_delete_rule_admin_success(
    client: AsyncClient, engineer_headers: dict, admin_headers: dict
) -> None:
    """DELETE /rules/{id} with admin role → 204 No Content."""
    await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Mimikatz", "content": _SIGMA_YAML},
    )
    resp = await client.delete(f"{BASE_URL}/test-rule-0001", headers=admin_headers)
    assert resp.status_code == 204


@pytest.mark.asyncio
async def test_delete_rule_gone_from_get(
    client: AsyncClient, hunter_headers: dict, engineer_headers: dict
) -> None:
    """After DELETE /rules/{id}, GET /rules/{id} returns 404."""
    await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Mimikatz", "content": _SIGMA_YAML},
    )
    await client.delete(f"{BASE_URL}/test-rule-0001", headers=engineer_headers)

    resp = await client.get(f"{BASE_URL}/test-rule-0001", headers=hunter_headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_delete_rule_absent_from_list(
    client: AsyncClient, hunter_headers: dict, engineer_headers: dict
) -> None:
    """After DELETE /rules/{id}, rule no longer appears in GET /rules listing."""
    await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Mimikatz", "content": _SIGMA_YAML},
    )
    await client.delete(f"{BASE_URL}/test-rule-0001", headers=engineer_headers)

    resp = await client.get(BASE_URL, headers=hunter_headers)
    assert resp.status_code == 200
    ids = [r["id"] for r in resp.json()]
    assert "test-rule-0001" not in ids


@pytest.mark.asyncio
async def test_delete_rule_double_delete_returns_404(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """Second DELETE on the same rule ID → 404."""
    await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Mimikatz", "content": _SIGMA_YAML},
    )
    await client.delete(f"{BASE_URL}/test-rule-0001", headers=engineer_headers)
    resp = await client.delete(f"{BASE_URL}/test-rule-0001", headers=engineer_headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_delete_rule_only_removes_target(
    client: AsyncClient, hunter_headers: dict, engineer_headers: dict
) -> None:
    """DELETE /rules/{id} removes only the targeted rule; others are unaffected."""
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
    await client.delete(f"{BASE_URL}/test-rule-0001", headers=engineer_headers)

    resp = await client.get(BASE_URL, headers=hunter_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["id"] == "test-rule-0002"


@pytest.mark.asyncio
async def test_delete_rule_stats_summary_decrements(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """GET /rules/stats/summary total decrements after DELETE."""
    await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Mimikatz", "content": _SIGMA_YAML},
    )
    summary_before = await client.get(
        f"{BASE_URL}/stats/summary", headers=engineer_headers
    )
    assert summary_before.json()["total"] == 1

    await client.delete(f"{BASE_URL}/test-rule-0001", headers=engineer_headers)

    summary_after = await client.get(
        f"{BASE_URL}/stats/summary", headers=engineer_headers
    )
    assert summary_after.json()["total"] == 0
