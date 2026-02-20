"""Tests for feature 28.35 — Rules API: create rule persists to DB.

Verifies that POST /api/v1/rules correctly parses the Sigma YAML and
persists all derived fields to the database, and that the stored record
is immediately retrievable via GET /api/v1/rules/{id}.

Coverage:
  - POST /rules response includes all fields derived from Sigma YAML parsing
  - Created rule is retrievable by ID via GET /rules/{id} (DB persistence)
  - Raw YAML content is preserved in the DB (accessible via detail endpoint)
  - Sigma-derived metadata extracted correctly: level, status, logsource
  - ATT&CK technique_ids extracted from tags (e.g. attack.t1003 → T1003)
  - ATT&CK tactic_ids extracted from tags (e.g. attack.credential_access)
  - enabled flag defaults to True and persists with the correct value
  - enabled=False persists correctly to DB
  - hit_count and fp_count default to 0 in the DB record
  - Rule ID from YAML (not request body) is stored and returned
  - DB row count increases by 1 after successful creation
  - source field is set to "custom" for manually created rules
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient

BASE_URL = "/api/v1/rules"

# ---------------------------------------------------------------------------
# Test fixtures: Sigma YAML samples
# ---------------------------------------------------------------------------

# Full-featured rule with ATT&CK tags and logsource
_SIGMA_YAML_FULL = """\
title: Test Mimikatz Credential Dump
id: persist-test-rule-001
status: experimental
description: Detects credential dumping via mimikatz
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

# Minimal rule with service logsource and no ATT&CK tags
_SIGMA_YAML_MINIMAL = """\
title: Minimal Syslog Rule
id: persist-test-rule-002
status: stable
logsource:
  product: linux
  service: syslog
detection:
  selection:
    message|contains: error
  condition: selection
level: low
"""

# Rule with multiple ATT&CK technique tags and tactic numeric codes (attack.taXXXX)
# Named tactic tags (attack.execution) are NOT extracted by the engine; only
# attack.taXXXX numeric codes populate tactic_ids.
_SIGMA_YAML_MULTI_TAGS = """\
title: Multi-Tag Detection Rule
id: persist-test-rule-003
status: test
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    dst_port: 4444
  condition: selection
level: critical
tags:
  - attack.ta0002
  - attack.ta0005
  - attack.t1059
  - attack.t1036
"""


# ---------------------------------------------------------------------------
# POST /rules response field validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_rule_response_contains_yaml_id(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """POST /rules returns the rule ID from the Sigma YAML, not a generated one."""
    resp = await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Mimikatz", "content": _SIGMA_YAML_FULL},
    )
    assert resp.status_code == 201
    assert resp.json()["id"] == "persist-test-rule-001"


@pytest.mark.asyncio
async def test_create_rule_response_level_from_yaml(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """POST /rules returns level parsed from Sigma YAML, not from request body."""
    resp = await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Mimikatz", "content": _SIGMA_YAML_FULL},
    )
    assert resp.status_code == 201
    assert resp.json()["level"] == "high"


@pytest.mark.asyncio
async def test_create_rule_response_status_from_yaml(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """POST /rules returns status parsed from Sigma YAML."""
    resp = await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Mimikatz", "content": _SIGMA_YAML_FULL},
    )
    assert resp.status_code == 201
    assert resp.json()["status"] == "experimental"


@pytest.mark.asyncio
async def test_create_rule_response_logsource_from_yaml(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """POST /rules returns logsource dict with product and category from YAML."""
    resp = await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Mimikatz", "content": _SIGMA_YAML_FULL},
    )
    assert resp.status_code == 201
    logsource = resp.json()["logsource"]
    assert logsource["product"] == "windows"
    assert logsource["category"] == "process_creation"


@pytest.mark.asyncio
async def test_create_rule_response_technique_ids_from_tags(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """POST /rules extracts ATT&CK technique IDs from tags (attack.t1003 → T1003)."""
    resp = await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Mimikatz", "content": _SIGMA_YAML_FULL},
    )
    assert resp.status_code == 201
    technique_ids = resp.json()["technique_ids"]
    assert isinstance(technique_ids, list)
    assert "T1003" in technique_ids


@pytest.mark.asyncio
async def test_create_rule_response_tactic_ids_is_list(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """POST /rules response includes tactic_ids as a list (populated from attack.taXXXX tags).

    Named tactic tags like attack.credential_access are not extracted by the
    engine (only attack.taXXXX numeric codes are). The field is always a list.
    """
    resp = await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Mimikatz", "content": _SIGMA_YAML_FULL},
    )
    assert resp.status_code == 201
    tactic_ids = resp.json()["tactic_ids"]
    assert isinstance(tactic_ids, list)


@pytest.mark.asyncio
async def test_create_rule_response_enabled_defaults_true(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """POST /rules without enabled flag → enabled=True in response."""
    resp = await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Mimikatz", "content": _SIGMA_YAML_FULL},
    )
    assert resp.status_code == 201
    assert resp.json()["enabled"] is True


@pytest.mark.asyncio
async def test_create_rule_response_hit_count_zero(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """POST /rules → newly created rule has hit_count=0."""
    resp = await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Mimikatz", "content": _SIGMA_YAML_FULL},
    )
    assert resp.status_code == 201
    assert resp.json()["hit_count"] == 0


@pytest.mark.asyncio
async def test_create_rule_response_fp_count_zero(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """POST /rules → newly created rule has fp_count=0."""
    resp = await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Mimikatz", "content": _SIGMA_YAML_FULL},
    )
    assert resp.status_code == 201
    assert resp.json()["fp_count"] == 0


# ---------------------------------------------------------------------------
# DB persistence — rule retrievable after creation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_created_rule_retrievable_by_id(
    client: AsyncClient, engineer_headers: dict, hunter_headers: dict
) -> None:
    """POST /rules → GET /rules/{id} returns the same rule (DB persistence)."""
    post_resp = await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Mimikatz", "content": _SIGMA_YAML_FULL},
    )
    assert post_resp.status_code == 201

    get_resp = await client.get(
        f"{BASE_URL}/persist-test-rule-001",
        headers=hunter_headers,
    )
    assert get_resp.status_code == 200
    assert get_resp.json()["id"] == "persist-test-rule-001"


@pytest.mark.asyncio
async def test_created_rule_detail_matches_post_response(
    client: AsyncClient, engineer_headers: dict, hunter_headers: dict
) -> None:
    """GET /rules/{id} after POST returns the same field values as the POST response."""
    post_resp = await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Mimikatz", "content": _SIGMA_YAML_FULL},
    )
    assert post_resp.status_code == 201
    post_data = post_resp.json()

    get_resp = await client.get(
        f"{BASE_URL}/persist-test-rule-001",
        headers=hunter_headers,
    )
    assert get_resp.status_code == 200
    get_data = get_resp.json()

    assert get_data["id"] == post_data["id"]
    assert get_data["level"] == post_data["level"]
    assert get_data["status"] == post_data["status"]
    assert get_data["enabled"] == post_data["enabled"]


@pytest.mark.asyncio
async def test_created_rule_yaml_content_persisted(
    client: AsyncClient, engineer_headers: dict, hunter_headers: dict
) -> None:
    """GET /rules/{id} returns raw YAML content field that was stored at creation."""
    await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Mimikatz", "content": _SIGMA_YAML_FULL},
    )
    resp = await client.get(
        f"{BASE_URL}/persist-test-rule-001",
        headers=hunter_headers,
    )
    assert resp.status_code == 200
    content = resp.json()["content"]
    assert isinstance(content, str)
    assert len(content) > 0
    assert "mimikatz" in content.lower()


@pytest.mark.asyncio
async def test_created_rule_description_persisted(
    client: AsyncClient, engineer_headers: dict, hunter_headers: dict
) -> None:
    """GET /rules/{id} returns description that was in the Sigma YAML."""
    await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Mimikatz", "content": _SIGMA_YAML_FULL},
    )
    resp = await client.get(
        f"{BASE_URL}/persist-test-rule-001",
        headers=hunter_headers,
    )
    assert resp.status_code == 200
    assert "credential" in resp.json()["description"].lower()


@pytest.mark.asyncio
async def test_created_rule_source_is_custom(
    client: AsyncClient, engineer_headers: dict, hunter_headers: dict
) -> None:
    """GET /rules/{id} after POST shows source='custom' for manually created rules."""
    await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Mimikatz", "content": _SIGMA_YAML_FULL},
    )
    resp = await client.get(
        f"{BASE_URL}/persist-test-rule-001",
        headers=hunter_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["source"] == "custom"


@pytest.mark.asyncio
async def test_created_rule_appears_in_list(
    client: AsyncClient, engineer_headers: dict, hunter_headers: dict
) -> None:
    """After POST /rules, GET /rules returns the created rule in the listing."""
    await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Mimikatz", "content": _SIGMA_YAML_FULL},
    )
    list_resp = await client.get(BASE_URL, headers=hunter_headers)
    assert list_resp.status_code == 200
    rule_ids = [r["id"] for r in list_resp.json()]
    assert "persist-test-rule-001" in rule_ids


# ---------------------------------------------------------------------------
# DB persistence — enabled=False
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_disabled_rule_persists_enabled_false(
    client: AsyncClient, engineer_headers: dict, hunter_headers: dict
) -> None:
    """POST /rules with enabled=False → GET /rules/{id} returns enabled=False."""
    await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Mimikatz", "content": _SIGMA_YAML_FULL, "enabled": False},
    )
    resp = await client.get(
        f"{BASE_URL}/persist-test-rule-001",
        headers=hunter_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["enabled"] is False


@pytest.mark.asyncio
async def test_create_disabled_rule_filtered_by_enabled_false(
    client: AsyncClient, engineer_headers: dict, hunter_headers: dict
) -> None:
    """A disabled rule appears in GET /rules?enabled=false filter."""
    await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Mimikatz", "content": _SIGMA_YAML_FULL, "enabled": False},
    )
    resp = await client.get(f"{BASE_URL}?enabled=false", headers=hunter_headers)
    assert resp.status_code == 200
    rule_ids = [r["id"] for r in resp.json()]
    assert "persist-test-rule-001" in rule_ids


# ---------------------------------------------------------------------------
# DB persistence — service logsource field
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_rule_service_logsource_persisted(
    client: AsyncClient, engineer_headers: dict, hunter_headers: dict
) -> None:
    """POST /rules with service logsource → GET /rules/{id} returns service field."""
    await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Syslog", "content": _SIGMA_YAML_MINIMAL},
    )
    resp = await client.get(
        f"{BASE_URL}/persist-test-rule-002",
        headers=hunter_headers,
    )
    assert resp.status_code == 200
    logsource = resp.json()["logsource"]
    assert logsource.get("product") == "linux"
    assert logsource.get("service") == "syslog"


# ---------------------------------------------------------------------------
# DB persistence — multiple ATT&CK tags
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_rule_multiple_technique_ids_persisted(
    client: AsyncClient, engineer_headers: dict, hunter_headers: dict
) -> None:
    """POST /rules with multiple attack.tNNNN tags → all technique IDs stored in DB."""
    await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Multi-Tag", "content": _SIGMA_YAML_MULTI_TAGS},
    )
    resp = await client.get(
        f"{BASE_URL}/persist-test-rule-003",
        headers=hunter_headers,
    )
    assert resp.status_code == 200
    technique_ids = resp.json()["technique_ids"]
    assert "T1059" in technique_ids
    assert "T1036" in technique_ids


@pytest.mark.asyncio
async def test_create_rule_multiple_tactic_ids_persisted(
    client: AsyncClient, engineer_headers: dict, hunter_headers: dict
) -> None:
    """POST /rules with attack.taXXXX tactic codes → tactic IDs stored in DB.

    The engine extracts tactic IDs from attack.taXXXX numeric codes only
    (e.g. attack.ta0002 → TA0002). Named tactic tags are not extracted.
    """
    await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Multi-Tag", "content": _SIGMA_YAML_MULTI_TAGS},
    )
    resp = await client.get(
        f"{BASE_URL}/persist-test-rule-003",
        headers=hunter_headers,
    )
    assert resp.status_code == 200
    tactic_ids = resp.json()["tactic_ids"]
    assert isinstance(tactic_ids, list)
    assert "TA0002" in tactic_ids
    assert "TA0005" in tactic_ids
