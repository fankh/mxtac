"""Tests for POST /rules/import — bulk YAML multi-doc import (feature 13.7).

Coverage:
  - RBAC: unauthenticated → 401/403
  - RBAC: viewer / analyst / hunter → 403 (rules:write requires engineer+)
  - RBAC: engineer / admin → 200
  - Single rule import → imported=1, total_rules=1
  - Multi-document import (2 rules via --- separator) → imported=2
  - Multi-document import (3 rules) → imported=3
  - Invalid YAML syntax → imported=0 (silently skipped), 200 OK
  - Empty string payload → imported=0
  - YAML null document (bare ---) → imported=0
  - Non-dict YAML scalar → imported=0
  - Mixed valid dict + non-dict doc → only dicts are counted
  - Persistence: imported rules appear in GET /rules listing
  - Persistence: imported rules retrievable via GET /rules/{id} with correct fields
  - total_rules reflects cumulative DB count across multiple imports
  - Response schema: 'imported' and 'total_rules' are integers
  - Duplicate rule ID on re-import → 422 (DB primary key constraint violation)
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient

BASE_URL = "/api/v1/rules"

# ---------------------------------------------------------------------------
# YAML test fixtures
# ---------------------------------------------------------------------------

_RULE_A = """\
title: Import Test Rule A
id: import-rule-0001
status: experimental
description: Test rule A for import tests
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

_RULE_B = """\
title: Import Test Rule B
id: import-rule-0002
status: stable
description: Test rule B for import tests
logsource:
  category: network_connection
  product: linux
detection:
  selection:
    dst_port: 4444
  condition: selection
level: medium
"""

_RULE_C = """\
title: Import Test Rule C
id: import-rule-0003
status: test
description: Test rule C for import tests
logsource:
  category: dns_query
  product: windows
detection:
  selection:
    QueryName|contains: evil.example.com
  condition: selection
level: low
"""

# Multi-document YAML: two rules separated by YAML document marker
_MULTI_AB = _RULE_A + "---\n" + _RULE_B

# Multi-document YAML: three rules
_MULTI_ABC = _RULE_A + "---\n" + _RULE_B + "---\n" + _RULE_C

# Mixed multi-doc: one valid dict rule + one YAML list (non-dict, skipped)
_MULTI_MIXED = _RULE_A + "---\n- item1\n- item2\n"


# ---------------------------------------------------------------------------
# RBAC — rules:write is required (engineer and admin only)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_import_unauthenticated(client: AsyncClient) -> None:
    """POST /rules/import without auth → 401 or 403."""
    resp = await client.post(
        f"{BASE_URL}/import",
        json={"yaml_content": _RULE_A},
    )
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_import_viewer_forbidden(client: AsyncClient, viewer_headers: dict) -> None:
    """POST /rules/import with viewer role → 403 (rules:write requires engineer+)."""
    resp = await client.post(
        f"{BASE_URL}/import",
        headers=viewer_headers,
        json={"yaml_content": _RULE_A},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_import_analyst_forbidden(client: AsyncClient, analyst_headers: dict) -> None:
    """POST /rules/import with analyst role → 403 (rules:write requires engineer+)."""
    resp = await client.post(
        f"{BASE_URL}/import",
        headers=analyst_headers,
        json={"yaml_content": _RULE_A},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_import_hunter_forbidden(client: AsyncClient, hunter_headers: dict) -> None:
    """POST /rules/import with hunter role → 403.

    Hunter has rules:read but NOT rules:write; import is blocked.
    """
    resp = await client.post(
        f"{BASE_URL}/import",
        headers=hunter_headers,
        json={"yaml_content": _RULE_A},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_import_engineer_allowed(client: AsyncClient, engineer_headers: dict) -> None:
    """POST /rules/import with engineer role and valid YAML → 200."""
    resp = await client.post(
        f"{BASE_URL}/import",
        headers=engineer_headers,
        json={"yaml_content": _RULE_A},
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_import_admin_allowed(client: AsyncClient, admin_headers: dict) -> None:
    """POST /rules/import with admin role and valid YAML → 200."""
    resp = await client.post(
        f"{BASE_URL}/import",
        headers=admin_headers,
        json={"yaml_content": _RULE_A},
    )
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Import count — single and multi-document
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_import_single_rule_count(client: AsyncClient, engineer_headers: dict) -> None:
    """POST /rules/import with a single Sigma YAML → imported=1, total_rules=1."""
    resp = await client.post(
        f"{BASE_URL}/import",
        headers=engineer_headers,
        json={"yaml_content": _RULE_A},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["imported"] == 1
    assert data["total_rules"] == 1


@pytest.mark.asyncio
async def test_import_multi_doc_two_rules(client: AsyncClient, engineer_headers: dict) -> None:
    """POST /rules/import with two YAML docs (--- separator) → imported=2, total_rules=2."""
    resp = await client.post(
        f"{BASE_URL}/import",
        headers=engineer_headers,
        json={"yaml_content": _MULTI_AB},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["imported"] == 2
    assert data["total_rules"] == 2


@pytest.mark.asyncio
async def test_import_multi_doc_three_rules(client: AsyncClient, engineer_headers: dict) -> None:
    """POST /rules/import with three YAML docs → imported=3, total_rules=3."""
    resp = await client.post(
        f"{BASE_URL}/import",
        headers=engineer_headers,
        json={"yaml_content": _MULTI_ABC},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["imported"] == 3
    assert data["total_rules"] == 3


# ---------------------------------------------------------------------------
# Error handling — invalid / empty / non-dict inputs
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_import_invalid_yaml_syntax(client: AsyncClient, engineer_headers: dict) -> None:
    """POST /rules/import with unparseable YAML syntax → 200, imported=0 (silently skipped)."""
    resp = await client.post(
        f"{BASE_URL}/import",
        headers=engineer_headers,
        json={"yaml_content": "key: [unclosed bracket"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["imported"] == 0


@pytest.mark.asyncio
async def test_import_empty_string(client: AsyncClient, engineer_headers: dict) -> None:
    """POST /rules/import with empty YAML string → 200, imported=0, total_rules=0."""
    resp = await client.post(
        f"{BASE_URL}/import",
        headers=engineer_headers,
        json={"yaml_content": ""},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["imported"] == 0
    assert data["total_rules"] == 0


@pytest.mark.asyncio
async def test_import_null_yaml_document(client: AsyncClient, engineer_headers: dict) -> None:
    """POST /rules/import with bare '---' (null document) → 200, imported=0.

    A bare '---' yields a None document; non-dict documents are skipped.
    """
    resp = await client.post(
        f"{BASE_URL}/import",
        headers=engineer_headers,
        json={"yaml_content": "---\n"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["imported"] == 0


@pytest.mark.asyncio
async def test_import_non_dict_yaml_scalar(client: AsyncClient, engineer_headers: dict) -> None:
    """POST /rules/import with a YAML scalar (plain string) → 200, imported=0.

    Scalar documents are not dicts and are silently skipped.
    """
    resp = await client.post(
        f"{BASE_URL}/import",
        headers=engineer_headers,
        json={"yaml_content": "just a plain string value"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["imported"] == 0


@pytest.mark.asyncio
async def test_import_non_dict_yaml_list(client: AsyncClient, engineer_headers: dict) -> None:
    """POST /rules/import with a YAML list (sequence) → 200, imported=0.

    List documents are not dicts and are silently skipped.
    """
    resp = await client.post(
        f"{BASE_URL}/import",
        headers=engineer_headers,
        json={"yaml_content": "- item1\n- item2\n- item3\n"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["imported"] == 0


# ---------------------------------------------------------------------------
# Mixed valid + non-dict documents
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_import_mixed_dict_and_non_dict(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """POST /rules/import with one valid dict rule + one YAML list → only dict is counted.

    Non-dict documents (lists, scalars, nulls) are silently skipped; valid
    dict documents are imported normally.
    """
    resp = await client.post(
        f"{BASE_URL}/import",
        headers=engineer_headers,
        json={"yaml_content": _MULTI_MIXED},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["imported"] == 1
    assert data["total_rules"] == 1


# ---------------------------------------------------------------------------
# Persistence verification
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_import_rule_appears_in_list(
    client: AsyncClient, engineer_headers: dict, hunter_headers: dict
) -> None:
    """After POST /rules/import, GET /rules lists the imported rule."""
    await client.post(
        f"{BASE_URL}/import",
        headers=engineer_headers,
        json={"yaml_content": _RULE_A},
    )
    resp = await client.get(BASE_URL, headers=hunter_headers)
    assert resp.status_code == 200
    ids = [r["id"] for r in resp.json()]
    assert "import-rule-0001" in ids


@pytest.mark.asyncio
async def test_import_rule_retrievable_by_id(
    client: AsyncClient, engineer_headers: dict, hunter_headers: dict
) -> None:
    """After POST /rules/import, GET /rules/{id} returns the rule with correct fields."""
    await client.post(
        f"{BASE_URL}/import",
        headers=engineer_headers,
        json={"yaml_content": _RULE_A},
    )
    resp = await client.get(f"{BASE_URL}/import-rule-0001", headers=hunter_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == "import-rule-0001"
    assert data["title"] == "Import Test Rule A"
    assert data["level"] == "high"
    assert data["status"] == "experimental"
    assert data["enabled"] is True
    assert data["logsource"]["product"] == "windows"
    assert data["logsource"]["category"] == "process_creation"
    assert "T1003" in data["technique_ids"]


@pytest.mark.asyncio
async def test_import_multi_doc_all_rules_persisted(
    client: AsyncClient, engineer_headers: dict, hunter_headers: dict
) -> None:
    """After multi-doc import, all imported rules appear in GET /rules listing."""
    await client.post(
        f"{BASE_URL}/import",
        headers=engineer_headers,
        json={"yaml_content": _MULTI_AB},
    )
    resp = await client.get(BASE_URL, headers=hunter_headers)
    assert resp.status_code == 200
    ids = {r["id"] for r in resp.json()}
    assert "import-rule-0001" in ids
    assert "import-rule-0002" in ids


@pytest.mark.asyncio
async def test_import_rule_enabled_by_default(
    client: AsyncClient, engineer_headers: dict, hunter_headers: dict
) -> None:
    """Rules imported via POST /rules/import are enabled by default."""
    await client.post(
        f"{BASE_URL}/import",
        headers=engineer_headers,
        json={"yaml_content": _RULE_A},
    )
    resp = await client.get(f"{BASE_URL}/import-rule-0001", headers=hunter_headers)
    assert resp.status_code == 200
    assert resp.json()["enabled"] is True


# ---------------------------------------------------------------------------
# total_rules is cumulative across multiple imports
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_import_total_rules_cumulative(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """total_rules reflects the total DB count including rules from prior imports."""
    # First import: 1 rule
    r1 = await client.post(
        f"{BASE_URL}/import",
        headers=engineer_headers,
        json={"yaml_content": _RULE_A},
    )
    assert r1.status_code == 200
    assert r1.json()["total_rules"] == 1

    # Second import: 2 more rules
    r2 = await client.post(
        f"{BASE_URL}/import",
        headers=engineer_headers,
        json={"yaml_content": _RULE_B + "---\n" + _RULE_C},
    )
    assert r2.status_code == 200
    assert r2.json()["imported"] == 2
    assert r2.json()["total_rules"] == 3


# ---------------------------------------------------------------------------
# Response schema
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_import_response_schema(client: AsyncClient, engineer_headers: dict) -> None:
    """POST /rules/import response always contains 'imported' and 'total_rules' as integers."""
    resp = await client.post(
        f"{BASE_URL}/import",
        headers=engineer_headers,
        json={"yaml_content": _RULE_A},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "imported" in data
    assert "total_rules" in data
    assert isinstance(data["imported"], int)
    assert isinstance(data["total_rules"], int)
    assert data["imported"] >= 0
    assert data["total_rules"] >= data["imported"]


# ---------------------------------------------------------------------------
# Duplicate ID handling
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_import_duplicate_rule_id_returns_422(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """POST /rules/import of a rule with an already-existing ID → 422.

    The second import attempts to insert a duplicate primary key into the DB,
    which raises an IntegrityError caught by the endpoint as a 422.
    """
    # First import succeeds
    r1 = await client.post(
        f"{BASE_URL}/import",
        headers=engineer_headers,
        json={"yaml_content": _RULE_A},
    )
    assert r1.status_code == 200
    assert r1.json()["imported"] == 1

    # Second import of same rule ID → DB constraint violation
    r2 = await client.post(
        f"{BASE_URL}/import",
        headers=engineer_headers,
        json={"yaml_content": _RULE_A},
    )
    assert r2.status_code == 422
