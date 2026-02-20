"""Tests for Rules API: invalid YAML → 422 — Feature 28.36.

Coverage:
  POST /rules — invalid YAML → 422:
    - YAML scalar (plain string) → non-dict document skipped → empty list → 422
    - YAML list (sequence) → non-dict document skipped → empty list → 422
    - YAML null document → non-dict skipped → empty list → 422
    - Empty YAML string → zero documents → empty list → 422
    - Integer YAML → non-dict skipped → empty list → 422
    - Syntactically broken YAML → yaml.YAMLError caught → empty list → 422

  PATCH /rules/{id} — invalid YAML → 422:
    - YAML scalar → engine.load_rule_yaml returns None → 422
    - YAML list → engine.load_rule_yaml returns None → 422
    - Syntactically broken YAML → yaml.safe_load raises, caught by engine → None → 422
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient

BASE_URL = "/api/v1/rules"

_VALID_SIGMA_YAML = """\
title: Mimikatz Detection
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
"""

# ---------------------------------------------------------------------------
# POST /rules — invalid YAML document type → 422
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_post_rules_scalar_yaml_returns_422(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """POST /rules with a YAML scalar (plain string) → 422.

    yaml.safe_load_all yields the string as-is; isinstance(..., dict) is False
    so it is skipped, leaving an empty created list → 422.
    """
    resp = await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Bad Rule", "content": "just a plain string"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_post_rules_list_yaml_returns_422(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """POST /rules with a YAML sequence (list) instead of a mapping → 422."""
    resp = await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Bad Rule", "content": "- item1\n- item2\n- item3"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_post_rules_null_yaml_returns_422(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """POST /rules with a YAML null document → 422."""
    resp = await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Bad Rule", "content": "null"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_post_rules_empty_yaml_returns_422(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """POST /rules with empty YAML string (yields no documents) → 422."""
    resp = await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Bad Rule", "content": ""},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_post_rules_integer_yaml_returns_422(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """POST /rules with a YAML integer document → 422."""
    resp = await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Bad Rule", "content": "42"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_post_rules_broken_yaml_syntax_returns_422(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """POST /rules with syntactically broken YAML → 422.

    _parse_and_persist wraps yaml.safe_load_all() consumption in try/except
    yaml.YAMLError, returning an empty list which triggers the 422 guard.
    """
    resp = await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Bad Rule", "content": "[unclosed bracket"},
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# PATCH /rules/{id} — invalid YAML → 422
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_patch_rules_scalar_yaml_returns_422(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """PATCH /rules/{id} with YAML scalar → 422.

    engine.load_rule_yaml checks isinstance(doc, dict) and returns None for
    scalar documents, triggering the 422 guard in update_rule.
    """
    await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Valid Rule", "content": _VALID_SIGMA_YAML},
    )
    resp = await client.patch(
        f"{BASE_URL}/test-rule-0001",
        headers=engineer_headers,
        json={"content": "just a plain string"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_patch_rules_list_yaml_returns_422(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """PATCH /rules/{id} with YAML list → 422."""
    await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Valid Rule", "content": _VALID_SIGMA_YAML},
    )
    resp = await client.patch(
        f"{BASE_URL}/test-rule-0001",
        headers=engineer_headers,
        json={"content": "- item1\n- item2"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_patch_rules_broken_yaml_syntax_returns_422(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """PATCH /rules/{id} with syntactically broken YAML → 422.

    engine.load_rule_yaml wraps yaml.safe_load() in a broad try/except so
    any yaml.YAMLError is caught and None is returned, triggering 422.
    """
    await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Valid Rule", "content": _VALID_SIGMA_YAML},
    )
    resp = await client.patch(
        f"{BASE_URL}/test-rule-0001",
        headers=engineer_headers,
        json={"content": "[unclosed bracket"},
    )
    assert resp.status_code == 422
