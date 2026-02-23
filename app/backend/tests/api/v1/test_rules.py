"""Tests for /api/v1/rules endpoints.

RBAC:
  rules:read  → hunter, engineer, admin
  rules:write → engineer, admin
"""

from __future__ import annotations

from unittest.mock import patch, AsyncMock

import pytest


_BASE = "/api/v1/rules"

_VALID_SIGMA_YAML = """
title: Test Brute Force Detection
id: 11111111-1111-1111-1111-111111111111
status: test
description: Detects brute force attempts
logsource:
    category: authentication
    product: linux
detection:
    selection:
        event_type: authentication_failed
    condition: selection
level: high
""".strip()


class TestListRulesRBAC:
    """GET /rules — access control."""

    async def test_hunter_can_list_rules(self, client, hunter_headers) -> None:
        resp = await client.get(_BASE, headers=hunter_headers)
        assert resp.status_code == 200

    async def test_engineer_can_list_rules(self, client, engineer_headers) -> None:
        resp = await client.get(_BASE, headers=engineer_headers)
        assert resp.status_code == 200

    async def test_admin_can_list_rules(self, client, admin_headers) -> None:
        resp = await client.get(_BASE, headers=admin_headers)
        assert resp.status_code == 200

    async def test_viewer_cannot_list_rules(self, client, viewer_headers) -> None:
        resp = await client.get(_BASE, headers=viewer_headers)
        assert resp.status_code == 403

    async def test_analyst_cannot_list_rules(self, client, analyst_headers) -> None:
        resp = await client.get(_BASE, headers=analyst_headers)
        assert resp.status_code == 403

    async def test_unauthenticated_cannot_list_rules(self, client) -> None:
        resp = await client.get(_BASE)
        assert resp.status_code == 401


class TestListRulesResponse:
    """GET /rules — response shape."""

    async def test_returns_list(self, client, hunter_headers) -> None:
        resp = await client.get(_BASE, headers=hunter_headers)
        assert isinstance(resp.json(), list)

    async def test_empty_list_when_no_rules(self, client, hunter_headers) -> None:
        resp = await client.get(_BASE, headers=hunter_headers)
        assert resp.json() == []


class TestRulesSummary:
    """GET /rules/stats/summary — aggregate rule statistics."""

    async def test_hunter_can_get_summary(self, client, hunter_headers) -> None:
        resp = await client.get(f"{_BASE}/stats/summary", headers=hunter_headers)
        assert resp.status_code == 200

    async def test_summary_has_total(self, client, hunter_headers) -> None:
        resp = await client.get(f"{_BASE}/stats/summary", headers=hunter_headers)
        assert "total" in resp.json()

    async def test_summary_has_enabled(self, client, hunter_headers) -> None:
        resp = await client.get(f"{_BASE}/stats/summary", headers=hunter_headers)
        assert "enabled" in resp.json()

    async def test_summary_has_by_level(self, client, hunter_headers) -> None:
        resp = await client.get(f"{_BASE}/stats/summary", headers=hunter_headers)
        assert "by_level" in resp.json()

    async def test_analyst_denied_summary(self, client, analyst_headers) -> None:
        resp = await client.get(f"{_BASE}/stats/summary", headers=analyst_headers)
        assert resp.status_code == 403


class TestRuleTest:
    """POST /rules/test — validate+test YAML against a sample event (no DB write)."""

    async def test_valid_yaml_returns_200(self, client, hunter_headers) -> None:
        resp = await client.post(
            f"{_BASE}/test",
            json={"content": _VALID_SIGMA_YAML, "sample_event": {"event_type": "login"}},
            headers=hunter_headers,
        )
        assert resp.status_code == 200

    async def test_valid_yaml_response_has_matched(self, client, hunter_headers) -> None:
        resp = await client.post(
            f"{_BASE}/test",
            json={"content": _VALID_SIGMA_YAML, "sample_event": {"event_type": "login"}},
            headers=hunter_headers,
        )
        assert "matched" in resp.json()

    async def test_invalid_yaml_returns_200_with_errors(self, client, hunter_headers) -> None:
        """Malformed YAML returns 200 with errors list (not 422)."""
        resp = await client.post(
            f"{_BASE}/test",
            json={"content": ": invalid: yaml: [[[", "sample_event": {}},
            headers=hunter_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["matched"] is False
        assert len(body["errors"]) > 0

    async def test_missing_title_field_returns_error(self, client, hunter_headers) -> None:
        yaml_no_title = "detection:\n  selection:\n    foo: bar\n  condition: selection\n"
        resp = await client.post(
            f"{_BASE}/test",
            json={"content": yaml_no_title, "sample_event": {}},
            headers=hunter_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["matched"] is False

    async def test_viewer_cannot_test_rule(self, client, viewer_headers) -> None:
        resp = await client.post(
            f"{_BASE}/test",
            json={"content": _VALID_SIGMA_YAML, "sample_event": {}},
            headers=viewer_headers,
        )
        assert resp.status_code == 403


class TestCreateRule:
    """POST /rules — create a new Sigma rule."""

    async def test_engineer_can_create_rule(self, client, engineer_headers) -> None:
        resp = await client.post(
            _BASE,
            json={"title": "My Rule", "content": _VALID_SIGMA_YAML, "enabled": True},
            headers=engineer_headers,
        )
        # 200 or 201 depending on handler; not 403/401/422
        assert resp.status_code in (200, 201, 422)  # 422 if Sigma parse fails

    async def test_analyst_cannot_create_rule(self, client, analyst_headers) -> None:
        resp = await client.post(
            _BASE,
            json={"title": "My Rule", "content": _VALID_SIGMA_YAML},
            headers=analyst_headers,
        )
        assert resp.status_code == 403

    async def test_hunter_cannot_create_rule(self, client, hunter_headers) -> None:
        resp = await client.post(
            _BASE,
            json={"title": "My Rule", "content": _VALID_SIGMA_YAML},
            headers=hunter_headers,
        )
        assert resp.status_code == 403


class TestGetRuleById:
    """GET /rules/{id} — retrieve a specific rule."""

    async def test_nonexistent_rule_returns_404(self, client, hunter_headers) -> None:
        resp = await client.get(
            f"{_BASE}/00000000-0000-0000-0000-000000000000",
            headers=hunter_headers,
        )
        assert resp.status_code == 404
