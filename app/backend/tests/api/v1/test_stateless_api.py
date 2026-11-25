"""Tests for feature 19.11 — Stateless API: no in-process session state.

Verifies that rule CRUD publishes reload signals to Valkey so every API
replica stays in sync without in-process state.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient

from app.core.valkey import RULE_RELOAD_CHANNEL, publish_rule_reload

# ── Rule reload pub/sub ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_publish_rule_reload_sends_to_correct_channel() -> None:
    """publish_rule_reload() publishes to RULE_RELOAD_CHANNEL."""
    mock_client = AsyncMock()
    mock_client.publish = AsyncMock()

    with patch("app.core.valkey.get_valkey_client", new=AsyncMock(return_value=mock_client)):
        await publish_rule_reload()

    mock_client.publish.assert_called_once_with(RULE_RELOAD_CHANNEL, "reload")


@pytest.mark.asyncio
async def test_publish_rule_reload_silent_on_valkey_error() -> None:
    """publish_rule_reload() does not raise when Valkey is unavailable."""
    with patch(
        "app.core.valkey.get_valkey_client",
        new=AsyncMock(side_effect=Exception("Valkey down")),
    ):
        await publish_rule_reload()  # must not raise


def _make_valkey_mock_for_rules() -> tuple[AsyncMock, list[tuple]]:
    """Build a Valkey mock that:
    - Returns None for .get() calls so token blacklist checks pass.
    - Captures (channel, message) tuples from .publish() calls.
    Returns (mock_client, published_list).
    """
    published: list[tuple] = []

    async def _capture_publish(channel, message):
        published.append((channel, message))

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=None)   # token not blacklisted
    mock_client.publish = _capture_publish
    return mock_client, published


@pytest.mark.asyncio
async def test_rule_create_publishes_reload(client: AsyncClient, engineer_headers: dict) -> None:
    """POST /rules publishes a rule reload signal after creating a rule."""
    valid_yaml = """
title: Test Rule
status: test
level: high
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains: mimikatz
  condition: selection
"""
    mock_client, published = _make_valkey_mock_for_rules()

    with patch("app.core.valkey.get_valkey_client", new=AsyncMock(return_value=mock_client)):
        resp = await client.post(
            "/api/v1/rules",
            headers=engineer_headers,
            json={"title": "Test Rule", "content": valid_yaml},
        )

    assert resp.status_code == 201
    assert len(published) == 1
    assert published[0] == (RULE_RELOAD_CHANNEL, "reload")


@pytest.mark.asyncio
async def test_rule_delete_publishes_reload(client: AsyncClient, engineer_headers: dict) -> None:
    """DELETE /rules/{id} publishes a rule reload signal after deleting a rule."""
    # First create a rule (without mocking Valkey — conftest uses is_token_blacklisted mock)
    valid_yaml = """
title: Delete Test Rule
status: test
level: medium
logsource:
  product: linux
detection:
  selection:
    CommandLine|contains: dropper
  condition: selection
"""
    mock_client, _ = _make_valkey_mock_for_rules()
    with patch("app.core.valkey.get_valkey_client", new=AsyncMock(return_value=mock_client)):
        create_resp = await client.post(
            "/api/v1/rules",
            headers=engineer_headers,
            json={"title": "Delete Test Rule", "content": valid_yaml},
        )
    assert create_resp.status_code == 201
    rule_id = create_resp.json()["id"]

    mock_client2, published = _make_valkey_mock_for_rules()
    with patch("app.core.valkey.get_valkey_client", new=AsyncMock(return_value=mock_client2)):
        del_resp = await client.delete(
            f"/api/v1/rules/{rule_id}",
            headers=engineer_headers,
        )

    assert del_resp.status_code == 204
    assert len(published) == 1
    assert published[0] == (RULE_RELOAD_CHANNEL, "reload")


@pytest.mark.asyncio
async def test_rule_update_publishes_reload(client: AsyncClient, engineer_headers: dict) -> None:
    """PATCH /rules/{id} publishes a rule reload signal after updating a rule."""
    valid_yaml = """
title: Update Test Rule
status: test
level: low
logsource:
  product: windows
detection:
  selection:
    CommandLine|contains: evil
  condition: selection
"""
    mock_client, _ = _make_valkey_mock_for_rules()
    with patch("app.core.valkey.get_valkey_client", new=AsyncMock(return_value=mock_client)):
        create_resp = await client.post(
            "/api/v1/rules",
            headers=engineer_headers,
            json={"title": "Update Test Rule", "content": valid_yaml},
        )
    assert create_resp.status_code == 201
    rule_id = create_resp.json()["id"]

    mock_client2, published = _make_valkey_mock_for_rules()
    with patch("app.core.valkey.get_valkey_client", new=AsyncMock(return_value=mock_client2)):
        patch_resp = await client.patch(
            f"/api/v1/rules/{rule_id}",
            headers=engineer_headers,
            json={"enabled": False},
        )

    assert patch_resp.status_code == 200
    assert len(published) == 1
    assert published[0] == (RULE_RELOAD_CHANNEL, "reload")


@pytest.mark.asyncio
async def test_rule_import_publishes_reload(client: AsyncClient, engineer_headers: dict) -> None:
    """POST /rules/import publishes a rule reload signal after importing rules."""
    import_yaml = """
title: Imported Rule
status: test
level: medium
logsource:
  product: windows
detection:
  selection:
    CommandLine|contains: injector
  condition: selection
"""
    mock_client, published = _make_valkey_mock_for_rules()

    with patch("app.core.valkey.get_valkey_client", new=AsyncMock(return_value=mock_client)):
        resp = await client.post(
            "/api/v1/rules/import",
            headers=engineer_headers,
            json={"yaml_content": import_yaml},
        )

    assert resp.status_code == 200
    assert resp.json()["imported"] == 1
    assert len(published) == 1
    assert published[0] == (RULE_RELOAD_CHANNEL, "reload")


@pytest.mark.asyncio
async def test_rule_update_no_changes_skips_reload(
    client: AsyncClient,
    engineer_headers: dict,
) -> None:
    """PATCH /rules/{id} with no actual changes does NOT publish a reload signal."""
    valid_yaml = """
title: No-Change Rule
status: test
level: low
logsource:
  product: windows
detection:
  selection:
    CommandLine|contains: test
  condition: selection
"""
    mock_client, _ = _make_valkey_mock_for_rules()
    with patch("app.core.valkey.get_valkey_client", new=AsyncMock(return_value=mock_client)):
        create_resp = await client.post(
            "/api/v1/rules",
            headers=engineer_headers,
            json={"title": "No-Change Rule", "content": valid_yaml},
        )
    assert create_resp.status_code == 201
    rule_id = create_resp.json()["id"]

    mock_client2, published = _make_valkey_mock_for_rules()
    with patch("app.core.valkey.get_valkey_client", new=AsyncMock(return_value=mock_client2)):
        # Send PATCH with an empty body (no fields to change)
        patch_resp = await client.patch(
            f"/api/v1/rules/{rule_id}",
            headers=engineer_headers,
            json={},  # nothing to update
        )

    assert patch_resp.status_code == 200
    # No DB mutation → no reload signal
    assert len(published) == 0
