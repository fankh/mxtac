"""Tests for feature 19.11 — Stateless API: no in-process session state.

Verifies:
  1. Ingest rate limiting uses Valkey (distributed), not an in-process dict.
  2. Rate limit is enforced correctly (429 on excess).
  3. Valkey unavailability falls back gracefully (fail-open for rate limiting).
  4. Rule CRUD publishes reload signals to Valkey.
  5. No in-process _rate_counters dict exists in events.py.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient

from app.core.api_key_auth import get_api_key
from app.core.valkey import (
    RULE_RELOAD_CHANNEL,
    check_ingest_rate_limit,
    publish_rule_reload,
)
from app.main import app
from app.models.api_key import APIKey
from app.pipeline.queue import MessageQueue, get_queue


# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_api_key(key_id: str = "test-key-1") -> APIKey:
    key = MagicMock(spec=APIKey)
    key.id = key_id
    key.is_active = True
    return key


def _make_queue() -> MessageQueue:
    queue = MagicMock(spec=MessageQueue)
    queue.publish = AsyncMock()
    return queue


# ── check_ingest_rate_limit unit tests ───────────────────────────────────────


@pytest.mark.asyncio
async def test_rate_limit_calls_valkey_eval() -> None:
    """check_ingest_rate_limit() uses Valkey.eval (Lua script), not an in-process dict."""
    mock_client = AsyncMock()
    mock_client.eval = AsyncMock(return_value=100)

    with patch("app.core.valkey.get_valkey_client", new=AsyncMock(return_value=mock_client)):
        result = await check_ingest_rate_limit("key-1", 100, limit=10_000, window_secs=60)

    assert result is True
    mock_client.eval.assert_called_once()


@pytest.mark.asyncio
async def test_rate_limit_key_contains_api_key_id() -> None:
    """The Valkey key used for rate limiting is scoped to the api_key_id."""
    mock_client = AsyncMock()
    mock_client.eval = AsyncMock(return_value=50)

    with patch("app.core.valkey.get_valkey_client", new=AsyncMock(return_value=mock_client)):
        await check_ingest_rate_limit("unique-key-abc", 50, limit=10_000, window_secs=60)

    call_args = mock_client.eval.call_args
    # Third positional arg to eval() is KEYS[1]
    assert "unique-key-abc" in call_args.args[2]


@pytest.mark.asyncio
async def test_rate_limit_passes_n_events_and_window_to_valkey() -> None:
    """check_ingest_rate_limit forwards n_events and window_secs as Lua ARGV."""
    mock_client = AsyncMock()
    mock_client.eval = AsyncMock(return_value=75)

    with patch("app.core.valkey.get_valkey_client", new=AsyncMock(return_value=mock_client)):
        await check_ingest_rate_limit("key-x", 75, limit=10_000, window_secs=60)

    call_args = mock_client.eval.call_args
    # eval(script, numkeys, KEYS[1], ARGV[1]=n_events, ARGV[2]=window_secs)
    assert call_args.args[3] == 75   # n_events
    assert call_args.args[4] == 60   # window_secs


@pytest.mark.asyncio
async def test_rate_limit_returns_true_when_below_limit() -> None:
    """Returns True (allowed) when Valkey counter is at or below the limit."""
    mock_client = AsyncMock()
    mock_client.eval = AsyncMock(return_value=10_000)  # exactly at limit

    with patch("app.core.valkey.get_valkey_client", new=AsyncMock(return_value=mock_client)):
        result = await check_ingest_rate_limit("key-1", 1, limit=10_000, window_secs=60)

    assert result is True


@pytest.mark.asyncio
async def test_rate_limit_returns_false_when_above_limit() -> None:
    """Returns False (blocked) when Valkey counter exceeds the limit."""
    mock_client = AsyncMock()
    mock_client.eval = AsyncMock(return_value=10_001)  # one over limit

    with patch("app.core.valkey.get_valkey_client", new=AsyncMock(return_value=mock_client)):
        result = await check_ingest_rate_limit("key-1", 1, limit=10_000, window_secs=60)

    assert result is False


@pytest.mark.asyncio
async def test_rate_limit_fails_open_when_valkey_unavailable() -> None:
    """When Valkey is unreachable, rate limiting fails open (allows the request)."""
    with patch(
        "app.core.valkey.get_valkey_client",
        new=AsyncMock(side_effect=Exception("connection refused")),
    ):
        result = await check_ingest_rate_limit("key-1", 100)

    assert result is True  # fail-open: prefer availability over strict enforcement


@pytest.mark.asyncio
async def test_rate_limit_different_keys_are_independent() -> None:
    """Different api_key_ids use different Valkey keys (no cross-key contamination)."""
    seen_keys: list[str] = []

    async def _capture_eval(script, numkeys, key, n_events, window_secs):
        seen_keys.append(key)
        return 100

    mock_client = AsyncMock()
    mock_client.eval = _capture_eval

    with patch("app.core.valkey.get_valkey_client", new=AsyncMock(return_value=mock_client)):
        await check_ingest_rate_limit("key-alpha", 50, limit=10_000, window_secs=60)
        await check_ingest_rate_limit("key-beta", 50, limit=10_000, window_secs=60)

    assert len(seen_keys) == 2
    assert seen_keys[0] != seen_keys[1]
    assert "key-alpha" in seen_keys[0]
    assert "key-beta" in seen_keys[1]


# ── Ingest endpoint integration ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_ingest_returns_429_when_rate_limit_exceeded(client: AsyncClient) -> None:
    """POST /events/ingest returns 429 when the Valkey counter exceeds the limit."""
    api_key = _make_api_key()
    queue = _make_queue()
    mock_valkey = AsyncMock()
    mock_valkey.eval = AsyncMock(return_value=10_001)

    app.dependency_overrides[get_api_key] = lambda: api_key
    app.dependency_overrides[get_queue] = lambda: queue
    try:
        with patch("app.core.valkey.get_valkey_client", new=AsyncMock(return_value=mock_valkey)):
            resp = await client.post(
                "/api/v1/events/ingest",
                json={"events": [{"class_name": "Process Activity"}]},
            )
        assert resp.status_code == 429
        assert "Rate limit exceeded" in resp.json()["detail"]
        # Queue must NOT be called when rate limited
        queue.publish.assert_not_called()
    finally:
        app.dependency_overrides.pop(get_api_key, None)
        app.dependency_overrides.pop(get_queue, None)


@pytest.mark.asyncio
async def test_ingest_returns_202_within_rate_limit(client: AsyncClient) -> None:
    """POST /events/ingest returns 202 when within the Valkey rate limit."""
    api_key = _make_api_key()
    queue = _make_queue()
    mock_valkey = AsyncMock()
    mock_valkey.eval = AsyncMock(return_value=1)  # well within limit

    app.dependency_overrides[get_api_key] = lambda: api_key
    app.dependency_overrides[get_queue] = lambda: queue
    try:
        with patch("app.core.valkey.get_valkey_client", new=AsyncMock(return_value=mock_valkey)):
            resp = await client.post(
                "/api/v1/events/ingest",
                json={"events": [{"class_name": "Network Activity"}]},
            )
        assert resp.status_code == 202
        data = resp.json()
        assert data["accepted"] == 1
        assert data["status"] == "queued"
        queue.publish.assert_called_once()
    finally:
        app.dependency_overrides.pop(get_api_key, None)
        app.dependency_overrides.pop(get_queue, None)


@pytest.mark.asyncio
async def test_ingest_allows_when_valkey_unavailable(client: AsyncClient) -> None:
    """POST /events/ingest accepts events when Valkey is down (fail-open)."""
    api_key = _make_api_key()
    queue = _make_queue()

    app.dependency_overrides[get_api_key] = lambda: api_key
    app.dependency_overrides[get_queue] = lambda: queue
    try:
        with patch(
            "app.core.valkey.get_valkey_client",
            new=AsyncMock(side_effect=Exception("Valkey unavailable")),
        ):
            resp = await client.post(
                "/api/v1/events/ingest",
                json={"events": [{"class_name": "Process Activity"}]},
            )
        # Fail-open: request succeeds even when Valkey is down
        assert resp.status_code == 202
    finally:
        app.dependency_overrides.pop(get_api_key, None)
        app.dependency_overrides.pop(get_queue, None)


@pytest.mark.asyncio
async def test_ingest_batch_size_counted_correctly(client: AsyncClient) -> None:
    """The full batch size (n_events) is passed to the Valkey rate limiter."""
    api_key = _make_api_key()
    queue = _make_queue()
    mock_valkey = AsyncMock()
    captured_n: list[int] = []

    async def _capture_eval(script, numkeys, key, n_events, window_secs):
        captured_n.append(n_events)
        return n_events  # within limit

    mock_valkey.eval = _capture_eval

    app.dependency_overrides[get_api_key] = lambda: api_key
    app.dependency_overrides[get_queue] = lambda: queue
    try:
        with patch("app.core.valkey.get_valkey_client", new=AsyncMock(return_value=mock_valkey)):
            resp = await client.post(
                "/api/v1/events/ingest",
                json={"events": [{"class_name": "A"}, {"class_name": "B"}, {"class_name": "C"}]},
            )
        assert resp.status_code == 202
        assert captured_n == [3]  # 3 events in the batch
    finally:
        app.dependency_overrides.pop(get_api_key, None)
        app.dependency_overrides.pop(get_queue, None)


# ── No in-process state ───────────────────────────────────────────────────────


def test_no_in_process_rate_counter_dict() -> None:
    """The _rate_counters module-level dict has been removed from events.py.

    Rate limiting must be distributed via Valkey — not stored in process memory.
    """
    import app.api.v1.endpoints.events as events_module

    assert not hasattr(events_module, "_rate_counters"), (
        "_rate_counters dict must not exist in events.py — "
        "rate limiting must be Valkey-backed for horizontal scaling"
    )


def test_no_sync_check_rate_limit_function() -> None:
    """The synchronous _check_rate_limit helper has been removed from events.py."""
    import app.api.v1.endpoints.events as events_module

    assert not hasattr(events_module, "_check_rate_limit"), (
        "_check_rate_limit must not exist in events.py — "
        "the distributed async check_ingest_rate_limit is used instead"
    )


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
