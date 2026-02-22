"""Tests for NotificationChannelRepo — feature 27.2.

Coverage:
  - list_enabled(): returns only enabled channels
  - list_enabled(): returns empty list when none enabled
  - list(): returns all channels with pagination
  - list(): returns ([], 0) when table empty
  - get_by_id(): found → returns NotificationChannel
  - get_by_id(): not found → returns None
  - create(): channel added to session, flushed, returned
  - update(): found → updates fields, flushes, returns channel
  - update(): not found → returns None without flush
  - update(): None kwarg values are skipped
  - delete(): found → deletes, flushes, returns True
  - delete(): not found → returns False
  - count(): returns scalar result; None → 0
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.repositories.notification_channel_repo import NotificationChannelRepo


# ---------------------------------------------------------------------------
# Session factory helpers
# ---------------------------------------------------------------------------


def _make_session() -> MagicMock:
    """MagicMock for AsyncSession with async methods patched."""
    session = MagicMock()
    session.execute = AsyncMock()
    session.flush = AsyncMock()
    session.delete = AsyncMock()
    session.scalar = AsyncMock()
    return session


def _scalars_result(items: list) -> MagicMock:
    result = MagicMock()
    result.scalars.return_value.all.return_value = items
    return result


def _make_channel(
    *,
    id: int = 1,
    name: str = "test-channel",
    channel_type: str = "slack",
    config_json: str = '{"webhook_url": "https://hooks.slack.com/test"}',
    enabled: bool = True,
    min_severity: str = "high",
) -> MagicMock:
    ch = MagicMock()
    ch.id = id
    ch.name = name
    ch.channel_type = channel_type
    ch.config_json = config_json
    ch.enabled = enabled
    ch.min_severity = min_severity
    return ch


# ---------------------------------------------------------------------------
# list_enabled()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_enabled_returns_enabled_channels():
    """list_enabled() must return only enabled channels."""
    channels = [_make_channel(id=1, enabled=True), _make_channel(id=2, enabled=True)]
    session = _make_session()
    session.execute.return_value = _scalars_result(channels)

    result = await NotificationChannelRepo.list_enabled(session)

    assert result == channels
    session.execute.assert_awaited_once()


@pytest.mark.asyncio
async def test_list_enabled_returns_empty_when_none():
    """list_enabled() must return an empty list when no channels are enabled."""
    session = _make_session()
    session.execute.return_value = _scalars_result([])

    result = await NotificationChannelRepo.list_enabled(session)

    assert result == []


# ---------------------------------------------------------------------------
# list()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_returns_items_and_total():
    """list() must return (items, total) with correct count."""
    channels = [_make_channel(id=1), _make_channel(id=2)]
    session = _make_session()
    session.execute.return_value = _scalars_result(channels)
    session.scalar.return_value = 2

    items, total = await NotificationChannelRepo.list(session, page=1, page_size=25)

    assert items == channels
    assert total == 2


@pytest.mark.asyncio
async def test_list_returns_empty_when_table_empty():
    """list() must return ([], 0) when no channels exist."""
    session = _make_session()
    session.execute.return_value = _scalars_result([])
    session.scalar.return_value = None  # scalar returns None when no rows

    items, total = await NotificationChannelRepo.list(session)

    assert items == []
    assert total == 0


# ---------------------------------------------------------------------------
# get_by_id()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_by_id_found():
    """get_by_id() must return the channel when it exists."""
    channel = _make_channel(id=42)
    session = _make_session()
    result_mock = MagicMock()
    result_mock.scalar_one_or_none.return_value = channel
    session.execute.return_value = result_mock

    found = await NotificationChannelRepo.get_by_id(session, 42)

    assert found is channel


@pytest.mark.asyncio
async def test_get_by_id_not_found():
    """get_by_id() must return None when channel does not exist."""
    session = _make_session()
    result_mock = MagicMock()
    result_mock.scalar_one_or_none.return_value = None
    session.execute.return_value = result_mock

    found = await NotificationChannelRepo.get_by_id(session, 999)

    assert found is None


# ---------------------------------------------------------------------------
# create()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_adds_and_flushes():
    """create() must add the channel to the session and flush."""
    session = _make_session()

    from app.models.notification import NotificationChannel

    ch = await NotificationChannelRepo.create(
        session,
        name="email-channel",
        channel_type="email",
        config_json='{"smtp_host": "smtp.example.com"}',
        enabled=True,
        min_severity="high",
    )

    session.add.assert_called_once()
    session.flush.assert_awaited_once()
    assert isinstance(ch, NotificationChannel)
    assert ch.name == "email-channel"


# ---------------------------------------------------------------------------
# update()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_update_found_sets_fields():
    """update() must update the channel's attributes and flush."""
    channel = _make_channel(id=1, name="old-name", min_severity="low")
    session = _make_session()

    with patch.object(
        NotificationChannelRepo,
        "get_by_id",
        new=AsyncMock(return_value=channel),
    ):
        result = await NotificationChannelRepo.update(
            session, 1, name="new-name", min_severity="high"
        )

    assert result is channel
    assert channel.name == "new-name"
    assert channel.min_severity == "high"
    session.flush.assert_awaited_once()


@pytest.mark.asyncio
async def test_update_not_found_returns_none():
    """update() must return None when the channel does not exist."""
    session = _make_session()

    with patch.object(
        NotificationChannelRepo,
        "get_by_id",
        new=AsyncMock(return_value=None),
    ):
        result = await NotificationChannelRepo.update(session, 999, name="x")

    assert result is None
    session.flush.assert_not_awaited()


@pytest.mark.asyncio
async def test_update_skips_none_values():
    """update() must not overwrite attributes whose new value is None."""
    channel = _make_channel(id=1, name="keep-me")
    session = _make_session()

    with patch.object(
        NotificationChannelRepo,
        "get_by_id",
        new=AsyncMock(return_value=channel),
    ):
        await NotificationChannelRepo.update(session, 1, name=None, min_severity="high")

    assert channel.name == "keep-me"
    assert channel.min_severity == "high"


# ---------------------------------------------------------------------------
# delete()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_delete_found_returns_true():
    """delete() must delete the channel, flush, and return True."""
    channel = _make_channel(id=1)
    session = _make_session()

    with patch.object(
        NotificationChannelRepo,
        "get_by_id",
        new=AsyncMock(return_value=channel),
    ):
        result = await NotificationChannelRepo.delete(session, 1)

    assert result is True
    session.delete.assert_awaited_once_with(channel)
    session.flush.assert_awaited_once()


@pytest.mark.asyncio
async def test_delete_not_found_returns_false():
    """delete() must return False when the channel does not exist."""
    session = _make_session()

    with patch.object(
        NotificationChannelRepo,
        "get_by_id",
        new=AsyncMock(return_value=None),
    ):
        result = await NotificationChannelRepo.delete(session, 999)

    assert result is False
    session.delete.assert_not_awaited()
    session.flush.assert_not_awaited()


# ---------------------------------------------------------------------------
# count()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_count_returns_scalar():
    """count() must return the scalar result from the DB."""
    session = _make_session()
    session.scalar.return_value = 7

    total = await NotificationChannelRepo.count(session)

    assert total == 7


@pytest.mark.asyncio
async def test_count_none_returns_zero():
    """count() must return 0 when the scalar result is None."""
    session = _make_session()
    session.scalar.return_value = None

    total = await NotificationChannelRepo.count(session)

    assert total == 0
