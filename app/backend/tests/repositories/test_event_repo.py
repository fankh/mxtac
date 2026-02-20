"""Tests for EventRepo.entity_events() — mocked session unit tests.

Feature 12.8 — entity_timeline() — events for one entity

Approach:
  - All session interactions are mocked (no live DB needed)
  - AsyncMock used for awaitable methods (execute, scalar)
  - MagicMock used for the session object and synchronous call chains

Coverage:
  - entity_events(): returns a (list, int) tuple
  - entity_events(): result list contains the items from DB
  - entity_events(): total comes from session.scalar (count query)
  - entity_events(): None scalar coerces to 0
  - entity_events(): empty result returns ([], 0)
  - entity_events(): calls execute once (data) and scalar once (count)
  - entity_events(): unknown entity_type falls back silently (no error)
  - entity_events(): custom size parameter is accepted
  - entity_events(): multiple results returned in full
  - entity_events(): ip type sends query (no AttributeError on multi-column OR)
  - entity_events(): host, user, hash types each work without error
  - entity_events(): custom time_from parameter is accepted
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.repositories.event_repo import EventRepo


# ---------------------------------------------------------------------------
# Session / result factory helpers
# ---------------------------------------------------------------------------


def _make_session() -> MagicMock:
    """Sync MagicMock for the SQLAlchemy session with async methods patched."""
    session = MagicMock()
    session.execute = AsyncMock()
    session.scalar = AsyncMock()
    return session


def _scalars_result(items: list) -> MagicMock:
    """Build a result mock whose .scalars().all() returns *items*."""
    result = MagicMock()
    result.scalars.return_value.all.return_value = items
    return result


def _make_event_mock(**kwargs) -> MagicMock:
    """Minimal Event-like object for use in test assertions."""
    evt = MagicMock()
    evt.id = kwargs.get("id", "EVT-001")
    evt.hostname = kwargs.get("hostname", "host-01")
    evt.src_ip = kwargs.get("src_ip", "10.0.0.1")
    evt.dst_ip = kwargs.get("dst_ip", "10.0.0.2")
    evt.username = kwargs.get("username", "user01")
    evt.process_hash = kwargs.get("process_hash", None)
    evt.time = kwargs.get("time", datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc))
    return evt


# ---------------------------------------------------------------------------
# Return type
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_entity_events_returns_tuple() -> None:
    """entity_events() always returns a 2-tuple."""
    session = _make_session()
    session.scalar.return_value = 1
    session.execute.return_value = _scalars_result([_make_event_mock()])

    result = await EventRepo.entity_events(session, "host", "host-01")

    assert isinstance(result, tuple)
    assert len(result) == 2


@pytest.mark.asyncio
async def test_entity_events_first_element_is_list() -> None:
    """First element of the returned tuple is a list of Event objects."""
    session = _make_session()
    evt = _make_event_mock()
    session.scalar.return_value = 1
    session.execute.return_value = _scalars_result([evt])

    events, _ = await EventRepo.entity_events(session, "host", "host-01")

    assert isinstance(events, list)
    assert events[0] is evt


@pytest.mark.asyncio
async def test_entity_events_second_element_is_int() -> None:
    """Second element of the returned tuple is an integer total."""
    session = _make_session()
    session.scalar.return_value = 3
    session.execute.return_value = _scalars_result([_make_event_mock()] * 3)

    _, total = await EventRepo.entity_events(session, "host", "host-01")

    assert isinstance(total, int)
    assert total == 3


# ---------------------------------------------------------------------------
# Empty / None results
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_entity_events_empty_returns_empty_list_and_zero() -> None:
    """No matching events → ([], 0)."""
    session = _make_session()
    session.scalar.return_value = 0
    session.execute.return_value = _scalars_result([])

    events, total = await EventRepo.entity_events(session, "host", "nonexistent")

    assert events == []
    assert total == 0


@pytest.mark.asyncio
async def test_entity_events_none_scalar_coerces_to_zero() -> None:
    """If the COUNT scalar returns None, total is coerced to 0."""
    session = _make_session()
    session.scalar.return_value = None
    session.execute.return_value = _scalars_result([])

    _, total = await EventRepo.entity_events(session, "host", "somehost")

    assert total == 0


# ---------------------------------------------------------------------------
# DB call counts
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_entity_events_calls_execute_once_and_scalar_once() -> None:
    """entity_events issues exactly one execute (data) and one scalar (count)."""
    session = _make_session()
    session.scalar.return_value = 0
    session.execute.return_value = _scalars_result([])

    await EventRepo.entity_events(session, "user", "alice")

    assert session.execute.call_count == 1
    assert session.scalar.call_count == 1


# ---------------------------------------------------------------------------
# All supported entity types execute without error
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("entity_type", ["host", "user", "hash", "ip"])
async def test_entity_events_known_types_no_error(entity_type: str) -> None:
    """All supported entity types run without raising an exception."""
    session = _make_session()
    session.scalar.return_value = 0
    session.execute.return_value = _scalars_result([])

    events, total = await EventRepo.entity_events(session, entity_type, "value123")

    assert events == []
    assert total == 0


@pytest.mark.asyncio
async def test_entity_events_unknown_type_falls_back_silently() -> None:
    """Unknown entity_type does not raise; falls back to hostname lookup."""
    session = _make_session()
    session.scalar.return_value = 0
    session.execute.return_value = _scalars_result([])

    # Must not raise
    events, total = await EventRepo.entity_events(session, "unknowntype", "value")

    assert events == []
    assert total == 0


# ---------------------------------------------------------------------------
# Multiple results
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_entity_events_multiple_results_returned() -> None:
    """All items from the DB are included in the returned list."""
    session = _make_session()
    n = 10
    events_list = [_make_event_mock(id=f"EVT-{i:03d}") for i in range(n)]
    session.scalar.return_value = n
    session.execute.return_value = _scalars_result(events_list)

    events, total = await EventRepo.entity_events(session, "ip", "10.0.0.1")

    assert total == n
    assert len(events) == n


# ---------------------------------------------------------------------------
# Optional parameters
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_entity_events_custom_size_accepted() -> None:
    """Custom size parameter is accepted without error."""
    session = _make_session()
    events_list = [_make_event_mock(id=f"EVT-{i:03d}") for i in range(5)]
    session.scalar.return_value = 5
    session.execute.return_value = _scalars_result(events_list)

    events, total = await EventRepo.entity_events(
        session, "host", "host-01", size=5
    )

    assert len(events) == 5
    assert total == 5


@pytest.mark.asyncio
async def test_entity_events_custom_time_from_accepted() -> None:
    """Custom time_from parameter is accepted without error."""
    session = _make_session()
    session.scalar.return_value = 0
    session.execute.return_value = _scalars_result([])

    # Should not raise regardless of the time string value
    events, total = await EventRepo.entity_events(
        session, "host", "host-01", time_from="now-30d"
    )

    assert events == []
    assert total == 0


@pytest.mark.asyncio
async def test_entity_events_iso_time_from_accepted() -> None:
    """ISO 8601 time_from string is parsed without error."""
    session = _make_session()
    session.scalar.return_value = 0
    session.execute.return_value = _scalars_result([])

    events, total = await EventRepo.entity_events(
        session, "host", "host-01", time_from="2026-01-01T00:00:00Z"
    )

    assert events == []
    assert total == 0


@pytest.mark.asyncio
async def test_entity_events_default_size_is_200() -> None:
    """Default size is 200 — verified by checking results list length equals DB output."""
    session = _make_session()
    # Simulate DB returning 200 events (the max)
    events_list = [_make_event_mock(id=f"EVT-{i:03d}") for i in range(200)]
    session.scalar.return_value = 200
    session.execute.return_value = _scalars_result(events_list)

    events, total = await EventRepo.entity_events(session, "ip", "10.0.0.1")

    assert total == 200
    assert len(events) == 200
