"""Unit tests for the event_persister service.

Covers the helper that extracts flat Event fields from an OCSF dict, plus
the dual-write behaviour (PostgreSQL + OpenSearch) using mocked dependencies.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.event_persister import _extract_event_fields


# ---------------------------------------------------------------------------
# _extract_event_fields — field extraction helper
# ---------------------------------------------------------------------------

_SAMPLE_OCSF = {
    "class_uid":        4001,
    "class_name":       "Network Activity",
    "category_uid":     4,
    "time":             "2026-02-20T12:00:00+00:00",
    "severity_id":      3,
    "metadata_product": "Wazuh",
    "metadata_version": "1.1.0",
    "metadata_uid":     "evt-abc-123",
    "src_endpoint": {
        "ip":       "192.168.1.10",
        "hostname": "WIN-DC01",
    },
    "dst_endpoint": {
        "ip":       "10.0.0.1",
        "hostname": None,
    },
    "actor_user": {
        "name": "CORP\\admin",
    },
    "process": {
        "hash_sha256": "deadbeef1234",
    },
    "unmapped": {
        "summary": "Suspicious outbound connection",
    },
    "raw": {},
}


def test_extract_basic_fields() -> None:
    fields = _extract_event_fields(_SAMPLE_OCSF)

    assert fields["class_uid"] == 4001
    assert fields["class_name"] == "Network Activity"
    assert fields["severity_id"] == 3
    assert fields["source"] == "Wazuh"
    assert fields["event_uid"] == "evt-abc-123"


def test_extract_time_parsed_to_datetime() -> None:
    fields = _extract_event_fields(_SAMPLE_OCSF)
    assert isinstance(fields["time"], datetime)
    assert fields["time"].tzinfo is not None


def test_extract_nested_endpoint_fields() -> None:
    fields = _extract_event_fields(_SAMPLE_OCSF)
    assert fields["src_ip"] == "192.168.1.10"
    assert fields["dst_ip"] == "10.0.0.1"
    assert fields["hostname"] == "WIN-DC01"


def test_extract_actor_user() -> None:
    fields = _extract_event_fields(_SAMPLE_OCSF)
    assert fields["username"] == "CORP\\admin"


def test_extract_process_hash() -> None:
    fields = _extract_event_fields(_SAMPLE_OCSF)
    assert fields["process_hash"] == "deadbeef1234"


def test_extract_summary_from_unmapped() -> None:
    fields = _extract_event_fields(_SAMPLE_OCSF)
    assert fields["summary"] == "Suspicious outbound connection"


def test_extract_summary_falls_back_to_finding_info() -> None:
    ocsf = {
        **_SAMPLE_OCSF,
        "unmapped": {},
        "finding_info": {"title": "Mimikatz detected", "severity_id": 5},
    }
    fields = _extract_event_fields(ocsf)
    assert fields["summary"] == "Mimikatz detected"


def test_extract_hostname_falls_back_to_dst_endpoint() -> None:
    """When src_endpoint.hostname is None, fall back to dst_endpoint.hostname."""
    ocsf = {
        **_SAMPLE_OCSF,
        "src_endpoint": {"ip": "10.0.0.1", "hostname": None},
        "dst_endpoint": {"ip": "10.0.0.2", "hostname": "REMOTE-HOST"},
    }
    fields = _extract_event_fields(ocsf)
    assert fields["hostname"] == "REMOTE-HOST"


def test_extract_missing_nested_dicts_safe() -> None:
    """Missing optional OCSF sub-dicts don't crash the extractor."""
    minimal = {
        "class_uid":        1007,
        "class_name":       "Process Activity",
        "category_uid":     1,
        "time":             "2026-02-20T08:00:00+00:00",
        "severity_id":      2,
        "metadata_product": "Zeek",
    }
    fields = _extract_event_fields(minimal)
    assert fields["src_ip"] is None
    assert fields["dst_ip"] is None
    assert fields["hostname"] is None
    assert fields["username"] is None
    assert fields["process_hash"] is None
    assert fields["summary"] is None


def test_extract_time_already_datetime() -> None:
    """If 'time' is already a datetime object it passes through unchanged."""
    dt = datetime(2026, 2, 20, 12, 0, 0, tzinfo=timezone.utc)
    ocsf = {**_SAMPLE_OCSF, "time": dt}
    fields = _extract_event_fields(ocsf)
    assert fields["time"] == dt


def test_extract_raw_set_to_full_dict() -> None:
    fields = _extract_event_fields(_SAMPLE_OCSF)
    assert fields["raw"] is _SAMPLE_OCSF


def test_extract_time_fallback_to_utcnow_when_missing() -> None:
    """When 'time' key is absent (not str or datetime), datetime.utcnow() is used."""
    ocsf = {
        "class_uid": 4001,
        "class_name": "Network Activity",
        "category_uid": 4,
        "severity_id": 2,
        # 'time' key is missing entirely — exercises the else branch
    }
    fields = _extract_event_fields(ocsf)
    assert isinstance(fields["time"], datetime)


# ---------------------------------------------------------------------------
# event_persister() function — dual-write behaviour
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_event_persister_subscribes_to_normalized_topic() -> None:
    """event_persister() registers a consumer on the mxtac.normalized topic."""
    from app.pipeline.queue import InMemoryQueue, Topic
    from app.services.event_persister import event_persister

    queue = InMemoryQueue()
    await queue.start()

    mock_os = MagicMock()
    mock_os.is_available = False

    await event_persister(queue, mock_os)

    task_names = {t.get_name() for t in queue._tasks}
    assert any("event-persister" in name for name in task_names)

    await queue.stop()


@pytest.mark.asyncio
async def test_event_persister_writes_to_postgresql() -> None:
    """_handle() persists the normalized event to PostgreSQL via EventRepo.create."""
    import asyncio

    from app.pipeline.queue import InMemoryQueue, Topic
    from app.services.event_persister import event_persister

    queue = InMemoryQueue()
    await queue.start()

    mock_os = MagicMock()
    mock_os.is_available = False

    mock_event = MagicMock()
    mock_event.id = "pg-uuid-001"

    mock_session = AsyncMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    with (
        patch("app.core.database.AsyncSessionLocal", return_value=mock_session),
        patch("app.repositories.event_repo.EventRepo") as mock_repo,
    ):
        mock_repo.create = AsyncMock(return_value=mock_event)

        await event_persister(queue, mock_os)
        await queue.publish(Topic.NORMALIZED, _SAMPLE_OCSF)
        await asyncio.sleep(0.1)

        mock_repo.create.assert_called_once()

    await queue.stop()


@pytest.mark.asyncio
async def test_event_persister_indexes_to_opensearch_when_available() -> None:
    """When os_client.is_available is True, _handle() calls os_client.index_event."""
    import asyncio

    from app.pipeline.queue import InMemoryQueue, Topic
    from app.services.event_persister import event_persister

    queue = InMemoryQueue()
    await queue.start()

    mock_event = MagicMock()
    mock_event.id = "pg-uuid-002"

    mock_os = AsyncMock()
    mock_os.is_available = True

    mock_session = AsyncMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    with (
        patch("app.core.database.AsyncSessionLocal", return_value=mock_session),
        patch("app.repositories.event_repo.EventRepo") as mock_repo,
    ):
        mock_repo.create = AsyncMock(return_value=mock_event)

        await event_persister(queue, mock_os)
        await queue.publish(Topic.NORMALIZED, _SAMPLE_OCSF)
        await asyncio.sleep(0.1)

        mock_os.index_event.assert_called_once()

    await queue.stop()


@pytest.mark.asyncio
async def test_event_persister_skips_opensearch_when_unavailable() -> None:
    """When os_client.is_available is False, index_event is never called."""
    import asyncio

    from app.pipeline.queue import InMemoryQueue, Topic
    from app.services.event_persister import event_persister

    queue = InMemoryQueue()
    await queue.start()

    mock_event = MagicMock()
    mock_event.id = "pg-uuid-003"

    mock_os = MagicMock()
    mock_os.is_available = False

    mock_session = AsyncMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    with (
        patch("app.core.database.AsyncSessionLocal", return_value=mock_session),
        patch("app.repositories.event_repo.EventRepo") as mock_repo,
    ):
        mock_repo.create = AsyncMock(return_value=mock_event)

        await event_persister(queue, mock_os)
        await queue.publish(Topic.NORMALIZED, _SAMPLE_OCSF)
        await asyncio.sleep(0.1)

        mock_os.index_event.assert_not_called()

    await queue.stop()


@pytest.mark.asyncio
async def test_event_persister_continues_on_postgresql_error() -> None:
    """A DB write failure is non-fatal — the pipeline does not crash."""
    import asyncio

    from app.pipeline.queue import InMemoryQueue, Topic
    from app.services.event_persister import event_persister

    queue = InMemoryQueue()
    await queue.start()

    mock_os = MagicMock()
    mock_os.is_available = False

    mock_session = AsyncMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    with (
        patch("app.core.database.AsyncSessionLocal", return_value=mock_session),
        patch("app.repositories.event_repo.EventRepo") as mock_repo,
    ):
        mock_repo.create = AsyncMock(side_effect=RuntimeError("DB connection lost"))

        await event_persister(queue, mock_os)

        # Should not raise even when DB fails
        await queue.publish(Topic.NORMALIZED, _SAMPLE_OCSF)
        await asyncio.sleep(0.1)

    await queue.stop()
