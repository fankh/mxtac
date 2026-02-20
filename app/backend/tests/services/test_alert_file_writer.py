"""Tests for AlertFileWriter — feature 20.4: alert output to file (JSON per line).

Coverage:
  - write(): appends a JSON line for each alert
  - write(): multiple alerts produce separate JSON lines
  - write(): each line is valid JSON that round-trips cleanly
  - write(): non-serialisable values are coerced via default=str
  - write(): creates parent directory if it does not exist
  - write(): non-fatal — swallows exceptions and logs them
  - write(): file handle is re-opened after doRollover (rotation correctness)
  - rotation: file rotates when max_bytes is exceeded
  - rotation: backup files are named <path>.1, <path>.2, …
  - rotation: max_bytes=0 disables rotation
  - close(): flushes and closes the underlying file
  - alert_file_writer(): subscribes to mxtac.enriched topic
  - alert_file_writer(): callback writes alert to file when message received
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from app.pipeline.queue import InMemoryQueue, Topic
from app.services.alert_file_writer import AlertFileWriter, alert_file_writer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_alert(
    *,
    rule_id: str = "sigma-T1059",
    host: str = "srv-01",
    score: float = 7.2,
) -> dict:
    return {
        "id": "test-uuid-001",
        "rule_id": rule_id,
        "rule_title": "Command Shell Execution",
        "level": "high",
        "severity_id": 4,
        "technique_ids": ["T1059"],
        "tactic_ids": ["execution"],
        "host": host,
        "time": datetime.now(timezone.utc).isoformat(),
        "score": score,
        "event_snapshot": {"pid": 1234},
    }


def _read_lines(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


# ---------------------------------------------------------------------------
# Section 1 — write() basic behaviour
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_write_creates_jsonl_file(tmp_path):
    """write() must append a valid JSON line to the output file."""
    out = tmp_path / "alerts.jsonl"
    writer = AlertFileWriter(out, max_bytes=0, backup_count=0)

    alert = _make_alert()
    await writer.write(alert)
    await writer.close()

    lines = _read_lines(out)
    assert len(lines) == 1
    assert lines[0]["id"] == "test-uuid-001"
    assert lines[0]["score"] == 7.2


@pytest.mark.asyncio
async def test_write_appends_multiple_alerts(tmp_path):
    """write() must produce one JSON line per alert, each on its own line."""
    out = tmp_path / "alerts.jsonl"
    writer = AlertFileWriter(out, max_bytes=0, backup_count=0)

    alerts = [_make_alert(rule_id=f"sigma-T{i}", host=f"host-{i}") for i in range(5)]
    for a in alerts:
        await writer.write(a)
    await writer.close()

    lines = _read_lines(out)
    assert len(lines) == 5
    for i, line in enumerate(lines):
        assert line["rule_id"] == f"sigma-T{i}"
        assert line["host"] == f"host-{i}"


@pytest.mark.asyncio
async def test_write_produces_valid_json_round_trip(tmp_path):
    """Each line written by write() must be valid JSON that round-trips cleanly."""
    out = tmp_path / "alerts.jsonl"
    writer = AlertFileWriter(out, max_bytes=0, backup_count=0)

    alert = _make_alert(score=3.14)
    await writer.write(alert)
    await writer.close()

    raw_line = out.read_text().strip()
    parsed = json.loads(raw_line)
    assert parsed["score"] == 3.14
    assert parsed["technique_ids"] == ["T1059"]


@pytest.mark.asyncio
async def test_write_coerces_non_serialisable_values(tmp_path):
    """Non-JSON-serialisable values (e.g. datetime) must be coerced via str()."""
    out = tmp_path / "alerts.jsonl"
    writer = AlertFileWriter(out, max_bytes=0, backup_count=0)

    alert = _make_alert()
    alert["extra"] = datetime(2026, 2, 21, 12, 0, 0)  # not JSON-serialisable by default

    await writer.write(alert)
    await writer.close()

    lines = _read_lines(out)
    assert "extra" in lines[0]
    assert isinstance(lines[0]["extra"], str)


@pytest.mark.asyncio
async def test_write_creates_parent_directory(tmp_path):
    """write() must create missing parent directories automatically."""
    out = tmp_path / "nested" / "deep" / "alerts.jsonl"
    writer = AlertFileWriter(out, max_bytes=0, backup_count=0)

    await writer.write(_make_alert())
    await writer.close()

    assert out.exists()
    lines = _read_lines(out)
    assert len(lines) == 1


@pytest.mark.asyncio
async def test_write_is_non_fatal_on_error(tmp_path):
    """write() must swallow exceptions so the pipeline is never interrupted."""
    out = tmp_path / "alerts.jsonl"
    writer = AlertFileWriter(out, max_bytes=0, backup_count=0)

    with patch.object(writer, "_write_sync", side_effect=OSError("disk full")):
        # Must not raise
        await writer.write(_make_alert())

    await writer.close()


# ---------------------------------------------------------------------------
# Section 2 — file rotation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rotation_creates_backup_file(tmp_path):
    """When max_bytes is exceeded the active file is rotated to <path>.1."""
    out = tmp_path / "alerts.jsonl"
    # Use a very small limit so the first alert triggers rotation.
    writer = AlertFileWriter(out, max_bytes=10, backup_count=3)

    await writer.write(_make_alert())  # exceeds 10 bytes → rotation
    await writer.write(_make_alert())  # lands in fresh file
    await writer.close()

    assert (tmp_path / "alerts.jsonl.1").exists(), "backup file .1 must be created"


@pytest.mark.asyncio
async def test_rotation_disabled_when_max_bytes_zero(tmp_path):
    """When max_bytes=0 no rotation files should be created regardless of size."""
    out = tmp_path / "alerts.jsonl"
    writer = AlertFileWriter(out, max_bytes=0, backup_count=5)

    for _ in range(20):
        await writer.write(_make_alert())
    await writer.close()

    # No rotated backup files
    backups = list(tmp_path.glob("alerts.jsonl.*"))
    assert backups == [], f"unexpected backup files: {backups}"


@pytest.mark.asyncio
async def test_rotation_honours_backup_count(tmp_path):
    """At most backup_count rotated files should exist after many writes."""
    out = tmp_path / "alerts.jsonl"
    backup_count = 2
    writer = AlertFileWriter(out, max_bytes=10, backup_count=backup_count)

    for _ in range(20):
        await writer.write(_make_alert())
    await writer.close()

    backups = sorted(tmp_path.glob("alerts.jsonl.*"))
    assert len(backups) <= backup_count


# ---------------------------------------------------------------------------
# Section 3 — close()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_close_closes_file_handle(tmp_path):
    """close() must close the underlying RotatingFileHandler stream."""
    out = tmp_path / "alerts.jsonl"
    writer = AlertFileWriter(out, max_bytes=0, backup_count=0)

    await writer.write(_make_alert())
    await writer.close()

    assert writer._handler.stream is None or writer._handler.stream.closed


# ---------------------------------------------------------------------------
# Section 4 — alert_file_writer() factory / queue integration
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_alert_file_writer_subscribes_to_enriched_topic(tmp_path):
    """alert_file_writer() must subscribe to Topic.ENRICHED."""
    queue = InMemoryQueue()
    await queue.start()

    subscribed_topics: list[str] = []
    original_subscribe = queue.subscribe

    async def capture_subscribe(topic, group, handler):
        subscribed_topics.append(topic)
        return await original_subscribe(topic, group, handler)

    with patch.object(queue, "subscribe", side_effect=capture_subscribe):
        writer = await alert_file_writer(
            queue,
            path=str(tmp_path / "alerts.jsonl"),
            max_bytes=0,
            backup_count=0,
        )

    assert Topic.ENRICHED in subscribed_topics

    await writer.close()
    await queue.stop()


@pytest.mark.asyncio
async def test_alert_file_writer_writes_on_publish(tmp_path):
    """Publishing to mxtac.enriched must trigger a file write."""
    out = tmp_path / "alerts.jsonl"
    queue = InMemoryQueue()
    await queue.start()

    writer = await alert_file_writer(
        queue,
        path=str(out),
        max_bytes=0,
        backup_count=0,
    )

    alert = _make_alert()
    await queue.publish(Topic.ENRICHED, alert)

    # Give the consumer task a moment to process
    import asyncio
    await asyncio.sleep(0.05)

    await writer.close()
    await queue.stop()

    lines = _read_lines(out)
    assert len(lines) == 1
    assert lines[0]["id"] == alert["id"]


@pytest.mark.asyncio
async def test_alert_file_writer_returns_writer_instance(tmp_path):
    """alert_file_writer() must return the AlertFileWriter for shutdown cleanup."""
    queue = InMemoryQueue()
    await queue.start()

    writer = await alert_file_writer(
        queue,
        path=str(tmp_path / "alerts.jsonl"),
        max_bytes=0,
        backup_count=0,
    )

    assert isinstance(writer, AlertFileWriter)

    await writer.close()
    await queue.stop()
