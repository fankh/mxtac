"""
Tests for SuricataConnector.

Feature 20.1 — Pipeline runs without UI or user action:
  Suricata EVE JSON ingestion component.

Coverage:
  Initialization:
    - topic is mxtac.raw.suricata
    - topic literal string is "mxtac.raw.suricata"
    - file_position starts at 0
    - health status is INACTIVE on init

  _connect():
    - raises ConnectionError when eve file does not exist
    - sets file_position to file size on connect (tail-only new events)
    - sets file_position to 0 when file is empty

  _fetch_events():
    - yields nothing when eve file does not exist
    - yields parsed JSON events from file
    - skips blank lines
    - skips malformed JSON lines
    - advances file_position after each read
    - does not re-read already consumed lines
    - picks up newly appended lines on subsequent calls
    - yields multiple events from one file

  Poll loop integration:
    - publishes each event to mxtac.raw.suricata topic
    - health.events_total increments per published event
    - health.last_event_at updated after first publish
    - no publish when fetch yields nothing
    - fetch error caught without crash; health.errors_total increments
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from app.connectors.base import ConnectorConfig, ConnectorStatus
from app.connectors.suricata import SuricataConnector
from app.pipeline.queue import InMemoryQueue, Topic


# ── Helpers ────────────────────────────────────────────────────────────────────


def _make_config(eve_file: str = "/var/log/suricata/eve.json", **extra_overrides: Any) -> ConnectorConfig:
    return ConnectorConfig(
        name="suricata-test",
        connector_type="suricata",
        enabled=True,
        poll_interval_seconds=60,
        extra={
            "eve_file": eve_file,
            **extra_overrides,
        },
    )


async def _collect(conn: SuricataConnector) -> list[dict]:
    results = []
    async for event in conn._fetch_events():
        results.append(event)
    return results


# ── Initialization ─────────────────────────────────────────────────────────────


class TestSuricataConnectorInit:
    def test_topic_is_raw_suricata(self) -> None:
        conn = SuricataConnector(_make_config(), InMemoryQueue())
        assert conn.topic == Topic.RAW_SURICATA

    def test_topic_literal_string(self) -> None:
        conn = SuricataConnector(_make_config(), InMemoryQueue())
        assert conn.topic == "mxtac.raw.suricata"

    def test_file_position_starts_at_zero(self) -> None:
        conn = SuricataConnector(_make_config(), InMemoryQueue())
        assert conn._file_position == 0

    def test_health_status_inactive_on_init(self) -> None:
        conn = SuricataConnector(_make_config(), InMemoryQueue())
        assert conn.health.status == ConnectorStatus.INACTIVE


# ── _connect() ─────────────────────────────────────────────────────────────────


class TestSuricataConnect:
    async def test_connect_raises_when_eve_file_missing(self) -> None:
        conn = SuricataConnector(
            _make_config(eve_file="/nonexistent/path/eve.json"),
            InMemoryQueue(),
        )
        with pytest.raises(ConnectionError, match="eve.json"):
            await conn._connect()

    async def test_connect_sets_position_to_eof(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write('{"event_type":"alert"}\n{"event_type":"flow"}\n')
            eve_path = f.name
        try:
            expected_size = os.path.getsize(eve_path)
            conn = SuricataConnector(_make_config(eve_file=eve_path), InMemoryQueue())
            await conn._connect()
            assert conn._file_position == expected_size
        finally:
            os.unlink(eve_path)

    async def test_connect_empty_file_sets_position_to_zero(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            eve_path = f.name
        try:
            conn = SuricataConnector(_make_config(eve_file=eve_path), InMemoryQueue())
            await conn._connect()
            assert conn._file_position == 0
        finally:
            os.unlink(eve_path)


# ── _fetch_events() ────────────────────────────────────────────────────────────


class TestSuricataFetchEvents:
    async def test_yields_nothing_when_file_missing(self) -> None:
        conn = SuricataConnector(
            _make_config(eve_file="/nonexistent/eve.json"),
            InMemoryQueue(),
        )
        events = await _collect(conn)
        assert events == []

    async def test_yields_parsed_json_events(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write('{"event_type":"alert","src_ip":"10.0.0.1"}\n')
            f.write('{"event_type":"flow","dest_ip":"8.8.8.8"}\n')
            eve_path = f.name
        try:
            conn = SuricataConnector(_make_config(eve_file=eve_path), InMemoryQueue())
            conn._file_position = 0
            events = await _collect(conn)
            assert len(events) == 2
            assert events[0]["event_type"] == "alert"
            assert events[1]["event_type"] == "flow"
        finally:
            os.unlink(eve_path)

    async def test_skips_blank_lines(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write('{"event_type":"alert"}\n')
            f.write('\n')
            f.write('   \n')
            f.write('{"event_type":"dns"}\n')
            eve_path = f.name
        try:
            conn = SuricataConnector(_make_config(eve_file=eve_path), InMemoryQueue())
            conn._file_position = 0
            events = await _collect(conn)
            assert len(events) == 2
        finally:
            os.unlink(eve_path)

    async def test_skips_malformed_json_lines(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write('{"event_type":"alert"}\n')
            f.write('NOT_JSON_AT_ALL\n')
            f.write('{"event_type":"flow"}\n')
            eve_path = f.name
        try:
            conn = SuricataConnector(_make_config(eve_file=eve_path), InMemoryQueue())
            conn._file_position = 0
            events = await _collect(conn)
            assert len(events) == 2
            assert events[0]["event_type"] == "alert"
            assert events[1]["event_type"] == "flow"
        finally:
            os.unlink(eve_path)

    async def test_advances_file_position_after_read(self) -> None:
        content = '{"event_type":"alert"}\n'
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(content)
            eve_path = f.name
        try:
            conn = SuricataConnector(_make_config(eve_file=eve_path), InMemoryQueue())
            conn._file_position = 0
            before = conn._file_position
            await _collect(conn)
            assert conn._file_position > before
        finally:
            os.unlink(eve_path)

    async def test_does_not_reread_consumed_lines(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write('{"event_type":"alert"}\n')
            eve_path = f.name
        try:
            conn = SuricataConnector(_make_config(eve_file=eve_path), InMemoryQueue())
            conn._file_position = 0
            first = await _collect(conn)
            assert len(first) == 1
            # Second call: position is at EOF, nothing new
            second = await _collect(conn)
            assert second == []
        finally:
            os.unlink(eve_path)

    async def test_picks_up_newly_appended_lines(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write('{"event_type":"alert"}\n')
            eve_path = f.name
        try:
            conn = SuricataConnector(_make_config(eve_file=eve_path), InMemoryQueue())
            conn._file_position = 0
            await _collect(conn)  # consume first line
            # Append a new line
            with open(eve_path, "a") as fa:
                fa.write('{"event_type":"flow"}\n')
            second = await _collect(conn)
            assert len(second) == 1
            assert second[0]["event_type"] == "flow"
        finally:
            os.unlink(eve_path)

    async def test_yields_multiple_events_from_one_file(self) -> None:
        events_data = [{"event_type": f"type-{i}", "i": i} for i in range(5)]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            for ev in events_data:
                f.write(json.dumps(ev) + "\n")
            eve_path = f.name
        try:
            conn = SuricataConnector(_make_config(eve_file=eve_path), InMemoryQueue())
            conn._file_position = 0
            events = await _collect(conn)
            assert len(events) == 5
        finally:
            os.unlink(eve_path)


# ── Poll loop integration ──────────────────────────────────────────────────────


class TestSuricataPollLoop:
    async def test_publishes_events_to_raw_suricata_topic(self) -> None:
        """_poll_loop() publishes each fetched event to mxtac.raw.suricata."""
        queue = InMemoryQueue()
        await queue.start()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write('{"event_type":"alert","src_ip":"1.2.3.4"}\n')
            eve_path = f.name
        try:
            conn = SuricataConnector(_make_config(eve_file=eve_path), queue)
            conn._file_position = 0

            received: list[tuple[str, dict]] = []

            async def capture(topic: str, msg: dict) -> None:
                received.append((topic, msg))

            original_fetch = conn._fetch_events

            async def _fetch_once():
                async for ev in original_fetch():
                    yield ev
                conn._stop_event.set()

            conn._fetch_events = _fetch_once

            with patch.object(queue, "publish", side_effect=capture):
                await conn._poll_loop()

            assert len(received) == 1
            assert received[0][0] == Topic.RAW_SURICATA
            assert received[0][1]["event_type"] == "alert"
        finally:
            os.unlink(eve_path)
            await queue.stop()

    async def test_events_total_increments_per_published_event(self) -> None:
        queue = InMemoryQueue()
        await queue.start()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write('{"event_type":"alert"}\n{"event_type":"flow"}\n')
            eve_path = f.name
        try:
            conn = SuricataConnector(_make_config(eve_file=eve_path), queue)
            conn._file_position = 0

            original_fetch = conn._fetch_events

            async def _fetch_once():
                async for ev in original_fetch():
                    yield ev
                conn._stop_event.set()

            conn._fetch_events = _fetch_once

            with patch.object(queue, "publish", new=AsyncMock(return_value=None)):
                await conn._poll_loop()

            assert conn.health.events_total == 2
        finally:
            os.unlink(eve_path)
            await queue.stop()

    async def test_last_event_at_updated_after_publish(self) -> None:
        queue = InMemoryQueue()
        await queue.start()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write('{"event_type":"alert"}\n')
            eve_path = f.name
        try:
            conn = SuricataConnector(_make_config(eve_file=eve_path), queue)
            conn._file_position = 0
            assert conn.health.last_event_at is None

            original_fetch = conn._fetch_events

            async def _fetch_once():
                async for ev in original_fetch():
                    yield ev
                conn._stop_event.set()

            conn._fetch_events = _fetch_once

            with patch.object(queue, "publish", new=AsyncMock(return_value=None)):
                await conn._poll_loop()

            assert conn.health.last_event_at is not None
        finally:
            os.unlink(eve_path)
            await queue.stop()

    async def test_no_publish_when_fetch_yields_nothing(self) -> None:
        queue = InMemoryQueue()
        await queue.start()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            eve_path = f.name  # empty file
        try:
            conn = SuricataConnector(_make_config(eve_file=eve_path), queue)
            # Position at EOF so nothing to read
            conn._file_position = os.path.getsize(eve_path)

            async def _fetch_once():
                return
                yield  # make it an async generator

            conn._fetch_events = _fetch_once
            conn._stop_event.set()  # stop after one iteration

            publish_mock = AsyncMock()
            with patch.object(queue, "publish", publish_mock):
                await conn._poll_loop()

            publish_mock.assert_not_called()
            assert conn.health.events_total == 0
        finally:
            os.unlink(eve_path)
            await queue.stop()

    async def test_fetch_error_increments_errors_total(self) -> None:
        queue = InMemoryQueue()
        await queue.start()

        conn = SuricataConnector(_make_config(), queue)

        async def _bad_fetch():
            # Signal stop so the loop exits after handling this error
            conn._stop_event.set()
            raise RuntimeError("disk read error")
            yield  # make it an async generator

        conn._fetch_events = _bad_fetch

        await conn._poll_loop()

        assert conn.health.errors_total == 1
        assert "disk read error" in conn.health.error_message

        await queue.stop()
