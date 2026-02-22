"""
Tests for connector registry.

Feature 14.8 — DB persistence — connectors from DB on startup.

Coverage:
  build_connector():
    - returns None for unknown connector type
    - creates WazuhConnector from DB row
    - creates ZeekConnector from DB row
    - creates SuricataConnector from DB row
    - passes poll_interval_seconds from config_json
    - connector name matches DB row name
    - handles None config_json (empty extra dict)
    - Wazuh: sets initial_last_fetched_at from db_conn.last_seen_at
    - Wazuh: last_fetched_at has a default (~5 min ago) when last_seen_at is None
    - Wazuh: invalid last_seen_at is ignored gracefully (connector still created)
    - Zeek: loads initial positions from state file via _load_zeek_positions
    - Zeek: _file_positions empty dict when state file missing (initial_positions=None)
    - Suricata: loads initial position from state file via _load_suricata_position
    - Suricata: _file_position is 0 when state file missing (initial_position=None)

  start_connectors_from_db() — mock-based:
    - returns empty list when no enabled connectors
    - returns one connector per DB row with a valid type
    - skips rows when build_connector returns None (unknown type)
    - DB query filters by enabled=True

  start_connectors_from_db() — DB integration (real SQLite session):
    - only enabled connectors are loaded; disabled ones are excluded
    - returns empty list when only disabled connectors exist in DB
    - all enabled connectors across types are returned

  Zeek state file helpers:
    - _zeek_state_file returns path named zeek_offsets_{name}.json
    - _load_zeek_positions returns None for missing file
    - _load_zeek_positions returns dict with int values
    - _load_zeek_positions converts string values to int
    - _load_zeek_positions returns None for malformed JSON
    - _load_zeek_positions returns None when JSON root is not a dict
    - _save_zeek_positions writes valid JSON to the file
    - _save_zeek_positions creates missing parent directories

  Suricata state file helpers (Feature 6.17):
    - _suricata_state_file returns path named suricata_offset_{name}.json
    - _load_suricata_position returns None for missing file
    - _load_suricata_position returns int for valid file
    - _load_suricata_position returns None for malformed JSON
    - _load_suricata_position returns None when JSON root is not an int
    - _save_suricata_position writes valid JSON to the file
    - _save_suricata_position creates missing parent directories
    - save then load roundtrip preserves offset value
"""

from __future__ import annotations

import json
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.connectors.registry import (
    _load_suricata_position,
    _load_zeek_positions,
    _save_suricata_position,
    _save_zeek_positions,
    _suricata_state_file,
    _zeek_state_file,
    build_connector,
    start_connectors_from_db,
)
from app.connectors.suricata import SuricataConnector
from app.connectors.wazuh import WazuhConnector
from app.connectors.zeek import ZeekConnector
from app.pipeline.queue import InMemoryQueue


# ── Helpers ────────────────────────────────────────────────────────────────────


def _make_db_connector(
    *,
    name: str = "test-conn",
    connector_type: str = "wazuh",
    enabled: bool = True,
    config_json: str | None = None,
    last_seen_at: str | None = None,
    id: str = "conn-uuid-001",
) -> MagicMock:
    """Return a MagicMock simulating a Connector ORM row."""
    m = MagicMock()
    m.id = id
    m.name = name
    m.connector_type = connector_type
    m.enabled = enabled
    m.config_json = config_json
    m.last_seen_at = last_seen_at
    return m


def _wazuh_config_json(**extra) -> str:
    base = {"url": "https://wazuh.test:55000", "username": "wazuh-wui", "password": "secret"}
    base.update(extra)
    return json.dumps(base)


# ── build_connector() ──────────────────────────────────────────────────────────


class TestBuildConnector:
    def test_returns_none_for_unknown_type(self) -> None:
        db_conn = _make_db_connector(connector_type="unknown-source")
        result = build_connector(db_conn, InMemoryQueue())
        assert result is None

    def test_creates_wazuh_connector(self) -> None:
        db_conn = _make_db_connector(connector_type="wazuh", config_json=_wazuh_config_json())
        conn = build_connector(db_conn, InMemoryQueue())
        assert isinstance(conn, WazuhConnector)

    def test_creates_suricata_connector(self) -> None:
        config_json = json.dumps({"eve_file": "/var/log/suricata/eve.json"})
        db_conn = _make_db_connector(connector_type="suricata", config_json=config_json)
        conn = build_connector(db_conn, InMemoryQueue())
        assert isinstance(conn, SuricataConnector)

    def test_creates_zeek_connector(self) -> None:
        config_json = json.dumps({"log_dir": "/opt/zeek/logs/current"})
        db_conn = _make_db_connector(connector_type="zeek", config_json=config_json)
        with patch("app.connectors.registry._load_zeek_positions", return_value=None):
            conn = build_connector(db_conn, InMemoryQueue())
        assert isinstance(conn, ZeekConnector)

    def test_passes_poll_interval_from_config_json(self) -> None:
        config_json = _wazuh_config_json(poll_interval_seconds=120)
        db_conn = _make_db_connector(connector_type="wazuh", config_json=config_json)
        conn = build_connector(db_conn, InMemoryQueue())
        assert conn.config.poll_interval_seconds == 120

    def test_connector_name_matches_db_row(self) -> None:
        db_conn = _make_db_connector(
            name="wazuh-prod",
            connector_type="wazuh",
            config_json=_wazuh_config_json(),
        )
        conn = build_connector(db_conn, InMemoryQueue())
        assert conn.config.name == "wazuh-prod"

    def test_handles_none_config_json(self) -> None:
        """None config_json should not raise; extra defaults to empty dict."""
        db_conn = _make_db_connector(connector_type="suricata", config_json=None)
        conn = build_connector(db_conn, InMemoryQueue())
        assert isinstance(conn, SuricataConnector)

    # -- Wazuh: last_seen_at handling ------------------------------------------

    def test_wazuh_sets_initial_last_fetched_at_from_db(self) -> None:
        ts = "2026-02-20T10:00:00+00:00"
        db_conn = _make_db_connector(
            connector_type="wazuh",
            config_json=_wazuh_config_json(),
            last_seen_at=ts,
        )
        conn = build_connector(db_conn, InMemoryQueue())
        assert isinstance(conn, WazuhConnector)
        assert conn._last_fetched_at is not None
        assert conn._last_fetched_at.year == 2026
        assert conn._last_fetched_at.month == 2
        assert conn._last_fetched_at.day == 20

    def test_wazuh_last_fetched_at_default_when_db_none(self) -> None:
        """When last_seen_at is None, connector falls back to ~5 minutes ago."""
        db_conn = _make_db_connector(
            connector_type="wazuh",
            config_json=_wazuh_config_json(),
            last_seen_at=None,
        )
        conn = build_connector(db_conn, InMemoryQueue())
        assert isinstance(conn, WazuhConnector)
        # Default is set by WazuhConnector itself; must not be None
        assert conn._last_fetched_at is not None

    def test_wazuh_invalid_last_seen_at_is_ignored(self) -> None:
        """Invalid timestamp string is ignored gracefully; connector is still created."""
        db_conn = _make_db_connector(
            connector_type="wazuh",
            config_json=_wazuh_config_json(),
            last_seen_at="NOT-A-DATE",
        )
        conn = build_connector(db_conn, InMemoryQueue())
        assert isinstance(conn, WazuhConnector)

    # -- Zeek: initial_positions handling ----------------------------------------

    def test_zeek_loads_initial_positions_from_state_file(self) -> None:
        positions = {"conn.log": 1024, "dns.log": 512}
        config_json = json.dumps({"log_dir": "/opt/zeek/logs/current"})
        db_conn = _make_db_connector(name="zeek-main", connector_type="zeek", config_json=config_json)
        with patch("app.connectors.registry._load_zeek_positions", return_value=positions):
            conn = build_connector(db_conn, InMemoryQueue())
        assert isinstance(conn, ZeekConnector)
        assert conn._file_positions == positions

    def test_zeek_file_positions_empty_when_state_file_missing(self) -> None:
        config_json = json.dumps({"log_dir": "/opt/zeek/logs/current"})
        db_conn = _make_db_connector(name="zeek-main", connector_type="zeek", config_json=config_json)
        with patch("app.connectors.registry._load_zeek_positions", return_value=None):
            conn = build_connector(db_conn, InMemoryQueue())
        assert isinstance(conn, ZeekConnector)
        # initial_positions=None means _file_positions starts as empty dict
        assert conn._file_positions == {}

    # -- Suricata: initial_position handling (Feature 6.17) --------------------

    def test_suricata_loads_initial_position_from_state_file(self) -> None:
        saved_offset = 4096
        config_json = json.dumps({"eve_file": "/var/log/suricata/eve.json"})
        db_conn = _make_db_connector(name="suricata-main", connector_type="suricata", config_json=config_json)
        with patch("app.connectors.registry._load_suricata_position", return_value=saved_offset):
            conn = build_connector(db_conn, InMemoryQueue())
        assert isinstance(conn, SuricataConnector)
        assert conn._file_position == saved_offset

    def test_suricata_file_position_zero_when_state_file_missing(self) -> None:
        config_json = json.dumps({"eve_file": "/var/log/suricata/eve.json"})
        db_conn = _make_db_connector(name="suricata-main", connector_type="suricata", config_json=config_json)
        with patch("app.connectors.registry._load_suricata_position", return_value=None):
            conn = build_connector(db_conn, InMemoryQueue())
        assert isinstance(conn, SuricataConnector)
        # initial_position=None means _file_position starts at 0
        assert conn._file_position == 0

    def test_suricata_checkpoint_callback_is_set(self) -> None:
        """build_connector sets a checkpoint_callback on the SuricataConnector."""
        config_json = json.dumps({"eve_file": "/var/log/suricata/eve.json"})
        db_conn = _make_db_connector(name="suricata-cb", connector_type="suricata", config_json=config_json)
        with patch("app.connectors.registry._load_suricata_position", return_value=None):
            conn = build_connector(db_conn, InMemoryQueue())
        assert isinstance(conn, SuricataConnector)
        assert conn._checkpoint_callback is not None


# ── start_connectors_from_db() ─────────────────────────────────────────────────


class TestStartConnectorsFromDb:
    async def _run_with_rows(self, db_rows: list) -> dict:
        """Helper: run start_connectors_from_db with given mock DB rows."""
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = db_rows
        mock_session.execute = AsyncMock(return_value=mock_result)
        return await start_connectors_from_db(mock_session, InMemoryQueue())

    async def test_returns_empty_list_when_no_connectors(self) -> None:
        connectors = await self._run_with_rows([])
        assert connectors == {}

    async def test_returns_one_connector_per_valid_row(self) -> None:
        rows = [
            _make_db_connector(
                name="wazuh-01",
                connector_type="wazuh",
                config_json=_wazuh_config_json(),
                id="id-1",
            ),
            _make_db_connector(
                name="suricata-01",
                connector_type="suricata",
                config_json=json.dumps({"eve_file": "/var/log/suricata/eve.json"}),
                id="id-2",
            ),
        ]
        connectors = await self._run_with_rows(rows)
        assert len(connectors) == 2

    async def test_skips_row_when_build_connector_returns_none(self) -> None:
        """Rows with unknown types (build_connector returns None) are skipped."""
        rows = [_make_db_connector(name="unknown-01", connector_type="unknown-source")]
        connectors = await self._run_with_rows(rows)
        assert connectors == {}

    async def test_returns_wazuh_connector_instances(self) -> None:
        wazuh_row = _make_db_connector(
            name="wazuh-prod",
            connector_type="wazuh",
            config_json=_wazuh_config_json(),
        )
        connectors = await self._run_with_rows([wazuh_row])
        assert len(connectors) == 1
        assert isinstance(next(iter(connectors.values())), WazuhConnector)

    async def test_mixed_valid_and_invalid_types(self) -> None:
        """Only valid-type rows result in connectors; unknown types are skipped."""
        rows = [
            _make_db_connector(
                name="wazuh-prod",
                connector_type="wazuh",
                config_json=_wazuh_config_json(),
                id="id-1",
            ),
            _make_db_connector(
                name="bad-type",
                connector_type="splunk",  # unknown
                id="id-2",
            ),
        ]
        connectors = await self._run_with_rows(rows)
        assert len(connectors) == 1
        assert isinstance(next(iter(connectors.values())), WazuhConnector)


# ── Zeek state file helpers ────────────────────────────────────────────────────


class TestZeekStateFileHelpers:
    def test_zeek_state_file_returns_correct_filename(self) -> None:
        result = _zeek_state_file("my-zeek")
        assert result.name == "zeek_offsets_my-zeek.json"

    def test_zeek_state_file_is_path_object(self) -> None:
        result = _zeek_state_file("zeek-prod")
        assert isinstance(result, Path)

    # -- _load_zeek_positions --------------------------------------------------

    def test_load_returns_none_for_missing_file(self) -> None:
        missing = Path("/tmp/does_not_exist_mxtac_test_abc123.json")
        result = _load_zeek_positions(missing)
        assert result is None

    def test_load_returns_dict_with_int_values(self) -> None:
        data = {"conn.log": 1024, "dns.log": 512}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            tmp = Path(f.name)
        try:
            result = _load_zeek_positions(tmp)
            assert result == {"conn.log": 1024, "dns.log": 512}
        finally:
            tmp.unlink()

    def test_load_converts_string_values_to_int(self) -> None:
        data = {"conn.log": "2048"}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            tmp = Path(f.name)
        try:
            result = _load_zeek_positions(tmp)
            assert result == {"conn.log": 2048}
            assert isinstance(result["conn.log"], int)
        finally:
            tmp.unlink()

    def test_load_returns_none_for_malformed_json(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("NOT_VALID_JSON")
            tmp = Path(f.name)
        try:
            result = _load_zeek_positions(tmp)
            assert result is None
        finally:
            tmp.unlink()

    def test_load_returns_none_when_json_root_is_not_dict(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump([1, 2, 3], f)  # list, not dict
            tmp = Path(f.name)
        try:
            result = _load_zeek_positions(tmp)
            assert result is None
        finally:
            tmp.unlink()

    # -- _save_zeek_positions --------------------------------------------------

    def test_save_writes_valid_json(self) -> None:
        positions = {"conn.log": 1024, "dns.log": 256}
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = Path(tmpdir) / "zeek_offsets_test.json"
            _save_zeek_positions(state_file, positions)
            assert state_file.exists()
            loaded = json.loads(state_file.read_text())
            assert loaded == positions

    def test_save_creates_missing_parent_directories(self) -> None:
        positions = {"conn.log": 100}
        with tempfile.TemporaryDirectory() as tmpdir:
            nested = Path(tmpdir) / "sub" / "dir" / "zeek_offsets.json"
            _save_zeek_positions(nested, positions)
            assert nested.exists()

    def test_save_then_load_roundtrip(self) -> None:
        positions = {"conn.log": 4096, "http.log": 8192}
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = Path(tmpdir) / "zeek_offsets_roundtrip.json"
            _save_zeek_positions(state_file, positions)
            loaded = _load_zeek_positions(state_file)
            assert loaded == positions


# ── Suricata state file helpers (Feature 6.17) ────────────────────────────────


class TestSuricataStateFileHelpers:
    def test_suricata_state_file_returns_correct_filename(self) -> None:
        result = _suricata_state_file("my-suricata")
        assert result.name == "suricata_offset_my-suricata.json"

    def test_suricata_state_file_is_path_object(self) -> None:
        result = _suricata_state_file("suricata-prod")
        assert isinstance(result, Path)

    # -- _load_suricata_position -----------------------------------------------

    def test_load_returns_none_for_missing_file(self) -> None:
        missing = Path("/tmp/does_not_exist_mxtac_suricata_test_abc123.json")
        result = _load_suricata_position(missing)
        assert result is None

    def test_load_returns_int_for_valid_file(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(8192, f)
            tmp = Path(f.name)
        try:
            result = _load_suricata_position(tmp)
            assert result == 8192
            assert isinstance(result, int)
        finally:
            tmp.unlink()

    def test_load_returns_none_for_malformed_json(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("NOT_VALID_JSON")
            tmp = Path(f.name)
        try:
            result = _load_suricata_position(tmp)
            assert result is None
        finally:
            tmp.unlink()

    def test_load_returns_none_when_json_root_is_not_int(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"offset": 123}, f)  # dict, not int
            tmp = Path(f.name)
        try:
            result = _load_suricata_position(tmp)
            assert result is None
        finally:
            tmp.unlink()

    # -- _save_suricata_position -----------------------------------------------

    def test_save_writes_valid_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = Path(tmpdir) / "suricata_offset_test.json"
            _save_suricata_position(state_file, 4096)
            assert state_file.exists()
            loaded = json.loads(state_file.read_text())
            assert loaded == 4096

    def test_save_creates_missing_parent_directories(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            nested = Path(tmpdir) / "sub" / "dir" / "suricata_offset.json"
            _save_suricata_position(nested, 100)
            assert nested.exists()

    def test_save_then_load_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = Path(tmpdir) / "suricata_offset_roundtrip.json"
            _save_suricata_position(state_file, 12345)
            loaded = _load_suricata_position(state_file)
            assert loaded == 12345


# ── DB integration: start_connectors_from_db with real SQLite session ─────────


def _wazuh_config() -> str:
    return json.dumps({"url": "https://wazuh.test:55000", "username": "admin", "password": "secret"})


class TestStartConnectorsFromDbIntegration:
    """
    Feature 14.8 — DB persistence — connectors from DB on startup.

    These tests exercise start_connectors_from_db() against a real in-memory
    SQLite session so that the WHERE enabled=True filter in the SQL query is
    actually executed, not bypassed by mocks.
    """

    async def test_only_enabled_connectors_are_loaded(self, db_session: AsyncSession) -> None:
        """Disabled connectors must be excluded; the SQL WHERE enabled=True filter must work."""
        from app.models.connector import Connector

        enabled_row = Connector(
            id=str(uuid.uuid4()),
            name="wazuh-enabled",
            connector_type="wazuh",
            config_json=_wazuh_config(),
            enabled=True,
        )
        disabled_row = Connector(
            id=str(uuid.uuid4()),
            name="zeek-disabled",
            connector_type="zeek",
            config_json=json.dumps({"log_dir": "/opt/zeek/logs/current"}),
            enabled=False,
        )
        db_session.add_all([enabled_row, disabled_row])
        await db_session.flush()

        with patch("app.connectors.registry._load_zeek_positions", return_value=None):
            connectors = await start_connectors_from_db(db_session, InMemoryQueue())

        assert len(connectors) == 1
        assert next(iter(connectors.values())).config.name == "wazuh-enabled"

    async def test_returns_empty_when_only_disabled_connectors_in_db(
        self, db_session: AsyncSession
    ) -> None:
        """When all DB rows have enabled=False, no connectors are instantiated."""
        from app.models.connector import Connector

        disabled = Connector(
            id=str(uuid.uuid4()),
            name="suricata-off",
            connector_type="suricata",
            config_json=json.dumps({"eve_file": "/var/log/suricata/eve.json"}),
            enabled=False,
        )
        db_session.add(disabled)
        await db_session.flush()

        connectors = await start_connectors_from_db(db_session, InMemoryQueue())

        assert connectors == {}

    async def test_all_enabled_types_are_loaded(self, db_session: AsyncSession) -> None:
        """All enabled connectors across different types are returned."""
        from app.models.connector import Connector

        wazuh = Connector(
            id=str(uuid.uuid4()),
            name="wazuh-main",
            connector_type="wazuh",
            config_json=_wazuh_config(),
            enabled=True,
        )
        suricata = Connector(
            id=str(uuid.uuid4()),
            name="suricata-main",
            connector_type="suricata",
            config_json=json.dumps({"eve_file": "/var/log/suricata/eve.json"}),
            enabled=True,
        )
        disabled_extra = Connector(
            id=str(uuid.uuid4()),
            name="zeek-ignored",
            connector_type="zeek",
            config_json=json.dumps({"log_dir": "/opt/zeek/logs/current"}),
            enabled=False,
        )
        db_session.add_all([wazuh, suricata, disabled_extra])
        await db_session.flush()

        with patch("app.connectors.registry._load_zeek_positions", return_value=None), \
             patch("app.connectors.registry._load_suricata_position", return_value=None):
            connectors = await start_connectors_from_db(db_session, InMemoryQueue())

        assert len(connectors) == 2
        names = {c.config.name for c in connectors.values()}
        assert names == {"wazuh-main", "suricata-main"}
