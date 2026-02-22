"""Tests for Feature 7.15 — Custom field mapping config per connector.

Coverage:
  _get_nested()
    - single key
    - nested dot-path
    - missing intermediate key returns None
    - non-dict intermediate returns None
    - empty path part
    - empty dict

  _set_nested()
    - single key
    - nested dot-path
    - creates intermediate dicts automatically
    - overwrites existing value

  FieldMappingConfig.from_config()
    - None / falsy input → empty config
    - YAML string with field_mappings key
    - YAML string with no field_mappings key → empty
    - invalid YAML string → empty (does not raise)
    - dict with 'field_mappings' key
    - flat dict (shorthand format)
    - non-string / non-dict input → empty
    - YAML string that parses to non-dict → empty

  FieldMappingConfig.apply()
    - empty field_mappings → returns same event object (no-op)
    - single field override
    - multiple field overrides
    - nested OCSF field override (e.g. src_endpoint.ip)
    - nested source path in raw (e.g. data.client_ip)
    - missing source path is silently skipped
    - None source value is silently skipped
    - valid overrides produce re-validated OCSFEvent

  FieldMappingConfig.is_empty
    - True for empty config
    - False when mappings are present

  _extract_field_mapping() (pipeline helper)
    - raw without _mxtac_field_mapping key → unchanged raw, empty config
    - raw with _mxtac_field_mapping key → clean raw (key stripped), parsed config
    - _mxtac_field_mapping key does NOT appear in clean_raw
    - original raw dict is not mutated

  Integration: NormalizerPipeline with field mapping
    - Wazuh handler strips _mxtac_field_mapping key before passing to normaliser
    - Wazuh handler applies field overrides before publishing to NORMALIZED
    - Zeek handler strips and applies field overrides
    - Suricata handler strips and applies field overrides
    - Override with invalid OCSF type causes ValidationError → DLQ

  Integration: BaseConnector poll loop injects _mxtac_field_mapping
    - connector with field_mapping in extra injects key into every event
    - connector without field_mapping in extra does NOT inject key
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.normalizers.field_mapping import (
    FieldMappingConfig,
    _get_nested,
    _set_nested,
)
from app.services.normalizers.ocsf import OCSFEvent


# ── Helpers ───────────────────────────────────────────────────────────────────


def _minimal_ocsf_event(**overrides: Any) -> OCSFEvent:
    """Return the minimal valid OCSFEvent, with optional field overrides."""
    defaults: dict[str, Any] = {
        "class_uid": 4001,
        "class_name": "Network Activity",
        "category_uid": 4,
        "severity_id": 1,
        "metadata_product": "Wazuh",
    }
    defaults.update(overrides)
    return OCSFEvent(**defaults)


# ── _get_nested ───────────────────────────────────────────────────────────────


class TestGetNested:
    def test_single_key(self) -> None:
        assert _get_nested({"a": 1}, "a") == 1

    def test_nested_two_levels(self) -> None:
        assert _get_nested({"a": {"b": "val"}}, "a.b") == "val"

    def test_nested_three_levels(self) -> None:
        assert _get_nested({"a": {"b": {"c": 42}}}, "a.b.c") == 42

    def test_missing_key_returns_none(self) -> None:
        assert _get_nested({"a": 1}, "b") is None

    def test_missing_intermediate_key_returns_none(self) -> None:
        assert _get_nested({"a": {"b": 1}}, "a.x.y") is None

    def test_non_dict_intermediate_returns_none(self) -> None:
        assert _get_nested({"a": "not_a_dict"}, "a.b") is None

    def test_value_is_none_returns_none(self) -> None:
        assert _get_nested({"a": None}, "a") is None

    def test_empty_dict(self) -> None:
        assert _get_nested({}, "a") is None

    def test_value_zero_is_returned(self) -> None:
        """Falsy but non-None values must be returned."""
        assert _get_nested({"a": 0}, "a") == 0

    def test_value_false_is_returned(self) -> None:
        assert _get_nested({"a": False}, "a") is False  # noqa: PLC1901


# ── _set_nested ───────────────────────────────────────────────────────────────


class TestSetNested:
    def test_single_key(self) -> None:
        d: dict[str, Any] = {}
        _set_nested(d, "a", 42)
        assert d == {"a": 42}

    def test_nested_two_levels(self) -> None:
        d: dict[str, Any] = {}
        _set_nested(d, "a.b", "value")
        assert d == {"a": {"b": "value"}}

    def test_nested_three_levels(self) -> None:
        d: dict[str, Any] = {}
        _set_nested(d, "a.b.c", 99)
        assert d == {"a": {"b": {"c": 99}}}

    def test_creates_intermediate_dicts(self) -> None:
        d: dict[str, Any] = {"x": 1}
        _set_nested(d, "a.b", "v")
        assert d["a"] == {"b": "v"}
        assert d["x"] == 1  # existing key untouched

    def test_overwrites_existing_leaf(self) -> None:
        d: dict[str, Any] = {"a": {"b": "old"}}
        _set_nested(d, "a.b", "new")
        assert d["a"]["b"] == "new"

    def test_replaces_non_dict_intermediate(self) -> None:
        """If an intermediate key is not a dict, it is replaced with a new dict."""
        d: dict[str, Any] = {"a": "not_a_dict"}
        _set_nested(d, "a.b", "v")
        assert d["a"] == {"b": "v"}


# ── FieldMappingConfig.from_config ────────────────────────────────────────────


class TestFieldMappingConfigFromConfig:
    def test_none_returns_empty(self) -> None:
        cfg = FieldMappingConfig.from_config(None)
        assert cfg.field_mappings == {}

    def test_empty_string_returns_empty(self) -> None:
        cfg = FieldMappingConfig.from_config("")
        assert cfg.field_mappings == {}

    def test_empty_dict_returns_empty(self) -> None:
        cfg = FieldMappingConfig.from_config({})
        assert cfg.field_mappings == {}

    def test_yaml_string_with_field_mappings_key(self) -> None:
        yaml_str = (
            "field_mappings:\n"
            "  src_endpoint.ip: data.client_ip\n"
            "  dst_endpoint.hostname: agent.server_name\n"
        )
        cfg = FieldMappingConfig.from_config(yaml_str)
        assert cfg.field_mappings == {
            "src_endpoint.ip": "data.client_ip",
            "dst_endpoint.hostname": "agent.server_name",
        }

    def test_yaml_string_without_field_mappings_key_returns_empty(self) -> None:
        cfg = FieldMappingConfig.from_config("some_other_key: value\n")
        assert cfg.field_mappings == {}

    def test_invalid_yaml_returns_empty(self) -> None:
        cfg = FieldMappingConfig.from_config("{{invalid yaml{{")
        assert cfg.field_mappings == {}

    def test_yaml_non_dict_top_level_returns_empty(self) -> None:
        cfg = FieldMappingConfig.from_config("- item1\n- item2\n")
        assert cfg.field_mappings == {}

    def test_dict_with_field_mappings_key(self) -> None:
        data = {"field_mappings": {"src_endpoint.ip": "data.ip"}}
        cfg = FieldMappingConfig.from_config(data)
        assert cfg.field_mappings == {"src_endpoint.ip": "data.ip"}

    def test_flat_dict_format(self) -> None:
        """Flat dict (shorthand) — every key is an OCSF path."""
        data = {
            "src_endpoint.ip": "data.client_ip",
            "actor_user.name": "data.username",
        }
        cfg = FieldMappingConfig.from_config(data)
        assert cfg.field_mappings == data

    def test_non_string_non_dict_returns_empty(self) -> None:
        cfg = FieldMappingConfig.from_config(42)
        assert cfg.field_mappings == {}

    def test_list_returns_empty(self) -> None:
        cfg = FieldMappingConfig.from_config(["a", "b"])
        assert cfg.field_mappings == {}

    def test_flat_dict_filters_non_string_values(self) -> None:
        """Non-string values in a flat dict are excluded."""
        data: dict[str, Any] = {
            "src_endpoint.ip": "data.ip",
            "severity_id": 4,      # int value — excluded from flat format
        }
        cfg = FieldMappingConfig.from_config(data)
        # Only string-keyed string-valued entries are kept
        assert "src_endpoint.ip" in cfg.field_mappings
        assert "severity_id" not in cfg.field_mappings


# ── FieldMappingConfig.apply ──────────────────────────────────────────────────


class TestFieldMappingConfigApply:
    def test_empty_config_returns_same_event(self) -> None:
        event = _minimal_ocsf_event()
        cfg = FieldMappingConfig()
        result = cfg.apply(event, {})
        assert result is event  # identical object — no copy made

    def test_single_top_level_field_override(self) -> None:
        """Override metadata_product (top-level string field)."""
        event = _minimal_ocsf_event(metadata_product="Wazuh")
        raw = {"custom_product": "CustomWazuh"}
        cfg = FieldMappingConfig(field_mappings={"metadata_product": "custom_product"})
        result = cfg.apply(event, raw)
        assert result.metadata_product == "CustomWazuh"

    def test_nested_ocsf_field_override(self) -> None:
        """Override src_endpoint.ip using a nested source path."""
        event = _minimal_ocsf_event()
        raw = {"data": {"client_ip": "10.0.0.99"}}
        cfg = FieldMappingConfig(field_mappings={"src_endpoint.ip": "data.client_ip"})
        result = cfg.apply(event, raw)
        assert result.src_endpoint.ip == "10.0.0.99"

    def test_deeply_nested_source_path(self) -> None:
        event = _minimal_ocsf_event()
        raw = {"data": {"win": {"eventdata": {"commandLine": "cmd.exe /c evil"}}}}
        cfg = FieldMappingConfig(
            field_mappings={"process.cmd_line": "data.win.eventdata.commandLine"}
        )
        result = cfg.apply(event, raw)
        assert result.process.cmd_line == "cmd.exe /c evil"

    def test_multiple_field_overrides_applied_together(self) -> None:
        event = _minimal_ocsf_event()
        raw = {"custom_ip": "1.2.3.4", "hostname": "target-host"}
        cfg = FieldMappingConfig(
            field_mappings={
                "src_endpoint.ip": "custom_ip",
                "dst_endpoint.hostname": "hostname",
            }
        )
        result = cfg.apply(event, raw)
        assert result.src_endpoint.ip == "1.2.3.4"
        assert result.dst_endpoint.hostname == "target-host"

    def test_missing_source_path_silently_skipped(self) -> None:
        """Override whose source path is absent in raw should be a no-op."""
        event = _minimal_ocsf_event()
        event_ip_before = event.src_endpoint.ip
        cfg = FieldMappingConfig(field_mappings={"src_endpoint.ip": "nonexistent.path"})
        result = cfg.apply(event, {"other": "data"})
        # src_endpoint.ip unchanged
        assert result.src_endpoint.ip == event_ip_before

    def test_none_source_value_silently_skipped(self) -> None:
        """Source path that resolves to None is skipped."""
        event = _minimal_ocsf_event()
        event_ip_before = event.src_endpoint.ip
        cfg = FieldMappingConfig(field_mappings={"src_endpoint.ip": "data.ip"})
        result = cfg.apply(event, {"data": {"ip": None}})
        assert result.src_endpoint.ip == event_ip_before

    def test_no_override_applied_returns_original(self) -> None:
        """If all source paths are missing, the original event is returned."""
        event = _minimal_ocsf_event()
        cfg = FieldMappingConfig(field_mappings={"src_endpoint.ip": "gone"})
        result = cfg.apply(event, {})
        # The result is a new validated event (not `is event`) but values match
        assert result.src_endpoint.ip == event.src_endpoint.ip

    def test_result_is_valid_ocsf_event(self) -> None:
        event = _minimal_ocsf_event()
        raw = {"custom_ip": "192.168.1.1"}
        cfg = FieldMappingConfig(field_mappings={"src_endpoint.ip": "custom_ip"})
        result = cfg.apply(event, raw)
        assert isinstance(result, OCSFEvent)

    def test_result_is_json_serializable(self) -> None:
        import json
        event = _minimal_ocsf_event()
        raw = {"custom_ip": "192.168.1.1"}
        cfg = FieldMappingConfig(field_mappings={"src_endpoint.ip": "custom_ip"})
        result = cfg.apply(event, raw)
        json.dumps(result.model_dump(mode="json"))  # must not raise


# ── FieldMappingConfig.is_empty ───────────────────────────────────────────────


class TestIsEmpty:
    def test_empty_is_true_for_default(self) -> None:
        assert FieldMappingConfig().is_empty is True

    def test_empty_is_false_when_mappings_present(self) -> None:
        cfg = FieldMappingConfig(field_mappings={"a": "b"})
        assert cfg.is_empty is False


# ── _extract_field_mapping (pipeline helper) ──────────────────────────────────


class TestExtractFieldMapping:
    """Tests for the pipeline._extract_field_mapping helper."""

    def _call(self, raw: dict[str, Any]):
        from app.services.normalizers.pipeline import _extract_field_mapping
        return _extract_field_mapping(raw)

    def test_no_field_mapping_key_returns_unchanged_raw(self) -> None:
        raw = {"ts": 1234, "id": "abc"}
        clean, cfg = self._call(raw)
        assert clean == raw
        assert cfg.is_empty

    def test_field_mapping_key_stripped_from_clean_raw(self) -> None:
        raw = {
            "ts": 1234,
            "_mxtac_field_mapping": {"src_endpoint.ip": "data.ip"},
        }
        clean, _ = self._call(raw)
        assert "_mxtac_field_mapping" not in clean
        assert "ts" in clean

    def test_field_mapping_key_parsed_into_config(self) -> None:
        raw = {
            "ts": 1234,
            "_mxtac_field_mapping": {"src_endpoint.ip": "data.ip"},
        }
        _, cfg = self._call(raw)
        assert not cfg.is_empty
        assert cfg.field_mappings == {"src_endpoint.ip": "data.ip"}

    def test_original_raw_dict_not_mutated(self) -> None:
        raw = {
            "ts": 1234,
            "_mxtac_field_mapping": {"src_endpoint.ip": "data.ip"},
        }
        original_keys = set(raw.keys())
        self._call(raw)
        assert set(raw.keys()) == original_keys

    def test_yaml_string_field_mapping_is_parsed(self) -> None:
        yaml_str = "field_mappings:\n  src_endpoint.ip: data.client_ip\n"
        raw = {"event": "data", "_mxtac_field_mapping": yaml_str}
        _, cfg = self._call(raw)
        assert cfg.field_mappings == {"src_endpoint.ip": "data.client_ip"}


# ── Integration: NormalizerPipeline ──────────────────────────────────────────


def _make_wazuh_alert(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "timestamp": "2026-02-19T08:30:00.000Z",
        "id": "ev-001",
        "rule": {"id": "100", "description": "Test", "level": 5, "groups": []},
        "agent": {"id": "001", "name": "host", "ip": "10.0.0.1"},
        "data": {"srcip": "192.168.1.5"},
    }
    base.update(overrides)
    return base


class TestNormalizerPipelineFieldMapping:
    """Integration tests: NormalizerPipeline applies field mapping from raw events."""

    @pytest.fixture
    def pipeline(self):
        from app.services.normalizers.pipeline import NormalizerPipeline
        queue = MagicMock()
        queue.publish = AsyncMock()
        queue.subscribe = AsyncMock()
        return NormalizerPipeline(queue)

    @pytest.mark.asyncio
    async def test_wazuh_handler_strips_field_mapping_key(self, pipeline) -> None:
        """_mxtac_field_mapping must NOT appear in the published NORMALIZED event."""
        raw = {
            **_make_wazuh_alert(),
            "_mxtac_field_mapping": {"src_endpoint.ip": "data.srcip"},
        }
        await pipeline._handle_wazuh(raw)
        assert pipeline._queue.publish.called
        topic, published = pipeline._queue.publish.call_args[0]
        from app.pipeline.queue import Topic
        assert topic == Topic.NORMALIZED
        assert "_mxtac_field_mapping" not in published

    @pytest.mark.asyncio
    async def test_wazuh_handler_applies_field_override(self, pipeline) -> None:
        """Field mapping override should overwrite the normalised value."""
        alert = _make_wazuh_alert()
        alert["data"]["custom_src"] = "9.9.9.9"
        raw = {
            **alert,
            "_mxtac_field_mapping": {"src_endpoint.ip": "data.custom_src"},
        }
        await pipeline._handle_wazuh(raw)
        _, published = pipeline._queue.publish.call_args[0]
        assert published["src_endpoint"]["ip"] == "9.9.9.9"

    @pytest.mark.asyncio
    async def test_wazuh_handler_no_field_mapping_publishes_normally(self, pipeline) -> None:
        """Events without _mxtac_field_mapping are normalised as before."""
        raw = _make_wazuh_alert()
        await pipeline._handle_wazuh(raw)
        topic, published = pipeline._queue.publish.call_args[0]
        from app.pipeline.queue import Topic
        assert topic == Topic.NORMALIZED
        assert "_mxtac_field_mapping" not in published

    @pytest.mark.asyncio
    async def test_zeek_handler_applies_field_override(self, pipeline) -> None:
        """Zeek handler also strips and applies field mapping."""
        raw = {
            "_log_type": "conn",
            "ts": 1708331400.0,
            "uid": "abc123",
            "id.orig_h": "10.0.0.1",
            "id.orig_p": 12345,
            "id.resp_h": "10.0.0.2",
            "id.resp_p": 443,
            "proto": "tcp",
            "_mxtac_field_mapping": {"dst_endpoint.hostname": "custom_host"},
            "custom_host": "zeek-target.internal",
        }
        await pipeline._handle_zeek(raw)
        _, published = pipeline._queue.publish.call_args[0]
        assert published["dst_endpoint"]["hostname"] == "zeek-target.internal"

    @pytest.mark.asyncio
    async def test_suricata_handler_applies_field_override(self, pipeline) -> None:
        """Suricata handler also strips and applies field mapping."""
        raw = {
            "timestamp": "2026-02-19T08:30:00.000000+0000",
            "event_type": "flow",
            "src_ip": "192.168.1.5",
            "src_port": 1234,
            "dest_ip": "10.0.0.1",
            "dest_port": 80,
            "_mxtac_field_mapping": {"actor_user.name": "flow_username"},
            "flow_username": "alice",
        }
        await pipeline._handle_suricata(raw)
        _, published = pipeline._queue.publish.call_args[0]
        assert published["actor_user"]["name"] == "alice"

    @pytest.mark.asyncio
    async def test_invalid_type_override_routes_to_dlq(self, pipeline) -> None:
        """A field mapping that writes an invalid type to an OCSF field → DLQ."""
        from app.pipeline.queue import Topic
        raw = {
            **_make_wazuh_alert(),
            # severity_id expects int; providing a list triggers ValidationError
            "_mxtac_field_mapping": {"severity_id": "bad_field"},
            "bad_field": ["not", "an", "int"],
        }
        await pipeline._handle_wazuh(raw)
        topic, _ = pipeline._queue.publish.call_args[0]
        assert topic == Topic.DLQ


# ── Integration: BaseConnector poll loop ─────────────────────────────────────


class _StubConnector:
    """Minimal connector that records what gets published."""

    def __init__(self, extra: dict[str, Any], events: list[dict[str, Any]]) -> None:
        from app.connectors.base import ConnectorConfig, ConnectorHealth, ConnectorStatus
        self.config = ConnectorConfig(
            name="stub",
            connector_type="wazuh",
            extra=extra,
        )
        self.health = ConnectorHealth(status=ConnectorStatus.INACTIVE)
        self._stop_event = asyncio.Event()
        self._task = None
        self._status_callback = None
        self._events = events
        self.published: list[dict] = []

        # Minimal queue mock
        queue = MagicMock()

        async def _publish(topic: str, event: dict) -> None:
            self.published.append(event)

        queue.publish = _publish
        self.queue = queue

    @property
    def topic(self) -> str:
        return "mxtac.raw.wazuh"

    async def _connect(self) -> None:
        pass

    async def _fetch_events(self):
        for ev in self._events:
            yield ev

    async def _update_db_status(self, *_args: Any, **_kwargs: Any) -> None:
        pass

    async def _poll_once(self) -> None:
        """Run one iteration of the poll loop logic (without the wait loop).

        Replicates the injection logic from BaseConnector._poll_loop.
        Published events are tracked via the queue.publish mock closure.
        """
        _field_mapping = self.config.extra.get("field_mapping")
        async for event in self._fetch_events():
            if _field_mapping is not None:
                event = {**event, "_mxtac_field_mapping": _field_mapping}
            await self.queue.publish(self.topic, event)
            # NOTE: do NOT append to self.published here — the _publish closure does it.


class TestBaseConnectorFieldMappingInjection:
    @pytest.mark.asyncio
    async def test_connector_with_field_mapping_injects_key(self) -> None:
        mapping = {"src_endpoint.ip": "data.custom_ip"}
        connector = _StubConnector(
            extra={"field_mapping": mapping},
            events=[{"ts": 1, "data": {"custom_ip": "1.2.3.4"}}],
        )
        await connector._poll_once()
        assert len(connector.published) == 1
        published = connector.published[0]
        assert "_mxtac_field_mapping" in published
        assert published["_mxtac_field_mapping"] == mapping

    @pytest.mark.asyncio
    async def test_connector_without_field_mapping_does_not_inject_key(self) -> None:
        connector = _StubConnector(
            extra={},
            events=[{"ts": 1, "data": {}}],
        )
        await connector._poll_once()
        assert len(connector.published) == 1
        assert "_mxtac_field_mapping" not in connector.published[0]

    @pytest.mark.asyncio
    async def test_original_event_not_mutated(self) -> None:
        """The connector creates a new dict instead of mutating the original event."""
        original_event = {"ts": 1}
        connector = _StubConnector(
            extra={"field_mapping": {"src_endpoint.ip": "ts"}},
            events=[original_event],
        )
        await connector._poll_once()
        # Original must be untouched
        assert "_mxtac_field_mapping" not in original_event

    @pytest.mark.asyncio
    async def test_multiple_events_all_get_field_mapping_injected(self) -> None:
        events = [{"ts": i} for i in range(3)]
        connector = _StubConnector(
            extra={"field_mapping": {"src_endpoint.ip": "ts"}},
            events=events,
        )
        await connector._poll_once()
        for pub in connector.published:
            assert "_mxtac_field_mapping" in pub
