"""Syslog (RFC 3164 / RFC 5424) → OCSF normalizer."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.connectors.syslog_receiver import parse_syslog
from app.services.normalizers.ocsf import OCSFCategory, OCSFClass, OCSFEvent
from app.services.normalizers.syslog import SyslogNormalizer

SENDER = ("10.0.0.7", 51400)

RFC3164 = "<38>Feb 19 08:30:00 web01 sshd[2211]: Failed password for root from 203.0.113.5 port 51122 ssh2"
RFC5424 = (
    "<86>1 2026-02-19T08:30:00.250Z web01 useradd 3120 ID47 "
    '[exampleSDID@32473 iut="3"] new user: name=svc_backup, UID=1001'
)


def normalize(line: str) -> OCSFEvent:
    return SyslogNormalizer().normalize(parse_syslog(line, SENDER))


# ── RFC 3164 ─────────────────────────────────────────────────────────────────


def test_rfc3164_common_fields() -> None:
    event = normalize(RFC3164)

    assert event.metadata_product == "Syslog"
    assert event.dst_endpoint.hostname == "web01"
    assert event.dst_endpoint.ip == "10.0.0.7"
    assert event.severity_id == 1                      # syslog informational
    assert event.unmapped["message"] == "Failed password for root from 203.0.113.5 port 51122 ssh2"
    assert event.unmapped["app_name"] == "sshd"
    assert event.unmapped["facility"] == 4
    assert event.unmapped["facility_name"] == "auth"
    assert event.unmapped["severity_name"] == "informational"
    assert event.unmapped["summary"].startswith("sshd: Failed password for root")
    assert event.raw["raw"] == RFC3164


def test_rfc3164_timestamp_gets_current_year_in_utc() -> None:
    now = datetime.now(UTC)
    event = normalize(RFC3164)

    assert (event.time.month, event.time.day, event.time.hour, event.time.minute) == (2, 19, 8, 30)
    assert event.time.tzinfo is not None
    assert event.time.year in (now.year, now.year - 1)
    assert event.time - now <= timedelta(days=1)


def test_rfc3164_without_pid() -> None:
    event = normalize("<13>Feb 19 08:30:00 web01 myapp: started worker")

    assert event.process.name == "myapp"
    assert event.process.pid is None
    assert event.unmapped["message"] == "started worker"


# ── RFC 5424 ─────────────────────────────────────────────────────────────────


def test_rfc5424_fields() -> None:
    event = normalize(RFC5424)

    assert event.time == datetime(2026, 2, 19, 8, 30, 0, 250000, tzinfo=UTC)
    assert event.dst_endpoint.hostname == "web01"
    assert event.process.name == "useradd"
    assert event.process.pid == 3120
    assert event.unmapped["message"] == "new user: name=svc_backup, UID=1001"
    assert event.unmapped["facility_name"] == "authpriv"
    assert event.severity_id == 1


def test_rfc5424_nil_values() -> None:
    event = normalize("<165>1 2026-02-19T08:30:00+09:00 - - - - - disk almost full")

    assert event.dst_endpoint.hostname is None
    assert event.process.name is None
    assert event.process.pid is None
    assert event.time == datetime(2026, 2, 18, 23, 30, tzinfo=UTC)
    assert event.unmapped["message"] == "disk almost full"
    assert event.severity_id == 2                      # syslog notice


# ── Severity ─────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("syslog_severity", "severity_id"),
    [(0, 5), (1, 5), (2, 5), (3, 4), (4, 3), (5, 2), (6, 1), (7, 1)],
)
def test_severity_mapping(syslog_severity: int, severity_id: int) -> None:
    pri = 3 * 8 + syslog_severity  # facility daemon
    assert normalize(f"<{pri}>Feb 19 08:30:00 web01 app: msg").severity_id == severity_id


# ── Classification ───────────────────────────────────────────────────────────


def test_ssh_failed_password_is_authentication_with_user_and_source() -> None:
    event = normalize(RFC3164)

    assert event.class_uid == OCSFClass.AUTHENTICATION
    assert event.category_uid == OCSFCategory.IAM
    assert event.actor_user.name == "root"
    assert event.src_endpoint.ip == "203.0.113.5"
    assert event.src_endpoint.port == 51122
    assert event.process.name == "sshd"
    assert event.process.pid == 2211


@pytest.mark.parametrize(
    ("message", "user", "ip"),
    [
        ("Accepted publickey for deploy from 10.0.0.4 port 40022 ssh2", "deploy", "10.0.0.4"),
        ("Failed password for invalid user admin from 203.0.113.5 port 1 ssh2", "admin", "203.0.113.5"),
        ("Invalid user oracle from 203.0.113.9 port 4022", "oracle", "203.0.113.9"),
        (
            "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh "
            "ruser= rhost=203.0.113.5  user=root",
            "root",
            "203.0.113.5",
        ),
    ],
)
def test_authentication_messages(message: str, user: str, ip: str) -> None:
    event = normalize(f"<38>Feb 19 08:30:00 web01 sshd[1]: {message}")

    assert event.class_uid == OCSFClass.AUTHENTICATION
    assert event.actor_user.name == user
    assert event.src_endpoint.ip == ip


def test_sudo_command_is_process_activity() -> None:
    event = normalize(
        "<85>Feb 19 08:31:00 web01 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; "
        "USER=root ; COMMAND=/usr/bin/cat /etc/shadow"
    )

    assert event.class_uid == OCSFClass.PROCESS_ACTIVITY
    assert event.actor_user.name == "alice"
    assert event.process.cmd_line == "/usr/bin/cat /etc/shadow"
    assert event.process.path == "/usr/bin/cat"
    assert event.process.name == "cat"
    assert event.process.parent_name == "sudo"
    assert event.unmapped["app_name"] == "sudo"


def test_denied_sudo_attempt_is_not_a_process_event() -> None:
    event = normalize(
        "<85>Feb 19 08:31:00 web01 sudo:    bob : user NOT in sudoers ; TTY=pts/1 ; "
        "PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/id"
    )

    assert event.class_uid == 0
    assert event.process.cmd_line is None


def test_other_message_is_base_event() -> None:
    event = normalize("<30>Feb 19 08:30:00 web01 systemd[1]: Started Daily apt activities.")

    assert (event.class_uid, event.class_name, event.category_uid) == (0, "Base Event", 0)
    assert event.actor_user.name is None
    assert event.src_endpoint.ip is None


# ── Services (Sigma logsource.service) ───────────────────────────────────────


def test_service_hints() -> None:
    assert normalize(RFC3164).unmapped["service"] == ["syslog", "sshd", "auth"]
    cron = normalize("<78>Feb 19 08:35:01 web01 CRON[4100]: (root) CMD (true)")
    assert cron.unmapped["service"] == ["syslog", "cron", "cron"]
    assert normalize("<13>no header at all").unmapped["service"] == ["syslog"]


# ── Robustness ───────────────────────────────────────────────────────────────


def test_line_without_priority_keeps_whole_line_as_message() -> None:
    event = normalize("plain text without a syslog header")

    assert event.unmapped["message"] == "plain text without a syslog header"
    assert event.severity_id == 1
    assert event.dst_endpoint.ip == "10.0.0.7"


def test_unparsed_dict_with_only_raw_line_is_parsed() -> None:
    event = SyslogNormalizer().normalize({"raw": RFC3164, "host": "10.0.0.7"})

    assert event.class_uid == OCSFClass.AUTHENTICATION
    assert event.dst_endpoint.hostname == "web01"
    assert event.actor_user.name == "root"


def test_output_round_trips_through_json() -> None:
    event = normalize(RFC3164)
    assert OCSFEvent(**event.model_dump(mode="json")) == event
