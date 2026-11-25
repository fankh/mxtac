"""
Syslog (RFC 3164 / RFC 5424) → OCSF normalizer.

Input is the dict published by the syslog connector and the syslog receiver
(``connectors/syslog_receiver.parse_syslog``):

{
  "_source": "syslog",
  "host": "10.0.0.7",              # sender address
  "raw": "<38>Feb 19 08:30:00 web01 sshd[2211]: Failed password for root from 203.0.113.5 port 51122 ssh2",
  "facility": 4, "facility_name": "auth",
  "severity": 6, "severity_name": "informational",
  "timestamp": "Feb 19 08:30:00",  # RFC 3164, or ISO 8601 for RFC 5424
  "hostname": "web01",
  "app_name": "sshd",
  "process_id": "2211",
  "message": "Failed password for root from 203.0.113.5 port 51122 ssh2"
}

A dict that only carries the unparsed line under ``raw`` is parsed first.

Mapping:
  timestamp            → time (RFC 3164 has no year or zone: current year, UTC)
  hostname, host       → dst_endpoint (the host that logged the message)
  app_name, process_id → process.name, process.pid
  severity (0-7)       → severity_id
  facility, message    → unmapped (also: app_name, service, summary)

Two message families get a more specific OCSF class:
  - SSH / PAM authentication results → Authentication (3002) with the user
    and the remote address in actor_user / src_endpoint
  - sudo command logs → Process Activity (1007) with the executed command in
    process.cmd_line and the invoking user in actor_user
Everything else is a Base Event (class_uid 0).
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any

from ...connectors.syslog_receiver import parse_syslog
from .ocsf import Endpoint, OCSFCategory, OCSFClass, OCSFEvent, ProcessInfo, UserInfo

# Syslog severity (0 = emergency … 7 = debug) → OCSF severity_id
SYSLOG_SEV_MAP: dict[int, int] = {
    0: 5,   # Emergency     → Critical
    1: 5,   # Alert         → Critical
    2: 5,   # Critical      → Critical
    3: 4,   # Error         → High
    4: 3,   # Warning       → Medium
    5: 2,   # Notice        → Low
    6: 1,   # Informational → Informational
    7: 1,   # Debug         → Informational
}

# Facilities whose messages belong to a Sigma ``logsource.service``.
_FACILITY_SERVICES: dict[str, str] = {"auth": "auth", "authpriv": "auth", "cron": "cron"}

_SUMMARY_MAX_CHARS = 500

# sshd: "Failed password for invalid user admin from 203.0.113.5 port 51122 ssh2"
#       "Accepted publickey for deploy from 10.0.0.4 port 40022 ssh2"
_SSH_AUTH_RE = re.compile(
    r"^(?:Failed|Accepted) \S+ for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\S+) port (?P<port>\d+)"
)
# sshd: "Invalid user admin from 203.0.113.5 port 51122"
_SSH_INVALID_USER_RE = re.compile(
    r"^Invalid user (?P<user>\S*) from (?P<ip>\S+)(?: port (?P<port>\d+))?"
)
# PAM: "pam_unix(sshd:auth): authentication failure; logname= uid=0 ... rhost=203.0.113.5  user=root"
_PAM_FAILURE_RE = re.compile(
    r"authentication failure;(?:.*?\brhost=(?P<ip>\S+))?(?:.*?\buser=(?P<user>\S+))?"
)
# sudo: "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow"
# A denied attempt ("alice : 3 incorrect password attempts ; TTY=... ; COMMAND=...")
# has text before the first KEY= pair and is not treated as an executed command.
_SUDO_COMMAND_RE = re.compile(
    r"^\s*(?P<user>\S+) : (?:TTY|PWD|USER)=.*?\bCOMMAND=(?P<command>.+)$"
)


class SyslogNormalizer:
    """Transforms a parsed syslog message into an OCSFEvent."""

    def normalize(self, raw: dict[str, Any]) -> OCSFEvent:
        parsed = raw
        if "message" not in raw and isinstance(raw.get("raw"), str):
            parsed = {**parse_syslog(raw["raw"], (raw.get("host") or "", 0)), **raw}

        message = str(parsed.get("message") or "")
        app_name = parsed.get("app_name")
        facility_name = parsed.get("facility_name")

        process = ProcessInfo(name=app_name, pid=self._safe_int(parsed.get("process_id")))
        src = Endpoint()
        user = UserInfo()
        class_uid, class_name, category_uid = 0, "Base Event", 0

        auth = self._parse_authentication(message)
        sudo = _SUDO_COMMAND_RE.match(message) if app_name == "sudo" else None
        if auth is not None:
            class_uid, class_name, category_uid = (
                OCSFClass.AUTHENTICATION, "Authentication", OCSFCategory.IAM,
            )
            user = UserInfo(name=auth.get("user") or None)
            src = Endpoint(ip=auth.get("ip"), port=self._safe_int(auth.get("port")))
        elif sudo is not None:
            class_uid, class_name, category_uid = (
                OCSFClass.PROCESS_ACTIVITY, "Process Activity", OCSFCategory.SYSTEM_ACTIVITY,
            )
            command = sudo.group("command").strip()
            executable = command.split(" ", 1)[0]
            user = UserInfo(name=sudo.group("user"))
            process = ProcessInfo(
                name=executable.rsplit("/", 1)[-1],
                path=executable,
                cmd_line=command,
                parent_name="sudo",
            )

        services = ["syslog"]
        if app_name:
            services.append(app_name.lower())
        if facility_name in _FACILITY_SERVICES:
            services.append(_FACILITY_SERVICES[facility_name])

        summary = f"{app_name}: {message}" if app_name else message
        return OCSFEvent(
            class_uid=class_uid,
            class_name=class_name,
            category_uid=category_uid,
            time=self._parse_time(parsed.get("timestamp")),
            severity_id=SYSLOG_SEV_MAP.get(parsed.get("severity"), 1),
            metadata_product="Syslog",
            src_endpoint=src,
            dst_endpoint=Endpoint(hostname=parsed.get("hostname"), ip=parsed.get("host")),
            actor_user=user,
            process=process,
            raw=raw,
            unmapped={
                "message":       message,
                "app_name":      app_name,
                "facility":      parsed.get("facility"),
                "facility_name": facility_name,
                "severity_name": parsed.get("severity_name"),
                "service":       services,
                "summary":       summary[:_SUMMARY_MAX_CHARS],
            },
        )

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _parse_authentication(self, message: str) -> dict[str, Any] | None:
        """Extract user / remote address from SSH and PAM authentication messages."""
        for pattern in (_SSH_AUTH_RE, _SSH_INVALID_USER_RE):
            if m := pattern.match(message):
                return m.groupdict()
        if m := _PAM_FAILURE_RE.search(message):
            return m.groupdict()
        return None

    def _parse_time(self, ts: Any) -> datetime:
        now = datetime.now(timezone.utc)
        if not isinstance(ts, str) or not ts:
            return now
        try:  # RFC 5424: ISO 8601
            parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
        try:  # RFC 3164: "Feb 19 08:30:00" — no year, no zone
            parsed = datetime.strptime(f"{now.year} {ts}", "%Y %b %d %H:%M:%S").replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            return now
        # A December message read in January belongs to the previous year.
        if parsed - now > timedelta(days=1):
            parsed = parsed.replace(year=now.year - 1)
        return parsed

    def _safe_int(self, val: Any) -> int | None:
        try:
            return int(val) if val is not None else None
        except (TypeError, ValueError):
            return None
