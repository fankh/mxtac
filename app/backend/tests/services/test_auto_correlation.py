"""Tests for alert-to-incident auto-correlation — feature 26.8.

Covers:
  - Config fields: auto_create_incident_enabled, auto_create_incident_min_severity,
    correlation_window_seconds present with correct defaults.
  - IncidentRepo.find_open_by_host_tactic: returns matching open incident within window.
  - IncidentRepo.find_open_by_host_tactic: returns None when no match.
  - IncidentRepo.find_open_by_host_tactic: ignores resolved/closed incidents.
  - IncidentRepo.find_open_by_host_tactic: ignores incidents outside the time window.
  - AlertManager._correlate_incident: disabled when auto_create_incident_enabled=False.
  - AlertManager._correlate_incident: appends detection_id to existing open incident.
  - AlertManager._correlate_incident: does not duplicate detection_id if already present.
  - AlertManager._correlate_incident: creates new incident when no match and severity>=high.
  - AlertManager._correlate_incident: skips creation when severity < min threshold.
  - AlertManager._correlate_incident: skips when host is empty.
  - AlertManager._correlate_incident: skips when tactic is empty (no tactic_ids).
  - AlertManager._correlate_incident: skips when detection_id is empty.
  - AlertManager._correlate_incident: new incident title includes rule_title and host.
  - AlertManager._correlate_incident: new incident created_by is "system".
  - AlertManager._correlate_incident: new incident detection_ids contains the detection_id.
  - AlertManager._correlate_incident: new incident hosts contains the host.
  - AlertManager._correlate_incident: new incident tactic_ids matches scored tactic_ids.
  - AlertManager._correlate_incident: severity=critical meets default threshold (high).
  - AlertManager._correlate_incident: severity=medium does NOT meet default threshold (high).
  - AlertManager._correlate_incident: severity=low does NOT meet default threshold (high).
  - AlertManager._correlate_incident: severity rank ordering: low<medium<high<critical.
  - AlertManager._persist_to_db: calls _correlate_incident with the scored alert.
  - Integration: end-to-end process() creates incident for high-severity alert.
  - Integration: end-to-end process() appends to existing incident for same host+tactic.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.models import Base
from app.models.incident import Incident
from app.pipeline.queue import InMemoryQueue
from app.repositories.incident_repo import IncidentRepo
from app.services.alert_manager import AlertManager

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_alert_dict(
    *,
    alert_id: str = "det-001",
    rule_id: str = "sigma-T1059",
    rule_title: str = "Command Shell Execution",
    level: str = "high",
    severity_id: int = 4,
    technique_ids: list[str] | None = None,
    tactic_ids: list[str] | None = None,
    host: str = "srv-01",
) -> dict:
    return {
        "id": alert_id,
        "rule_id": rule_id,
        "rule_title": rule_title,
        "level": level,
        "severity_id": severity_id,
        "technique_ids": ["T1059"] if technique_ids is None else technique_ids,
        "tactic_ids": ["execution"] if tactic_ids is None else tactic_ids,
        "host": host,
        "time": datetime.now(timezone.utc).isoformat(),
        "event_snapshot": {"pid": 1234},
    }


def _make_mock_manager() -> AlertManager:
    """Return an AlertManager with a mocked Valkey client (not connected)."""
    queue = InMemoryQueue()
    mgr = AlertManager.__new__(AlertManager)
    mgr._queue = queue
    mgr._valkey = MagicMock()
    mgr._valkey.set = AsyncMock(return_value=True)
    mgr._valkey.aclose = AsyncMock()
    return mgr


# ---------------------------------------------------------------------------
# In-memory SQLite session for repository tests
# ---------------------------------------------------------------------------

_SQLITE_URL = "sqlite+aiosqlite:///:memory:"


async def _make_db_session() -> AsyncSession:
    engine = create_async_engine(_SQLITE_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(bind=engine, expire_on_commit=False)
    return factory()


# ---------------------------------------------------------------------------
# Section 1 — Config defaults
# ---------------------------------------------------------------------------


def test_config_auto_create_enabled_default():
    """auto_create_incident_enabled defaults to True."""
    from app.core.config import settings

    assert settings.auto_create_incident_enabled is True


def test_config_min_severity_default():
    """auto_create_incident_min_severity defaults to 'high'."""
    from app.core.config import settings

    assert settings.auto_create_incident_min_severity == "high"


def test_config_correlation_window_default():
    """correlation_window_seconds defaults to 3600 (1 hour)."""
    from app.core.config import settings

    assert settings.correlation_window_seconds == 3600


# ---------------------------------------------------------------------------
# Section 2 — IncidentRepo.find_open_by_host_tactic
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_find_open_by_host_tactic_returns_match(db_session):
    """Returns the most recent open incident matching host + tactic within window."""
    incident = Incident(
        title="Test",
        severity="high",
        status="new",
        priority=3,
        created_by="system",
        detection_ids=["det-001"],
        technique_ids=["T1059"],
        tactic_ids=["execution"],
        hosts=["srv-01"],
    )
    db_session.add(incident)
    await db_session.flush()

    found = await IncidentRepo.find_open_by_host_tactic(
        db_session, host="srv-01", tactic="execution", window_seconds=3600
    )
    assert found is not None
    assert "srv-01" in found.hosts
    assert "execution" in found.tactic_ids


@pytest.mark.asyncio
async def test_find_open_by_host_tactic_returns_none_no_match(db_session):
    """Returns None when no incident matches the host + tactic pair."""
    found = await IncidentRepo.find_open_by_host_tactic(
        db_session, host="dc-01", tactic="persistence", window_seconds=3600
    )
    assert found is None


@pytest.mark.asyncio
async def test_find_open_by_host_tactic_ignores_resolved(db_session):
    """Resolved incidents are excluded from correlation candidates."""
    incident = Incident(
        title="Resolved incident",
        severity="high",
        status="resolved",
        priority=3,
        created_by="system",
        detection_ids=[],
        technique_ids=[],
        tactic_ids=["execution"],
        hosts=["srv-01"],
    )
    db_session.add(incident)
    await db_session.flush()

    found = await IncidentRepo.find_open_by_host_tactic(
        db_session, host="srv-01", tactic="execution", window_seconds=3600
    )
    assert found is None


@pytest.mark.asyncio
async def test_find_open_by_host_tactic_ignores_closed(db_session):
    """Closed incidents are excluded from correlation candidates."""
    incident = Incident(
        title="Closed incident",
        severity="high",
        status="closed",
        priority=3,
        created_by="system",
        detection_ids=[],
        technique_ids=[],
        tactic_ids=["execution"],
        hosts=["srv-01"],
    )
    db_session.add(incident)
    await db_session.flush()

    found = await IncidentRepo.find_open_by_host_tactic(
        db_session, host="srv-01", tactic="execution", window_seconds=3600
    )
    assert found is None


@pytest.mark.asyncio
async def test_find_open_by_host_tactic_respects_window(db_session):
    """Incidents older than window_seconds are excluded."""
    incident = Incident(
        title="Old incident",
        severity="high",
        status="new",
        priority=3,
        created_by="system",
        detection_ids=[],
        technique_ids=[],
        tactic_ids=["execution"],
        hosts=["srv-01"],
    )
    db_session.add(incident)
    await db_session.flush()

    # Force created_at to be 2 hours ago (outside 1-hour window)
    from sqlalchemy import update
    await db_session.execute(
        update(Incident)
        .where(Incident.id == incident.id)
        .values(created_at=datetime.now(timezone.utc) - timedelta(hours=2))
    )

    found = await IncidentRepo.find_open_by_host_tactic(
        db_session, host="srv-01", tactic="execution", window_seconds=3600
    )
    assert found is None


@pytest.mark.asyncio
async def test_find_open_by_host_tactic_investigating_is_open(db_session):
    """Investigating status is considered open (not resolved/closed)."""
    incident = Incident(
        title="In progress",
        severity="critical",
        status="investigating",
        priority=1,
        created_by="system",
        detection_ids=[],
        technique_ids=[],
        tactic_ids=["lateral-movement"],
        hosts=["dc-01"],
    )
    db_session.add(incident)
    await db_session.flush()

    found = await IncidentRepo.find_open_by_host_tactic(
        db_session, host="dc-01", tactic="lateral-movement", window_seconds=3600
    )
    assert found is not None


# ---------------------------------------------------------------------------
# Section 3 — AlertManager._correlate_incident (unit tests with mocked session)
# ---------------------------------------------------------------------------


def _make_session_mock() -> MagicMock:
    session = MagicMock(spec=AsyncSession)
    session.add = MagicMock()
    session.flush = AsyncMock()
    return session


@pytest.mark.asyncio
async def test_correlate_disabled_when_feature_off():
    """_correlate_incident is a no-op when auto_create_incident_enabled=False."""
    mgr = _make_mock_manager()
    session = _make_session_mock()
    scored = _make_alert_dict()

    with patch("app.core.config.settings.auto_create_incident_enabled", False):
        await mgr._correlate_incident(session, scored)

    session.add.assert_not_called()


@pytest.mark.asyncio
async def test_correlate_appends_to_existing_incident():
    """Appends detection_id to an existing open incident matching host + tactic."""
    mgr = _make_mock_manager()
    session = _make_session_mock()
    scored = _make_alert_dict(alert_id="det-002", host="srv-01", tactic_ids=["execution"])

    existing = MagicMock()
    existing.detection_ids = ["det-001"]
    existing.id = 42

    with (
        patch("app.core.config.settings.auto_create_incident_enabled", True),
        patch("app.core.config.settings.auto_create_incident_min_severity", "high"),
        patch("app.core.config.settings.correlation_window_seconds", 3600),
        patch(
            "app.repositories.incident_repo.IncidentRepo.find_open_by_host_tactic",
            new=AsyncMock(return_value=existing),
        ),
        patch(
            "app.repositories.incident_repo.IncidentRepo.create",
            new=AsyncMock(),
        ) as mock_create,
    ):
        await mgr._correlate_incident(session, scored)

    assert "det-002" in existing.detection_ids
    mock_create.assert_not_awaited()


@pytest.mark.asyncio
async def test_correlate_no_duplicate_detection_id():
    """Detection id is not appended twice if already in the incident's list."""
    mgr = _make_mock_manager()
    session = _make_session_mock()
    scored = _make_alert_dict(alert_id="det-001", host="srv-01", tactic_ids=["execution"])

    existing = MagicMock()
    existing.detection_ids = ["det-001"]  # already present
    existing.id = 42

    with (
        patch("app.core.config.settings.auto_create_incident_enabled", True),
        patch("app.core.config.settings.auto_create_incident_min_severity", "high"),
        patch("app.core.config.settings.correlation_window_seconds", 3600),
        patch(
            "app.repositories.incident_repo.IncidentRepo.find_open_by_host_tactic",
            new=AsyncMock(return_value=existing),
        ),
    ):
        await mgr._correlate_incident(session, scored)

    assert existing.detection_ids.count("det-001") == 1


@pytest.mark.asyncio
async def test_correlate_creates_new_incident_for_high_severity():
    """Creates a new incident when no match exists and severity is high."""
    mgr = _make_mock_manager()
    session = _make_session_mock()
    scored = _make_alert_dict(alert_id="det-003", level="high", host="srv-02")

    with (
        patch("app.core.config.settings.auto_create_incident_enabled", True),
        patch("app.core.config.settings.auto_create_incident_min_severity", "high"),
        patch("app.core.config.settings.correlation_window_seconds", 3600),
        patch(
            "app.repositories.incident_repo.IncidentRepo.find_open_by_host_tactic",
            new=AsyncMock(return_value=None),
        ),
        patch(
            "app.repositories.incident_repo.IncidentRepo.create",
            new=AsyncMock(),
        ) as mock_create,
    ):
        await mgr._correlate_incident(session, scored)

    mock_create.assert_awaited_once()
    call_kwargs = mock_create.call_args.kwargs
    assert call_kwargs["severity"] == "high"
    assert "det-003" in call_kwargs["detection_ids"]
    assert call_kwargs["created_by"] == "system"


@pytest.mark.asyncio
async def test_correlate_creates_new_incident_for_critical_severity():
    """Critical severity meets the 'high' minimum threshold."""
    mgr = _make_mock_manager()
    session = _make_session_mock()
    scored = _make_alert_dict(alert_id="det-004", level="critical", severity_id=5)

    with (
        patch("app.core.config.settings.auto_create_incident_enabled", True),
        patch("app.core.config.settings.auto_create_incident_min_severity", "high"),
        patch("app.core.config.settings.correlation_window_seconds", 3600),
        patch(
            "app.repositories.incident_repo.IncidentRepo.find_open_by_host_tactic",
            new=AsyncMock(return_value=None),
        ),
        patch(
            "app.repositories.incident_repo.IncidentRepo.create",
            new=AsyncMock(),
        ) as mock_create,
    ):
        await mgr._correlate_incident(session, scored)

    mock_create.assert_awaited_once()


@pytest.mark.asyncio
async def test_correlate_skips_creation_for_medium_severity():
    """Medium severity does NOT meet the 'high' minimum threshold."""
    mgr = _make_mock_manager()
    session = _make_session_mock()
    scored = _make_alert_dict(alert_id="det-005", level="medium", severity_id=3)

    with (
        patch("app.core.config.settings.auto_create_incident_enabled", True),
        patch("app.core.config.settings.auto_create_incident_min_severity", "high"),
        patch("app.core.config.settings.correlation_window_seconds", 3600),
        patch(
            "app.repositories.incident_repo.IncidentRepo.find_open_by_host_tactic",
            new=AsyncMock(return_value=None),
        ),
        patch(
            "app.repositories.incident_repo.IncidentRepo.create",
            new=AsyncMock(),
        ) as mock_create,
    ):
        await mgr._correlate_incident(session, scored)

    mock_create.assert_not_awaited()


@pytest.mark.asyncio
async def test_correlate_skips_creation_for_low_severity():
    """Low severity does NOT meet the 'high' minimum threshold."""
    mgr = _make_mock_manager()
    session = _make_session_mock()
    scored = _make_alert_dict(alert_id="det-006", level="low", severity_id=1)

    with (
        patch("app.core.config.settings.auto_create_incident_enabled", True),
        patch("app.core.config.settings.auto_create_incident_min_severity", "high"),
        patch("app.core.config.settings.correlation_window_seconds", 3600),
        patch(
            "app.repositories.incident_repo.IncidentRepo.find_open_by_host_tactic",
            new=AsyncMock(return_value=None),
        ),
        patch(
            "app.repositories.incident_repo.IncidentRepo.create",
            new=AsyncMock(),
        ) as mock_create,
    ):
        await mgr._correlate_incident(session, scored)

    mock_create.assert_not_awaited()


@pytest.mark.asyncio
async def test_correlate_skips_when_host_empty():
    """Skips correlation entirely when host is empty string."""
    mgr = _make_mock_manager()
    session = _make_session_mock()
    scored = _make_alert_dict(alert_id="det-007", host="")

    with (
        patch("app.core.config.settings.auto_create_incident_enabled", True),
        patch(
            "app.repositories.incident_repo.IncidentRepo.find_open_by_host_tactic",
            new=AsyncMock(),
        ) as mock_find,
        patch(
            "app.repositories.incident_repo.IncidentRepo.create",
            new=AsyncMock(),
        ) as mock_create,
    ):
        await mgr._correlate_incident(session, scored)

    mock_find.assert_not_awaited()
    mock_create.assert_not_awaited()


@pytest.mark.asyncio
async def test_correlate_skips_when_tactic_empty():
    """Skips correlation when tactic_ids is empty (no primary tactic)."""
    mgr = _make_mock_manager()
    session = _make_session_mock()
    scored = _make_alert_dict(alert_id="det-008", tactic_ids=[])

    with (
        patch("app.core.config.settings.auto_create_incident_enabled", True),
        patch(
            "app.repositories.incident_repo.IncidentRepo.find_open_by_host_tactic",
            new=AsyncMock(),
        ) as mock_find,
        patch(
            "app.repositories.incident_repo.IncidentRepo.create",
            new=AsyncMock(),
        ) as mock_create,
    ):
        await mgr._correlate_incident(session, scored)

    mock_find.assert_not_awaited()
    mock_create.assert_not_awaited()


@pytest.mark.asyncio
async def test_correlate_new_incident_title_contains_rule_and_host():
    """New incident title includes the rule_title and host."""
    mgr = _make_mock_manager()
    session = _make_session_mock()
    scored = _make_alert_dict(
        alert_id="det-009",
        rule_title="Suspicious PowerShell",
        host="dc-01",
        level="high",
    )

    with (
        patch("app.core.config.settings.auto_create_incident_enabled", True),
        patch("app.core.config.settings.auto_create_incident_min_severity", "high"),
        patch("app.core.config.settings.correlation_window_seconds", 3600),
        patch(
            "app.repositories.incident_repo.IncidentRepo.find_open_by_host_tactic",
            new=AsyncMock(return_value=None),
        ),
        patch(
            "app.repositories.incident_repo.IncidentRepo.create",
            new=AsyncMock(),
        ) as mock_create,
    ):
        await mgr._correlate_incident(session, scored)

    title = mock_create.call_args.kwargs["title"]
    assert "Suspicious PowerShell" in title
    assert "dc-01" in title


@pytest.mark.asyncio
async def test_correlate_new_incident_hosts_contains_host():
    """New incident hosts list contains the alert's host."""
    mgr = _make_mock_manager()
    session = _make_session_mock()
    scored = _make_alert_dict(alert_id="det-010", host="win-05", level="high")

    with (
        patch("app.core.config.settings.auto_create_incident_enabled", True),
        patch("app.core.config.settings.auto_create_incident_min_severity", "high"),
        patch("app.core.config.settings.correlation_window_seconds", 3600),
        patch(
            "app.repositories.incident_repo.IncidentRepo.find_open_by_host_tactic",
            new=AsyncMock(return_value=None),
        ),
        patch(
            "app.repositories.incident_repo.IncidentRepo.create",
            new=AsyncMock(),
        ) as mock_create,
    ):
        await mgr._correlate_incident(session, scored)

    assert "win-05" in mock_create.call_args.kwargs["hosts"]


@pytest.mark.asyncio
async def test_correlate_severity_rank_ordering():
    """Severity rank: low(0) < medium(1) < high(2) < critical(3)."""
    rank = AlertManager._SEVERITY_RANK
    assert rank["low"] < rank["medium"]
    assert rank["medium"] < rank["high"]
    assert rank["high"] < rank["critical"]


# ---------------------------------------------------------------------------
# Section 4 — _persist_to_db calls _correlate_incident
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_persist_to_db_calls_correlate_incident():
    """_persist_to_db calls _correlate_incident with the scored dict."""
    mgr = _make_mock_manager()
    scored = _make_alert_dict()
    scored["score"] = 6.5

    # AsyncSessionLocal is imported inside _persist_to_db, so patch it at its source
    mock_session = AsyncMock()
    mock_cm = MagicMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_session)
    mock_cm.__aexit__ = AsyncMock(return_value=False)

    with (
        patch("app.core.database.AsyncSessionLocal", return_value=mock_cm),
        patch(
            "app.repositories.detection_repo.DetectionRepo.create",
            new=AsyncMock(),
        ),
        patch.object(mgr, "_correlate_incident", new=AsyncMock()) as mock_correlate,
    ):
        await mgr._persist_to_db(scored)

    mock_correlate.assert_awaited_once()
    # _correlate_incident(session, scored) — args[1] is the scored dict
    assert mock_correlate.call_args.args[1]["id"] == scored["id"]


# ---------------------------------------------------------------------------
# Section 5 — Severity threshold configurability
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_correlate_medium_threshold_allows_medium():
    """When min_severity=medium, a medium-severity alert triggers incident creation."""
    mgr = _make_mock_manager()
    session = _make_session_mock()
    scored = _make_alert_dict(alert_id="det-011", level="medium", severity_id=3)

    with (
        patch("app.core.config.settings.auto_create_incident_enabled", True),
        patch("app.core.config.settings.auto_create_incident_min_severity", "medium"),
        patch("app.core.config.settings.correlation_window_seconds", 3600),
        patch(
            "app.repositories.incident_repo.IncidentRepo.find_open_by_host_tactic",
            new=AsyncMock(return_value=None),
        ),
        patch(
            "app.repositories.incident_repo.IncidentRepo.create",
            new=AsyncMock(),
        ) as mock_create,
    ):
        await mgr._correlate_incident(session, scored)

    mock_create.assert_awaited_once()


@pytest.mark.asyncio
async def test_correlate_medium_threshold_blocks_low():
    """When min_severity=medium, a low-severity alert does NOT trigger incident creation."""
    mgr = _make_mock_manager()
    session = _make_session_mock()
    scored = _make_alert_dict(alert_id="det-012", level="low", severity_id=1)

    with (
        patch("app.core.config.settings.auto_create_incident_enabled", True),
        patch("app.core.config.settings.auto_create_incident_min_severity", "medium"),
        patch("app.core.config.settings.correlation_window_seconds", 3600),
        patch(
            "app.repositories.incident_repo.IncidentRepo.find_open_by_host_tactic",
            new=AsyncMock(return_value=None),
        ),
        patch(
            "app.repositories.incident_repo.IncidentRepo.create",
            new=AsyncMock(),
        ) as mock_create,
    ):
        await mgr._correlate_incident(session, scored)

    mock_create.assert_not_awaited()
