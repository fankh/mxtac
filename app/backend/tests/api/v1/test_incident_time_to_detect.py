"""Time to detect of an incident.

Found while driving the real UI against the real backend: nothing ever set
``ttd_seconds``, so "Mean time to detect" on the Overview and Incidents pages
stayed empty for every installation.  It is now the time from the earliest
linked event to the creation of the incident.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

from sqlalchemy import select

from app.models.incident import Incident
from app.repositories.detection_repo import DetectionRepo
from app.repositories.incident_repo import time_to_detect_seconds
from app.services.alert_manager import AlertManager

INCIDENTS = "/api/v1/incidents"
NOW = datetime(2026, 11, 24, 12, 0, tzinfo=UTC)


def test_time_to_detect_is_the_time_since_the_first_event() -> None:
    assert time_to_detect_seconds(NOW - timedelta(minutes=5), NOW) == 300
    # A naive time is read as UTC.
    assert time_to_detect_seconds(datetime(2026, 11, 24, 11, 0), NOW) == 3600


def test_time_to_detect_without_event_or_with_a_future_event() -> None:
    assert time_to_detect_seconds(None, NOW) is None
    assert time_to_detect_seconds(NOW + timedelta(hours=1), NOW) == 0


async def _detection(session, minutes_ago: int) -> str:
    detection = await DetectionRepo.create(
        session, score=5.8, severity="high", technique_id="T1059.004", technique_name="x",
        tactic="Execution", tactic_id="TA0002", name="Reverse Shell Command Line", host="web-01",
        time=datetime.now(UTC) - timedelta(minutes=minutes_ago),
    )
    return detection.id


async def test_incident_from_detections_gets_its_time_to_detect(client, analyst_headers, db_session) -> None:
    older = await _detection(db_session, 90)
    newer = await _detection(db_session, 10)

    resp = await client.post(
        INCIDENTS, headers=analyst_headers,
        json={"title": "Shells on web-01", "severity": "high", "detection_ids": [newer, older]},
    )

    assert resp.status_code == 201
    # Counted from the earliest event, 90 minutes ago.
    assert 5400 <= resp.json()["ttd_seconds"] <= 5460

    metrics = await client.get(f"{INCIDENTS}/metrics", headers=analyst_headers)
    assert 5400 <= metrics.json()["mttd_seconds"] <= 5460


async def test_incident_without_detections_has_no_time_to_detect(client, analyst_headers) -> None:
    resp = await client.post(INCIDENTS, headers=analyst_headers, json={"title": "Phishing report", "severity": "low"})
    assert resp.status_code == 201
    assert resp.json()["ttd_seconds"] is None


async def test_auto_created_incident_has_time_to_detect_and_readable_description(db_session) -> None:
    with patch("app.services.alert_manager.aioredis"):
        manager = AlertManager(MagicMock())
    scored = {
        "id": "2b0f4d1e-64a5-4a55-8a4c-0f6a2d0b9c11",
        "level": "high",
        "rule_id": "ec09518a-b81b-4fe5-9bdf-dd9fc96c01e2",
        "rule_title": "Reverse Shell Command Line",
        "technique_ids": ["T1059.004"],
        "tactic_ids": ["TA0002"],
        "host": "web-01.example.org",
        "time": (datetime.now(UTC) - timedelta(minutes=30)).isoformat(),
    }

    await manager._correlate_incident(db_session, scored)

    incident = (await db_session.execute(select(Incident))).scalar_one()
    assert 1800 <= incident.ttd_seconds <= 1860
    assert "Rule: Reverse Shell Command Line (ec09518a-b81b-4fe5-9bdf-dd9fc96c01e2)" in incident.description
    assert "Tactic: Execution (TA0002)" in incident.description
