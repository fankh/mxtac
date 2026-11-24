"""Incident lookups by host / tactic / detection id inside JSON array columns.

They must work on PostgreSQL (where ``LIKE`` on a ``json`` column is an
error) and match arrays with more than one element.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.incident import Incident
from app.repositories.incident_repo import IncidentRepo, _json_array_contains


async def _incident(db: AsyncSession, **kwargs) -> Incident:
    values = {
        "title": "Incident",
        "severity": "high",
        "created_by": "system",
        "hosts": ["web01"],
        "tactic_ids": ["TA0006"],
        "detection_ids": ["det-1"],
        **kwargs,
    }
    incident = await IncidentRepo.create(db, **values)
    await db.commit()
    return incident


def test_filter_casts_json_to_text_on_postgresql() -> None:
    statement = select(Incident.id).where(_json_array_contains(Incident.hosts, "web01"))
    sql = str(statement.compile(dialect=postgresql.dialect()))

    assert "CAST(incidents.hosts AS VARCHAR) LIKE" in sql


async def test_find_open_matches_host_and_tactic_in_multi_element_arrays(
    db_session: AsyncSession,
) -> None:
    incident = await _incident(
        db_session, hosts=["db02", "web01"], tactic_ids=["TA0001", "TA0006", "TA0008"]
    )

    found = await IncidentRepo.find_open_by_host_tactic(db_session, "web01", "TA0006", 3600)

    assert found is not None and found.id == incident.id


async def test_find_open_requires_both_host_and_tactic(db_session: AsyncSession) -> None:
    await _incident(db_session)

    assert await IncidentRepo.find_open_by_host_tactic(db_session, "web01", "TA0002", 3600) is None
    assert await IncidentRepo.find_open_by_host_tactic(db_session, "db02", "TA0006", 3600) is None


async def test_host_match_is_exact_not_a_substring(db_session: AsyncSession) -> None:
    await _incident(db_session, hosts=["web010", "xweb01"])

    assert await IncidentRepo.find_open_by_host_tactic(db_session, "web01", "TA0006", 3600) is None


async def test_like_wildcards_in_the_value_are_literal(db_session: AsyncSession) -> None:
    await _incident(db_session, hosts=["web01"])
    literal = await _incident(db_session, hosts=["web_1", "100%"])

    found = await IncidentRepo.find_open_by_host_tactic(db_session, "web_1", "TA0006", 3600)
    assert found is not None and found.id == literal.id
    found = await IncidentRepo.find_open_by_host_tactic(db_session, "100%", "TA0006", 3600)
    assert found is not None and found.id == literal.id
    assert await IncidentRepo.find_open_by_host_tactic(db_session, "%", "TA0006", 3600) is None


async def test_closed_incident_is_not_matched(db_session: AsyncSession) -> None:
    await _incident(db_session, status="closed")

    assert await IncidentRepo.find_open_by_host_tactic(db_session, "web01", "TA0006", 3600) is None


async def test_get_by_detection_finds_id_anywhere_in_the_array(db_session: AsyncSession) -> None:
    first = await _incident(db_session, detection_ids=["det-1", "det-2", "det-3"])
    await _incident(db_session, detection_ids=["det-20"])

    found = await IncidentRepo.get_by_detection(db_session, "det-2")

    assert [incident.id for incident in found] == [first.id]
