"""Detection tactic: the name is the stored and returned representation.

``Detection.tactic`` holds the tactic name (``Credential Access``) and
``tactic_id`` the ID (``TA0006``).  Rows written by earlier versions of the
pipeline hold the ID in ``tactic``; every reader treats such a row as the
tactic it names.
"""

from __future__ import annotations

import csv
import io
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.engine.sigma_engine import TACTIC_ID_TO_NAME, TACTIC_NAME_TO_ID, tactic_name
from app.models.detection import Detection
from app.repositories.detection_repo import _TACTIC_LABEL_MAP
from app.services.alert_manager import AlertManager


def _detection(tactic: str, technique_id: str, *, host: str = "host-1", **kwargs) -> Detection:
    return Detection(
        score=7.0, severity="high", technique_id=technique_id, technique_name="Technique",
        tactic=tactic, name=f"{technique_id} on {host}", host=host,
        time=datetime.now(UTC) - timedelta(hours=1), **kwargs,
    )


@pytest.fixture
async def mixed_rows(db_session: AsyncSession) -> None:
    """Detections with the tactic stored as a name and, in legacy rows, as an ID."""
    db_session.add_all([
        _detection("Credential Access", "T1003.001", host="dc01", tactic_id="TA0006"),
        _detection("TA0006", "T1003.008", host="db01", tactic_id="TA0006"),     # legacy
        _detection("TA0002", "T1059.004", host="app02", tactic_id="TA0002"),    # legacy
        _detection("TA0011", "T1071.004", host="dns01", tactic_id="TA0011"),    # legacy
        _detection("unknown", "T1059.001", host="ws07"),
    ])
    await db_session.flush()


def test_tactic_name_maps_ids_and_keeps_names() -> None:
    assert tactic_name("TA0006") == "Credential Access"
    assert tactic_name("ta0011") == "Command and Control"
    assert tactic_name("Credential Access") == "Credential Access"
    assert tactic_name("unknown") == "unknown"
    assert tactic_name(None) is None


def test_every_tactic_id_has_a_name() -> None:
    assert set(TACTIC_ID_TO_NAME) == set(TACTIC_NAME_TO_ID.values())
    # The names are the Sigma tag names, written with spaces
    for sigma_name, tactic_id in TACTIC_NAME_TO_ID.items():
        assert TACTIC_ID_TO_NAME[tactic_id].lower() == sigma_name.replace("_", " ")
    # The heatmap columns are keyed by these names
    assert set(_TACTIC_LABEL_MAP) <= set(TACTIC_ID_TO_NAME.values())


def test_detection_severity_is_one_of_the_four_levels() -> None:
    for level in ("critical", "high", "medium", "low"):
        assert AlertManager._detection_severity(level) == level
    # Sigma "informational" has no detection severity of its own
    assert AlertManager._detection_severity("informational") == "low"
    assert AlertManager._detection_severity(None) == "low"


async def test_overview_tactics_counts_legacy_rows_under_the_name(
    client: AsyncClient, auth_headers: dict, mixed_rows: None,
) -> None:
    resp = await client.get("/api/v1/overview/tactics", headers=auth_headers)
    assert resp.status_code == 200
    assert {row["tactic"]: row["count"] for row in resp.json()} == {
        "Credential Access": 2, "Execution": 1, "Command and Control": 1, "unknown": 1,
    }
    assert resp.json()[0]["tactic"] == "Credential Access"   # highest count first


async def test_overview_heatmap_counts_legacy_rows(
    client: AsyncClient, auth_headers: dict, mixed_rows: None,
) -> None:
    resp = await client.get("/api/v1/overview/coverage/heatmap", headers=auth_headers)
    assert resp.status_code == 200
    covered = {
        (row["technique_id"], cell["tactic"]): cell["covered"]
        for row in resp.json() for cell in row["cells"] if cell["covered"]
    }
    assert covered == {("T1003", "CRED"): 2, ("T1059", "EXEC"): 1}


async def test_detections_return_and_filter_by_tactic_name(
    client: AsyncClient, auth_headers: dict, mixed_rows: None,
) -> None:
    resp = await client.get("/api/v1/detections", headers=auth_headers)
    assert {d["host"]: d["tactic"] for d in resp.json()["items"]} == {
        "dc01": "Credential Access", "db01": "Credential Access", "app02": "Execution",
        "dns01": "Command and Control", "ws07": "unknown",
    }

    for value, hosts in (
        ("Credential Access", {"dc01", "db01"}),
        ("credential", {"dc01", "db01"}),
        ("command and", {"dns01"}),
        ("TA0002", {"app02"}),
        ("exfil", set()),
    ):
        resp = await client.get("/api/v1/detections", params={"tactic": value}, headers=auth_headers)
        assert resp.status_code == 200
        assert {d["host"] for d in resp.json()["items"]} == hosts, value


async def test_detection_export_and_recent_detections_use_the_tactic_name(
    client: AsyncClient, auth_headers: dict, mixed_rows: None,
) -> None:
    resp = await client.get("/api/v1/detections/export", headers=auth_headers)
    assert resp.status_code == 200
    rows = list(csv.DictReader(io.StringIO(resp.text)))
    assert {r["host"]: r["tactic"] for r in rows}["db01"] == "Credential Access"

    resp = await client.get("/api/v1/overview/recent-detections", params={"limit": 20},
                            headers=auth_headers)
    assert "TA0006" not in {d["tactic"] for d in resp.json()}
    assert {d["host"]: d["tactic"] for d in resp.json()}["app02"] == "Execution"
