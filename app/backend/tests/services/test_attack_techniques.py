"""The bundled MITRE ATT&CK technique name table and its uses.

Coverage:
  - the data file: provenance header (source, ATT&CK version, retrieval date,
    MITRE notice), well-formed IDs, a parent for every sub-technique
  - the NOTICE file at the repository root carries the MITRE attribution
  - technique_name(): techniques, sub-techniques ("Parent: Sub"), unknown IDs
  - resolve_technique_name(): table first, then the stored value, then the ID
  - alert manager: a new detection stores the ATT&CK name, never the rule title
  - readers: rows written before the table existed (rule title in
    technique_name) are answered with the ATT&CK name in the detection list,
    the Overview list and the incident detail
  - GET /attack/techniques: any signed-in user, not public
"""

from __future__ import annotations

import json
import re
from datetime import UTC, date, datetime
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.detection import Detection
from app.models.incident import Incident
from app.pipeline.queue import InMemoryQueue
from app.services.alert_manager import AlertManager
from app.services.attack_techniques import (
    DATA_FILE,
    attack_retrieved,
    attack_version,
    resolve_technique_name,
    technique_name,
    technique_names,
)

REPO_ROOT = Path(__file__).resolve().parents[4]
TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

RULE_TITLE = "Suspicious LSASS Memory Access"


# ── Data file ────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def table() -> dict:
    return json.loads(DATA_FILE.read_text(encoding="utf-8"))


def test_data_file_states_its_provenance_before_the_techniques(table: dict) -> None:
    keys = list(table)
    assert keys.index("techniques") == len(keys) - 1          # the header comes first
    assert table["source"] == "MITRE ATT&CK Enterprise"
    assert re.fullmatch(r"\d+\.\d+", table["attack_version"])
    assert f"ATT%26CK-v{table['attack_version']}" in table["source_url"]
    assert table["source_url"].startswith("https://raw.githubusercontent.com/mitre/cti/")
    assert date.fromisoformat(table["retrieved"]) <= date.today()
    assert "The MITRE Corporation" in table["notice"]


def test_data_file_has_the_enterprise_techniques(table: dict) -> None:
    techniques = table["techniques"]
    assert len(techniques) > 600
    assert all(TECHNIQUE_ID_RE.match(tid) for tid in techniques)
    assert all(isinstance(name, str) and name.strip() == name and name for name in techniques.values())


def test_every_sub_technique_has_its_parent(table: dict) -> None:
    techniques = table["techniques"]
    orphans = [tid for tid in techniques if "." in tid and tid.split(".")[0] not in techniques]
    assert orphans == []


def test_data_file_has_lf_line_endings() -> None:
    assert b"\r" not in DATA_FILE.read_bytes()


def test_notice_file_carries_the_mitre_attribution(table: dict) -> None:
    notice = (REPO_ROOT / "NOTICE").read_text(encoding="utf-8")
    assert "The MITRE Corporation" in notice
    assert "This work is reproduced and distributed with the permission of The MITRE Corporation" in notice
    assert "ATT&CK" in notice
    assert "app/backend/app/data/attack_techniques.json" in notice
    assert table["attack_version"] in notice


# ── Lookup ───────────────────────────────────────────────────────────────────


def test_version_and_retrieval_date_come_from_the_file(table: dict) -> None:
    assert attack_version() == table["attack_version"]
    assert attack_retrieved() == table["retrieved"]


def test_technique_name_of_a_technique(table: dict) -> None:
    assert technique_name("T1059") == table["techniques"]["T1059"] == "Command and Scripting Interpreter"


def test_sub_technique_name_carries_the_parent(table: dict) -> None:
    assert table["techniques"]["T1003.001"] == "LSASS Memory"
    assert technique_name("T1003.001") == "OS Credential Dumping: LSASS Memory"
    assert technique_name("T1059.004") == "Command and Scripting Interpreter: Unix Shell"


def test_sub_techniques_with_the_same_short_name_stay_apart(table: dict) -> None:
    assert table["techniques"]["T1078.003"] == "Local Accounts"
    assert technique_name("T1078.003") == "Valid Accounts: Local Accounts"
    assert technique_name("T1136.001") == "Create Account: Local Account"


@pytest.mark.parametrize("technique_id", ["t1059", " T1059 ", "t1003.001"])
def test_lookup_ignores_case_and_surrounding_space(technique_id: str) -> None:
    assert technique_name(technique_id) == technique_name(technique_id.strip().upper())
    assert technique_name(technique_id)


@pytest.mark.parametrize("technique_id", [None, "", "unknown", "T9999", "T1059.999", "TA0002"])
def test_unknown_ids_have_no_name(technique_id: str | None) -> None:
    assert technique_name(technique_id) is None


def test_technique_names_covers_the_whole_table(table: dict) -> None:
    names = technique_names()
    assert set(names) == set(table["techniques"])
    assert all(": " in names[tid] for tid in names if "." in tid)


def test_resolve_prefers_the_table_then_the_stored_value_then_the_id() -> None:
    assert resolve_technique_name("T1059", RULE_TITLE) == "Command and Scripting Interpreter"
    assert resolve_technique_name("T9999", "Stored name") == "Stored name"
    assert resolve_technique_name("T9999", None) == "T9999"
    assert resolve_technique_name("unknown", "") == "unknown"
    assert resolve_technique_name(None, None) == ""


# ── Alert manager: new detections ────────────────────────────────────────────


async def _persisted(technique_ids: list[str]) -> dict:
    scored = {
        "id": "8a1f0f0e-2f4b-4a51-9b9d-1b1c8f4f7c55",
        "score": 7.2,
        "level": "high",
        "rule_id": "7d0c5a0e-52c7-4c0e-9d0a-6f1f3a2b9c11",
        "rule_title": RULE_TITLE,
        "technique_ids": technique_ids,
        "tactic_ids": ["TA0006"],
        "host": "dc01",
        "time": datetime.now(UTC).isoformat(),
    }
    session = AsyncMock()
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)
    manager = AlertManager(InMemoryQueue())
    with (
        patch.object(manager, "_correlate_incident", new=AsyncMock()),
        patch("app.core.database.AsyncSessionLocal", return_value=session),
        patch("app.repositories.detection_repo.DetectionRepo.create", new=AsyncMock()) as create,
    ):
        await manager._persist_to_db(scored)
    return create.await_args.kwargs


async def test_new_detection_stores_the_attack_name_not_the_rule_title() -> None:
    stored = await _persisted(["T1003.001", "T1059"])

    assert stored["technique_id"] == "T1003.001"
    assert stored["technique_name"] == "OS Credential Dumping: LSASS Memory"
    assert stored["name"] == RULE_TITLE


async def test_new_detection_with_an_unknown_technique_stores_the_id() -> None:
    assert (await _persisted(["T9999"]))["technique_name"] == "T9999"


async def test_new_detection_without_a_technique_stores_unknown() -> None:
    stored = await _persisted([])

    assert stored["technique_id"] == "unknown"
    assert stored["technique_name"] == "unknown"


# ── Readers: existing rows ───────────────────────────────────────────────────


@pytest.fixture
async def legacy_rows(db_session: AsyncSession) -> None:
    """Rows as the pipeline wrote them before the table existed: the rule title
    sits in technique_name."""
    now = datetime.now(UTC)
    db_session.add_all([
        Detection(
            id="det-known", score=9.0, severity="critical", technique_id="T1003.001",
            technique_name=RULE_TITLE, name=RULE_TITLE, host="dc01", tactic="TA0006", time=now,
        ),
        Detection(
            id="det-unknown-id", score=8.0, severity="high", technique_id="T9999",
            technique_name="Custom rule title", name="Custom rule title", host="app02",
            tactic="TA0002", time=now,
        ),
        Incident(
            title="Credential theft on dc01", severity="critical", status="new",
            detection_ids=["det-known"], technique_ids=["T1003.001"], tactic_ids=["TA0006"],
            hosts=["dc01"], created_by="analyst@mxtac.local",
        ),
    ])
    await db_session.commit()


async def test_detection_list_answers_legacy_rows_with_the_attack_name(
    client: AsyncClient, auth_headers: dict, legacy_rows: None,
) -> None:
    resp = await client.get("/api/v1/detections", headers=auth_headers)

    names = {d["id"]: d["technique_name"] for d in resp.json()["items"]}
    assert names == {
        "det-known": "OS Credential Dumping: LSASS Memory",
        "det-unknown-id": "Custom rule title",        # unknown ID: the stored value is kept
    }


async def test_overview_recent_detections_use_the_attack_name(
    client: AsyncClient, auth_headers: dict, legacy_rows: None,
) -> None:
    resp = await client.get("/api/v1/overview/recent-detections", headers=auth_headers)

    names = {d["id"]: d["technique_name"] for d in resp.json()}
    assert names["det-known"] == "OS Credential Dumping: LSASS Memory"


async def test_incident_detail_uses_the_attack_name(
    client: AsyncClient, auth_headers: dict, legacy_rows: None,
) -> None:
    incident_id = (await client.get("/api/v1/incidents", headers=auth_headers)).json()["items"][0]["id"]

    resp = await client.get(f"/api/v1/incidents/{incident_id}", headers=auth_headers)

    (detection,) = resp.json()["detections"]
    assert detection["technique_name"] == "OS Credential Dumping: LSASS Memory"


async def test_stored_rows_are_not_rewritten_by_reading(
    client: AsyncClient, auth_headers: dict, legacy_rows: None, db_session: AsyncSession,
) -> None:
    await client.get("/api/v1/detections", headers=auth_headers)

    row = await db_session.get(Detection, "det-known")
    assert row.technique_name == RULE_TITLE


# ── GET /attack/techniques ───────────────────────────────────────────────────


async def test_technique_table_endpoint(client: AsyncClient, viewer_headers: dict, table: dict) -> None:
    resp = await client.get("/api/v1/attack/techniques", headers=viewer_headers)

    assert resp.status_code == 200
    body = resp.json()
    assert body["attack_version"] == table["attack_version"]
    assert body["retrieved"] == table["retrieved"]
    assert body["techniques"] == technique_names()
    assert body["techniques"]["T1003.001"] == "OS Credential Dumping: LSASS Memory"


async def test_technique_table_endpoint_needs_a_session(client: AsyncClient) -> None:
    assert (await client.get("/api/v1/attack/techniques")).status_code == 401


# ── Coverage heatmap ─────────────────────────────────────────────────────────


async def test_heatmap_rows_name_their_technique_family(
    client: AsyncClient, auth_headers: dict,
) -> None:
    resp = await client.get("/api/v1/overview/coverage/heatmap", headers=auth_headers)

    assert resp.status_code == 200
    rows = resp.json()
    assert rows
    for row in rows:
        assert row["technique_name"] == technique_name(row["technique_id"])
        assert row["technique_name"]
