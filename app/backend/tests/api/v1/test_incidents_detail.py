"""Tests for Feature 26.5 — GET /incidents/{id} — detail with timeline.

Verifies:
- Full incident fields are present in the response
- Linked detections returned as full detection objects
- Missing/deleted detection_ids are silently skipped
- Notes/timeline entries appear in the detail response
- duration_seconds is computed from created_at to closed_at for closed incidents
- duration_seconds is computed from created_at to now for open incidents
- 404 returned when incident does not exist
- Viewer+ role required (viewer can access; unauthenticated gets 401)
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.detection import Detection

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_BASE_INCIDENT = {
    "title": "Detail Test Incident",
    "description": "Created for detail endpoint testing.",
    "severity": "high",
    "detection_ids": [],
}


async def _create_incident(client: AsyncClient, headers: dict, **overrides) -> int:
    body = {**_BASE_INCIDENT, **overrides}
    resp = await client.post("/api/v1/incidents", json=body, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


async def _insert_detection(
    db: AsyncSession,
    *,
    technique_id: str = "T1059",
    tactic_id: str = "TA0002",
    host: str = "ws-01",
) -> str:
    det_id = str(uuid.uuid4())
    det = Detection(
        id=det_id,
        score=8.0,
        severity="high",
        technique_id=technique_id,
        technique_name="Command and Scripting Interpreter",
        tactic="Execution",
        tactic_id=tactic_id,
        name="Suspicious Script Execution",
        host=host,
        status="active",
        time=datetime.now(timezone.utc),
    )
    db.add(det)
    await db.flush()
    return det_id


# ---------------------------------------------------------------------------
# Full field coverage
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_detail_contains_all_incident_fields(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """GET /incidents/{id} returns all expected incident fields."""
    incident_id = await _create_incident(
        client,
        analyst_headers,
        title="Full Fields Check",
        description="Testing all fields.",
        severity="critical",
        assigned_to="hunter@mxtac.local",
    )

    resp = await client.get(f"/api/v1/incidents/{incident_id}", headers=analyst_headers)

    assert resp.status_code == 200
    data = resp.json()

    # Core identity
    assert data["id"] == incident_id
    assert data["title"] == "Full Fields Check"
    assert data["description"] == "Testing all fields."
    assert data["severity"] == "critical"
    assert data["status"] == "new"
    assert data["priority"] == 3
    assert data["assigned_to"] == "hunter@mxtac.local"
    assert data["created_by"] == "analyst@mxtac.local"

    # Entity lists
    assert isinstance(data["detection_ids"], list)
    assert isinstance(data["technique_ids"], list)
    assert isinstance(data["tactic_ids"], list)
    assert isinstance(data["hosts"], list)

    # Metrics
    assert data["ttd_seconds"] is None
    assert data["ttr_seconds"] is None
    assert data["closed_at"] is None

    # Timestamps
    assert "created_at" in data
    assert "updated_at" in data

    # Detail-specific
    assert isinstance(data["detections"], list)
    assert isinstance(data["notes"], list)
    assert isinstance(data["duration_seconds"], int)


# ---------------------------------------------------------------------------
# Linked detections
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_detail_returns_full_detection_objects(
    client: AsyncClient,
    analyst_headers: dict,
    db_session: AsyncSession,
) -> None:
    """When detections are linked, the detail response includes full detection objects."""
    det_id = await _insert_detection(
        db_session, technique_id="T1003", tactic_id="TA0006", host="dc-victim"
    )
    incident_id = await _create_incident(
        client, analyst_headers, detection_ids=[det_id]
    )

    resp = await client.get(f"/api/v1/incidents/{incident_id}", headers=analyst_headers)

    assert resp.status_code == 200
    data = resp.json()
    assert len(data["detections"]) == 1

    det = data["detections"][0]
    assert det["id"] == det_id
    assert det["technique_id"] == "T1003"
    assert det["tactic_id"] == "TA0006"
    assert det["host"] == "dc-victim"
    assert det["severity"] == "high"
    assert det["status"] == "active"


@pytest.mark.asyncio
async def test_detail_returns_multiple_detections(
    client: AsyncClient,
    analyst_headers: dict,
    db_session: AsyncSession,
) -> None:
    """All linked detection IDs appear as full objects in the response."""
    det_id_1 = await _insert_detection(
        db_session, technique_id="T1003", tactic_id="TA0006", host="host-a"
    )
    det_id_2 = await _insert_detection(
        db_session, technique_id="T1059", tactic_id="TA0002", host="host-b"
    )
    incident_id = await _create_incident(
        client, analyst_headers, detection_ids=[det_id_1, det_id_2]
    )

    resp = await client.get(f"/api/v1/incidents/{incident_id}", headers=analyst_headers)

    assert resp.status_code == 200
    data = resp.json()
    assert len(data["detections"]) == 2
    returned_ids = {d["id"] for d in data["detections"]}
    assert returned_ids == {det_id_1, det_id_2}


@pytest.mark.asyncio
async def test_detail_skips_missing_detection_ids(
    client: AsyncClient,
    analyst_headers: dict,
    db_session: AsyncSession,
) -> None:
    """Detection IDs that no longer exist in the DB are silently skipped."""
    # Insert one real detection, then patch detection_ids to include a ghost ID
    det_id = await _insert_detection(db_session)
    incident_id = await _create_incident(
        client, analyst_headers, detection_ids=[det_id]
    )

    # Patch in a non-existent detection ID by first adding it directly via DB
    # We simulate a "deleted" detection by using a UUID that was never inserted
    ghost_id = str(uuid.uuid4())

    # Bypass the endpoint (which validates detection existence) by updating the DB
    from app.models.incident import Incident as IncidentModel
    from sqlalchemy import select

    result = await db_session.execute(
        select(IncidentModel).where(IncidentModel.id == incident_id)
    )
    inc = result.scalar_one()
    inc.detection_ids = [det_id, ghost_id]
    await db_session.flush()

    resp = await client.get(f"/api/v1/incidents/{incident_id}", headers=analyst_headers)

    assert resp.status_code == 200
    data = resp.json()
    # Only the real detection is returned; the ghost is skipped
    assert len(data["detections"]) == 1
    assert data["detections"][0]["id"] == det_id


# ---------------------------------------------------------------------------
# Notes / timeline
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_detail_includes_notes_added_via_post(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Notes added via POST /notes appear in the GET detail response."""
    incident_id = await _create_incident(client, analyst_headers)

    await client.post(
        f"/api/v1/incidents/{incident_id}/notes",
        json={"content": "Initial triage.", "note_type": "comment"},
        headers=analyst_headers,
    )
    await client.post(
        f"/api/v1/incidents/{incident_id}/notes",
        json={"content": "Memory dump collected.", "note_type": "evidence"},
        headers=analyst_headers,
    )

    resp = await client.get(f"/api/v1/incidents/{incident_id}", headers=analyst_headers)

    assert resp.status_code == 200
    notes = resp.json()["notes"]
    assert len(notes) == 2
    contents = {n["content"] for n in notes}
    assert "Initial triage." in contents
    assert "Memory dump collected." in contents


@pytest.mark.asyncio
async def test_detail_notes_have_required_fields(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Each note in detail response contains id, author, content, note_type, created_at."""
    incident_id = await _create_incident(client, analyst_headers)
    await client.post(
        f"/api/v1/incidents/{incident_id}/notes",
        json={"content": "Field check note.", "note_type": "comment"},
        headers=analyst_headers,
    )

    resp = await client.get(f"/api/v1/incidents/{incident_id}", headers=analyst_headers)

    note = resp.json()["notes"][0]
    assert "id" in note
    assert note["author"] == "analyst@mxtac.local"
    assert note["content"] == "Field check note."
    assert note["note_type"] == "comment"
    assert "created_at" in note


@pytest.mark.asyncio
async def test_detail_includes_status_change_auto_notes(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Status-change auto-notes from PATCH appear in the detail notes list."""
    incident_id = await _create_incident(client, analyst_headers)

    await client.patch(
        f"/api/v1/incidents/{incident_id}",
        json={"status": "investigating"},
        headers=analyst_headers,
    )

    resp = await client.get(f"/api/v1/incidents/{incident_id}", headers=analyst_headers)

    assert resp.status_code == 200
    notes = resp.json()["notes"]
    assert len(notes) == 1
    assert notes[0]["note_type"] == "status_change"
    assert "investigating" in notes[0]["content"]


# ---------------------------------------------------------------------------
# duration_seconds
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_detail_duration_seconds_non_negative_for_open_incident(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Open incident duration_seconds is >= 0 (measured from created_at to now)."""
    incident_id = await _create_incident(client, analyst_headers)

    resp = await client.get(f"/api/v1/incidents/{incident_id}", headers=analyst_headers)

    assert resp.status_code == 200
    assert resp.json()["duration_seconds"] >= 0


@pytest.mark.asyncio
async def test_detail_duration_seconds_for_closed_incident(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Closed incident duration_seconds is computed from created_at to closed_at."""
    incident_id = await _create_incident(client, analyst_headers)

    # Advance status to resolved to trigger closed_at
    patch_resp = await client.patch(
        f"/api/v1/incidents/{incident_id}",
        json={"status": "resolved"},
        headers=analyst_headers,
    )
    assert patch_resp.status_code == 200
    patch_data = patch_resp.json()
    assert patch_data["closed_at"] is not None

    detail_resp = await client.get(
        f"/api/v1/incidents/{incident_id}", headers=analyst_headers
    )

    assert detail_resp.status_code == 200
    data = detail_resp.json()
    assert data["duration_seconds"] >= 0
    # For a resolved incident, ttr_seconds should equal duration_seconds (both use closed_at)
    assert data["ttr_seconds"] is not None
    # duration_seconds should be close to ttr_seconds since both measure created → closed_at
    assert abs(data["duration_seconds"] - data["ttr_seconds"]) <= 1


# ---------------------------------------------------------------------------
# 404 and auth
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_detail_returns_404_for_missing_incident(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """GET /incidents/999999 returns 404 when incident does not exist."""
    resp = await client.get("/api/v1/incidents/999999", headers=analyst_headers)

    assert resp.status_code == 404
    assert "999999" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_detail_viewer_can_access(
    client: AsyncClient, analyst_headers: dict, viewer_headers: dict
) -> None:
    """Viewer role (incidents:read) can retrieve incident detail."""
    incident_id = await _create_incident(client, analyst_headers)

    resp = await client.get(f"/api/v1/incidents/{incident_id}", headers=viewer_headers)

    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_detail_unauthenticated_returns_401(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Unauthenticated request to incident detail returns 401."""
    incident_id = await _create_incident(client, analyst_headers)

    resp = await client.get(f"/api/v1/incidents/{incident_id}")

    assert resp.status_code == 401
