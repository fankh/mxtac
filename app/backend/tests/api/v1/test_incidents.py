"""Tests for incidents CRUD endpoints — POST, GET list, GET detail, PATCH.

Covers:
- POST /incidents: create, auth, validation, detection linking
- GET /incidents: list, pagination, filtering
- GET /incidents/{id}: detail, 404, auth
- PATCH /incidents/{id}: update, status transitions, detection sync, auth
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
    "title": "Test Incident",
    "description": "Integration test incident.",
    "severity": "high",
    "detection_ids": [],
}


async def _create_incident(client: AsyncClient, headers: dict, **overrides) -> int:
    """POST a new incident and return its id."""
    body = {**_BASE_INCIDENT, **overrides}
    resp = await client.post("/api/v1/incidents", json=body, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


async def _insert_detection(
    db: AsyncSession,
    *,
    technique_id: str = "T1003",
    tactic_id: str = "TA0006",
    host: str = "host-01",
) -> str:
    """Insert a Detection directly into the test DB and return its ID."""
    det_id = str(uuid.uuid4())
    det = Detection(
        id=det_id,
        score=7.5,
        severity="high",
        technique_id=technique_id,
        technique_name="OS Credential Dumping",
        tactic="Credential Access",
        tactic_id=tactic_id,
        name="Credential Access Detection",
        host=host,
        status="active",
        time=datetime.now(timezone.utc),
    )
    db.add(det)
    await db.flush()
    return det_id


# ============================================================================
# POST /incidents — CREATE
# ============================================================================


@pytest.mark.asyncio
async def test_create_incident_returns_201(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Analyst can create an incident; response is 201 with the incident body."""
    resp = await client.post(
        "/api/v1/incidents", json=_BASE_INCIDENT, headers=analyst_headers
    )

    assert resp.status_code == 201
    data = resp.json()
    assert data["title"] == _BASE_INCIDENT["title"]
    assert data["severity"] == _BASE_INCIDENT["severity"]
    assert data["id"] > 0


@pytest.mark.asyncio
async def test_create_incident_default_fields(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Newly created incident has correct defaults populated."""
    resp = await client.post(
        "/api/v1/incidents", json=_BASE_INCIDENT, headers=analyst_headers
    )

    data = resp.json()
    assert data["status"] == "new"
    assert data["priority"] == 3
    assert data["created_by"] == "analyst@mxtac.local"
    assert data["assigned_to"] is None
    assert data["detection_ids"] == []
    assert data["technique_ids"] == []
    assert data["tactic_ids"] == []
    assert data["hosts"] == []
    assert data["ttd_seconds"] is None
    assert data["ttr_seconds"] is None
    assert data["closed_at"] is None


@pytest.mark.asyncio
async def test_create_incident_with_assignment(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """assigned_to is preserved when provided."""
    resp = await client.post(
        "/api/v1/incidents",
        json={**_BASE_INCIDENT, "assigned_to": "hunter@mxtac.local"},
        headers=analyst_headers,
    )

    assert resp.status_code == 201
    assert resp.json()["assigned_to"] == "hunter@mxtac.local"


@pytest.mark.asyncio
async def test_create_incident_links_detection_and_extracts_entities(
    client: AsyncClient,
    analyst_headers: dict,
    db_session: AsyncSession,
) -> None:
    """Linking a detection extracts technique_id, tactic_id, and host."""
    det_id = await _insert_detection(
        db_session, technique_id="T1059", tactic_id="TA0002", host="ws-victim"
    )

    resp = await client.post(
        "/api/v1/incidents",
        json={**_BASE_INCIDENT, "detection_ids": [det_id]},
        headers=analyst_headers,
    )

    assert resp.status_code == 201
    data = resp.json()
    assert det_id in data["detection_ids"]
    assert "T1059" in data["technique_ids"]
    assert "TA0002" in data["tactic_ids"]
    assert "ws-victim" in data["hosts"]


@pytest.mark.asyncio
async def test_create_incident_missing_detection_returns_404(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Linking a nonexistent detection_id returns 404."""
    resp = await client.post(
        "/api/v1/incidents",
        json={**_BASE_INCIDENT, "detection_ids": ["nonexistent-uuid"]},
        headers=analyst_headers,
    )

    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_create_incident_viewer_denied(
    client: AsyncClient, viewer_headers: dict
) -> None:
    """Viewer cannot create incidents (403)."""
    resp = await client.post(
        "/api/v1/incidents", json=_BASE_INCIDENT, headers=viewer_headers
    )

    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_create_incident_unauthenticated(client: AsyncClient) -> None:
    """Unauthenticated request returns 401."""
    resp = await client.post("/api/v1/incidents", json=_BASE_INCIDENT)

    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_create_incident_empty_title_returns_422(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Empty title fails validation (422)."""
    resp = await client.post(
        "/api/v1/incidents",
        json={**_BASE_INCIDENT, "title": ""},
        headers=analyst_headers,
    )

    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_incident_invalid_severity_returns_422(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Invalid severity value fails validation (422)."""
    resp = await client.post(
        "/api/v1/incidents",
        json={**_BASE_INCIDENT, "severity": "extreme"},
        headers=analyst_headers,
    )

    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_incident_invalid_assigned_to_email_returns_422(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """assigned_to must be a valid email; invalid value returns 422."""
    resp = await client.post(
        "/api/v1/incidents",
        json={**_BASE_INCIDENT, "assigned_to": "not-an-email"},
        headers=analyst_headers,
    )

    assert resp.status_code == 422


# ============================================================================
# GET /incidents — LIST
# ============================================================================


@pytest.mark.asyncio
async def test_list_incidents_empty(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Empty DB returns empty items list with correct pagination metadata."""
    resp = await client.get("/api/v1/incidents", headers=analyst_headers)

    assert resp.status_code == 200
    data = resp.json()
    assert data["items"] == []
    assert data["pagination"]["total"] == 0
    assert data["pagination"]["page"] == 1


@pytest.mark.asyncio
async def test_list_incidents_returns_created(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Created incidents appear in the list response."""
    await _create_incident(client, analyst_headers, title="Incident Alpha")
    await _create_incident(client, analyst_headers, title="Incident Beta")

    resp = await client.get("/api/v1/incidents", headers=analyst_headers)

    assert resp.status_code == 200
    data = resp.json()
    assert data["pagination"]["total"] == 2
    titles = [item["title"] for item in data["items"]]
    assert "Incident Alpha" in titles
    assert "Incident Beta" in titles


@pytest.mark.asyncio
async def test_list_incidents_viewer_can_access(
    client: AsyncClient, analyst_headers: dict, viewer_headers: dict
) -> None:
    """Viewer role (incidents:read) can list incidents."""
    await _create_incident(client, analyst_headers)

    resp = await client.get("/api/v1/incidents", headers=viewer_headers)

    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_list_incidents_unauthenticated(client: AsyncClient) -> None:
    """Unauthenticated request returns 401."""
    resp = await client.get("/api/v1/incidents")

    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_list_incidents_filter_by_severity(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """severity filter returns only matching incidents."""
    await _create_incident(client, analyst_headers, severity="critical")
    await _create_incident(client, analyst_headers, severity="low")

    resp = await client.get("/api/v1/incidents?severity=critical", headers=analyst_headers)

    assert resp.status_code == 200
    data = resp.json()
    assert data["pagination"]["total"] == 1
    assert data["items"][0]["severity"] == "critical"


@pytest.mark.asyncio
async def test_list_incidents_filter_by_status(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """status filter returns only matching incidents."""
    inc_id = await _create_incident(client, analyst_headers)
    await client.patch(
        f"/api/v1/incidents/{inc_id}",
        json={"status": "investigating"},
        headers=analyst_headers,
    )
    await _create_incident(client, analyst_headers)  # stays 'new'

    resp = await client.get(
        "/api/v1/incidents?status=investigating", headers=analyst_headers
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data["pagination"]["total"] == 1
    assert data["items"][0]["status"] == "investigating"


@pytest.mark.asyncio
async def test_list_incidents_filter_by_assigned_to(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """assigned_to filter returns only matching incidents."""
    await _create_incident(client, analyst_headers, assigned_to="hunter@mxtac.local")
    await _create_incident(client, analyst_headers)  # unassigned

    resp = await client.get(
        "/api/v1/incidents?assigned_to=hunter@mxtac.local", headers=analyst_headers
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data["pagination"]["total"] == 1
    assert data["items"][0]["assigned_to"] == "hunter@mxtac.local"


@pytest.mark.asyncio
async def test_list_incidents_search_title(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """search parameter matches incident title."""
    await _create_incident(client, analyst_headers, title="DCSync Attack Detected")
    await _create_incident(client, analyst_headers, title="Phishing Campaign")

    resp = await client.get("/api/v1/incidents?search=DCSync", headers=analyst_headers)

    assert resp.status_code == 200
    data = resp.json()
    assert data["pagination"]["total"] == 1
    assert "DCSync" in data["items"][0]["title"]


@pytest.mark.asyncio
async def test_list_incidents_pagination_limits_results(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """page_size limits returned items; pagination metadata is correct."""
    for i in range(5):
        await _create_incident(client, analyst_headers, title=f"Incident {i}")

    resp = await client.get(
        "/api/v1/incidents?page=1&page_size=2", headers=analyst_headers
    )

    assert resp.status_code == 200
    data = resp.json()
    assert len(data["items"]) == 2
    assert data["pagination"]["total"] == 5
    assert data["pagination"]["page_size"] == 2
    assert data["pagination"]["total_pages"] == 3


@pytest.mark.asyncio
async def test_list_incidents_pagination_page_two(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Page 2 returns the correct offset of results."""
    for i in range(5):
        await _create_incident(client, analyst_headers, title=f"Incident {i}")

    resp = await client.get(
        "/api/v1/incidents?page=2&page_size=2", headers=analyst_headers
    )

    assert resp.status_code == 200
    data = resp.json()
    assert len(data["items"]) == 2
    assert data["pagination"]["page"] == 2


# ============================================================================
# GET /incidents/{id} — DETAIL
# ============================================================================


@pytest.mark.asyncio
async def test_get_incident_returns_detail(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """GET /incidents/{id} returns full incident detail."""
    incident_id = await _create_incident(client, analyst_headers, title="Detail Test")

    resp = await client.get(f"/api/v1/incidents/{incident_id}", headers=analyst_headers)

    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == incident_id
    assert data["title"] == "Detail Test"
    assert data["status"] == "new"
    assert isinstance(data["notes"], list)
    assert isinstance(data["detections"], list)
    assert isinstance(data["duration_seconds"], int)
    assert data["duration_seconds"] >= 0


@pytest.mark.asyncio
async def test_get_incident_fresh_has_empty_notes_and_detections(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Newly created incident has empty notes and detections lists."""
    incident_id = await _create_incident(client, analyst_headers)

    resp = await client.get(f"/api/v1/incidents/{incident_id}", headers=analyst_headers)

    data = resp.json()
    assert data["notes"] == []
    assert data["detections"] == []


@pytest.mark.asyncio
async def test_get_incident_viewer_can_access(
    client: AsyncClient, analyst_headers: dict, viewer_headers: dict
) -> None:
    """Viewer role (incidents:read) can retrieve incident detail."""
    incident_id = await _create_incident(client, analyst_headers)

    resp = await client.get(f"/api/v1/incidents/{incident_id}", headers=viewer_headers)

    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_get_incident_404_for_missing(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Returns 404 when incident does not exist."""
    resp = await client.get("/api/v1/incidents/999999", headers=analyst_headers)

    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_get_incident_unauthenticated(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Unauthenticated request returns 401."""
    incident_id = await _create_incident(client, analyst_headers)

    resp = await client.get(f"/api/v1/incidents/{incident_id}")

    assert resp.status_code == 401


# ============================================================================
# PATCH /incidents/{id} — UPDATE
# ============================================================================


@pytest.mark.asyncio
async def test_patch_incident_title(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """PATCH updates the incident title."""
    incident_id = await _create_incident(client, analyst_headers)

    resp = await client.patch(
        f"/api/v1/incidents/{incident_id}",
        json={"title": "Updated Title"},
        headers=analyst_headers,
    )

    assert resp.status_code == 200
    assert resp.json()["title"] == "Updated Title"


@pytest.mark.asyncio
async def test_patch_incident_severity(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """PATCH updates incident severity."""
    incident_id = await _create_incident(client, analyst_headers, severity="low")

    resp = await client.patch(
        f"/api/v1/incidents/{incident_id}",
        json={"severity": "critical"},
        headers=analyst_headers,
    )

    assert resp.status_code == 200
    assert resp.json()["severity"] == "critical"


@pytest.mark.asyncio
async def test_patch_incident_status_forward(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Valid forward status transition (new → investigating) succeeds."""
    incident_id = await _create_incident(client, analyst_headers)

    resp = await client.patch(
        f"/api/v1/incidents/{incident_id}",
        json={"status": "investigating"},
        headers=analyst_headers,
    )

    assert resp.status_code == 200
    assert resp.json()["status"] == "investigating"


@pytest.mark.asyncio
async def test_patch_incident_status_backward_rejected(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Backward status transition is rejected with 422."""
    incident_id = await _create_incident(client, analyst_headers)
    await client.patch(
        f"/api/v1/incidents/{incident_id}",
        json={"status": "investigating"},
        headers=analyst_headers,
    )

    resp = await client.patch(
        f"/api/v1/incidents/{incident_id}",
        json={"status": "new"},
        headers=analyst_headers,
    )

    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_patch_incident_status_to_resolved_sets_closed_at(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Transitioning to 'resolved' auto-sets closed_at and ttr_seconds."""
    incident_id = await _create_incident(client, analyst_headers)

    resp = await client.patch(
        f"/api/v1/incidents/{incident_id}",
        json={"status": "resolved"},
        headers=analyst_headers,
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data["closed_at"] is not None
    assert data["ttr_seconds"] is not None
    assert data["ttr_seconds"] >= 0


@pytest.mark.asyncio
async def test_patch_incident_status_change_creates_auto_note(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Status change auto-creates a status_change note in the timeline."""
    incident_id = await _create_incident(client, analyst_headers)

    await client.patch(
        f"/api/v1/incidents/{incident_id}",
        json={"status": "investigating"},
        headers=analyst_headers,
    )

    notes_resp = await client.get(
        f"/api/v1/incidents/{incident_id}/notes",
        headers=analyst_headers,
    )
    notes = notes_resp.json()
    assert len(notes) == 1
    assert notes[0]["note_type"] == "status_change"
    assert "investigating" in notes[0]["content"].lower()


@pytest.mark.asyncio
async def test_patch_incident_assign(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """PATCH can set assigned_to."""
    incident_id = await _create_incident(client, analyst_headers)

    resp = await client.patch(
        f"/api/v1/incidents/{incident_id}",
        json={"assigned_to": "hunter@mxtac.local"},
        headers=analyst_headers,
    )

    assert resp.status_code == 200
    assert resp.json()["assigned_to"] == "hunter@mxtac.local"


@pytest.mark.asyncio
async def test_patch_incident_unassign(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """PATCH can clear assigned_to by sending null."""
    incident_id = await _create_incident(
        client, analyst_headers, assigned_to="analyst@mxtac.local"
    )

    resp = await client.patch(
        f"/api/v1/incidents/{incident_id}",
        json={"assigned_to": None},
        headers=analyst_headers,
    )

    assert resp.status_code == 200
    assert resp.json()["assigned_to"] is None


@pytest.mark.asyncio
async def test_patch_incident_invalid_email_returns_422(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Invalid email for assigned_to returns 422."""
    incident_id = await _create_incident(client, analyst_headers)

    resp = await client.patch(
        f"/api/v1/incidents/{incident_id}",
        json={"assigned_to": "bad-email"},
        headers=analyst_headers,
    )

    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_patch_incident_viewer_denied(
    client: AsyncClient, analyst_headers: dict, viewer_headers: dict
) -> None:
    """Viewer role is denied (403)."""
    incident_id = await _create_incident(client, analyst_headers)

    resp = await client.patch(
        f"/api/v1/incidents/{incident_id}",
        json={"title": "Viewer Cannot Do This"},
        headers=viewer_headers,
    )

    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_patch_incident_unauthenticated(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Unauthenticated request returns 401."""
    incident_id = await _create_incident(client, analyst_headers)

    resp = await client.patch(
        f"/api/v1/incidents/{incident_id}",
        json={"title": "Anon Cannot Do This"},
    )

    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_patch_incident_404_for_missing(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Returns 404 when incident does not exist."""
    resp = await client.patch(
        "/api/v1/incidents/999999",
        json={"title": "Ghost"},
        headers=analyst_headers,
    )

    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_patch_incident_update_detection_ids_syncs_entities(
    client: AsyncClient,
    analyst_headers: dict,
    db_session: AsyncSession,
) -> None:
    """Updating detection_ids re-syncs technique_ids, tactic_ids, and hosts."""
    det_id = await _insert_detection(
        db_session, technique_id="T1078", tactic_id="TA0001", host="dc-01"
    )
    incident_id = await _create_incident(client, analyst_headers)

    resp = await client.patch(
        f"/api/v1/incidents/{incident_id}",
        json={"detection_ids": [det_id]},
        headers=analyst_headers,
    )

    assert resp.status_code == 200
    data = resp.json()
    assert det_id in data["detection_ids"]
    assert "T1078" in data["technique_ids"]
    assert "TA0001" in data["tactic_ids"]
    assert "dc-01" in data["hosts"]


@pytest.mark.asyncio
async def test_patch_incident_missing_detection_returns_404(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Updating detection_ids with a nonexistent ID returns 404."""
    incident_id = await _create_incident(client, analyst_headers)

    resp = await client.patch(
        f"/api/v1/incidents/{incident_id}",
        json={"detection_ids": ["does-not-exist"]},
        headers=analyst_headers,
    )

    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_patch_incident_empty_body_no_error(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """PATCH with empty body returns 200 and leaves incident unchanged."""
    incident_id = await _create_incident(client, analyst_headers, title="Stable")

    resp = await client.patch(
        f"/api/v1/incidents/{incident_id}",
        json={},
        headers=analyst_headers,
    )

    assert resp.status_code == 200
    assert resp.json()["title"] == "Stable"
