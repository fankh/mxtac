"""Tests for Feature 26.7 — Incident notes / timeline.

Verifies:
- POST /incidents/{id}/notes — adds a timestamped note (analyst+)
- GET  /incidents/{id}/notes — lists notes sorted chronologically (viewer+)
- Auto-note is created when incident status changes via PATCH
- note_type defaults to "comment"; accepts "evidence" and "status_change"
- Viewer cannot add notes (403); unauthenticated gets 401
- 404 returned when incident does not exist
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_BASE_INCIDENT = {
    "title": "Test Incident for Notes",
    "description": "Integration test incident.",
    "severity": "high",
    "detection_ids": [],
}


async def _create_incident(client: AsyncClient, headers: dict) -> int:
    resp = await client.post("/api/v1/incidents", json=_BASE_INCIDENT, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


# ---------------------------------------------------------------------------
# POST /incidents/{id}/notes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_analyst_can_add_comment_note(client: AsyncClient, analyst_headers: dict) -> None:
    """Analyst adds a comment note; response includes all expected fields."""
    incident_id = await _create_incident(client, analyst_headers)

    resp = await client.post(
        f"/api/v1/incidents/{incident_id}/notes",
        json={"content": "Initial triage complete.", "note_type": "comment"},
        headers=analyst_headers,
    )

    assert resp.status_code == 201
    data = resp.json()
    assert data["content"] == "Initial triage complete."
    assert data["note_type"] == "comment"
    assert data["author"] == "analyst@mxtac.local"
    assert "id" in data
    assert "created_at" in data


@pytest.mark.asyncio
async def test_analyst_can_add_evidence_note(client: AsyncClient, analyst_headers: dict) -> None:
    """Analyst adds an evidence note with note_type='evidence'."""
    incident_id = await _create_incident(client, analyst_headers)

    resp = await client.post(
        f"/api/v1/incidents/{incident_id}/notes",
        json={"content": "Collected memory dump from WS-CORP-42.", "note_type": "evidence"},
        headers=analyst_headers,
    )

    assert resp.status_code == 201
    assert resp.json()["note_type"] == "evidence"


@pytest.mark.asyncio
async def test_note_type_defaults_to_comment(client: AsyncClient, analyst_headers: dict) -> None:
    """Omitting note_type defaults to 'comment'."""
    incident_id = await _create_incident(client, analyst_headers)

    resp = await client.post(
        f"/api/v1/incidents/{incident_id}/notes",
        json={"content": "No explicit type."},
        headers=analyst_headers,
    )

    assert resp.status_code == 201
    assert resp.json()["note_type"] == "comment"


@pytest.mark.asyncio
async def test_add_note_author_from_jwt(client: AsyncClient, hunter_headers: dict) -> None:
    """Author is automatically set from the JWT, not from request body."""
    # Create incident as analyst, add note as hunter
    analyst_resp = await client.post(
        "/api/v1/incidents",
        json=_BASE_INCIDENT,
        headers={"Authorization": "Bearer " + _token_from_headers(hunter_headers)},
    )
    # Use hunter to create and add note
    incident_id = await _create_incident(client, hunter_headers)

    resp = await client.post(
        f"/api/v1/incidents/{incident_id}/notes",
        json={"content": "Hunter added this note."},
        headers=hunter_headers,
    )

    assert resp.status_code == 201
    assert resp.json()["author"] == "hunter@mxtac.local"


def _token_from_headers(headers: dict) -> str:
    return headers["Authorization"].split(" ", 1)[1]


@pytest.mark.asyncio
async def test_add_note_returns_404_for_missing_incident(
    client: AsyncClient, analyst_headers: dict
) -> None:
    resp = await client.post(
        "/api/v1/incidents/999999/notes",
        json={"content": "Won't save."},
        headers=analyst_headers,
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_viewer_cannot_add_note(client: AsyncClient, analyst_headers: dict, viewer_headers: dict) -> None:
    """Viewer role must be denied (403) when posting a note."""
    incident_id = await _create_incident(client, analyst_headers)

    resp = await client.post(
        f"/api/v1/incidents/{incident_id}/notes",
        json={"content": "Should be blocked."},
        headers=viewer_headers,
    )

    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_unauthenticated_cannot_add_note(client: AsyncClient, analyst_headers: dict) -> None:
    incident_id = await _create_incident(client, analyst_headers)

    resp = await client.post(
        f"/api/v1/incidents/{incident_id}/notes",
        json={"content": "No token."},
    )

    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_add_note_empty_content_rejected(client: AsyncClient, analyst_headers: dict) -> None:
    """Empty content should fail validation (422)."""
    incident_id = await _create_incident(client, analyst_headers)

    resp = await client.post(
        f"/api/v1/incidents/{incident_id}/notes",
        json={"content": ""},
        headers=analyst_headers,
    )

    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# GET /incidents/{id}/notes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_notes_returns_empty_for_new_incident(
    client: AsyncClient, analyst_headers: dict, viewer_headers: dict
) -> None:
    """Fresh incident has no notes."""
    incident_id = await _create_incident(client, analyst_headers)

    resp = await client.get(
        f"/api/v1/incidents/{incident_id}/notes",
        headers=viewer_headers,
    )

    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_list_notes_returns_added_notes(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Notes added via POST appear in GET response."""
    incident_id = await _create_incident(client, analyst_headers)

    await client.post(
        f"/api/v1/incidents/{incident_id}/notes",
        json={"content": "First note.", "note_type": "comment"},
        headers=analyst_headers,
    )
    await client.post(
        f"/api/v1/incidents/{incident_id}/notes",
        json={"content": "Second note.", "note_type": "evidence"},
        headers=analyst_headers,
    )

    resp = await client.get(
        f"/api/v1/incidents/{incident_id}/notes",
        headers=analyst_headers,
    )

    assert resp.status_code == 200
    notes = resp.json()
    assert len(notes) == 2
    contents = [n["content"] for n in notes]
    assert "First note." in contents
    assert "Second note." in contents


@pytest.mark.asyncio
async def test_list_notes_sorted_chronologically(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Notes are returned sorted by created_at ascending (oldest first)."""
    incident_id = await _create_incident(client, analyst_headers)

    for i in range(3):
        await client.post(
            f"/api/v1/incidents/{incident_id}/notes",
            json={"content": f"Note {i}"},
            headers=analyst_headers,
        )

    resp = await client.get(
        f"/api/v1/incidents/{incident_id}/notes",
        headers=analyst_headers,
    )

    assert resp.status_code == 200
    notes = resp.json()
    assert len(notes) == 3
    # Verify timestamps are non-decreasing
    timestamps = [n["created_at"] for n in notes]
    assert timestamps == sorted(timestamps)


@pytest.mark.asyncio
async def test_viewer_can_list_notes(
    client: AsyncClient, analyst_headers: dict, viewer_headers: dict
) -> None:
    """Viewer can read notes (incidents:read permission)."""
    incident_id = await _create_incident(client, analyst_headers)
    await client.post(
        f"/api/v1/incidents/{incident_id}/notes",
        json={"content": "Visible to viewer."},
        headers=analyst_headers,
    )

    resp = await client.get(
        f"/api/v1/incidents/{incident_id}/notes",
        headers=viewer_headers,
    )

    assert resp.status_code == 200
    assert len(resp.json()) == 1


@pytest.mark.asyncio
async def test_list_notes_returns_404_for_missing_incident(
    client: AsyncClient, analyst_headers: dict
) -> None:
    resp = await client.get(
        "/api/v1/incidents/999999/notes",
        headers=analyst_headers,
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_unauthenticated_cannot_list_notes(
    client: AsyncClient, analyst_headers: dict
) -> None:
    incident_id = await _create_incident(client, analyst_headers)

    resp = await client.get(f"/api/v1/incidents/{incident_id}/notes")

    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Auto-note on status change (PATCH /incidents/{id})
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_status_change_creates_auto_note(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """PATCH status transition auto-creates a status_change note."""
    incident_id = await _create_incident(client, analyst_headers)

    patch_resp = await client.patch(
        f"/api/v1/incidents/{incident_id}",
        json={"status": "investigating"},
        headers=analyst_headers,
    )
    assert patch_resp.status_code == 200

    notes_resp = await client.get(
        f"/api/v1/incidents/{incident_id}/notes",
        headers=analyst_headers,
    )
    assert notes_resp.status_code == 200
    notes = notes_resp.json()

    assert len(notes) == 1
    note = notes[0]
    assert note["note_type"] == "status_change"
    assert "new" in note["content"]
    assert "investigating" in note["content"]
    assert note["author"] == "analyst@mxtac.local"


@pytest.mark.asyncio
async def test_multiple_status_changes_create_multiple_auto_notes(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Each status transition creates a separate auto note."""
    incident_id = await _create_incident(client, analyst_headers)

    for new_status in ("investigating", "contained", "resolved"):
        resp = await client.patch(
            f"/api/v1/incidents/{incident_id}",
            json={"status": new_status},
            headers=analyst_headers,
        )
        assert resp.status_code == 200

    notes_resp = await client.get(
        f"/api/v1/incidents/{incident_id}/notes",
        headers=analyst_headers,
    )
    notes = notes_resp.json()

    assert len(notes) == 3
    assert all(n["note_type"] == "status_change" for n in notes)


@pytest.mark.asyncio
async def test_status_change_note_appears_in_incident_detail(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Status-change auto note is included in GET /incidents/{id} detail view."""
    incident_id = await _create_incident(client, analyst_headers)

    await client.patch(
        f"/api/v1/incidents/{incident_id}",
        json={"status": "investigating"},
        headers=analyst_headers,
    )

    detail_resp = await client.get(
        f"/api/v1/incidents/{incident_id}",
        headers=analyst_headers,
    )
    assert detail_resp.status_code == 200
    detail = detail_resp.json()

    assert len(detail["notes"]) == 1
    assert detail["notes"][0]["note_type"] == "status_change"


@pytest.mark.asyncio
async def test_no_auto_note_when_status_unchanged(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """PATCH without status change does not add any auto note."""
    incident_id = await _create_incident(client, analyst_headers)

    await client.patch(
        f"/api/v1/incidents/{incident_id}",
        json={"priority": 1},
        headers=analyst_headers,
    )

    notes_resp = await client.get(
        f"/api/v1/incidents/{incident_id}/notes",
        headers=analyst_headers,
    )
    assert notes_resp.json() == []


@pytest.mark.asyncio
async def test_manual_and_auto_notes_coexist(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Manual notes and auto status-change notes appear together in chronological order."""
    incident_id = await _create_incident(client, analyst_headers)

    # Add manual note before status change
    await client.post(
        f"/api/v1/incidents/{incident_id}/notes",
        json={"content": "Starting investigation.", "note_type": "comment"},
        headers=analyst_headers,
    )

    # Trigger auto-note via status change
    await client.patch(
        f"/api/v1/incidents/{incident_id}",
        json={"status": "investigating"},
        headers=analyst_headers,
    )

    # Add another manual note after status change
    await client.post(
        f"/api/v1/incidents/{incident_id}/notes",
        json={"content": "Collected evidence.", "note_type": "evidence"},
        headers=analyst_headers,
    )

    notes_resp = await client.get(
        f"/api/v1/incidents/{incident_id}/notes",
        headers=analyst_headers,
    )
    notes = notes_resp.json()

    assert len(notes) == 3
    note_types = [n["note_type"] for n in notes]
    assert "comment" in note_types
    assert "status_change" in note_types
    assert "evidence" in note_types
    # Verify chronological order
    timestamps = [n["created_at"] for n in notes]
    assert timestamps == sorted(timestamps)
