"""Tests for Feature 26.10 — DELETE /incidents/{id} soft delete.

Verifies:
- Admin can soft-delete (status → 'closed'), returns 204 No Content.
- Analyst, hunter, engineer, and viewer are denied (403).
- Unauthenticated request returns 401.
- 404 returned when incident does not exist.
- Soft-deleted incident retains its data but has status 'closed'.
- A timeline note is added recording the deletion.
- Deleting an already-closed incident is idempotent (204).
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_BASE_INCIDENT = {
    "title": "Test Incident for Delete",
    "description": "Integration test incident.",
    "severity": "high",
    "detection_ids": [],
}


async def _create_incident(client: AsyncClient, headers: dict) -> int:
    resp = await client.post("/api/v1/incidents", json=_BASE_INCIDENT, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


# ---------------------------------------------------------------------------
# Happy path — admin soft-delete
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_admin_can_delete_incident(
    client: AsyncClient, analyst_headers: dict, admin_headers: dict
) -> None:
    """Admin soft-deletes an incident; response is 204 with empty body."""
    incident_id = await _create_incident(client, analyst_headers)

    resp = await client.delete(
        f"/api/v1/incidents/{incident_id}",
        headers=admin_headers,
    )

    assert resp.status_code == 204
    assert resp.content == b""


@pytest.mark.asyncio
async def test_delete_sets_status_to_closed(
    client: AsyncClient, analyst_headers: dict, admin_headers: dict
) -> None:
    """After soft delete, incident status is 'closed' and still retrievable."""
    incident_id = await _create_incident(client, analyst_headers)

    await client.delete(f"/api/v1/incidents/{incident_id}", headers=admin_headers)

    get_resp = await client.get(
        f"/api/v1/incidents/{incident_id}",
        headers=analyst_headers,
    )
    assert get_resp.status_code == 200
    data = get_resp.json()
    assert data["status"] == "closed"
    assert data["title"] == _BASE_INCIDENT["title"]


@pytest.mark.asyncio
async def test_delete_sets_closed_at(
    client: AsyncClient, analyst_headers: dict, admin_headers: dict
) -> None:
    """Soft delete populates closed_at timestamp."""
    incident_id = await _create_incident(client, analyst_headers)

    await client.delete(f"/api/v1/incidents/{incident_id}", headers=admin_headers)

    get_resp = await client.get(
        f"/api/v1/incidents/{incident_id}",
        headers=analyst_headers,
    )
    assert get_resp.json()["closed_at"] is not None


@pytest.mark.asyncio
async def test_delete_adds_timeline_note(
    client: AsyncClient, analyst_headers: dict, admin_headers: dict
) -> None:
    """Soft delete appends a status_change note to the incident timeline."""
    incident_id = await _create_incident(client, analyst_headers)

    await client.delete(f"/api/v1/incidents/{incident_id}", headers=admin_headers)

    notes_resp = await client.get(
        f"/api/v1/incidents/{incident_id}/notes",
        headers=analyst_headers,
    )
    assert notes_resp.status_code == 200
    notes = notes_resp.json()
    assert len(notes) == 1
    note = notes[0]
    assert note["note_type"] == "status_change"
    assert note["author"] == "admin@mxtac.local"
    assert "closed" in note["content"].lower()


@pytest.mark.asyncio
async def test_delete_already_closed_incident_is_idempotent(
    client: AsyncClient, analyst_headers: dict, admin_headers: dict
) -> None:
    """Deleting an already-closed incident returns 204 without error."""
    incident_id = await _create_incident(client, analyst_headers)

    # First delete
    resp1 = await client.delete(f"/api/v1/incidents/{incident_id}", headers=admin_headers)
    assert resp1.status_code == 204

    # Second delete
    resp2 = await client.delete(f"/api/v1/incidents/{incident_id}", headers=admin_headers)
    assert resp2.status_code == 204


# ---------------------------------------------------------------------------
# Authorization — non-admin roles must be denied
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_analyst_cannot_delete_incident(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Analyst role is denied (403) when attempting to delete an incident."""
    incident_id = await _create_incident(client, analyst_headers)

    resp = await client.delete(
        f"/api/v1/incidents/{incident_id}",
        headers=analyst_headers,
    )

    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_hunter_cannot_delete_incident(
    client: AsyncClient, analyst_headers: dict, hunter_headers: dict
) -> None:
    """Hunter role is denied (403)."""
    incident_id = await _create_incident(client, analyst_headers)

    resp = await client.delete(
        f"/api/v1/incidents/{incident_id}",
        headers=hunter_headers,
    )

    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_engineer_cannot_delete_incident(
    client: AsyncClient, analyst_headers: dict, engineer_headers: dict
) -> None:
    """Engineer role is denied (403)."""
    incident_id = await _create_incident(client, analyst_headers)

    resp = await client.delete(
        f"/api/v1/incidents/{incident_id}",
        headers=engineer_headers,
    )

    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_viewer_cannot_delete_incident(
    client: AsyncClient, analyst_headers: dict, viewer_headers: dict
) -> None:
    """Viewer role is denied (403)."""
    incident_id = await _create_incident(client, analyst_headers)

    resp = await client.delete(
        f"/api/v1/incidents/{incident_id}",
        headers=viewer_headers,
    )

    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_unauthenticated_cannot_delete_incident(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Unauthenticated request returns 401."""
    incident_id = await _create_incident(client, analyst_headers)

    resp = await client.delete(f"/api/v1/incidents/{incident_id}")

    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# 404 — incident not found
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_delete_returns_404_for_missing_incident(
    client: AsyncClient, admin_headers: dict
) -> None:
    """Returns 404 when the incident does not exist."""
    resp = await client.delete("/api/v1/incidents/999999", headers=admin_headers)

    assert resp.status_code == 404
