"""Tests for 404 behaviour across Detections API endpoints — Feature 28.33.

Coverage:
  - GET /detections/{id} with unknown ID → 404
  - GET /detections/{id} — 404 detail message contains the detection ID
  - GET /detections/{id} — 404 response body has 'detail' key
  - PATCH /detections/{id} with unknown ID → 404
  - PATCH /detections/{id} — 404 detail message contains the detection ID
  - DELETE /detections/{id} with unknown ID (admin) → 404
  - DELETE /detections/{id} — 404 detail message contains the detection ID
  - Various unknown ID formats (UUID-style, alphanumeric, numeric string)
  - GET with authorised viewer role → 404 (viewer can read but not write)
  - PATCH/DELETE with insufficient role → 403 precedes 404 (RBAC runs first)
  - Repo returning None triggers 404 (GET, PATCH)
  - Repo returning False triggers 404 (DELETE)
  - Existing ID → 200, then re-request after repo returns None → 404

All tests mock DetectionRepo so no live PostgreSQL instance is needed.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient

from app.core.security import create_access_token

MOCK_REPO = "app.api.v1.endpoints.detections.DetectionRepo"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _token_headers(role: str) -> dict[str, str]:
    token = create_access_token(
        {"sub": f"{role}@mxtac.local", "role": role},
        expires_delta=timedelta(hours=1),
    )
    return {"Authorization": f"Bearer {token}"}


def _analyst_headers() -> dict[str, str]:
    return _token_headers("analyst")


def _admin_headers() -> dict[str, str]:
    return _token_headers("admin")


def _viewer_headers() -> dict[str, str]:
    return _token_headers("viewer")


def _make_detection(**overrides) -> SimpleNamespace:
    defaults = dict(
        id="DET-2026-00001",
        score=7.5,
        severity="high",
        technique_id="T1059",
        technique_name="Command Scripting",
        name="Suspicious PowerShell",
        host="WS-01",
        tactic="Execution",
        status="active",
        time=datetime(2026, 2, 19, 14, 21, 7, tzinfo=timezone.utc),
        user="admin",
        process="powershell.exe",
        rule_name="win_powershell",
        log_source="Wazuh",
        event_id="4688",
        occurrence_count=1,
        description="Suspicious PowerShell execution detected.",
        cvss_v3=7.5,
        confidence=85,
        tactic_id="TA0002",
        assigned_to=None,
        priority="P2",
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


# ---------------------------------------------------------------------------
# GET /detections/{id} — 404 for unknown ID
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_detection_unknown_id_returns_404(client: AsyncClient) -> None:
    """GET /detections/{id} where repo returns None → 404 Not Found."""
    with patch(f"{MOCK_REPO}.get", new=AsyncMock(return_value=None)):
        resp = await client.get(
            "/api/v1/detections/nonexistent-id",
            headers=_analyst_headers(),
        )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_get_detection_404_has_detail_key(client: AsyncClient) -> None:
    """GET /detections/{id} 404 response body contains a 'detail' key."""
    with patch(f"{MOCK_REPO}.get", new=AsyncMock(return_value=None)):
        resp = await client.get(
            "/api/v1/detections/nonexistent-id",
            headers=_analyst_headers(),
        )
    assert resp.status_code == 404
    assert "detail" in resp.json()


@pytest.mark.asyncio
async def test_get_detection_404_detail_contains_id(client: AsyncClient) -> None:
    """GET /detections/{id} 404 detail message includes the requested detection ID."""
    unknown_id = "DET-UNKNOWN-99999"
    with patch(f"{MOCK_REPO}.get", new=AsyncMock(return_value=None)):
        resp = await client.get(
            f"/api/v1/detections/{unknown_id}",
            headers=_analyst_headers(),
        )
    assert resp.status_code == 404
    assert unknown_id in resp.json()["detail"]


@pytest.mark.asyncio
async def test_get_detection_404_uuid_style_id(client: AsyncClient) -> None:
    """GET /detections/{id} with UUID-style unknown ID → 404."""
    with patch(f"{MOCK_REPO}.get", new=AsyncMock(return_value=None)):
        resp = await client.get(
            "/api/v1/detections/00000000-0000-0000-0000-000000000000",
            headers=_analyst_headers(),
        )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_get_detection_404_numeric_string_id(client: AsyncClient) -> None:
    """GET /detections/{id} with numeric string unknown ID → 404."""
    with patch(f"{MOCK_REPO}.get", new=AsyncMock(return_value=None)):
        resp = await client.get(
            "/api/v1/detections/9999999999",
            headers=_analyst_headers(),
        )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_get_detection_404_viewer_role(client: AsyncClient) -> None:
    """Viewer role (detections:read) also receives 404 for unknown detection ID."""
    with patch(f"{MOCK_REPO}.get", new=AsyncMock(return_value=None)):
        resp = await client.get(
            "/api/v1/detections/nonexistent-id",
            headers=_viewer_headers(),
        )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_get_detection_known_id_returns_200(client: AsyncClient) -> None:
    """GET /detections/{id} where repo returns a detection → 200 (not 404)."""
    det = _make_detection(id="DET-2026-00001")
    with patch(f"{MOCK_REPO}.get", new=AsyncMock(return_value=det)):
        resp = await client.get(
            "/api/v1/detections/DET-2026-00001",
            headers=_analyst_headers(),
        )
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# PATCH /detections/{id} — 404 for unknown ID
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_patch_detection_unknown_id_returns_404(client: AsyncClient) -> None:
    """PATCH /detections/{id} where repo returns None → 404 Not Found."""
    with patch(f"{MOCK_REPO}.update", new=AsyncMock(return_value=None)):
        resp = await client.patch(
            "/api/v1/detections/nonexistent-id",
            headers=_analyst_headers(),
            json={"status": "investigating"},
        )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_patch_detection_404_has_detail_key(client: AsyncClient) -> None:
    """PATCH /detections/{id} 404 response body contains a 'detail' key."""
    with patch(f"{MOCK_REPO}.update", new=AsyncMock(return_value=None)):
        resp = await client.patch(
            "/api/v1/detections/nonexistent-id",
            headers=_analyst_headers(),
            json={"status": "resolved"},
        )
    assert resp.status_code == 404
    assert "detail" in resp.json()


@pytest.mark.asyncio
async def test_patch_detection_404_detail_contains_id(client: AsyncClient) -> None:
    """PATCH /detections/{id} 404 detail message includes the requested detection ID."""
    unknown_id = "DET-UNKNOWN-PATCH"
    with patch(f"{MOCK_REPO}.update", new=AsyncMock(return_value=None)):
        resp = await client.patch(
            f"/api/v1/detections/{unknown_id}",
            headers=_analyst_headers(),
            json={"status": "resolved"},
        )
    assert resp.status_code == 404
    assert unknown_id in resp.json()["detail"]


@pytest.mark.asyncio
async def test_patch_detection_404_for_assigned_to_update(client: AsyncClient) -> None:
    """PATCH /detections/{id} with assigned_to field on unknown ID → 404."""
    with patch(f"{MOCK_REPO}.update", new=AsyncMock(return_value=None)):
        resp = await client.patch(
            "/api/v1/detections/nonexistent-id",
            headers=_analyst_headers(),
            json={"assigned_to": "J. Doe"},
        )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_patch_detection_404_for_priority_update(client: AsyncClient) -> None:
    """PATCH /detections/{id} with priority field on unknown ID → 404."""
    with patch(f"{MOCK_REPO}.update", new=AsyncMock(return_value=None)):
        resp = await client.patch(
            "/api/v1/detections/nonexistent-id",
            headers=_analyst_headers(),
            json={"priority": "P1 Urgent"},
        )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_patch_detection_viewer_gets_403_not_404(client: AsyncClient) -> None:
    """PATCH /detections/{id} with viewer role → 403 (RBAC runs before DB lookup).

    A viewer lacks detections:write permission, so the RBAC check fires before
    the repository is called, yielding 403 regardless of whether the ID exists.
    """
    resp = await client.patch(
        "/api/v1/detections/nonexistent-id",
        headers=_viewer_headers(),
        json={"status": "investigating"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_patch_detection_known_id_returns_200(client: AsyncClient) -> None:
    """PATCH /detections/{id} where repo returns updated detection → 200 (not 404)."""
    det = _make_detection(id="DET-KNOWN", status="investigating")
    with patch(f"{MOCK_REPO}.update", new=AsyncMock(return_value=det)):
        resp = await client.patch(
            "/api/v1/detections/DET-KNOWN",
            headers=_analyst_headers(),
            json={"status": "investigating"},
        )
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# DELETE /detections/{id} — 404 for unknown ID (admin only)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_delete_detection_unknown_id_returns_404(client: AsyncClient) -> None:
    """DELETE /detections/{id} where repo returns False → 404 Not Found."""
    with patch(f"{MOCK_REPO}.delete", new=AsyncMock(return_value=False)):
        resp = await client.delete(
            "/api/v1/detections/nonexistent-id",
            headers=_admin_headers(),
        )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_delete_detection_404_has_detail_key(client: AsyncClient) -> None:
    """DELETE /detections/{id} 404 response body contains a 'detail' key."""
    with patch(f"{MOCK_REPO}.delete", new=AsyncMock(return_value=False)):
        resp = await client.delete(
            "/api/v1/detections/nonexistent-id",
            headers=_admin_headers(),
        )
    assert resp.status_code == 404
    assert "detail" in resp.json()


@pytest.mark.asyncio
async def test_delete_detection_404_detail_contains_id(client: AsyncClient) -> None:
    """DELETE /detections/{id} 404 detail message includes the requested detection ID."""
    unknown_id = "DET-UNKNOWN-DELETE"
    with patch(f"{MOCK_REPO}.delete", new=AsyncMock(return_value=False)):
        resp = await client.delete(
            f"/api/v1/detections/{unknown_id}",
            headers=_admin_headers(),
        )
    assert resp.status_code == 404
    assert unknown_id in resp.json()["detail"]


@pytest.mark.asyncio
async def test_delete_detection_non_admin_gets_403_not_404(client: AsyncClient) -> None:
    """DELETE /detections/{id} with analyst role → 403 (RBAC runs before DB lookup).

    An analyst lacks detections:delete permission, so the RBAC check fires before
    the repository is called, yielding 403 regardless of whether the ID exists.
    """
    resp = await client.delete(
        "/api/v1/detections/nonexistent-id",
        headers=_analyst_headers(),
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_delete_detection_known_id_returns_204(client: AsyncClient) -> None:
    """DELETE /detections/{id} where repo returns True → 204 (not 404)."""
    with patch(f"{MOCK_REPO}.delete", new=AsyncMock(return_value=True)):
        resp = await client.delete(
            "/api/v1/detections/DET-KNOWN",
            headers=_admin_headers(),
        )
    assert resp.status_code == 204


# ---------------------------------------------------------------------------
# Parametrised: various unknown ID formats all return 404 for GET
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "unknown_id",
    [
        "nonexistent-id",
        "DET-9999999",
        "00000000-0000-0000-0000-000000000000",
        "99999",
        "DOES_NOT_EXIST",
        "det-lowercase-unknown",
    ],
)
@pytest.mark.asyncio
async def test_get_detection_various_unknown_ids_return_404(
    client: AsyncClient, unknown_id: str
) -> None:
    """GET /detections/{id} returns 404 for any ID that the repo does not find."""
    with patch(f"{MOCK_REPO}.get", new=AsyncMock(return_value=None)):
        resp = await client.get(
            f"/api/v1/detections/{unknown_id}",
            headers=_analyst_headers(),
        )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Repo not called for RBAC failures (403 short-circuits before 404)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_patch_viewer_repo_not_called(client: AsyncClient) -> None:
    """PATCH by viewer → 403 and DetectionRepo.update is never invoked."""
    mock_update = AsyncMock(return_value=None)
    with patch(f"{MOCK_REPO}.update", new=mock_update):
        resp = await client.patch(
            "/api/v1/detections/nonexistent-id",
            headers=_viewer_headers(),
            json={"status": "resolved"},
        )
    assert resp.status_code == 403
    mock_update.assert_not_called()


@pytest.mark.asyncio
async def test_delete_analyst_repo_not_called(client: AsyncClient) -> None:
    """DELETE by analyst → 403 and DetectionRepo.delete is never invoked."""
    mock_delete = AsyncMock(return_value=False)
    with patch(f"{MOCK_REPO}.delete", new=mock_delete):
        resp = await client.delete(
            "/api/v1/detections/nonexistent-id",
            headers=_analyst_headers(),
        )
    assert resp.status_code == 403
    mock_delete.assert_not_called()
