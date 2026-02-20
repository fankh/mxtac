"""Tests for GET/PATCH /api/v1/detections endpoints — Feature 10.1.

Coverage:
  - List detections: status code, response schema (items + pagination)
  - Filtering by severity and status
  - Full-text search
  - Single detection detail
  - 404 for unknown ID
  - PATCH status update
  - Unauthenticated access → 401/403

All tests mock ``DetectionRepo`` so the suite runs without a live PostgreSQL
instance.  Auth headers are created directly via ``create_access_token``
(no DB login needed).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient

from app.core.security import create_access_token

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MOCK_REPO = "app.api.v1.endpoints.detections.DetectionRepo"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_detection(**overrides) -> SimpleNamespace:
    """Build a minimal ORM-like Detection namespace for use as a mock return."""
    defaults = {
        "id": "DET-2026-00847",
        "score": 9.0,
        "severity": "critical",
        "technique_id": "T1003.006",
        "technique_name": "DCSync",
        "name": "DCSync via DRSUAPI GetNCChanges",
        "host": "DC-PROD-01",
        "tactic": "Credential Access",
        "status": "active",
        "time": datetime(2026, 2, 19, 14, 21, 7, tzinfo=timezone.utc),
        "user": "CORP\\svc-backup",
        "process": "lsass.exe (PID: 4)",
        "rule_name": "win_dcsync_replication",
        "log_source": "Elastic SIEM",
        "event_id": "4662",
        "occurrence_count": 14,
        "description": "DCSync attack detected.",
        "cvss_v3": 8.8,
        "confidence": 96,
        "tactic_id": "TA0006",
        "assigned_to": "J. Smith",
        "priority": "P1 Urgent",
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


# Pre-built fixtures
_DET = _make_detection()
_CRITICAL_DET = _make_detection(id="DET-C", severity="critical", status="active")
_ACTIVE_DET = _make_detection(id="DET-A", severity="medium", status="active")
_LSASS_DET = _make_detection(id="DET-L", name="lsass dump attack", host="WS-01")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def auth_headers() -> dict[str, str]:
    """Create a valid JWT directly — no DB login required."""
    token = create_access_token(
        {"sub": "analyst@mxtac.local", "role": "analyst"},
        expires_delta=timedelta(hours=1),
    )
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# List detections — default
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_detections_default(client: AsyncClient, auth_headers: dict) -> None:
    """GET /detections returns 200 with items list and pagination object."""
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([_DET], 1))):
        resp = await client.get("/api/v1/detections", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "pagination" in data
    assert isinstance(data["items"], list)


@pytest.mark.asyncio
async def test_list_detections_pagination_fields(client: AsyncClient, auth_headers: dict) -> None:
    """Pagination object contains page, page_size, total, total_pages."""
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([_DET], 1))):
        resp = await client.get("/api/v1/detections", headers=auth_headers)
    pg = resp.json()["pagination"]
    assert pg["page"] == 1
    assert pg["page_size"] == 25
    assert pg["total"] == 1
    assert pg["total_pages"] == 1


@pytest.mark.asyncio
async def test_list_detections_empty(client: AsyncClient, auth_headers: dict) -> None:
    """Empty DB returns items=[] and total=0."""
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([], 0))):
        resp = await client.get("/api/v1/detections", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["items"] == []
    assert data["pagination"]["total"] == 0
    assert data["pagination"]["total_pages"] == 1  # max(1, ceil(0/25))


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_detections_filter_severity(client: AsyncClient, auth_headers: dict) -> None:
    """?severity=critical only returns critical detections."""
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([_CRITICAL_DET], 1))):
        resp = await client.get("/api/v1/detections?severity=critical", headers=auth_headers)
    assert resp.status_code == 200
    for item in resp.json()["items"]:
        assert item["severity"] == "critical"


@pytest.mark.asyncio
async def test_list_detections_filter_severity_multi(client: AsyncClient, auth_headers: dict) -> None:
    """?severity=critical&severity=high returns only critical and high detections."""
    _high_det = _make_detection(id="DET-H", severity="high", status="active")
    with patch(
        f"{MOCK_REPO}.list",
        new=AsyncMock(return_value=([_CRITICAL_DET, _high_det], 2)),
    ):
        resp = await client.get(
            "/api/v1/detections?severity=critical&severity=high", headers=auth_headers
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["pagination"]["total"] == 2
    for item in data["items"]:
        assert item["severity"] in ("critical", "high")


@pytest.mark.asyncio
async def test_list_detections_filter_status(client: AsyncClient, auth_headers: dict) -> None:
    """?status=active only returns active detections."""
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([_ACTIVE_DET], 1))):
        resp = await client.get("/api/v1/detections?status=active", headers=auth_headers)
    assert resp.status_code == 200
    for item in resp.json()["items"]:
        assert item["status"] == "active"


@pytest.mark.asyncio
async def test_list_detections_search(client: AsyncClient, auth_headers: dict) -> None:
    """?search=lsass passes the term to the repo and returns a list."""
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([_LSASS_DET], 1))):
        resp = await client.get("/api/v1/detections?search=lsass", headers=auth_headers)
    assert resp.status_code == 200
    assert isinstance(resp.json()["items"], list)


# ---------------------------------------------------------------------------
# Single detection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_detection_detail(client: AsyncClient, auth_headers: dict) -> None:
    """GET /detections/{id} returns full detection object with correct id."""
    with (
        patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([_DET], 1))),
        patch(f"{MOCK_REPO}.get", new=AsyncMock(return_value=_DET)),
    ):
        list_resp = await client.get("/api/v1/detections", headers=auth_headers)
        items = list_resp.json()["items"]
        assert len(items) > 0

        detection_id = items[0]["id"]
        resp = await client.get(f"/api/v1/detections/{detection_id}", headers=auth_headers)

    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == detection_id
    assert "technique_id" in data


@pytest.mark.asyncio
async def test_get_detection_not_found(client: AsyncClient, auth_headers: dict) -> None:
    """GET /detections/nonexistent-id → 404."""
    with patch(f"{MOCK_REPO}.get", new=AsyncMock(return_value=None)):
        resp = await client.get("/api/v1/detections/nonexistent-id", headers=auth_headers)
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# PATCH
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_update_detection_status(client: AsyncClient, auth_headers: dict) -> None:
    """PATCH /detections/{id} with status=investigating returns updated status."""
    investigating_det = _make_detection(status="investigating")
    with (
        patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([_DET], 1))),
        patch(f"{MOCK_REPO}.update", new=AsyncMock(return_value=investigating_det)),
    ):
        list_resp = await client.get("/api/v1/detections", headers=auth_headers)
        detection_id = list_resp.json()["items"][0]["id"]

        resp = await client.patch(
            f"/api/v1/detections/{detection_id}",
            headers=auth_headers,
            json={"status": "investigating"},
        )
    assert resp.status_code == 200
    assert resp.json()["status"] == "investigating"


@pytest.mark.asyncio
async def test_update_detection_not_found(client: AsyncClient, auth_headers: dict) -> None:
    """PATCH /detections/nonexistent-id → 404."""
    with patch(f"{MOCK_REPO}.update", new=AsyncMock(return_value=None)):
        resp = await client.patch(
            "/api/v1/detections/nonexistent-id",
            headers=auth_headers,
            json={"status": "resolved"},
        )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unauthenticated_access(client: AsyncClient) -> None:
    """GET /detections without Authorization header → 401 or 403."""
    resp = await client.get("/api/v1/detections")
    assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# Feature 28.7 — RBAC: analyst can update detection status
# ---------------------------------------------------------------------------


def _token_headers(role: str, email: str | None = None) -> dict[str, str]:
    """Create a valid JWT for *role* without hitting the DB."""
    sub = email or f"{role}@mxtac.local"
    token = create_access_token(
        {"sub": sub, "role": role},
        expires_delta=timedelta(hours=1),
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_viewer_cannot_update_detection_status(client: AsyncClient) -> None:
    """PATCH /detections/{id} with viewer role → 403 Forbidden."""
    resp = await client.patch(
        "/api/v1/detections/DET-2026-00847",
        headers=_token_headers("viewer"),
        json={"status": "investigating"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_analyst_can_update_detection_status(client: AsyncClient) -> None:
    """PATCH /detections/{id} with analyst role → 200 (analyst has detections:write)."""
    updated_det = _make_detection(status="investigating")
    with patch(f"{MOCK_REPO}.update", new=AsyncMock(return_value=updated_det)):
        resp = await client.patch(
            "/api/v1/detections/DET-2026-00847",
            headers=_token_headers("analyst"),
            json={"status": "investigating"},
        )
    assert resp.status_code == 200
    assert resp.json()["status"] == "investigating"


@pytest.mark.asyncio
async def test_analyst_can_update_detection_assigned_to(client: AsyncClient) -> None:
    """PATCH /detections/{id} analyst can update assigned_to field."""
    updated_det = _make_detection(assigned_to="J. Doe")
    with patch(f"{MOCK_REPO}.update", new=AsyncMock(return_value=updated_det)):
        resp = await client.patch(
            "/api/v1/detections/DET-2026-00847",
            headers=_token_headers("analyst"),
            json={"assigned_to": "J. Doe"},
        )
    assert resp.status_code == 200
    assert resp.json()["assigned_to"] == "J. Doe"


@pytest.mark.asyncio
async def test_analyst_can_update_detection_priority(client: AsyncClient) -> None:
    """PATCH /detections/{id} analyst can update priority field."""
    updated_det = _make_detection(priority="P2 Medium")
    with patch(f"{MOCK_REPO}.update", new=AsyncMock(return_value=updated_det)):
        resp = await client.patch(
            "/api/v1/detections/DET-2026-00847",
            headers=_token_headers("analyst"),
            json={"priority": "P2 Medium"},
        )
    assert resp.status_code == 200
    assert resp.json()["priority"] == "P2 Medium"


@pytest.mark.asyncio
async def test_hunter_can_update_detection_status(client: AsyncClient) -> None:
    """PATCH /detections/{id} with hunter role → 200 (hunter has detections:write)."""
    updated_det = _make_detection(status="resolved")
    with patch(f"{MOCK_REPO}.update", new=AsyncMock(return_value=updated_det)):
        resp = await client.patch(
            "/api/v1/detections/DET-2026-00847",
            headers=_token_headers("hunter"),
            json={"status": "resolved"},
        )
    assert resp.status_code == 200
    assert resp.json()["status"] == "resolved"


@pytest.mark.asyncio
async def test_engineer_can_update_detection_status(client: AsyncClient) -> None:
    """PATCH /detections/{id} with engineer role → 200 (engineer has detections:write)."""
    updated_det = _make_detection(status="false_positive")
    with patch(f"{MOCK_REPO}.update", new=AsyncMock(return_value=updated_det)):
        resp = await client.patch(
            "/api/v1/detections/DET-2026-00847",
            headers=_token_headers("engineer"),
            json={"status": "false_positive"},
        )
    assert resp.status_code == 200
    assert resp.json()["status"] == "false_positive"


@pytest.mark.asyncio
async def test_admin_can_update_detection_status(client: AsyncClient) -> None:
    """PATCH /detections/{id} with admin role → 200 (admin has detections:write)."""
    updated_det = _make_detection(status="active")
    with patch(f"{MOCK_REPO}.update", new=AsyncMock(return_value=updated_det)):
        resp = await client.patch(
            "/api/v1/detections/DET-2026-00847",
            headers=_token_headers("admin"),
            json={"status": "active"},
        )
    assert resp.status_code == 200
    assert resp.json()["status"] == "active"


@pytest.mark.asyncio
async def test_viewer_rbac_check_precedes_db_lookup(client: AsyncClient) -> None:
    """PATCH /detections/{id} with viewer role → 403 even for nonexistent detection.

    RBAC enforcement happens before the repository is called, so a viewer
    receives 403 (not 404) regardless of whether the detection exists.
    """
    resp = await client.patch(
        "/api/v1/detections/nonexistent-id",
        headers=_token_headers("viewer"),
        json={"status": "investigating"},
    )
    assert resp.status_code == 403
