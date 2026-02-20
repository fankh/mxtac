"""Tests for GET /api/v1/detections pagination — Feature 28.30.

Coverage:
  - page / page_size query params are forwarded to DetectionRepo.list
  - pagination response fields reflect the supplied page / page_size
  - total_pages is computed correctly (ceil division, min 1)
  - invalid param values (page < 1, page_size < 1, page_size > 100) → 422
  - boundary values (page_size=1, page_size=100) are accepted

All tests mock DetectionRepo.list so no live PostgreSQL instance is needed.
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


def _analyst_headers() -> dict[str, str]:
    token = create_access_token(
        {"sub": "analyst@mxtac.local", "role": "analyst"},
        expires_delta=timedelta(hours=1),
    )
    return {"Authorization": f"Bearer {token}"}


def _make_detection(det_id: str = "DET-0001") -> SimpleNamespace:
    return SimpleNamespace(
        id=det_id,
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


# ---------------------------------------------------------------------------
# page param forwarding
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_page_param_forwarded_to_repo(client: AsyncClient) -> None:
    """?page=3 forwards page=3 to DetectionRepo.list."""
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        resp = await client.get(
            "/api/v1/detections?page=3", headers=_analyst_headers()
        )
    assert resp.status_code == 200
    assert mock_list.call_args.kwargs.get("page") == 3


@pytest.mark.asyncio
async def test_page_size_param_forwarded_to_repo(client: AsyncClient) -> None:
    """?page_size=10 forwards page_size=10 to DetectionRepo.list."""
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        resp = await client.get(
            "/api/v1/detections?page_size=10", headers=_analyst_headers()
        )
    assert resp.status_code == 200
    assert mock_list.call_args.kwargs.get("page_size") == 10


@pytest.mark.asyncio
async def test_page_and_page_size_both_forwarded(client: AsyncClient) -> None:
    """?page=2&page_size=10 forwards both params to DetectionRepo.list."""
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        resp = await client.get(
            "/api/v1/detections?page=2&page_size=10", headers=_analyst_headers()
        )
    assert resp.status_code == 200
    kwargs = mock_list.call_args.kwargs
    assert kwargs.get("page") == 2
    assert kwargs.get("page_size") == 10


# ---------------------------------------------------------------------------
# Pagination response fields
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pagination_response_reflects_page_param(client: AsyncClient) -> None:
    """Response pagination.page matches the ?page= query param."""
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([], 0))):
        resp = await client.get(
            "/api/v1/detections?page=5", headers=_analyst_headers()
        )
    assert resp.status_code == 200
    assert resp.json()["pagination"]["page"] == 5


@pytest.mark.asyncio
async def test_pagination_response_reflects_page_size_param(client: AsyncClient) -> None:
    """Response pagination.page_size matches the ?page_size= query param."""
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([], 0))):
        resp = await client.get(
            "/api/v1/detections?page_size=50", headers=_analyst_headers()
        )
    assert resp.status_code == 200
    assert resp.json()["pagination"]["page_size"] == 50


# ---------------------------------------------------------------------------
# total_pages computation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_total_pages_computed_correctly(client: AsyncClient) -> None:
    """total=50, page_size=10 → total_pages=5."""
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([], 50))):
        resp = await client.get(
            "/api/v1/detections?page_size=10", headers=_analyst_headers()
        )
    assert resp.status_code == 200
    assert resp.json()["pagination"]["total_pages"] == 5


@pytest.mark.asyncio
async def test_total_pages_rounds_up(client: AsyncClient) -> None:
    """total=51, page_size=10 → total_pages=6 (ceiling division)."""
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([], 51))):
        resp = await client.get(
            "/api/v1/detections?page_size=10", headers=_analyst_headers()
        )
    assert resp.status_code == 200
    assert resp.json()["pagination"]["total_pages"] == 6


@pytest.mark.asyncio
async def test_total_pages_minimum_one_when_empty(client: AsyncClient) -> None:
    """total=0 → total_pages=1 (min 1 — never return zero pages)."""
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([], 0))):
        resp = await client.get("/api/v1/detections", headers=_analyst_headers())
    assert resp.status_code == 200
    assert resp.json()["pagination"]["total_pages"] == 1


@pytest.mark.asyncio
async def test_total_pages_single_full_page(client: AsyncClient) -> None:
    """total == page_size → total_pages=1 (exactly one full page)."""
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([], 25))):
        resp = await client.get(
            "/api/v1/detections?page_size=25", headers=_analyst_headers()
        )
    assert resp.status_code == 200
    assert resp.json()["pagination"]["total_pages"] == 1


@pytest.mark.asyncio
async def test_total_in_response_matches_repo_count(client: AsyncClient) -> None:
    """pagination.total reflects the count returned by DetectionRepo.list."""
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([], 137))):
        resp = await client.get("/api/v1/detections", headers=_analyst_headers())
    assert resp.status_code == 200
    assert resp.json()["pagination"]["total"] == 137


@pytest.mark.asyncio
async def test_second_page_response_contains_items(client: AsyncClient) -> None:
    """GET /detections?page=2 returns items provided by the repo for that page."""
    det = _make_detection("DET-PAGE2")
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([det], 30))):
        resp = await client.get(
            "/api/v1/detections?page=2&page_size=25", headers=_analyst_headers()
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["pagination"]["page"] == 2
    assert data["pagination"]["total"] == 30
    assert data["pagination"]["total_pages"] == 2
    assert len(data["items"]) == 1
    assert data["items"][0]["id"] == "DET-PAGE2"


# ---------------------------------------------------------------------------
# Input validation — invalid values must return 422
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_page_zero_returns_422(client: AsyncClient) -> None:
    """?page=0 violates ge=1 constraint → 422 Unprocessable Entity."""
    resp = await client.get("/api/v1/detections?page=0", headers=_analyst_headers())
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_page_negative_returns_422(client: AsyncClient) -> None:
    """?page=-1 violates ge=1 constraint → 422 Unprocessable Entity."""
    resp = await client.get("/api/v1/detections?page=-1", headers=_analyst_headers())
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_page_size_zero_returns_422(client: AsyncClient) -> None:
    """?page_size=0 violates ge=1 constraint → 422 Unprocessable Entity."""
    resp = await client.get(
        "/api/v1/detections?page_size=0", headers=_analyst_headers()
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_page_size_over_max_returns_422(client: AsyncClient) -> None:
    """?page_size=101 violates le=100 constraint → 422 Unprocessable Entity."""
    resp = await client.get(
        "/api/v1/detections?page_size=101", headers=_analyst_headers()
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Input validation — boundary values must be accepted (200)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_page_size_one_is_valid(client: AsyncClient) -> None:
    """?page_size=1 is the minimum allowed value → 200 OK."""
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([], 0))):
        resp = await client.get(
            "/api/v1/detections?page_size=1", headers=_analyst_headers()
        )
    assert resp.status_code == 200
    assert resp.json()["pagination"]["page_size"] == 1


@pytest.mark.asyncio
async def test_page_size_max_is_valid(client: AsyncClient) -> None:
    """?page_size=100 is the maximum allowed value → 200 OK."""
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([], 0))):
        resp = await client.get(
            "/api/v1/detections?page_size=100", headers=_analyst_headers()
        )
    assert resp.status_code == 200
    assert resp.json()["pagination"]["page_size"] == 100


@pytest.mark.asyncio
async def test_page_one_is_valid(client: AsyncClient) -> None:
    """?page=1 is the minimum allowed value → 200 OK."""
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([], 0))):
        resp = await client.get(
            "/api/v1/detections?page=1", headers=_analyst_headers()
        )
    assert resp.status_code == 200
    assert resp.json()["pagination"]["page"] == 1


@pytest.mark.asyncio
async def test_page_large_value_is_valid(client: AsyncClient) -> None:
    """?page=999 (large page number) is a valid request → 200 OK with empty items."""
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([], 0))):
        resp = await client.get(
            "/api/v1/detections?page=999", headers=_analyst_headers()
        )
    assert resp.status_code == 200
    assert resp.json()["pagination"]["page"] == 999
