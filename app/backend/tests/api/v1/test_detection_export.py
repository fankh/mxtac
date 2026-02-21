"""Tests for GET /api/v1/detections/export — Feature 31.3.

Coverage:
  - 200 with CSV content-type and Content-Disposition header
  - CSV header row matches expected columns
  - Data rows match detection fields
  - Filter params forwarded to DetectionRepo.list
  - Empty result → header row only
  - Auth: unauthenticated → 401/403; analyst (detections:read) → 200
"""

from __future__ import annotations

import csv
import io
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient

from app.core.security import create_access_token

MOCK_REPO = "app.api.v1.endpoints.detections.DetectionRepo"
BASE_URL = "/api/v1/detections/export"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_detection(**overrides) -> SimpleNamespace:
    defaults = {
        "id": "DET-2026-00001",
        "score": 9.0,
        "severity": "critical",
        "technique_id": "T1003.006",
        "technique_name": "DCSync",
        "name": "DCSync via DRSUAPI",
        "host": "DC-PROD-01",
        "tactic": "Credential Access",
        "status": "active",
        "time": datetime(2026, 2, 19, 14, 21, 7, tzinfo=timezone.utc),
        "user": None,
        "process": None,
        "rule_name": None,
        "log_source": None,
        "event_id": None,
        "occurrence_count": None,
        "description": None,
        "cvss_v3": None,
        "confidence": None,
        "tactic_id": "TA0006",
        "assigned_to": None,
        "priority": None,
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _auth_headers(role: str = "analyst") -> dict[str, str]:
    token = create_access_token(
        {"sub": f"{role}@mxtac.local", "role": role},
        expires_delta=timedelta(hours=1),
    )
    return {"Authorization": f"Bearer {token}"}


def _parse_csv(text: str) -> list[list[str]]:
    return list(csv.reader(io.StringIO(text)))


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_export_unauthenticated(client: AsyncClient) -> None:
    """GET /detections/export without auth → 401 or 403."""
    resp = await client.get(BASE_URL)
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_export_analyst_allowed(client: AsyncClient) -> None:
    """Analyst role (detections:read) can access the export endpoint."""
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([], 0))):
        resp = await client.get(BASE_URL, headers=_auth_headers("analyst"))
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Response format
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_export_content_type(client: AsyncClient) -> None:
    """Response has text/csv content-type."""
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([], 0))):
        resp = await client.get(BASE_URL, headers=_auth_headers())
    assert "text/csv" in resp.headers["content-type"]


@pytest.mark.asyncio
async def test_export_content_disposition(client: AsyncClient) -> None:
    """Response has Content-Disposition: attachment with a .csv filename."""
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([], 0))):
        resp = await client.get(BASE_URL, headers=_auth_headers())
    cd = resp.headers.get("content-disposition", "")
    assert "attachment" in cd
    assert ".csv" in cd


@pytest.mark.asyncio
async def test_export_csv_header_row(client: AsyncClient) -> None:
    """First CSV row contains the expected column names."""
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([], 0))):
        resp = await client.get(BASE_URL, headers=_auth_headers())
    rows = _parse_csv(resp.text)
    assert rows[0] == ["id", "name", "severity", "tactic", "technique_id", "host", "status", "score", "time"]


@pytest.mark.asyncio
async def test_export_empty_result(client: AsyncClient) -> None:
    """Empty DB → CSV contains header row only."""
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([], 0))):
        resp = await client.get(BASE_URL, headers=_auth_headers())
    rows = _parse_csv(resp.text)
    # Header only — no data rows
    assert len(rows) == 1


# ---------------------------------------------------------------------------
# Data rows
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_export_single_detection(client: AsyncClient) -> None:
    """Single detection → header + 1 data row with correct values."""
    det = _make_detection()
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([det], 1))):
        resp = await client.get(BASE_URL, headers=_auth_headers())

    rows = _parse_csv(resp.text)
    assert len(rows) == 2
    data = rows[1]
    assert data[0] == det.id
    assert data[1] == det.name
    assert data[2] == det.severity
    assert data[3] == det.tactic
    assert data[4] == det.technique_id
    assert data[5] == det.host
    assert data[6] == det.status
    assert data[7] == str(det.score)
    assert data[8] == det.time.isoformat()


@pytest.mark.asyncio
async def test_export_multiple_detections(client: AsyncClient) -> None:
    """Multiple detections → header + N data rows."""
    dets = [
        _make_detection(id="DET-001", severity="critical"),
        _make_detection(id="DET-002", severity="high"),
        _make_detection(id="DET-003", severity="medium"),
    ]
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=(dets, 3))):
        resp = await client.get(BASE_URL, headers=_auth_headers())

    rows = _parse_csv(resp.text)
    assert len(rows) == 4  # 1 header + 3 data rows
    assert rows[1][0] == "DET-001"
    assert rows[2][0] == "DET-002"
    assert rows[3][0] == "DET-003"


# ---------------------------------------------------------------------------
# Filter parameters forwarded to DetectionRepo.list
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_export_filter_severity_forwarded(client: AsyncClient) -> None:
    """?severity=critical is forwarded to DetectionRepo.list."""
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        await client.get(BASE_URL + "?severity=critical", headers=_auth_headers())
    call_kwargs = mock_list.call_args.kwargs
    assert call_kwargs["severity"] == ["critical"]


@pytest.mark.asyncio
async def test_export_filter_status_forwarded(client: AsyncClient) -> None:
    """?status=active is forwarded to DetectionRepo.list."""
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        await client.get(BASE_URL + "?status=active", headers=_auth_headers())
    call_kwargs = mock_list.call_args.kwargs
    assert call_kwargs["status"] == ["active"]


@pytest.mark.asyncio
async def test_export_filter_tactic_forwarded(client: AsyncClient) -> None:
    """?tactic=Credential+Access is forwarded to DetectionRepo.list."""
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        await client.get(BASE_URL + "?tactic=Credential+Access", headers=_auth_headers())
    call_kwargs = mock_list.call_args.kwargs
    assert call_kwargs["tactic"] == "Credential Access"


@pytest.mark.asyncio
async def test_export_page_size_capped_at_10000(client: AsyncClient) -> None:
    """Export always uses page=1 and page_size=10,000 regardless of filter params."""
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        await client.get(BASE_URL, headers=_auth_headers())
    call_kwargs = mock_list.call_args.kwargs
    assert call_kwargs["page"] == 1
    assert call_kwargs["page_size"] == 10_000


@pytest.mark.asyncio
async def test_export_sort_order_forwarded(client: AsyncClient) -> None:
    """?sort=score&order=asc is forwarded to DetectionRepo.list."""
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        await client.get(BASE_URL + "?sort=score&order=asc", headers=_auth_headers())
    call_kwargs = mock_list.call_args.kwargs
    assert call_kwargs["sort"] == "score"
    assert call_kwargs["order"] == "asc"
