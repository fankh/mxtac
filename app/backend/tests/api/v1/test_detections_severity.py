"""Tests for GET /api/v1/detections?severity= — Feature 28.31.

Coverage:
  - Each individual severity level (critical, high, medium, low) is accepted and forwarded
  - severity param is passed to DetectionRepo.list as a list
  - Multi-value severity filter (?severity=X&severity=Y) works correctly
  - Invalid severity value → 422 Unprocessable Entity
  - Severity filter combined with pagination params
  - Severity filter combined with sort params
  - Severity filter with no matching detections → empty results
  - Omitting severity → None is forwarded (no filter applied)

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


def _make_detection(det_id: str = "DET-0001", **overrides) -> SimpleNamespace:
    defaults = dict(
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
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


# ---------------------------------------------------------------------------
# Single severity values — param forwarded to repo
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_severity_critical_forwarded_to_repo(client: AsyncClient) -> None:
    """?severity=critical forwards severity=['critical'] to DetectionRepo.list."""
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        resp = await client.get(
            "/api/v1/detections?severity=critical", headers=_analyst_headers()
        )
    assert resp.status_code == 200
    assert mock_list.call_args.kwargs.get("severity") == ["critical"]


@pytest.mark.asyncio
async def test_severity_high_forwarded_to_repo(client: AsyncClient) -> None:
    """?severity=high forwards severity=['high'] to DetectionRepo.list."""
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        resp = await client.get(
            "/api/v1/detections?severity=high", headers=_analyst_headers()
        )
    assert resp.status_code == 200
    assert mock_list.call_args.kwargs.get("severity") == ["high"]


@pytest.mark.asyncio
async def test_severity_medium_forwarded_to_repo(client: AsyncClient) -> None:
    """?severity=medium forwards severity=['medium'] to DetectionRepo.list."""
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        resp = await client.get(
            "/api/v1/detections?severity=medium", headers=_analyst_headers()
        )
    assert resp.status_code == 200
    assert mock_list.call_args.kwargs.get("severity") == ["medium"]


@pytest.mark.asyncio
async def test_severity_low_forwarded_to_repo(client: AsyncClient) -> None:
    """?severity=low forwards severity=['low'] to DetectionRepo.list."""
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        resp = await client.get(
            "/api/v1/detections?severity=low", headers=_analyst_headers()
        )
    assert resp.status_code == 200
    assert mock_list.call_args.kwargs.get("severity") == ["low"]


@pytest.mark.asyncio
async def test_no_severity_param_sends_none_to_repo(client: AsyncClient) -> None:
    """Omitting ?severity= forwards severity=None (no filter) to DetectionRepo.list."""
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        resp = await client.get("/api/v1/detections", headers=_analyst_headers())
    assert resp.status_code == 200
    assert mock_list.call_args.kwargs.get("severity") is None


# ---------------------------------------------------------------------------
# Single severity values — response content
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_severity_critical_returns_critical_detections(client: AsyncClient) -> None:
    """?severity=critical response items all have severity='critical'."""
    det = _make_detection("DET-CRIT", severity="critical")
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([det], 1))):
        resp = await client.get(
            "/api/v1/detections?severity=critical", headers=_analyst_headers()
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["pagination"]["total"] == 1
    assert data["items"][0]["severity"] == "critical"


@pytest.mark.asyncio
async def test_severity_high_returns_high_detections(client: AsyncClient) -> None:
    """?severity=high response items all have severity='high'."""
    det = _make_detection("DET-HIGH", severity="high")
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([det], 1))):
        resp = await client.get(
            "/api/v1/detections?severity=high", headers=_analyst_headers()
        )
    assert resp.status_code == 200
    assert resp.json()["items"][0]["severity"] == "high"


@pytest.mark.asyncio
async def test_severity_medium_returns_medium_detections(client: AsyncClient) -> None:
    """?severity=medium response items all have severity='medium'."""
    det = _make_detection("DET-MED", severity="medium")
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([det], 1))):
        resp = await client.get(
            "/api/v1/detections?severity=medium", headers=_analyst_headers()
        )
    assert resp.status_code == 200
    assert resp.json()["items"][0]["severity"] == "medium"


@pytest.mark.asyncio
async def test_severity_low_returns_low_detections(client: AsyncClient) -> None:
    """?severity=low response items all have severity='low'."""
    det = _make_detection("DET-LOW", severity="low")
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([det], 1))):
        resp = await client.get(
            "/api/v1/detections?severity=low", headers=_analyst_headers()
        )
    assert resp.status_code == 200
    assert resp.json()["items"][0]["severity"] == "low"


# ---------------------------------------------------------------------------
# Multi-value severity filter
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_severity_multi_critical_high_forwarded(client: AsyncClient) -> None:
    """?severity=critical&severity=high forwards severity=['critical','high'] to repo."""
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        resp = await client.get(
            "/api/v1/detections?severity=critical&severity=high",
            headers=_analyst_headers(),
        )
    assert resp.status_code == 200
    forwarded = mock_list.call_args.kwargs.get("severity")
    assert set(forwarded) == {"critical", "high"}


@pytest.mark.asyncio
async def test_severity_multi_all_levels_forwarded(client: AsyncClient) -> None:
    """?severity=critical&severity=high&severity=medium&severity=low forwards all 4."""
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        resp = await client.get(
            "/api/v1/detections?severity=critical&severity=high&severity=medium&severity=low",
            headers=_analyst_headers(),
        )
    assert resp.status_code == 200
    forwarded = mock_list.call_args.kwargs.get("severity")
    assert set(forwarded) == {"critical", "high", "medium", "low"}


@pytest.mark.asyncio
async def test_severity_multi_returns_correct_items(client: AsyncClient) -> None:
    """?severity=critical&severity=medium response contains both severities."""
    crit = _make_detection("DET-C", severity="critical")
    med = _make_detection("DET-M", severity="medium")
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([crit, med], 2))):
        resp = await client.get(
            "/api/v1/detections?severity=critical&severity=medium",
            headers=_analyst_headers(),
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["pagination"]["total"] == 2
    severities = {item["severity"] for item in data["items"]}
    assert severities == {"critical", "medium"}


# ---------------------------------------------------------------------------
# Invalid severity values → 422
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_severity_invalid_value_returns_422(client: AsyncClient) -> None:
    """?severity=extreme is not a valid SeverityLevel → 422 Unprocessable Entity."""
    resp = await client.get(
        "/api/v1/detections?severity=extreme", headers=_analyst_headers()
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_severity_unknown_string_returns_422(client: AsyncClient) -> None:
    """?severity=urgent (unknown level) → 422 Unprocessable Entity."""
    resp = await client.get(
        "/api/v1/detections?severity=urgent", headers=_analyst_headers()
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_severity_empty_string_returns_422(client: AsyncClient) -> None:
    """?severity= (empty string) → 422 Unprocessable Entity."""
    resp = await client.get(
        "/api/v1/detections?severity=", headers=_analyst_headers()
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# No matching detections → empty results
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_severity_filter_no_match_returns_empty(client: AsyncClient) -> None:
    """?severity=low with no matching detections returns items=[] and total=0."""
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([], 0))):
        resp = await client.get(
            "/api/v1/detections?severity=low", headers=_analyst_headers()
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["items"] == []
    assert data["pagination"]["total"] == 0
    assert data["pagination"]["total_pages"] == 1


# ---------------------------------------------------------------------------
# Severity combined with pagination
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_severity_combined_with_page(client: AsyncClient) -> None:
    """?severity=critical&page=2 forwards both params to DetectionRepo.list."""
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        resp = await client.get(
            "/api/v1/detections?severity=critical&page=2",
            headers=_analyst_headers(),
        )
    assert resp.status_code == 200
    kwargs = mock_list.call_args.kwargs
    assert kwargs.get("severity") == ["critical"]
    assert kwargs.get("page") == 2


@pytest.mark.asyncio
async def test_severity_combined_with_page_size(client: AsyncClient) -> None:
    """?severity=high&page_size=10 forwards both params to DetectionRepo.list."""
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        resp = await client.get(
            "/api/v1/detections?severity=high&page_size=10",
            headers=_analyst_headers(),
        )
    assert resp.status_code == 200
    kwargs = mock_list.call_args.kwargs
    assert kwargs.get("severity") == ["high"]
    assert kwargs.get("page_size") == 10


@pytest.mark.asyncio
async def test_severity_pagination_total_pages_computed(client: AsyncClient) -> None:
    """?severity=critical with 30 total results and page_size=10 → total_pages=3."""
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([], 30))):
        resp = await client.get(
            "/api/v1/detections?severity=critical&page_size=10",
            headers=_analyst_headers(),
        )
    assert resp.status_code == 200
    assert resp.json()["pagination"]["total_pages"] == 3


# ---------------------------------------------------------------------------
# Severity combined with sort
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_severity_combined_with_sort_score(client: AsyncClient) -> None:
    """?severity=critical&sort=score&order=desc forwards all three params to repo."""
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        resp = await client.get(
            "/api/v1/detections?severity=critical&sort=score&order=desc",
            headers=_analyst_headers(),
        )
    assert resp.status_code == 200
    kwargs = mock_list.call_args.kwargs
    assert kwargs.get("severity") == ["critical"]
    assert kwargs.get("sort") == "score"
    assert kwargs.get("order") == "desc"


@pytest.mark.asyncio
async def test_severity_combined_with_sort_time_asc(client: AsyncClient) -> None:
    """?severity=medium&sort=time&order=asc forwards all params to repo."""
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        resp = await client.get(
            "/api/v1/detections?severity=medium&sort=time&order=asc",
            headers=_analyst_headers(),
        )
    assert resp.status_code == 200
    kwargs = mock_list.call_args.kwargs
    assert kwargs.get("severity") == ["medium"]
    assert kwargs.get("sort") == "time"
    assert kwargs.get("order") == "asc"


# ---------------------------------------------------------------------------
# Severity combined with other filters
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_severity_combined_with_status(client: AsyncClient) -> None:
    """?severity=critical&status=active forwards both filter params to repo."""
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        resp = await client.get(
            "/api/v1/detections?severity=critical&status=active",
            headers=_analyst_headers(),
        )
    assert resp.status_code == 200
    kwargs = mock_list.call_args.kwargs
    assert kwargs.get("severity") == ["critical"]
    assert kwargs.get("status") == ["active"]


@pytest.mark.asyncio
async def test_severity_combined_with_host(client: AsyncClient) -> None:
    """?severity=high&host=DC-01 forwards both filter params to repo."""
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        resp = await client.get(
            "/api/v1/detections?severity=high&host=DC-01",
            headers=_analyst_headers(),
        )
    assert resp.status_code == 200
    kwargs = mock_list.call_args.kwargs
    assert kwargs.get("severity") == ["high"]
    assert kwargs.get("host") == "DC-01"


@pytest.mark.asyncio
async def test_severity_combined_with_search(client: AsyncClient) -> None:
    """?severity=critical&search=lsass forwards both params to repo."""
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        resp = await client.get(
            "/api/v1/detections?severity=critical&search=lsass",
            headers=_analyst_headers(),
        )
    assert resp.status_code == 200
    kwargs = mock_list.call_args.kwargs
    assert kwargs.get("severity") == ["critical"]
    assert kwargs.get("search") == "lsass"


@pytest.mark.asyncio
async def test_severity_combined_with_tactic(client: AsyncClient) -> None:
    """?severity=high&tactic=Execution forwards both filter params to repo."""
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        resp = await client.get(
            "/api/v1/detections?severity=high&tactic=Execution",
            headers=_analyst_headers(),
        )
    assert resp.status_code == 200
    kwargs = mock_list.call_args.kwargs
    assert kwargs.get("severity") == ["high"]
    assert kwargs.get("tactic") == "Execution"


# ---------------------------------------------------------------------------
# Multi-severity combined with other filters
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_multi_severity_combined_with_status(client: AsyncClient) -> None:
    """?severity=critical&severity=high&status=active forwards all params correctly."""
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        resp = await client.get(
            "/api/v1/detections?severity=critical&severity=high&status=active",
            headers=_analyst_headers(),
        )
    assert resp.status_code == 200
    kwargs = mock_list.call_args.kwargs
    assert set(kwargs.get("severity")) == {"critical", "high"}
    assert kwargs.get("status") == ["active"]


@pytest.mark.asyncio
async def test_multi_severity_combined_with_sort_and_page(client: AsyncClient) -> None:
    """?severity=critical&severity=high&sort=score&order=desc&page=2 forwards all params."""
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        resp = await client.get(
            "/api/v1/detections?severity=critical&severity=high&sort=score&order=desc&page=2",
            headers=_analyst_headers(),
        )
    assert resp.status_code == 200
    kwargs = mock_list.call_args.kwargs
    assert set(kwargs.get("severity")) == {"critical", "high"}
    assert kwargs.get("sort") == "score"
    assert kwargs.get("order") == "desc"
    assert kwargs.get("page") == 2


# ---------------------------------------------------------------------------
# Response structure with severity filter
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_severity_filter_returns_correct_response_structure(
    client: AsyncClient,
) -> None:
    """?severity=critical response has items list and pagination object."""
    det = _make_detection("DET-CRIT", severity="critical")
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([det], 1))):
        resp = await client.get(
            "/api/v1/detections?severity=critical", headers=_analyst_headers()
        )
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "pagination" in data
    pg = data["pagination"]
    assert "page" in pg
    assert "page_size" in pg
    assert "total" in pg
    assert "total_pages" in pg
