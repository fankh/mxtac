"""Tests for GET /api/v1/detections?sort=score — Feature 28.32.

Coverage:
  - ?sort=score&order=desc forwards sort='score' and order='desc' to repo
  - ?sort=score (no order) uses default order='desc'
  - ?sort=score&order=asc forwards order='asc' to repo
  - Default (no sort param) uses sort='time' — score is NOT the default
  - All valid sort fields are accepted: score, time, severity, host, tactic
  - Invalid sort field → 422 Unprocessable Entity
  - Invalid order value → 422 Unprocessable Entity
  - Response items preserve the order returned by the repo (score desc)
  - Response item 'score' field is present and correct
  - sort=score combined with severity filter
  - sort=score combined with pagination params
  - sort=score combined with status filter
  - sort=score combined with host filter
  - sort=score combined with search param
  - sort=score with empty results → 200 with empty items list

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
# sort=score&order=desc — explicit descending
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sort_score_desc_forwarded_to_repo(client: AsyncClient) -> None:
    """?sort=score&order=desc forwards sort='score' and order='desc' to repo."""
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        resp = await client.get(
            "/api/v1/detections?sort=score&order=desc",
            headers=_analyst_headers(),
        )
    assert resp.status_code == 200
    kwargs = mock_list.call_args.kwargs
    assert kwargs.get("sort") == "score"
    assert kwargs.get("order") == "desc"


@pytest.mark.asyncio
async def test_sort_score_default_order_is_desc(client: AsyncClient) -> None:
    """?sort=score without order param defaults to order='desc'."""
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        resp = await client.get(
            "/api/v1/detections?sort=score",
            headers=_analyst_headers(),
        )
    assert resp.status_code == 200
    kwargs = mock_list.call_args.kwargs
    assert kwargs.get("sort") == "score"
    assert kwargs.get("order") == "desc"


# ---------------------------------------------------------------------------
# sort=score&order=asc — ascending also supported
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sort_score_asc_forwarded_to_repo(client: AsyncClient) -> None:
    """?sort=score&order=asc forwards order='asc' to repo."""
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        resp = await client.get(
            "/api/v1/detections?sort=score&order=asc",
            headers=_analyst_headers(),
        )
    assert resp.status_code == 200
    kwargs = mock_list.call_args.kwargs
    assert kwargs.get("sort") == "score"
    assert kwargs.get("order") == "asc"


# ---------------------------------------------------------------------------
# Default sort is 'time', not 'score'
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_default_sort_is_time_not_score(client: AsyncClient) -> None:
    """No sort param → default sort='time', order='desc' (score is not the default)."""
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        resp = await client.get("/api/v1/detections", headers=_analyst_headers())
    assert resp.status_code == 200
    kwargs = mock_list.call_args.kwargs
    assert kwargs.get("sort") == "time"
    assert kwargs.get("order") == "desc"


# ---------------------------------------------------------------------------
# All valid sort fields are accepted
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("sort_field", ["score", "time", "severity", "host", "tactic"])
@pytest.mark.asyncio
async def test_all_valid_sort_fields_accepted(
    client: AsyncClient, sort_field: str
) -> None:
    """All SortField values (score, time, severity, host, tactic) → 200 OK."""
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        resp = await client.get(
            f"/api/v1/detections?sort={sort_field}",
            headers=_analyst_headers(),
        )
    assert resp.status_code == 200
    assert mock_list.call_args.kwargs.get("sort") == sort_field


# ---------------------------------------------------------------------------
# Invalid sort / order values → 422
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_invalid_sort_field_returns_422(client: AsyncClient) -> None:
    """?sort=unknown is not a valid SortField → 422 Unprocessable Entity."""
    resp = await client.get(
        "/api/v1/detections?sort=unknown", headers=_analyst_headers()
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_invalid_sort_field_name_returns_422(client: AsyncClient) -> None:
    """?sort=risk_score (not in SortField enum) → 422 Unprocessable Entity."""
    resp = await client.get(
        "/api/v1/detections?sort=risk_score", headers=_analyst_headers()
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_invalid_order_value_returns_422(client: AsyncClient) -> None:
    """?sort=score&order=random is not a valid order value → 422 Unprocessable Entity."""
    resp = await client.get(
        "/api/v1/detections?sort=score&order=random", headers=_analyst_headers()
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_invalid_order_ascending_typo_returns_422(client: AsyncClient) -> None:
    """?order=ascending (not 'asc') → 422 Unprocessable Entity."""
    resp = await client.get(
        "/api/v1/detections?sort=score&order=ascending", headers=_analyst_headers()
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Response item order preserves repo result (score descending)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sort_score_desc_response_preserves_repo_order(
    client: AsyncClient,
) -> None:
    """Items in response preserve the order the repo returns (highest score first)."""
    high_score = _make_detection("DET-HIGH", score=9.8, severity="critical")
    mid_score = _make_detection("DET-MID", score=6.5, severity="high")
    low_score = _make_detection("DET-LOW", score=3.2, severity="medium")
    mock_list = AsyncMock(return_value=([high_score, mid_score, low_score], 3))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        resp = await client.get(
            "/api/v1/detections?sort=score&order=desc",
            headers=_analyst_headers(),
        )
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert len(items) == 3
    assert items[0]["id"] == "DET-HIGH"
    assert items[1]["id"] == "DET-MID"
    assert items[2]["id"] == "DET-LOW"


@pytest.mark.asyncio
async def test_sort_score_desc_response_score_values_correct(
    client: AsyncClient,
) -> None:
    """Response items carry the correct 'score' values from the repo result."""
    det_a = _make_detection("DET-A", score=9.5)
    det_b = _make_detection("DET-B", score=5.0)
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([det_a, det_b], 2))):
        resp = await client.get(
            "/api/v1/detections?sort=score&order=desc",
            headers=_analyst_headers(),
        )
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert items[0]["score"] == 9.5
    assert items[1]["score"] == 5.0


@pytest.mark.asyncio
async def test_sort_score_asc_response_preserves_repo_order(
    client: AsyncClient,
) -> None:
    """Items in response preserve the order the repo returns (lowest score first)."""
    low_score = _make_detection("DET-LOW", score=2.1, severity="low")
    mid_score = _make_detection("DET-MID", score=5.5, severity="medium")
    high_score = _make_detection("DET-HIGH", score=8.9, severity="high")
    mock_list = AsyncMock(return_value=([low_score, mid_score, high_score], 3))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        resp = await client.get(
            "/api/v1/detections?sort=score&order=asc",
            headers=_analyst_headers(),
        )
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert items[0]["id"] == "DET-LOW"
    assert items[2]["id"] == "DET-HIGH"


# ---------------------------------------------------------------------------
# sort=score with empty results
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sort_score_desc_empty_results(client: AsyncClient) -> None:
    """?sort=score&order=desc with no detections → 200 with items=[] and total=0."""
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([], 0))):
        resp = await client.get(
            "/api/v1/detections?sort=score&order=desc",
            headers=_analyst_headers(),
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["items"] == []
    assert data["pagination"]["total"] == 0
    assert data["pagination"]["total_pages"] == 1


# ---------------------------------------------------------------------------
# sort=score combined with severity filter
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sort_score_desc_combined_with_severity(client: AsyncClient) -> None:
    """?sort=score&order=desc&severity=critical forwards all params to repo."""
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        resp = await client.get(
            "/api/v1/detections?sort=score&order=desc&severity=critical",
            headers=_analyst_headers(),
        )
    assert resp.status_code == 200
    kwargs = mock_list.call_args.kwargs
    assert kwargs.get("sort") == "score"
    assert kwargs.get("order") == "desc"
    assert kwargs.get("severity") == ["critical"]


@pytest.mark.asyncio
async def test_sort_score_desc_combined_with_multi_severity(
    client: AsyncClient,
) -> None:
    """?sort=score&order=desc&severity=critical&severity=high forwards all params."""
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        resp = await client.get(
            "/api/v1/detections?sort=score&order=desc&severity=critical&severity=high",
            headers=_analyst_headers(),
        )
    assert resp.status_code == 200
    kwargs = mock_list.call_args.kwargs
    assert kwargs.get("sort") == "score"
    assert kwargs.get("order") == "desc"
    assert set(kwargs.get("severity")) == {"critical", "high"}


# ---------------------------------------------------------------------------
# sort=score combined with pagination
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sort_score_desc_combined_with_page(client: AsyncClient) -> None:
    """?sort=score&order=desc&page=2 forwards all params to repo."""
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        resp = await client.get(
            "/api/v1/detections?sort=score&order=desc&page=2",
            headers=_analyst_headers(),
        )
    assert resp.status_code == 200
    kwargs = mock_list.call_args.kwargs
    assert kwargs.get("sort") == "score"
    assert kwargs.get("order") == "desc"
    assert kwargs.get("page") == 2


@pytest.mark.asyncio
async def test_sort_score_desc_combined_with_page_size(client: AsyncClient) -> None:
    """?sort=score&order=desc&page_size=10 forwards all params to repo."""
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        resp = await client.get(
            "/api/v1/detections?sort=score&order=desc&page_size=10",
            headers=_analyst_headers(),
        )
    assert resp.status_code == 200
    kwargs = mock_list.call_args.kwargs
    assert kwargs.get("sort") == "score"
    assert kwargs.get("order") == "desc"
    assert kwargs.get("page_size") == 10


@pytest.mark.asyncio
async def test_sort_score_desc_pagination_total_pages(client: AsyncClient) -> None:
    """?sort=score&order=desc with 50 total items, page_size=10 → total_pages=5."""
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([], 50))):
        resp = await client.get(
            "/api/v1/detections?sort=score&order=desc&page_size=10",
            headers=_analyst_headers(),
        )
    assert resp.status_code == 200
    assert resp.json()["pagination"]["total_pages"] == 5


# ---------------------------------------------------------------------------
# sort=score combined with status filter
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sort_score_desc_combined_with_status(client: AsyncClient) -> None:
    """?sort=score&order=desc&status=active forwards all params to repo."""
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        resp = await client.get(
            "/api/v1/detections?sort=score&order=desc&status=active",
            headers=_analyst_headers(),
        )
    assert resp.status_code == 200
    kwargs = mock_list.call_args.kwargs
    assert kwargs.get("sort") == "score"
    assert kwargs.get("order") == "desc"
    assert kwargs.get("status") == ["active"]


# ---------------------------------------------------------------------------
# sort=score combined with host filter
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sort_score_desc_combined_with_host(client: AsyncClient) -> None:
    """?sort=score&order=desc&host=DC-01 forwards all params to repo."""
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        resp = await client.get(
            "/api/v1/detections?sort=score&order=desc&host=DC-01",
            headers=_analyst_headers(),
        )
    assert resp.status_code == 200
    kwargs = mock_list.call_args.kwargs
    assert kwargs.get("sort") == "score"
    assert kwargs.get("order") == "desc"
    assert kwargs.get("host") == "DC-01"


# ---------------------------------------------------------------------------
# sort=score combined with search param
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sort_score_desc_combined_with_search(client: AsyncClient) -> None:
    """?sort=score&order=desc&search=lsass forwards all params to repo."""
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        resp = await client.get(
            "/api/v1/detections?sort=score&order=desc&search=lsass",
            headers=_analyst_headers(),
        )
    assert resp.status_code == 200
    kwargs = mock_list.call_args.kwargs
    assert kwargs.get("sort") == "score"
    assert kwargs.get("order") == "desc"
    assert kwargs.get("search") == "lsass"


# ---------------------------------------------------------------------------
# sort=score combined with tactic filter
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sort_score_desc_combined_with_tactic(client: AsyncClient) -> None:
    """?sort=score&order=desc&tactic=Execution forwards all params to repo."""
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        resp = await client.get(
            "/api/v1/detections?sort=score&order=desc&tactic=Execution",
            headers=_analyst_headers(),
        )
    assert resp.status_code == 200
    kwargs = mock_list.call_args.kwargs
    assert kwargs.get("sort") == "score"
    assert kwargs.get("order") == "desc"
    assert kwargs.get("tactic") == "Execution"


# ---------------------------------------------------------------------------
# Response structure with sort=score
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sort_score_desc_response_has_correct_structure(
    client: AsyncClient,
) -> None:
    """?sort=score&order=desc response has items list and pagination object."""
    det = _make_detection("DET-STRUCT", score=8.0, severity="critical")
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([det], 1))):
        resp = await client.get(
            "/api/v1/detections?sort=score&order=desc",
            headers=_analyst_headers(),
        )
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "pagination" in data
    pg = data["pagination"]
    assert pg["page"] == 1
    assert pg["page_size"] == 25
    assert pg["total"] == 1
    assert pg["total_pages"] == 1


@pytest.mark.asyncio
async def test_sort_score_desc_single_item_score_field_present(
    client: AsyncClient,
) -> None:
    """Response item contains 'score' field with the correct value."""
    det = _make_detection("DET-SCORE", score=9.1)
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([det], 1))):
        resp = await client.get(
            "/api/v1/detections?sort=score&order=desc",
            headers=_analyst_headers(),
        )
    assert resp.status_code == 200
    item = resp.json()["items"][0]
    assert "score" in item
    assert item["score"] == 9.1


# ---------------------------------------------------------------------------
# Full combined scenario: score desc + severity + pagination
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sort_score_desc_full_combination(client: AsyncClient) -> None:
    """?sort=score&order=desc&severity=critical&page=1&page_size=10 forwards all params."""
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        resp = await client.get(
            "/api/v1/detections?sort=score&order=desc&severity=critical&page=1&page_size=10",
            headers=_analyst_headers(),
        )
    assert resp.status_code == 200
    kwargs = mock_list.call_args.kwargs
    assert kwargs.get("sort") == "score"
    assert kwargs.get("order") == "desc"
    assert kwargs.get("severity") == ["critical"]
    assert kwargs.get("page") == 1
    assert kwargs.get("page_size") == 10
