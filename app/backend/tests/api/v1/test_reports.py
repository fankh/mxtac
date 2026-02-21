"""Tests for Feature 31.2 — Report API (generate, list, download, delete).

Verifies:
- POST /reports/generate returns 202 with report_id and status='generating'.
- GET /reports lists reports with pagination.
- GET /reports/{id} returns report metadata.
- GET /reports/{id}/download returns JSON or CSV content for ready reports.
- DELETE /reports/{id} hard-deletes a report (204).
- RBAC: viewer is denied (403); analyst+ can access.
- Unauthenticated requests return 401.
- 404 returned for non-existent reports.
- 409 returned when downloading a generating or failed report.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.base import new_uuid
from app.repositories.report_repo import ReportRepo

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_BASE_URL = "/api/v1/reports"

_GENERATE_BODY = {
    "template_type": "executive_summary",
    "from_date": "2025-01-01T00:00:00Z",
    "to_date": "2025-01-31T23:59:59Z",
    "format": "json",
}

_SAMPLE_CONTENT = {
    "template": "executive_summary",
    "generated_at": "2025-02-01T00:00:00+00:00",
    "period": {"from": "2025-01-01T00:00:00+00:00", "to": "2025-01-31T23:59:59+00:00"},
    "kpis": {
        "total_detections": 42,
        "critical_detections": 5,
        "critical_today": 1,
        "detection_trend_pct": 10.0,
        "total_incidents": 3,
        "open_incidents": 1,
        "mttr_hours": 2.5,
        "coverage_pct": 35.0,
    },
    "top_risks": [],
    "incident_severity_breakdown": {},
    "incident_status_breakdown": {},
}


# ---------------------------------------------------------------------------
# Helper: create a ready report directly in the DB
# ---------------------------------------------------------------------------


async def _seed_ready_report(
    db_session: AsyncSession,
    *,
    format: str = "json",
    content_json: dict | None = None,
    created_by: str = "analyst@mxtac.local",
    status: str = "ready",
) -> str:
    """Insert a report record and return its id."""
    report_id = new_uuid()
    await ReportRepo.create(
        db_session,
        id=report_id,
        template_type="executive_summary",
        format=format,
        params_json={
            "from_date": "2025-01-01T00:00:00+00:00",
            "to_date": "2025-01-31T23:59:59+00:00",
        },
        created_by=created_by,
    )
    if status != "generating":
        await ReportRepo.update_status(
            db_session,
            report_id,
            status,
            content_json=content_json if status == "ready" else None,
            error="engine error" if status == "failed" else None,
        )
    await db_session.commit()
    return report_id


# ---------------------------------------------------------------------------
# POST /reports/generate
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_generate_returns_202(client: AsyncClient, analyst_headers: dict) -> None:
    """POST /reports/generate returns 202 with report_id and status='generating'."""
    with patch("app.api.v1.endpoints.reports.asyncio.create_task") as mock_ct:
        mock_ct.return_value = None
        resp = await client.post(_BASE_URL + "/generate", json=_GENERATE_BODY, headers=analyst_headers)

    assert resp.status_code == 202
    data = resp.json()
    assert "report_id" in data
    assert data["status"] == "generating"
    assert len(data["report_id"]) == 36  # UUID format


@pytest.mark.asyncio
async def test_generate_creates_db_record(
    client: AsyncClient, db_session: AsyncSession, analyst_headers: dict
) -> None:
    """POST /reports/generate persists a report record in the DB."""
    with patch("app.api.v1.endpoints.reports.asyncio.create_task") as mock_ct:
        mock_ct.return_value = None
        resp = await client.post(_BASE_URL + "/generate", json=_GENERATE_BODY, headers=analyst_headers)

    report_id = resp.json()["report_id"]
    report = await ReportRepo.get_by_id(db_session, report_id)
    assert report is not None
    assert report.status == "generating"
    assert report.template_type == "executive_summary"
    assert report.format == "json"
    assert report.created_by == "analyst@mxtac.local"


@pytest.mark.asyncio
async def test_generate_csv_format(client: AsyncClient, analyst_headers: dict) -> None:
    """CSV format is accepted for report generation."""
    body = {**_GENERATE_BODY, "format": "csv"}
    with patch("app.api.v1.endpoints.reports.asyncio.create_task") as mock_ct:
        mock_ct.return_value = None
        resp = await client.post(_BASE_URL + "/generate", json=body, headers=analyst_headers)

    assert resp.status_code == 202


@pytest.mark.asyncio
async def test_generate_invalid_template(client: AsyncClient, analyst_headers: dict) -> None:
    """Invalid template_type returns 422."""
    body = {**_GENERATE_BODY, "template_type": "invalid_template"}
    resp = await client.post(_BASE_URL + "/generate", json=body, headers=analyst_headers)
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_generate_invalid_date_range(client: AsyncClient, analyst_headers: dict) -> None:
    """from_date after to_date returns 422."""
    body = {
        **_GENERATE_BODY,
        "from_date": "2025-02-01T00:00:00Z",
        "to_date": "2025-01-01T00:00:00Z",
    }
    resp = await client.post(_BASE_URL + "/generate", json=body, headers=analyst_headers)
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# GET /reports
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_reports_empty(client: AsyncClient, analyst_headers: dict) -> None:
    """GET /reports returns empty list when no reports exist."""
    resp = await client.get(_BASE_URL, headers=analyst_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["items"] == []
    assert data["pagination"]["total"] == 0


@pytest.mark.asyncio
async def test_list_reports_returns_items(
    client: AsyncClient, db_session: AsyncSession, analyst_headers: dict
) -> None:
    """GET /reports returns seeded report records."""
    await _seed_ready_report(db_session, content_json=_SAMPLE_CONTENT)
    await _seed_ready_report(db_session, content_json=_SAMPLE_CONTENT)

    resp = await client.get(_BASE_URL, headers=analyst_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["pagination"]["total"] == 2
    assert len(data["items"]) == 2


@pytest.mark.asyncio
async def test_list_reports_pagination(
    client: AsyncClient, db_session: AsyncSession, analyst_headers: dict
) -> None:
    """Pagination parameters are respected."""
    for _ in range(5):
        await _seed_ready_report(db_session, content_json=_SAMPLE_CONTENT)

    resp = await client.get(_BASE_URL + "?page=1&page_size=2", headers=analyst_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["items"]) == 2
    assert data["pagination"]["total"] == 5
    assert data["pagination"]["total_pages"] == 3


@pytest.mark.asyncio
async def test_list_reports_filter_status(
    client: AsyncClient, db_session: AsyncSession, analyst_headers: dict
) -> None:
    """Status filter returns only matching reports."""
    await _seed_ready_report(db_session, content_json=_SAMPLE_CONTENT, status="ready")
    await _seed_ready_report(db_session, status="generating")

    resp = await client.get(_BASE_URL + "?status=ready", headers=analyst_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["pagination"]["total"] == 1
    assert data["items"][0]["status"] == "ready"


# ---------------------------------------------------------------------------
# GET /reports/{id}
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_report_metadata(
    client: AsyncClient, db_session: AsyncSession, analyst_headers: dict
) -> None:
    """GET /reports/{id} returns report metadata."""
    report_id = await _seed_ready_report(db_session, content_json=_SAMPLE_CONTENT)

    resp = await client.get(f"{_BASE_URL}/{report_id}", headers=analyst_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == report_id
    assert data["template_type"] == "executive_summary"
    assert data["status"] == "ready"
    assert data["format"] == "json"
    assert "params_json" in data
    assert "error" in data


@pytest.mark.asyncio
async def test_get_report_not_found(client: AsyncClient, analyst_headers: dict) -> None:
    """GET /reports/{id} returns 404 for unknown id."""
    resp = await client.get(f"{_BASE_URL}/{new_uuid()}", headers=analyst_headers)
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# GET /reports/{id}/download
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_download_json_report(
    client: AsyncClient, db_session: AsyncSession, analyst_headers: dict
) -> None:
    """Download a ready JSON report returns application/json."""
    report_id = await _seed_ready_report(
        db_session, format="json", content_json=_SAMPLE_CONTENT
    )

    resp = await client.get(f"{_BASE_URL}/{report_id}/download", headers=analyst_headers)
    assert resp.status_code == 200
    assert "application/json" in resp.headers["content-type"]
    payload = resp.json()
    assert payload["template"] == "executive_summary"


@pytest.mark.asyncio
async def test_download_csv_report(
    client: AsyncClient, db_session: AsyncSession, analyst_headers: dict
) -> None:
    """Download a ready CSV report returns text/csv."""
    report_id = await _seed_ready_report(
        db_session, format="csv", content_json=_SAMPLE_CONTENT
    )

    resp = await client.get(f"{_BASE_URL}/{report_id}/download", headers=analyst_headers)
    assert resp.status_code == 200
    assert "text/csv" in resp.headers["content-type"]
    body = resp.text
    assert "metric" in body or "total_detections" in body  # CSV header


@pytest.mark.asyncio
async def test_download_generating_report_returns_409(
    client: AsyncClient, db_session: AsyncSession, analyst_headers: dict
) -> None:
    """Downloading a still-generating report returns 409 Conflict."""
    report_id = await _seed_ready_report(db_session, status="generating")

    resp = await client.get(f"{_BASE_URL}/{report_id}/download", headers=analyst_headers)
    assert resp.status_code == 409
    assert "generated" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_download_failed_report_returns_409(
    client: AsyncClient, db_session: AsyncSession, analyst_headers: dict
) -> None:
    """Downloading a failed report returns 409 Conflict."""
    report_id = await _seed_ready_report(db_session, status="failed")

    resp = await client.get(f"{_BASE_URL}/{report_id}/download", headers=analyst_headers)
    assert resp.status_code == 409
    assert "failed" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_download_not_found(client: AsyncClient, analyst_headers: dict) -> None:
    """Downloading a non-existent report returns 404."""
    resp = await client.get(f"{_BASE_URL}/{new_uuid()}/download", headers=analyst_headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_download_has_content_disposition_header(
    client: AsyncClient, db_session: AsyncSession, analyst_headers: dict
) -> None:
    """Download response includes Content-Disposition attachment header."""
    report_id = await _seed_ready_report(
        db_session, format="json", content_json=_SAMPLE_CONTENT
    )

    resp = await client.get(f"{_BASE_URL}/{report_id}/download", headers=analyst_headers)
    assert resp.status_code == 200
    assert "attachment" in resp.headers.get("content-disposition", "")


# ---------------------------------------------------------------------------
# DELETE /reports/{id}
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_delete_report(
    client: AsyncClient, db_session: AsyncSession, analyst_headers: dict
) -> None:
    """DELETE /reports/{id} returns 204 and removes the record."""
    report_id = await _seed_ready_report(db_session, content_json=_SAMPLE_CONTENT)

    resp = await client.delete(f"{_BASE_URL}/{report_id}", headers=analyst_headers)
    assert resp.status_code == 204
    assert resp.content == b""

    # Confirm it's gone
    get_resp = await client.get(f"{_BASE_URL}/{report_id}", headers=analyst_headers)
    assert get_resp.status_code == 404


@pytest.mark.asyncio
async def test_delete_report_not_found(client: AsyncClient, analyst_headers: dict) -> None:
    """DELETE /reports/{id} returns 404 for unknown id."""
    resp = await client.delete(f"{_BASE_URL}/{new_uuid()}", headers=analyst_headers)
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# RBAC — viewer denied
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_viewer_cannot_generate_report(
    client: AsyncClient, viewer_headers: dict
) -> None:
    """Viewer role is denied (403) when generating a report."""
    resp = await client.post(_BASE_URL + "/generate", json=_GENERATE_BODY, headers=viewer_headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_viewer_cannot_list_reports(
    client: AsyncClient, viewer_headers: dict
) -> None:
    """Viewer role is denied (403) when listing reports."""
    resp = await client.get(_BASE_URL, headers=viewer_headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_viewer_cannot_get_report(
    client: AsyncClient, viewer_headers: dict
) -> None:
    """Viewer role is denied (403) when fetching report metadata."""
    resp = await client.get(f"{_BASE_URL}/{new_uuid()}", headers=viewer_headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_viewer_cannot_download_report(
    client: AsyncClient, viewer_headers: dict
) -> None:
    """Viewer role is denied (403) when downloading a report."""
    resp = await client.get(f"{_BASE_URL}/{new_uuid()}/download", headers=viewer_headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_viewer_cannot_delete_report(
    client: AsyncClient, viewer_headers: dict
) -> None:
    """Viewer role is denied (403) when deleting a report."""
    resp = await client.delete(f"{_BASE_URL}/{new_uuid()}", headers=viewer_headers)
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Unauthenticated — 401
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unauthenticated_generate(client: AsyncClient) -> None:
    resp = await client.post(_BASE_URL + "/generate", json=_GENERATE_BODY)
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_unauthenticated_list(client: AsyncClient) -> None:
    resp = await client.get(_BASE_URL)
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_unauthenticated_get(client: AsyncClient) -> None:
    resp = await client.get(f"{_BASE_URL}/{new_uuid()}")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_unauthenticated_download(client: AsyncClient) -> None:
    resp = await client.get(f"{_BASE_URL}/{new_uuid()}/download")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_unauthenticated_delete(client: AsyncClient) -> None:
    resp = await client.delete(f"{_BASE_URL}/{new_uuid()}")
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Analyst and engineer can use reports
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_hunter_can_list_reports(client: AsyncClient, hunter_headers: dict) -> None:
    """Hunter role can list reports."""
    resp = await client.get(_BASE_URL, headers=hunter_headers)
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_engineer_can_generate_report(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """Engineer role can generate reports."""
    with patch("app.api.v1.endpoints.reports.asyncio.create_task") as mock_ct:
        mock_ct.return_value = None
        resp = await client.post(
            _BASE_URL + "/generate", json=_GENERATE_BODY, headers=engineer_headers
        )
    assert resp.status_code == 202
