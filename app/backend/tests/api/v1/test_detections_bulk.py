"""Tests for POST /detections/bulk — bulk status update — Feature 10.10.

Coverage:
  - Happy path: all IDs found → 200 with updated=N, not_found=[]
  - Partial match: some IDs missing → 200 with correct updated count and not_found list
  - None found: no IDs match → 200 with updated=0, not_found=[all_ids]
  - Single ID: bulk works with a single-element list
  - All valid status values: active, investigating, resolved, false_positive
  - Validation: empty ids list → 422
  - Validation: missing ids field → 422
  - Validation: missing status field → 422
  - Validation: invalid status value → 422
  - Auth: no auth header → 401
  - RBAC: viewer role → 403
  - RBAC: analyst role → 200 (has detections:write)
  - RBAC: admin role → 200 (has detections:write)
  - Repo not called when viewer sends request (403 short-circuits)
  - Response structure: updated (int), not_found (list[str])
  - not_found preserves input order of missing IDs

All tests mock DetectionRepo so no live PostgreSQL instance is needed.
"""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient

from app.core.security import create_access_token

MOCK_REPO = "app.api.v1.endpoints.detections.DetectionRepo"
BULK_URL = "/api/v1/detections/bulk"

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


# ---------------------------------------------------------------------------
# Happy path — all IDs found
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bulk_update_all_found_returns_200(client: AsyncClient) -> None:
    """POST /detections/bulk where all IDs exist → 200."""
    mock_result = {"updated": 3, "not_found": []}
    with patch(f"{MOCK_REPO}.bulk_update_status", new=AsyncMock(return_value=mock_result)):
        resp = await client.post(
            BULK_URL,
            headers=_analyst_headers(),
            json={"ids": ["DET-001", "DET-002", "DET-003"], "status": "resolved"},
        )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_bulk_update_all_found_returns_correct_updated_count(client: AsyncClient) -> None:
    """POST /detections/bulk — updated count equals the number of matched IDs."""
    mock_result = {"updated": 3, "not_found": []}
    with patch(f"{MOCK_REPO}.bulk_update_status", new=AsyncMock(return_value=mock_result)):
        resp = await client.post(
            BULK_URL,
            headers=_analyst_headers(),
            json={"ids": ["DET-001", "DET-002", "DET-003"], "status": "resolved"},
        )
    assert resp.json()["updated"] == 3


@pytest.mark.asyncio
async def test_bulk_update_all_found_returns_empty_not_found(client: AsyncClient) -> None:
    """POST /detections/bulk — not_found is empty when all IDs exist."""
    mock_result = {"updated": 2, "not_found": []}
    with patch(f"{MOCK_REPO}.bulk_update_status", new=AsyncMock(return_value=mock_result)):
        resp = await client.post(
            BULK_URL,
            headers=_analyst_headers(),
            json={"ids": ["DET-001", "DET-002"], "status": "investigating"},
        )
    assert resp.json()["not_found"] == []


# ---------------------------------------------------------------------------
# Partial match — some IDs missing
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bulk_update_partial_match_returns_200(client: AsyncClient) -> None:
    """POST /detections/bulk — partial match still returns 200 (not 404)."""
    mock_result = {"updated": 1, "not_found": ["DET-MISSING"]}
    with patch(f"{MOCK_REPO}.bulk_update_status", new=AsyncMock(return_value=mock_result)):
        resp = await client.post(
            BULK_URL,
            headers=_analyst_headers(),
            json={"ids": ["DET-001", "DET-MISSING"], "status": "resolved"},
        )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_bulk_update_partial_match_not_found_list(client: AsyncClient) -> None:
    """POST /detections/bulk — not_found contains missing IDs."""
    mock_result = {"updated": 1, "not_found": ["DET-MISSING"]}
    with patch(f"{MOCK_REPO}.bulk_update_status", new=AsyncMock(return_value=mock_result)):
        resp = await client.post(
            BULK_URL,
            headers=_analyst_headers(),
            json={"ids": ["DET-001", "DET-MISSING"], "status": "resolved"},
        )
    assert resp.json()["not_found"] == ["DET-MISSING"]


@pytest.mark.asyncio
async def test_bulk_update_partial_match_updated_count(client: AsyncClient) -> None:
    """POST /detections/bulk — updated count is only the matched detections."""
    mock_result = {"updated": 2, "not_found": ["DET-X", "DET-Y"]}
    with patch(f"{MOCK_REPO}.bulk_update_status", new=AsyncMock(return_value=mock_result)):
        resp = await client.post(
            BULK_URL,
            headers=_analyst_headers(),
            json={"ids": ["DET-001", "DET-002", "DET-X", "DET-Y"], "status": "active"},
        )
    assert resp.json()["updated"] == 2


# ---------------------------------------------------------------------------
# None found
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bulk_update_none_found_returns_200(client: AsyncClient) -> None:
    """POST /detections/bulk — no IDs match still returns 200."""
    mock_result = {"updated": 0, "not_found": ["DET-A", "DET-B"]}
    with patch(f"{MOCK_REPO}.bulk_update_status", new=AsyncMock(return_value=mock_result)):
        resp = await client.post(
            BULK_URL,
            headers=_analyst_headers(),
            json={"ids": ["DET-A", "DET-B"], "status": "resolved"},
        )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_bulk_update_none_found_updated_is_zero(client: AsyncClient) -> None:
    """POST /detections/bulk — updated is 0 when no IDs match."""
    mock_result = {"updated": 0, "not_found": ["DET-A"]}
    with patch(f"{MOCK_REPO}.bulk_update_status", new=AsyncMock(return_value=mock_result)):
        resp = await client.post(
            BULK_URL,
            headers=_analyst_headers(),
            json={"ids": ["DET-A"], "status": "false_positive"},
        )
    assert resp.json()["updated"] == 0


@pytest.mark.asyncio
async def test_bulk_update_none_found_all_in_not_found(client: AsyncClient) -> None:
    """POST /detections/bulk — all input IDs appear in not_found when none match."""
    input_ids = ["DET-A", "DET-B"]
    mock_result = {"updated": 0, "not_found": input_ids}
    with patch(f"{MOCK_REPO}.bulk_update_status", new=AsyncMock(return_value=mock_result)):
        resp = await client.post(
            BULK_URL,
            headers=_analyst_headers(),
            json={"ids": input_ids, "status": "resolved"},
        )
    assert resp.json()["not_found"] == input_ids


# ---------------------------------------------------------------------------
# Single ID
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bulk_update_single_id_found(client: AsyncClient) -> None:
    """POST /detections/bulk with a single matching ID → updated=1."""
    mock_result = {"updated": 1, "not_found": []}
    with patch(f"{MOCK_REPO}.bulk_update_status", new=AsyncMock(return_value=mock_result)):
        resp = await client.post(
            BULK_URL,
            headers=_analyst_headers(),
            json={"ids": ["DET-SOLO"], "status": "investigating"},
        )
    assert resp.status_code == 200
    assert resp.json()["updated"] == 1
    assert resp.json()["not_found"] == []


# ---------------------------------------------------------------------------
# All valid status values
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("status", ["active", "investigating", "resolved", "false_positive"])
@pytest.mark.asyncio
async def test_bulk_update_all_status_values_accepted(
    client: AsyncClient, status: str
) -> None:
    """POST /detections/bulk accepts all valid DetectionStatus values."""
    mock_result = {"updated": 1, "not_found": []}
    with patch(f"{MOCK_REPO}.bulk_update_status", new=AsyncMock(return_value=mock_result)):
        resp = await client.post(
            BULK_URL,
            headers=_analyst_headers(),
            json={"ids": ["DET-001"], "status": status},
        )
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Validation errors — 422
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bulk_update_empty_ids_returns_422(client: AsyncClient) -> None:
    """POST /detections/bulk with empty ids list → 422 Unprocessable Entity."""
    resp = await client.post(
        BULK_URL,
        headers=_analyst_headers(),
        json={"ids": [], "status": "resolved"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_bulk_update_missing_ids_field_returns_422(client: AsyncClient) -> None:
    """POST /detections/bulk without ids field → 422."""
    resp = await client.post(
        BULK_URL,
        headers=_analyst_headers(),
        json={"status": "resolved"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_bulk_update_missing_status_field_returns_422(client: AsyncClient) -> None:
    """POST /detections/bulk without status field → 422."""
    resp = await client.post(
        BULK_URL,
        headers=_analyst_headers(),
        json={"ids": ["DET-001"]},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_bulk_update_invalid_status_value_returns_422(client: AsyncClient) -> None:
    """POST /detections/bulk with invalid status value → 422."""
    resp = await client.post(
        BULK_URL,
        headers=_analyst_headers(),
        json={"ids": ["DET-001"], "status": "unknown_status"},
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Authentication — 401
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bulk_update_no_auth_returns_401(client: AsyncClient) -> None:
    """POST /detections/bulk without auth header → 401 Unauthorized."""
    resp = await client.post(
        BULK_URL,
        json={"ids": ["DET-001"], "status": "resolved"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_bulk_update_invalid_token_returns_401(client: AsyncClient) -> None:
    """POST /detections/bulk with malformed JWT → 401 Unauthorized."""
    resp = await client.post(
        BULK_URL,
        headers={"Authorization": "Bearer not-a-valid-token"},
        json={"ids": ["DET-001"], "status": "resolved"},
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# RBAC — 403
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bulk_update_viewer_returns_403(client: AsyncClient) -> None:
    """POST /detections/bulk with viewer role → 403 (lacks detections:write)."""
    resp = await client.post(
        BULK_URL,
        headers=_viewer_headers(),
        json={"ids": ["DET-001"], "status": "resolved"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_bulk_update_analyst_returns_200(client: AsyncClient) -> None:
    """POST /detections/bulk with analyst role → 200 (has detections:write)."""
    mock_result = {"updated": 1, "not_found": []}
    with patch(f"{MOCK_REPO}.bulk_update_status", new=AsyncMock(return_value=mock_result)):
        resp = await client.post(
            BULK_URL,
            headers=_analyst_headers(),
            json={"ids": ["DET-001"], "status": "resolved"},
        )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_bulk_update_admin_returns_200(client: AsyncClient) -> None:
    """POST /detections/bulk with admin role → 200 (has detections:write)."""
    mock_result = {"updated": 1, "not_found": []}
    with patch(f"{MOCK_REPO}.bulk_update_status", new=AsyncMock(return_value=mock_result)):
        resp = await client.post(
            BULK_URL,
            headers=_admin_headers(),
            json={"ids": ["DET-001"], "status": "resolved"},
        )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_bulk_update_viewer_repo_not_called(client: AsyncClient) -> None:
    """POST /detections/bulk by viewer → 403 and repo is never called."""
    mock_bulk = AsyncMock(return_value={"updated": 0, "not_found": []})
    with patch(f"{MOCK_REPO}.bulk_update_status", new=mock_bulk):
        resp = await client.post(
            BULK_URL,
            headers=_viewer_headers(),
            json={"ids": ["DET-001"], "status": "resolved"},
        )
    assert resp.status_code == 403
    mock_bulk.assert_not_called()


# ---------------------------------------------------------------------------
# Response structure
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bulk_update_response_has_updated_key(client: AsyncClient) -> None:
    """POST /detections/bulk response body contains an 'updated' key."""
    mock_result = {"updated": 2, "not_found": []}
    with patch(f"{MOCK_REPO}.bulk_update_status", new=AsyncMock(return_value=mock_result)):
        resp = await client.post(
            BULK_URL,
            headers=_analyst_headers(),
            json={"ids": ["DET-001", "DET-002"], "status": "resolved"},
        )
    assert "updated" in resp.json()


@pytest.mark.asyncio
async def test_bulk_update_response_has_not_found_key(client: AsyncClient) -> None:
    """POST /detections/bulk response body contains a 'not_found' key."""
    mock_result = {"updated": 1, "not_found": []}
    with patch(f"{MOCK_REPO}.bulk_update_status", new=AsyncMock(return_value=mock_result)):
        resp = await client.post(
            BULK_URL,
            headers=_analyst_headers(),
            json={"ids": ["DET-001"], "status": "resolved"},
        )
    assert "not_found" in resp.json()


@pytest.mark.asyncio
async def test_bulk_update_updated_is_integer(client: AsyncClient) -> None:
    """POST /detections/bulk — 'updated' field is an integer."""
    mock_result = {"updated": 3, "not_found": []}
    with patch(f"{MOCK_REPO}.bulk_update_status", new=AsyncMock(return_value=mock_result)):
        resp = await client.post(
            BULK_URL,
            headers=_analyst_headers(),
            json={"ids": ["DET-001", "DET-002", "DET-003"], "status": "active"},
        )
    assert isinstance(resp.json()["updated"], int)


@pytest.mark.asyncio
async def test_bulk_update_not_found_is_list(client: AsyncClient) -> None:
    """POST /detections/bulk — 'not_found' field is a list."""
    mock_result = {"updated": 1, "not_found": ["DET-MISSING"]}
    with patch(f"{MOCK_REPO}.bulk_update_status", new=AsyncMock(return_value=mock_result)):
        resp = await client.post(
            BULK_URL,
            headers=_analyst_headers(),
            json={"ids": ["DET-001", "DET-MISSING"], "status": "resolved"},
        )
    assert isinstance(resp.json()["not_found"], list)


# ---------------------------------------------------------------------------
# Repo called with correct arguments
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bulk_update_passes_ids_to_repo(client: AsyncClient) -> None:
    """POST /detections/bulk passes the exact ids list to the repository."""
    input_ids = ["DET-001", "DET-002", "DET-003"]
    mock_bulk = AsyncMock(return_value={"updated": 3, "not_found": []})
    with patch(f"{MOCK_REPO}.bulk_update_status", new=mock_bulk):
        await client.post(
            BULK_URL,
            headers=_analyst_headers(),
            json={"ids": input_ids, "status": "resolved"},
        )
    mock_bulk.assert_called_once()
    call_args = mock_bulk.call_args
    assert call_args.args[1] == input_ids


@pytest.mark.asyncio
async def test_bulk_update_passes_status_to_repo(client: AsyncClient) -> None:
    """POST /detections/bulk passes the status string to the repository."""
    mock_bulk = AsyncMock(return_value={"updated": 1, "not_found": []})
    with patch(f"{MOCK_REPO}.bulk_update_status", new=mock_bulk):
        await client.post(
            BULK_URL,
            headers=_analyst_headers(),
            json={"ids": ["DET-001"], "status": "false_positive"},
        )
    mock_bulk.assert_called_once()
    call_args = mock_bulk.call_args
    assert call_args.args[2] == "false_positive"
