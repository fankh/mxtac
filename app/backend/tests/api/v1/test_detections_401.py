"""Tests for 401 behaviour across Detections API endpoints — Feature 28.34.

Coverage:
  - GET /detections — no Authorization header → 401
  - GET /detections — malformed Authorization header → 401
  - GET /detections — invalid/tampered JWT token → 401
  - GET /detections — expired JWT token → 401
  - GET /detections — 401 response body has 'detail' key
  - GET /detections/{id} — no Authorization header → 401
  - GET /detections/{id} — invalid JWT → 401
  - GET /detections/{id} — 401 response body has 'detail' key
  - PATCH /detections/{id} — no Authorization header → 401
  - PATCH /detections/{id} — invalid JWT → 401
  - PATCH /detections/{id} — 401 response body has 'detail' key
  - DELETE /detections/{id} — no Authorization header → 401
  - DELETE /detections/{id} — invalid JWT → 401
  - DELETE /detections/{id} — 401 response body has 'detail' key
  - Parametrised: all four endpoints return 401 when no auth is provided
  - Parametrised: all four endpoints return 401 with an invalid JWT
  - Repo is never called for unauthenticated requests (auth checked first)
  - 401 precedes 403: authentication failure beats authorisation failure

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

_INVALID_TOKEN = "this.is.not.a.valid.jwt"
_GARBAGE_TOKEN = "Bearer eyJhbGciOiJub25lIn0.e30."  # alg=none — must be rejected


def _expired_token() -> str:
    """Create a JWT that expired one hour ago."""
    return create_access_token(
        {"sub": "expired@mxtac.local", "role": "analyst"},
        expires_delta=timedelta(hours=-1),
    )


def _valid_analyst_headers() -> dict[str, str]:
    token = create_access_token(
        {"sub": "analyst@mxtac.local", "role": "analyst"},
        expires_delta=timedelta(hours=1),
    )
    return {"Authorization": f"Bearer {token}"}


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
# GET /detections — unauthenticated → 401
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_detections_no_auth_returns_401(client: AsyncClient) -> None:
    """GET /detections without Authorization header → 401."""
    resp = await client.get("/api/v1/detections")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_list_detections_no_auth_has_detail_key(client: AsyncClient) -> None:
    """GET /detections without auth — 401 response body contains 'detail' key."""
    resp = await client.get("/api/v1/detections")
    assert resp.status_code == 401
    assert "detail" in resp.json()


@pytest.mark.asyncio
async def test_list_detections_invalid_token_returns_401(client: AsyncClient) -> None:
    """GET /detections with an invalid JWT token → 401."""
    resp = await client.get(
        "/api/v1/detections",
        headers={"Authorization": f"Bearer {_INVALID_TOKEN}"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_list_detections_invalid_token_has_detail_key(
    client: AsyncClient,
) -> None:
    """GET /detections with invalid JWT — 401 response body contains 'detail' key."""
    resp = await client.get(
        "/api/v1/detections",
        headers={"Authorization": f"Bearer {_INVALID_TOKEN}"},
    )
    assert resp.status_code == 401
    assert "detail" in resp.json()


@pytest.mark.asyncio
async def test_list_detections_expired_token_returns_401(client: AsyncClient) -> None:
    """GET /detections with an expired JWT → 401."""
    resp = await client.get(
        "/api/v1/detections",
        headers={"Authorization": f"Bearer {_expired_token()}"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_list_detections_malformed_header_returns_401(
    client: AsyncClient,
) -> None:
    """GET /detections with a malformed Authorization header (no Bearer prefix) → 401."""
    resp = await client.get(
        "/api/v1/detections",
        headers={"Authorization": "not-a-bearer-token"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_list_detections_no_auth_repo_not_called(client: AsyncClient) -> None:
    """GET /detections without auth — DetectionRepo.list is never invoked (auth first)."""
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        resp = await client.get("/api/v1/detections")
    assert resp.status_code == 401
    mock_list.assert_not_called()


# ---------------------------------------------------------------------------
# GET /detections/{id} — unauthenticated → 401
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_detection_no_auth_returns_401(client: AsyncClient) -> None:
    """GET /detections/{id} without Authorization header → 401."""
    resp = await client.get("/api/v1/detections/DET-2026-00001")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_get_detection_no_auth_has_detail_key(client: AsyncClient) -> None:
    """GET /detections/{id} without auth — 401 response body contains 'detail' key."""
    resp = await client.get("/api/v1/detections/DET-2026-00001")
    assert resp.status_code == 401
    assert "detail" in resp.json()


@pytest.mark.asyncio
async def test_get_detection_invalid_token_returns_401(client: AsyncClient) -> None:
    """GET /detections/{id} with an invalid JWT token → 401."""
    resp = await client.get(
        "/api/v1/detections/DET-2026-00001",
        headers={"Authorization": f"Bearer {_INVALID_TOKEN}"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_get_detection_expired_token_returns_401(client: AsyncClient) -> None:
    """GET /detections/{id} with an expired JWT token → 401."""
    resp = await client.get(
        "/api/v1/detections/DET-2026-00001",
        headers={"Authorization": f"Bearer {_expired_token()}"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_get_detection_no_auth_repo_not_called(client: AsyncClient) -> None:
    """GET /detections/{id} without auth — DetectionRepo.get is never invoked."""
    mock_get = AsyncMock(return_value=_make_detection())
    with patch(f"{MOCK_REPO}.get", new=mock_get):
        resp = await client.get("/api/v1/detections/DET-2026-00001")
    assert resp.status_code == 401
    mock_get.assert_not_called()


# ---------------------------------------------------------------------------
# PATCH /detections/{id} — unauthenticated → 401
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_patch_detection_no_auth_returns_401(client: AsyncClient) -> None:
    """PATCH /detections/{id} without Authorization header → 401."""
    resp = await client.patch(
        "/api/v1/detections/DET-2026-00001",
        json={"status": "investigating"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_patch_detection_no_auth_has_detail_key(client: AsyncClient) -> None:
    """PATCH /detections/{id} without auth — 401 response body contains 'detail' key."""
    resp = await client.patch(
        "/api/v1/detections/DET-2026-00001",
        json={"status": "investigating"},
    )
    assert resp.status_code == 401
    assert "detail" in resp.json()


@pytest.mark.asyncio
async def test_patch_detection_invalid_token_returns_401(client: AsyncClient) -> None:
    """PATCH /detections/{id} with an invalid JWT token → 401."""
    resp = await client.patch(
        "/api/v1/detections/DET-2026-00001",
        headers={"Authorization": f"Bearer {_INVALID_TOKEN}"},
        json={"status": "resolved"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_patch_detection_expired_token_returns_401(client: AsyncClient) -> None:
    """PATCH /detections/{id} with an expired JWT token → 401."""
    resp = await client.patch(
        "/api/v1/detections/DET-2026-00001",
        headers={"Authorization": f"Bearer {_expired_token()}"},
        json={"status": "resolved"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_patch_detection_no_auth_repo_not_called(client: AsyncClient) -> None:
    """PATCH /detections/{id} without auth — DetectionRepo.update is never invoked."""
    mock_update = AsyncMock(return_value=_make_detection())
    with patch(f"{MOCK_REPO}.update", new=mock_update):
        resp = await client.patch(
            "/api/v1/detections/DET-2026-00001",
            json={"status": "investigating"},
        )
    assert resp.status_code == 401
    mock_update.assert_not_called()


# ---------------------------------------------------------------------------
# DELETE /detections/{id} — unauthenticated → 401
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_delete_detection_no_auth_returns_401(client: AsyncClient) -> None:
    """DELETE /detections/{id} without Authorization header → 401."""
    resp = await client.delete("/api/v1/detections/DET-2026-00001")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_delete_detection_no_auth_has_detail_key(client: AsyncClient) -> None:
    """DELETE /detections/{id} without auth — 401 response body contains 'detail' key."""
    resp = await client.delete("/api/v1/detections/DET-2026-00001")
    assert resp.status_code == 401
    assert "detail" in resp.json()


@pytest.mark.asyncio
async def test_delete_detection_invalid_token_returns_401(client: AsyncClient) -> None:
    """DELETE /detections/{id} with an invalid JWT token → 401."""
    resp = await client.delete(
        "/api/v1/detections/DET-2026-00001",
        headers={"Authorization": f"Bearer {_INVALID_TOKEN}"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_delete_detection_expired_token_returns_401(client: AsyncClient) -> None:
    """DELETE /detections/{id} with an expired JWT token → 401."""
    resp = await client.delete(
        "/api/v1/detections/DET-2026-00001",
        headers={"Authorization": f"Bearer {_expired_token()}"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_delete_detection_no_auth_repo_not_called(client: AsyncClient) -> None:
    """DELETE /detections/{id} without auth — DetectionRepo.delete is never invoked."""
    mock_delete = AsyncMock(return_value=True)
    with patch(f"{MOCK_REPO}.delete", new=mock_delete):
        resp = await client.delete("/api/v1/detections/DET-2026-00001")
    assert resp.status_code == 401
    mock_delete.assert_not_called()


# ---------------------------------------------------------------------------
# Parametrised: all four endpoints → 401 with no Authorization header
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "method, url, body",
    [
        ("GET", "/api/v1/detections", None),
        ("GET", "/api/v1/detections/DET-2026-00001", None),
        ("PATCH", "/api/v1/detections/DET-2026-00001", {"status": "investigating"}),
        ("DELETE", "/api/v1/detections/DET-2026-00001", None),
    ],
)
@pytest.mark.asyncio
async def test_all_endpoints_no_auth_returns_401(
    client: AsyncClient, method: str, url: str, body: dict | None
) -> None:
    """Every Detections API endpoint returns 401 when no Authorization header is sent."""
    resp = await client.request(method, url, json=body)
    assert resp.status_code == 401, (
        f"{method} {url} should return 401 when unauthenticated, got {resp.status_code}"
    )


@pytest.mark.parametrize(
    "method, url, body",
    [
        ("GET", "/api/v1/detections", None),
        ("GET", "/api/v1/detections/DET-2026-00001", None),
        ("PATCH", "/api/v1/detections/DET-2026-00001", {"status": "investigating"}),
        ("DELETE", "/api/v1/detections/DET-2026-00001", None),
    ],
)
@pytest.mark.asyncio
async def test_all_endpoints_invalid_token_returns_401(
    client: AsyncClient, method: str, url: str, body: dict | None
) -> None:
    """Every Detections API endpoint returns 401 when an invalid JWT is provided."""
    resp = await client.request(
        method,
        url,
        json=body,
        headers={"Authorization": f"Bearer {_INVALID_TOKEN}"},
    )
    assert resp.status_code == 401, (
        f"{method} {url} should return 401 with invalid token, got {resp.status_code}"
    )


# ---------------------------------------------------------------------------
# 401 precedes 403: authentication failure beats authorisation failure
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_detections_401_precedes_403(client: AsyncClient) -> None:
    """Unauthenticated GET /detections returns 401, not 403.

    Even though an anonymous caller would also fail authorisation, the
    authentication layer must respond first with 401.
    """
    resp = await client.get("/api/v1/detections")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_patch_detection_401_precedes_403(client: AsyncClient) -> None:
    """Unauthenticated PATCH /detections/{id} returns 401, not 403.

    RBAC (which would yield 403) must never be reached before authentication.
    """
    resp = await client.patch(
        "/api/v1/detections/DET-2026-00001",
        json={"status": "resolved"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_delete_detection_401_precedes_403(client: AsyncClient) -> None:
    """Unauthenticated DELETE /detections/{id} returns 401, not 403.

    DELETE requires admin role (403 for non-admins), but auth must fail first.
    """
    resp = await client.delete("/api/v1/detections/DET-2026-00001")
    assert resp.status_code == 401
