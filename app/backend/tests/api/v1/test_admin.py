"""Tests for /api/v1/admin/* endpoint coverage gaps.

Covers scenarios not addressed by the specialised admin test files:

  test_admin_audit_log.py   — GET  /admin/audit-log   (full coverage)
  test_admin_snapshots.py   — GET/POST /admin/snapshots, POST /admin/snapshots/{name}/restore
  test_admin_retention.py   — GET  /admin/retention   (full coverage)

Gaps addressed here:
  1. Superadmin role (role="superadmin") is allowed by _require_admin but untested.
  2. Hunter and engineer roles get 403 on snapshot endpoints
     (existing tests only check analyst/viewer).
  3. Hunter role gets 403 on retention endpoint.
  4. "Admin access required" detail appears consistently on snapshot/retention 403s.
  5. Snapshot name path-param validation: valid and invalid name patterns.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient

from app.main import app
from app.services.opensearch_client import get_opensearch_dep

_AUDIT_LOG = "/api/v1/admin/audit-log"
_SNAPSHOTS = "/api/v1/admin/snapshots"
_RETENTION = "/api/v1/admin/retention"

_FAKE_STATS = {
    "detections_total": 0,
    "incidents_total": 0,
    "iocs_total": 0,
    "detections_eligible_for_deletion": 0,
    "incidents_eligible_for_deletion": 0,
    "iocs_eligible_for_deletion": 0,
}

_FAKE_SNAPSHOTS = [
    {
        "name": "mxtac-20240101-120000",
        "state": "SUCCESS",
        "start_time": "2024-01-01T12:00:00.000Z",
        "end_time": "2024-01-01T12:00:05.000Z",
        "duration_millis": 5000,
        "indices": ["mxtac-events-2024.01.01"],
        "size_bytes": 0,
        "shards_total": 1,
        "shards_successful": 1,
        "shards_failed": 0,
    }
]

_MOCK_AUDIT_LOGGER = "app.api.v1.endpoints.admin.get_audit_logger"
_MOCK_RETENTION_STATS = "app.api.v1.endpoints.admin.get_retention_storage_stats"


def _available_os() -> MagicMock:
    mock = MagicMock()
    mock.is_available = True
    mock.create_snapshot_repo = AsyncMock(return_value=True)
    mock.create_snapshot = AsyncMock(return_value={"snapshot": {}})
    mock.list_snapshots = AsyncMock(return_value=_FAKE_SNAPSHOTS)
    mock.restore_snapshot = AsyncMock(return_value=True)
    return mock


def _mock_audit_logger() -> MagicMock:
    mock = MagicMock()
    mock.search = AsyncMock(return_value={"total": 0, "items": []})
    return mock


# ---------------------------------------------------------------------------
# 1. Superadmin role — allowed by _require_admin
# ---------------------------------------------------------------------------


@pytest.fixture
def superadmin_headers() -> dict[str, str]:
    """JWT auth headers for the superadmin role."""
    from datetime import timedelta
    from app.core.security import create_access_token

    token = create_access_token(
        {"sub": "superadmin@mxtac.local", "role": "superadmin"},
        expires_delta=timedelta(hours=1),
    )
    return {"Authorization": f"Bearer {token}"}


class TestSuperadminAccess:
    """Superadmin role must be permitted on all admin-only endpoints."""

    @pytest.mark.asyncio
    async def test_superadmin_audit_log_returns_200(
        self, client: AsyncClient, superadmin_headers: dict
    ) -> None:
        with patch(_MOCK_AUDIT_LOGGER, return_value=_mock_audit_logger()):
            resp = await client.get(_AUDIT_LOG, headers=superadmin_headers)
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_superadmin_create_snapshot_returns_202(
        self, client: AsyncClient, superadmin_headers: dict
    ) -> None:
        mock_os = _available_os()
        app.dependency_overrides[get_opensearch_dep] = lambda: mock_os
        try:
            resp = await client.post(_SNAPSHOTS, headers=superadmin_headers)
            assert resp.status_code == 202
        finally:
            app.dependency_overrides.pop(get_opensearch_dep, None)

    @pytest.mark.asyncio
    async def test_superadmin_list_snapshots_returns_200(
        self, client: AsyncClient, superadmin_headers: dict
    ) -> None:
        mock_os = _available_os()
        app.dependency_overrides[get_opensearch_dep] = lambda: mock_os
        try:
            resp = await client.get(_SNAPSHOTS, headers=superadmin_headers)
            assert resp.status_code == 200
        finally:
            app.dependency_overrides.pop(get_opensearch_dep, None)

    @pytest.mark.asyncio
    async def test_superadmin_restore_snapshot_returns_202(
        self, client: AsyncClient, superadmin_headers: dict
    ) -> None:
        mock_os = _available_os()
        app.dependency_overrides[get_opensearch_dep] = lambda: mock_os
        try:
            resp = await client.post(
                f"{_SNAPSHOTS}/mxtac-20240101-120000/restore",
                headers=superadmin_headers,
            )
            assert resp.status_code == 202
        finally:
            app.dependency_overrides.pop(get_opensearch_dep, None)

    @pytest.mark.asyncio
    async def test_superadmin_retention_returns_200(
        self, client: AsyncClient, superadmin_headers: dict
    ) -> None:
        with patch(
            _MOCK_RETENTION_STATS,
            new=AsyncMock(return_value=_FAKE_STATS),
        ):
            resp = await client.get(_RETENTION, headers=superadmin_headers)
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 2. Hunter/Engineer → 403 on snapshot endpoints
# ---------------------------------------------------------------------------


class TestSnapshotRbacHunterEngineer:
    """Hunter and engineer roles must be denied access to all snapshot endpoints."""

    @pytest.mark.asyncio
    async def test_hunter_cannot_create_snapshot(
        self, client: AsyncClient, hunter_headers: dict
    ) -> None:
        mock_os = _available_os()
        app.dependency_overrides[get_opensearch_dep] = lambda: mock_os
        try:
            resp = await client.post(_SNAPSHOTS, headers=hunter_headers)
            assert resp.status_code == 403
        finally:
            app.dependency_overrides.pop(get_opensearch_dep, None)

    @pytest.mark.asyncio
    async def test_engineer_cannot_create_snapshot(
        self, client: AsyncClient, engineer_headers: dict
    ) -> None:
        mock_os = _available_os()
        app.dependency_overrides[get_opensearch_dep] = lambda: mock_os
        try:
            resp = await client.post(_SNAPSHOTS, headers=engineer_headers)
            assert resp.status_code == 403
        finally:
            app.dependency_overrides.pop(get_opensearch_dep, None)

    @pytest.mark.asyncio
    async def test_hunter_cannot_list_snapshots(
        self, client: AsyncClient, hunter_headers: dict
    ) -> None:
        mock_os = _available_os()
        app.dependency_overrides[get_opensearch_dep] = lambda: mock_os
        try:
            resp = await client.get(_SNAPSHOTS, headers=hunter_headers)
            assert resp.status_code == 403
        finally:
            app.dependency_overrides.pop(get_opensearch_dep, None)

    @pytest.mark.asyncio
    async def test_engineer_cannot_list_snapshots(
        self, client: AsyncClient, engineer_headers: dict
    ) -> None:
        mock_os = _available_os()
        app.dependency_overrides[get_opensearch_dep] = lambda: mock_os
        try:
            resp = await client.get(_SNAPSHOTS, headers=engineer_headers)
            assert resp.status_code == 403
        finally:
            app.dependency_overrides.pop(get_opensearch_dep, None)

    @pytest.mark.asyncio
    async def test_hunter_cannot_restore_snapshot(
        self, client: AsyncClient, hunter_headers: dict
    ) -> None:
        mock_os = _available_os()
        app.dependency_overrides[get_opensearch_dep] = lambda: mock_os
        try:
            resp = await client.post(
                f"{_SNAPSHOTS}/mxtac-20240101-120000/restore",
                headers=hunter_headers,
            )
            assert resp.status_code == 403
        finally:
            app.dependency_overrides.pop(get_opensearch_dep, None)

    @pytest.mark.asyncio
    async def test_engineer_cannot_restore_snapshot(
        self, client: AsyncClient, engineer_headers: dict
    ) -> None:
        mock_os = _available_os()
        app.dependency_overrides[get_opensearch_dep] = lambda: mock_os
        try:
            resp = await client.post(
                f"{_SNAPSHOTS}/mxtac-20240101-120000/restore",
                headers=engineer_headers,
            )
            assert resp.status_code == 403
        finally:
            app.dependency_overrides.pop(get_opensearch_dep, None)


# ---------------------------------------------------------------------------
# 3. Hunter → 403 on retention endpoint
# ---------------------------------------------------------------------------


class TestRetentionRbacHunter:
    """Hunter role must be denied access to the retention endpoint."""

    @pytest.mark.asyncio
    async def test_hunter_cannot_access_retention(
        self, client: AsyncClient, hunter_headers: dict
    ) -> None:
        with patch(
            _MOCK_RETENTION_STATS,
            new=AsyncMock(return_value=_FAKE_STATS),
        ):
            resp = await client.get(_RETENTION, headers=hunter_headers)
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 4. "Admin access required" detail message is consistent across endpoints
# ---------------------------------------------------------------------------


class TestForbiddenDetailMessage:
    """403 responses from all admin endpoints carry 'Admin access required'."""

    @pytest.mark.asyncio
    async def test_create_snapshot_403_detail(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        mock_os = _available_os()
        app.dependency_overrides[get_opensearch_dep] = lambda: mock_os
        try:
            resp = await client.post(_SNAPSHOTS, headers=analyst_headers)
            assert resp.status_code == 403
            assert resp.json()["detail"] == "Admin access required"
        finally:
            app.dependency_overrides.pop(get_opensearch_dep, None)

    @pytest.mark.asyncio
    async def test_list_snapshots_403_detail(
        self, client: AsyncClient, viewer_headers: dict
    ) -> None:
        mock_os = _available_os()
        app.dependency_overrides[get_opensearch_dep] = lambda: mock_os
        try:
            resp = await client.get(_SNAPSHOTS, headers=viewer_headers)
            assert resp.status_code == 403
            assert resp.json()["detail"] == "Admin access required"
        finally:
            app.dependency_overrides.pop(get_opensearch_dep, None)

    @pytest.mark.asyncio
    async def test_restore_snapshot_403_detail(
        self, client: AsyncClient, hunter_headers: dict
    ) -> None:
        mock_os = _available_os()
        app.dependency_overrides[get_opensearch_dep] = lambda: mock_os
        try:
            resp = await client.post(
                f"{_SNAPSHOTS}/mxtac-20240101-120000/restore",
                headers=hunter_headers,
            )
            assert resp.status_code == 403
            assert resp.json()["detail"] == "Admin access required"
        finally:
            app.dependency_overrides.pop(get_opensearch_dep, None)

    @pytest.mark.asyncio
    async def test_retention_403_detail(
        self, client: AsyncClient, engineer_headers: dict
    ) -> None:
        with patch(
            _MOCK_RETENTION_STATS,
            new=AsyncMock(return_value=_FAKE_STATS),
        ):
            resp = await client.get(_RETENTION, headers=engineer_headers)
        assert resp.status_code == 403
        assert resp.json()["detail"] == "Admin access required"


# ---------------------------------------------------------------------------
# 5. Snapshot name path-param validation
# ---------------------------------------------------------------------------


class TestSnapshotNameValidation:
    """The {name} path param on /admin/snapshots/{name}/restore enforces
    pattern=r"^[a-zA-Z0-9._-]+$" and max_length=200."""

    @pytest.mark.asyncio
    async def test_alphanumeric_name_is_valid(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        mock_os = _available_os()
        app.dependency_overrides[get_opensearch_dep] = lambda: mock_os
        try:
            resp = await client.post(
                f"{_SNAPSHOTS}/snapshot123/restore", headers=admin_headers
            )
            assert resp.status_code == 202
        finally:
            app.dependency_overrides.pop(get_opensearch_dep, None)

    @pytest.mark.asyncio
    async def test_name_with_dots_dashes_underscores_is_valid(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        mock_os = _available_os()
        app.dependency_overrides[get_opensearch_dep] = lambda: mock_os
        try:
            resp = await client.post(
                f"{_SNAPSHOTS}/mxtac-2024.01.01_backup/restore",
                headers=admin_headers,
            )
            assert resp.status_code == 202
        finally:
            app.dependency_overrides.pop(get_opensearch_dep, None)

    @pytest.mark.asyncio
    async def test_name_with_space_is_invalid(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        """Snapshot names with spaces must be rejected with 422."""
        mock_os = _available_os()
        app.dependency_overrides[get_opensearch_dep] = lambda: mock_os
        try:
            resp = await client.post(
                f"{_SNAPSHOTS}/invalid name/restore", headers=admin_headers
            )
            assert resp.status_code in (404, 422)
        finally:
            app.dependency_overrides.pop(get_opensearch_dep, None)

    @pytest.mark.asyncio
    async def test_name_with_special_chars_is_invalid(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        """Snapshot names with special chars ($ @ !) must be rejected with 422."""
        mock_os = _available_os()
        app.dependency_overrides[get_opensearch_dep] = lambda: mock_os
        try:
            resp = await client.post(
                f"{_SNAPSHOTS}/snap$hot!/restore", headers=admin_headers
            )
            assert resp.status_code in (404, 422)
        finally:
            app.dependency_overrides.pop(get_opensearch_dep, None)
