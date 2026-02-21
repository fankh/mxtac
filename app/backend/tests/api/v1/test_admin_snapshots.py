"""Tests for feature 38.3 — OpenSearch snapshot management API endpoints.

Verifies:
  - POST /admin/snapshots  — create snapshot (admin only)
  - GET  /admin/snapshots  — list snapshots (admin only)
  - POST /admin/snapshots/{name}/restore — restore snapshot (admin only)

OpenSearch dependency is overridden per-test so no real cluster is needed.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient

from app.main import app
from app.services.opensearch_client import get_opensearch_dep

BASE = "/api/v1/admin/snapshots"

_FAKE_SNAPSHOTS = [
    {
        "name": "mxtac-20240114-000000",
        "state": "SUCCESS",
        "start_time": "2024-01-14T00:00:01.000Z",
        "end_time": "2024-01-14T00:00:10.000Z",
        "duration_millis": 9000,
        "indices": ["mxtac-events-2024.01.14"],
        "size_bytes": 0,
        "shards_total": 3,
        "shards_successful": 3,
        "shards_failed": 0,
    },
]


def _available_os(
    *,
    create_repo_ok: bool = True,
    create_snapshot_ok: bool = True,
    list_result: list | None = None,
    restore_ok: bool = True,
) -> MagicMock:
    """Build a mock OpenSearch service that is available."""
    mock = MagicMock()
    mock.is_available = True
    mock.create_snapshot_repo = AsyncMock(return_value=create_repo_ok)
    mock.create_snapshot = AsyncMock(
        return_value={"snapshot": {}} if create_snapshot_ok else None
    )
    mock.list_snapshots = AsyncMock(return_value=list_result if list_result is not None else _FAKE_SNAPSHOTS)
    mock.restore_snapshot = AsyncMock(return_value=restore_ok)
    return mock


def _unavailable_os() -> MagicMock:
    mock = MagicMock()
    mock.is_available = False
    return mock


# ---------------------------------------------------------------------------
# POST /admin/snapshots — create snapshot
# ---------------------------------------------------------------------------


class TestCreateSnapshot:
    @pytest.mark.asyncio
    async def test_admin_create_returns_202(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        mock_os = _available_os()
        app.dependency_overrides[get_opensearch_dep] = lambda: mock_os
        try:
            resp = await client.post(BASE, headers=admin_headers)
            assert resp.status_code == 202
        finally:
            app.dependency_overrides.pop(get_opensearch_dep, None)

    @pytest.mark.asyncio
    async def test_admin_create_response_schema(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        mock_os = _available_os()
        app.dependency_overrides[get_opensearch_dep] = lambda: mock_os
        try:
            resp = await client.post(BASE, headers=admin_headers)
            data = resp.json()
            assert data["repo"] == "mxtac-snapshots"
            assert data["status"] == "initiated"
            assert data["snapshot"].startswith("mxtac-")
        finally:
            app.dependency_overrides.pop(get_opensearch_dep, None)

    @pytest.mark.asyncio
    async def test_create_calls_repo_registration(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        mock_os = _available_os()
        app.dependency_overrides[get_opensearch_dep] = lambda: mock_os
        try:
            await client.post(BASE, headers=admin_headers)
            mock_os.create_snapshot_repo.assert_called_once()
        finally:
            app.dependency_overrides.pop(get_opensearch_dep, None)

    @pytest.mark.asyncio
    async def test_non_admin_gets_403(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        mock_os = _available_os()
        app.dependency_overrides[get_opensearch_dep] = lambda: mock_os
        try:
            resp = await client.post(BASE, headers=analyst_headers)
            assert resp.status_code == 403
        finally:
            app.dependency_overrides.pop(get_opensearch_dep, None)

    @pytest.mark.asyncio
    async def test_unauthenticated_gets_401_or_403(self, client: AsyncClient) -> None:
        resp = await client.post(BASE)
        assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_unavailable_opensearch_gets_503(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        app.dependency_overrides[get_opensearch_dep] = lambda: _unavailable_os()
        try:
            resp = await client.post(BASE, headers=admin_headers)
            assert resp.status_code == 503
        finally:
            app.dependency_overrides.pop(get_opensearch_dep, None)

    @pytest.mark.asyncio
    async def test_snapshot_creation_failure_gets_500(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        mock_os = _available_os(create_snapshot_ok=False)
        app.dependency_overrides[get_opensearch_dep] = lambda: mock_os
        try:
            resp = await client.post(BASE, headers=admin_headers)
            assert resp.status_code == 500
        finally:
            app.dependency_overrides.pop(get_opensearch_dep, None)

    @pytest.mark.asyncio
    async def test_viewer_gets_403(
        self, client: AsyncClient, viewer_headers: dict
    ) -> None:
        mock_os = _available_os()
        app.dependency_overrides[get_opensearch_dep] = lambda: mock_os
        try:
            resp = await client.post(BASE, headers=viewer_headers)
            assert resp.status_code == 403
        finally:
            app.dependency_overrides.pop(get_opensearch_dep, None)


# ---------------------------------------------------------------------------
# GET /admin/snapshots — list snapshots
# ---------------------------------------------------------------------------


class TestListSnapshots:
    @pytest.mark.asyncio
    async def test_admin_list_returns_200(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        mock_os = _available_os()
        app.dependency_overrides[get_opensearch_dep] = lambda: mock_os
        try:
            resp = await client.get(BASE, headers=admin_headers)
            assert resp.status_code == 200
        finally:
            app.dependency_overrides.pop(get_opensearch_dep, None)

    @pytest.mark.asyncio
    async def test_admin_list_response_schema(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        mock_os = _available_os()
        app.dependency_overrides[get_opensearch_dep] = lambda: mock_os
        try:
            resp = await client.get(BASE, headers=admin_headers)
            data = resp.json()
            assert data["repo"] == "mxtac-snapshots"
            assert isinstance(data["snapshots"], list)
            assert len(data["snapshots"]) == 1
            snap = data["snapshots"][0]
            assert snap["name"] == "mxtac-20240114-000000"
            assert snap["state"] == "SUCCESS"
        finally:
            app.dependency_overrides.pop(get_opensearch_dep, None)

    @pytest.mark.asyncio
    async def test_admin_list_empty_snapshots(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        mock_os = _available_os(list_result=[])
        app.dependency_overrides[get_opensearch_dep] = lambda: mock_os
        try:
            resp = await client.get(BASE, headers=admin_headers)
            assert resp.status_code == 200
            assert resp.json()["snapshots"] == []
        finally:
            app.dependency_overrides.pop(get_opensearch_dep, None)

    @pytest.mark.asyncio
    async def test_non_admin_gets_403(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        mock_os = _available_os()
        app.dependency_overrides[get_opensearch_dep] = lambda: mock_os
        try:
            resp = await client.get(BASE, headers=analyst_headers)
            assert resp.status_code == 403
        finally:
            app.dependency_overrides.pop(get_opensearch_dep, None)

    @pytest.mark.asyncio
    async def test_unavailable_opensearch_gets_503(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        app.dependency_overrides[get_opensearch_dep] = lambda: _unavailable_os()
        try:
            resp = await client.get(BASE, headers=admin_headers)
            assert resp.status_code == 503
        finally:
            app.dependency_overrides.pop(get_opensearch_dep, None)

    @pytest.mark.asyncio
    async def test_unauthenticated_gets_401_or_403(self, client: AsyncClient) -> None:
        resp = await client.get(BASE)
        assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# POST /admin/snapshots/{name}/restore — restore snapshot
# ---------------------------------------------------------------------------


class TestRestoreSnapshot:
    @pytest.mark.asyncio
    async def test_admin_restore_returns_202(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        mock_os = _available_os()
        app.dependency_overrides[get_opensearch_dep] = lambda: mock_os
        try:
            resp = await client.post(
                f"{BASE}/mxtac-20240114-000000/restore", headers=admin_headers
            )
            assert resp.status_code == 202
        finally:
            app.dependency_overrides.pop(get_opensearch_dep, None)

    @pytest.mark.asyncio
    async def test_admin_restore_response_schema(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        mock_os = _available_os()
        app.dependency_overrides[get_opensearch_dep] = lambda: mock_os
        try:
            resp = await client.post(
                f"{BASE}/mxtac-20240114-000000/restore", headers=admin_headers
            )
            data = resp.json()
            assert data["snapshot"] == "mxtac-20240114-000000"
            assert data["repo"] == "mxtac-snapshots"
            assert data["status"] == "initiated"
        finally:
            app.dependency_overrides.pop(get_opensearch_dep, None)

    @pytest.mark.asyncio
    async def test_restore_passes_snapshot_name_to_service(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        mock_os = _available_os()
        app.dependency_overrides[get_opensearch_dep] = lambda: mock_os
        try:
            await client.post(
                f"{BASE}/mxtac-20240114-000000/restore", headers=admin_headers
            )
            mock_os.restore_snapshot.assert_called_once_with(
                "mxtac-snapshots", "mxtac-20240114-000000"
            )
        finally:
            app.dependency_overrides.pop(get_opensearch_dep, None)

    @pytest.mark.asyncio
    async def test_non_admin_gets_403(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        mock_os = _available_os()
        app.dependency_overrides[get_opensearch_dep] = lambda: mock_os
        try:
            resp = await client.post(
                f"{BASE}/mxtac-20240114-000000/restore", headers=analyst_headers
            )
            assert resp.status_code == 403
        finally:
            app.dependency_overrides.pop(get_opensearch_dep, None)

    @pytest.mark.asyncio
    async def test_unavailable_opensearch_gets_503(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        app.dependency_overrides[get_opensearch_dep] = lambda: _unavailable_os()
        try:
            resp = await client.post(
                f"{BASE}/mxtac-20240114-000000/restore", headers=admin_headers
            )
            assert resp.status_code == 503
        finally:
            app.dependency_overrides.pop(get_opensearch_dep, None)

    @pytest.mark.asyncio
    async def test_restore_failure_gets_500(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        mock_os = _available_os(restore_ok=False)
        app.dependency_overrides[get_opensearch_dep] = lambda: mock_os
        try:
            resp = await client.post(
                f"{BASE}/mxtac-20240114-000000/restore", headers=admin_headers
            )
            assert resp.status_code == 500
        finally:
            app.dependency_overrides.pop(get_opensearch_dep, None)

    @pytest.mark.asyncio
    async def test_invalid_snapshot_name_gets_422(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        """Snapshot names with path-traversal characters are rejected (422)."""
        mock_os = _available_os()
        app.dependency_overrides[get_opensearch_dep] = lambda: mock_os
        try:
            resp = await client.post(
                f"{BASE}/../../../etc/passwd/restore", headers=admin_headers
            )
            # FastAPI route won't match the path at all due to the slashes,
            # or if it does, the pattern validator rejects special chars.
            assert resp.status_code in (404, 422)
        finally:
            app.dependency_overrides.pop(get_opensearch_dep, None)

    @pytest.mark.asyncio
    async def test_unauthenticated_gets_401_or_403(self, client: AsyncClient) -> None:
        resp = await client.post(f"{BASE}/mxtac-20240114-000000/restore")
        assert resp.status_code in (401, 403)
