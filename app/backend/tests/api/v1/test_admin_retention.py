"""Tests for GET /admin/retention — feature 38.4.

Verifies:
  - Admin receives 200 with correct schema
  - Non-admin (analyst, viewer) receives 403
  - Unauthenticated request receives 401 or 403
  - Policy values reflect current settings
  - Storage stats section is present and well-formed
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient

BASE = "/api/v1/admin/retention"

_FAKE_STATS = {
    "detections_total": 42,
    "incidents_total": 10,
    "iocs_total": 7,
    "detections_eligible_for_deletion": 5,
    "incidents_eligible_for_deletion": 2,
    "iocs_eligible_for_deletion": 1,
}


class TestGetRetention:

    @pytest.mark.asyncio
    async def test_admin_returns_200(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        with patch(
            "app.api.v1.endpoints.admin.get_retention_storage_stats",
            new=AsyncMock(return_value=_FAKE_STATS),
        ):
            resp = await client.get(BASE, headers=admin_headers)
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_response_schema_policy_block(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        with patch(
            "app.api.v1.endpoints.admin.get_retention_storage_stats",
            new=AsyncMock(return_value=_FAKE_STATS),
        ):
            resp = await client.get(BASE, headers=admin_headers)

        data = resp.json()
        assert "policy" in data
        policy = data["policy"]
        assert "retention_events_days" in policy
        assert "retention_alerts_days" in policy
        assert "retention_incidents_days" in policy
        assert "retention_audit_days" in policy
        assert "retention_iocs_days" in policy
        assert policy["retention_events_days"] == 90
        assert policy["retention_alerts_days"] == 365
        assert policy["retention_incidents_days"] == 730
        assert policy["retention_audit_days"] == 1095
        assert policy["retention_iocs_days"] == 180

    @pytest.mark.asyncio
    async def test_response_schema_storage_block(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        with patch(
            "app.api.v1.endpoints.admin.get_retention_storage_stats",
            new=AsyncMock(return_value=_FAKE_STATS),
        ):
            resp = await client.get(BASE, headers=admin_headers)

        data = resp.json()
        assert "storage" in data
        storage = data["storage"]
        assert storage["detections_total"] == 42
        assert storage["incidents_total"] == 10
        assert storage["iocs_total"] == 7
        assert storage["detections_eligible_for_deletion"] == 5
        assert storage["incidents_eligible_for_deletion"] == 2
        assert storage["iocs_eligible_for_deletion"] == 1

    @pytest.mark.asyncio
    async def test_analyst_gets_403(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        with patch(
            "app.api.v1.endpoints.admin.get_retention_storage_stats",
            new=AsyncMock(return_value=_FAKE_STATS),
        ):
            resp = await client.get(BASE, headers=analyst_headers)
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_viewer_gets_403(
        self, client: AsyncClient, viewer_headers: dict
    ) -> None:
        with patch(
            "app.api.v1.endpoints.admin.get_retention_storage_stats",
            new=AsyncMock(return_value=_FAKE_STATS),
        ):
            resp = await client.get(BASE, headers=viewer_headers)
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_unauthenticated_gets_401_or_403(
        self, client: AsyncClient
    ) -> None:
        resp = await client.get(BASE)
        assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_engineer_gets_403(
        self, client: AsyncClient, engineer_headers: dict
    ) -> None:
        with patch(
            "app.api.v1.endpoints.admin.get_retention_storage_stats",
            new=AsyncMock(return_value=_FAKE_STATS),
        ):
            resp = await client.get(BASE, headers=engineer_headers)
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_storage_stats_are_integers(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        """All storage stat values must be non-negative integers."""
        with patch(
            "app.api.v1.endpoints.admin.get_retention_storage_stats",
            new=AsyncMock(return_value=_FAKE_STATS),
        ):
            resp = await client.get(BASE, headers=admin_headers)

        storage = resp.json()["storage"]
        for key, value in storage.items():
            assert isinstance(value, int), f"{key} should be an int, got {type(value)}"
            assert value >= 0, f"{key} should be non-negative"
