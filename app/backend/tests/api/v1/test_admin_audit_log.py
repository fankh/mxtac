"""Tests for GET /api/v1/admin/audit-log — feature 38.x.

Verifies:
  - Admin receives 200 with correct AuditLogResponse schema
  - Response fields: total, page, page_size, items
  - Each AuditLogEntry item contains the expected fields
  - Empty result set is returned correctly
  - Filter parameters (actor, action, resource_type, time_from, time_to) are forwarded
  - Pagination parameters (page, page_size) are reflected in response and offset calculation
  - Validation: page < 1 → 422, page_size > 500 → 422
  - RBAC: non-admin roles (viewer, analyst, hunter, engineer) → 403
  - RBAC: admin role → 200
  - Unauthenticated request → 401 or 403
  - 403 detail message is "Admin access required"
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient

BASE = "/api/v1/admin/audit-log"

_MOCK_GET_AUDIT_LOGGER = "app.api.v1.endpoints.admin.get_audit_logger"

_FAKE_ITEM = {
    "id": "aaaaaaaa-0000-0000-0000-000000000001",
    "timestamp": "2026-02-21T10:00:00+00:00",
    "actor": "admin@mxtac.local",
    "action": "create",
    "resource_type": "rule",
    "resource_id": "rule-123",
    "details": {"name": "Test Rule"},
    "request_ip": "10.0.0.1",
    "request_method": "POST",
    "request_path": "/api/v1/rules",
    "user_agent": "pytest/1.0",
}

_FAKE_ITEM_2 = {
    "id": "bbbbbbbb-0000-0000-0000-000000000002",
    "timestamp": "2026-02-21T09:00:00+00:00",
    "actor": "analyst@mxtac.local",
    "action": "delete",
    "resource_type": "connector",
    "resource_id": "conn-42",
    "details": {},
    "request_ip": "10.0.0.2",
    "request_method": "DELETE",
    "request_path": "/api/v1/connectors/conn-42",
    "user_agent": "httpx/0.27.0",
}


def _mock_logger(items: list | None = None, total: int | None = None) -> MagicMock:
    """Build a mock AuditLogger with a configurable search() result."""
    items = items if items is not None else []
    total = total if total is not None else len(items)
    mock = MagicMock()
    mock.search = AsyncMock(return_value={"total": total, "items": items})
    return mock


# ---------------------------------------------------------------------------
# 1. Admin access — basic 200 and response schema
# ---------------------------------------------------------------------------


class TestAdminAuditLogAccess:

    @pytest.mark.asyncio
    async def test_admin_returns_200(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        with patch(_MOCK_GET_AUDIT_LOGGER, return_value=_mock_logger()):
            resp = await client.get(BASE, headers=admin_headers)
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_response_has_top_level_fields(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        with patch(_MOCK_GET_AUDIT_LOGGER, return_value=_mock_logger([_FAKE_ITEM], total=1)):
            resp = await client.get(BASE, headers=admin_headers)
        data = resp.json()
        assert "total" in data
        assert "page" in data
        assert "page_size" in data
        assert "items" in data

    @pytest.mark.asyncio
    async def test_response_items_is_list(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        with patch(_MOCK_GET_AUDIT_LOGGER, return_value=_mock_logger([_FAKE_ITEM], total=1)):
            resp = await client.get(BASE, headers=admin_headers)
        assert isinstance(resp.json()["items"], list)

    @pytest.mark.asyncio
    async def test_response_total_matches_search_result(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        with patch(_MOCK_GET_AUDIT_LOGGER, return_value=_mock_logger([_FAKE_ITEM], total=99)):
            resp = await client.get(BASE, headers=admin_headers)
        assert resp.json()["total"] == 99

    @pytest.mark.asyncio
    async def test_response_empty_items(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        with patch(_MOCK_GET_AUDIT_LOGGER, return_value=_mock_logger([], total=0)):
            resp = await client.get(BASE, headers=admin_headers)
        data = resp.json()
        assert data["total"] == 0
        assert data["items"] == []

    @pytest.mark.asyncio
    async def test_response_multiple_items(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        with patch(
            _MOCK_GET_AUDIT_LOGGER,
            return_value=_mock_logger([_FAKE_ITEM, _FAKE_ITEM_2], total=2),
        ):
            resp = await client.get(BASE, headers=admin_headers)
        assert len(resp.json()["items"]) == 2


# ---------------------------------------------------------------------------
# 2. AuditLogEntry item schema
# ---------------------------------------------------------------------------


class TestAuditLogEntrySchema:

    @pytest.mark.asyncio
    async def test_item_contains_required_fields(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        with patch(_MOCK_GET_AUDIT_LOGGER, return_value=_mock_logger([_FAKE_ITEM], total=1)):
            resp = await client.get(BASE, headers=admin_headers)
        item = resp.json()["items"][0]
        for field in (
            "id", "timestamp", "actor", "action", "resource_type",
            "resource_id", "details", "request_ip", "request_method",
            "request_path", "user_agent",
        ):
            assert field in item, f"Missing field: {field}"

    @pytest.mark.asyncio
    async def test_item_field_values(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        with patch(_MOCK_GET_AUDIT_LOGGER, return_value=_mock_logger([_FAKE_ITEM], total=1)):
            resp = await client.get(BASE, headers=admin_headers)
        item = resp.json()["items"][0]
        assert item["id"] == _FAKE_ITEM["id"]
        assert item["actor"] == _FAKE_ITEM["actor"]
        assert item["action"] == _FAKE_ITEM["action"]
        assert item["resource_type"] == _FAKE_ITEM["resource_type"]
        assert item["resource_id"] == _FAKE_ITEM["resource_id"]

    @pytest.mark.asyncio
    async def test_item_details_dict(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        item_with_details = {**_FAKE_ITEM, "details": {"key": "value", "count": 3}}
        with patch(_MOCK_GET_AUDIT_LOGGER, return_value=_mock_logger([item_with_details], total=1)):
            resp = await client.get(BASE, headers=admin_headers)
        assert resp.json()["items"][0]["details"] == {"key": "value", "count": 3}

    @pytest.mark.asyncio
    async def test_item_optional_fields_can_be_none(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        item_no_optional = {
            **_FAKE_ITEM,
            "request_ip": None,
            "request_method": None,
            "request_path": None,
            "user_agent": None,
        }
        with patch(_MOCK_GET_AUDIT_LOGGER, return_value=_mock_logger([item_no_optional], total=1)):
            resp = await client.get(BASE, headers=admin_headers)
        item = resp.json()["items"][0]
        assert item["request_ip"] is None
        assert item["request_method"] is None
        assert item["request_path"] is None
        assert item["user_agent"] is None


# ---------------------------------------------------------------------------
# 3. Pagination — defaults and custom values
# ---------------------------------------------------------------------------


class TestAuditLogPagination:

    @pytest.mark.asyncio
    async def test_default_page_is_1(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        with patch(_MOCK_GET_AUDIT_LOGGER, return_value=_mock_logger()):
            resp = await client.get(BASE, headers=admin_headers)
        assert resp.json()["page"] == 1

    @pytest.mark.asyncio
    async def test_default_page_size_is_50(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        with patch(_MOCK_GET_AUDIT_LOGGER, return_value=_mock_logger()):
            resp = await client.get(BASE, headers=admin_headers)
        assert resp.json()["page_size"] == 50

    @pytest.mark.asyncio
    async def test_custom_page_reflected_in_response(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        with patch(_MOCK_GET_AUDIT_LOGGER, return_value=_mock_logger()):
            resp = await client.get(f"{BASE}?page=3", headers=admin_headers)
        assert resp.json()["page"] == 3

    @pytest.mark.asyncio
    async def test_custom_page_size_reflected_in_response(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        with patch(_MOCK_GET_AUDIT_LOGGER, return_value=_mock_logger()):
            resp = await client.get(f"{BASE}?page_size=25", headers=admin_headers)
        assert resp.json()["page_size"] == 25

    @pytest.mark.asyncio
    async def test_page_offset_calculation(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        """page=3, page_size=10 → from_=20 passed to search."""
        mock_logger = _mock_logger()
        with patch(_MOCK_GET_AUDIT_LOGGER, return_value=mock_logger):
            await client.get(f"{BASE}?page=3&page_size=10", headers=admin_headers)
        mock_logger.search.assert_called_once()
        call_kwargs = mock_logger.search.call_args.kwargs
        assert call_kwargs["from_"] == 20
        assert call_kwargs["size"] == 10

    @pytest.mark.asyncio
    async def test_page_1_offset_is_0(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        mock_logger = _mock_logger()
        with patch(_MOCK_GET_AUDIT_LOGGER, return_value=mock_logger):
            await client.get(f"{BASE}?page=1&page_size=50", headers=admin_headers)
        assert mock_logger.search.call_args.kwargs["from_"] == 0

    @pytest.mark.asyncio
    async def test_page_size_max_allowed_is_500(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        with patch(_MOCK_GET_AUDIT_LOGGER, return_value=_mock_logger()):
            resp = await client.get(f"{BASE}?page_size=500", headers=admin_headers)
        assert resp.status_code == 200
        assert resp.json()["page_size"] == 500

    @pytest.mark.asyncio
    async def test_page_size_above_max_returns_422(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        with patch(_MOCK_GET_AUDIT_LOGGER, return_value=_mock_logger()):
            resp = await client.get(f"{BASE}?page_size=501", headers=admin_headers)
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_page_zero_returns_422(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        with patch(_MOCK_GET_AUDIT_LOGGER, return_value=_mock_logger()):
            resp = await client.get(f"{BASE}?page=0", headers=admin_headers)
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_page_negative_returns_422(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        with patch(_MOCK_GET_AUDIT_LOGGER, return_value=_mock_logger()):
            resp = await client.get(f"{BASE}?page=-1", headers=admin_headers)
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# 4. Filter forwarding — parameters passed through to audit.search()
# ---------------------------------------------------------------------------


class TestAuditLogFilters:

    @pytest.mark.asyncio
    async def test_default_time_from_forwarded(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        mock_logger = _mock_logger()
        with patch(_MOCK_GET_AUDIT_LOGGER, return_value=mock_logger):
            await client.get(BASE, headers=admin_headers)
        assert mock_logger.search.call_args.kwargs["time_from"] == "now-7d"

    @pytest.mark.asyncio
    async def test_default_time_to_forwarded(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        mock_logger = _mock_logger()
        with patch(_MOCK_GET_AUDIT_LOGGER, return_value=mock_logger):
            await client.get(BASE, headers=admin_headers)
        assert mock_logger.search.call_args.kwargs["time_to"] == "now"

    @pytest.mark.asyncio
    async def test_actor_filter_forwarded(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        mock_logger = _mock_logger()
        with patch(_MOCK_GET_AUDIT_LOGGER, return_value=mock_logger):
            await client.get(f"{BASE}?actor=alice@mxtac.local", headers=admin_headers)
        assert mock_logger.search.call_args.kwargs["actor"] == "alice@mxtac.local"

    @pytest.mark.asyncio
    async def test_action_filter_forwarded(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        mock_logger = _mock_logger()
        with patch(_MOCK_GET_AUDIT_LOGGER, return_value=mock_logger):
            await client.get(f"{BASE}?action=delete", headers=admin_headers)
        assert mock_logger.search.call_args.kwargs["action"] == "delete"

    @pytest.mark.asyncio
    async def test_resource_type_filter_forwarded(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        mock_logger = _mock_logger()
        with patch(_MOCK_GET_AUDIT_LOGGER, return_value=mock_logger):
            await client.get(f"{BASE}?resource_type=rule", headers=admin_headers)
        assert mock_logger.search.call_args.kwargs["resource_type"] == "rule"

    @pytest.mark.asyncio
    async def test_custom_time_from_forwarded(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        mock_logger = _mock_logger()
        with patch(_MOCK_GET_AUDIT_LOGGER, return_value=mock_logger):
            await client.get(f"{BASE}?time_from=now-30d", headers=admin_headers)
        assert mock_logger.search.call_args.kwargs["time_from"] == "now-30d"

    @pytest.mark.asyncio
    async def test_custom_time_to_forwarded(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        mock_logger = _mock_logger()
        with patch(_MOCK_GET_AUDIT_LOGGER, return_value=mock_logger):
            await client.get(f"{BASE}?time_to=now-1d", headers=admin_headers)
        assert mock_logger.search.call_args.kwargs["time_to"] == "now-1d"

    @pytest.mark.asyncio
    async def test_no_actor_filter_passes_none(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        mock_logger = _mock_logger()
        with patch(_MOCK_GET_AUDIT_LOGGER, return_value=mock_logger):
            await client.get(BASE, headers=admin_headers)
        assert mock_logger.search.call_args.kwargs["actor"] is None

    @pytest.mark.asyncio
    async def test_no_action_filter_passes_none(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        mock_logger = _mock_logger()
        with patch(_MOCK_GET_AUDIT_LOGGER, return_value=mock_logger):
            await client.get(BASE, headers=admin_headers)
        assert mock_logger.search.call_args.kwargs["action"] is None

    @pytest.mark.asyncio
    async def test_no_resource_type_filter_passes_none(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        mock_logger = _mock_logger()
        with patch(_MOCK_GET_AUDIT_LOGGER, return_value=mock_logger):
            await client.get(BASE, headers=admin_headers)
        assert mock_logger.search.call_args.kwargs["resource_type"] is None


# ---------------------------------------------------------------------------
# 5. RBAC — only admin role is permitted
# ---------------------------------------------------------------------------


class TestAuditLogRbac:

    @pytest.mark.asyncio
    async def test_viewer_gets_403(
        self, client: AsyncClient, viewer_headers: dict
    ) -> None:
        resp = await client.get(BASE, headers=viewer_headers)
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_analyst_gets_403(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        resp = await client.get(BASE, headers=analyst_headers)
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_hunter_gets_403(
        self, client: AsyncClient, hunter_headers: dict
    ) -> None:
        resp = await client.get(BASE, headers=hunter_headers)
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_engineer_gets_403(
        self, client: AsyncClient, engineer_headers: dict
    ) -> None:
        resp = await client.get(BASE, headers=engineer_headers)
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_admin_can_access(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        with patch(_MOCK_GET_AUDIT_LOGGER, return_value=_mock_logger()):
            resp = await client.get(BASE, headers=admin_headers)
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_unauthenticated_gets_401_or_403(
        self, client: AsyncClient
    ) -> None:
        resp = await client.get(BASE)
        assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_403_detail_is_admin_access_required(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        resp = await client.get(BASE, headers=analyst_headers)
        assert resp.status_code == 403
        assert resp.json()["detail"] == "Admin access required"

    @pytest.mark.asyncio
    async def test_rbac_check_before_search(
        self, client: AsyncClient, viewer_headers: dict
    ) -> None:
        """RBAC check runs before audit logger is called — search must not be invoked."""
        mock_logger = _mock_logger()
        with patch(_MOCK_GET_AUDIT_LOGGER, return_value=mock_logger):
            resp = await client.get(BASE, headers=viewer_headers)
        assert resp.status_code == 403
        mock_logger.search.assert_not_called()
