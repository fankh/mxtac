"""Tests for /api/v1/audit-logs endpoints — Feature 21.12.

Coverage:
  - GET /audit-logs             — paginated list, filters (actor/action/resource_type/from_ts/to_ts)
  - GET /audit-logs/{id}        — single entry, 404 on missing
  - RBAC: admin only (all other roles → 403)
  - Unauthenticated → 401/403
  - DB write via AuditLogger.log() with session
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient

from app.core.security import create_access_token

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MOCK_REPO = "app.api.v1.endpoints.audit_logs.AuditLogRepo"
BASE = "/api/v1/audit-logs"
_NOW = datetime(2026, 2, 21, 10, 0, 0, tzinfo=timezone.utc)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _entry(**overrides) -> SimpleNamespace:
    """Build a minimal ORM-like AuditLog namespace for use as a mock return."""
    defaults = {
        "id": "aaaaaaaa-0000-0000-0000-000000000001",
        "timestamp": _NOW,
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
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _token_headers(role: str) -> dict[str, str]:
    token = create_access_token(
        {"sub": f"{role}@mxtac.local", "role": role},
        expires_delta=timedelta(hours=1),
    )
    return {"Authorization": f"Bearer {token}"}


_ENTRY = _entry()

# ---------------------------------------------------------------------------
# GET /audit-logs — list
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_audit_logs_returns_200(client: AsyncClient) -> None:
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([_ENTRY], 1))):
        resp = await client.get(BASE, headers=_token_headers("admin"))
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "pagination" in data
    assert len(data["items"]) == 1


@pytest.mark.asyncio
async def test_list_audit_logs_pagination_fields(client: AsyncClient) -> None:
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([_ENTRY], 1))):
        resp = await client.get(BASE, headers=_token_headers("admin"))
    pg = resp.json()["pagination"]
    assert pg["page"] == 1
    assert pg["page_size"] == 50
    assert pg["total"] == 1
    assert pg["total_pages"] == 1


@pytest.mark.asyncio
async def test_list_audit_logs_empty(client: AsyncClient) -> None:
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([], 0))):
        resp = await client.get(BASE, headers=_token_headers("admin"))
    assert resp.status_code == 200
    data = resp.json()
    assert data["items"] == []
    assert data["pagination"]["total"] == 0
    assert data["pagination"]["total_pages"] == 1


@pytest.mark.asyncio
async def test_list_audit_logs_item_fields(client: AsyncClient) -> None:
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([_ENTRY], 1))):
        resp = await client.get(BASE, headers=_token_headers("admin"))
    item = resp.json()["items"][0]
    for field in (
        "id", "timestamp", "actor", "action", "resource_type",
        "resource_id", "details", "request_ip", "request_method",
        "request_path", "user_agent",
    ):
        assert field in item, f"Missing field: {field}"


@pytest.mark.asyncio
async def test_list_audit_logs_filter_actor_forwarded(client: AsyncClient) -> None:
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        await client.get(f"{BASE}?actor=alice@mxtac.local", headers=_token_headers("admin"))
    assert mock_list.call_args.kwargs.get("actor") == "alice@mxtac.local"


@pytest.mark.asyncio
async def test_list_audit_logs_filter_action_forwarded(client: AsyncClient) -> None:
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        await client.get(f"{BASE}?action=delete", headers=_token_headers("admin"))
    assert mock_list.call_args.kwargs.get("action") == "delete"


@pytest.mark.asyncio
async def test_list_audit_logs_filter_resource_type_forwarded(client: AsyncClient) -> None:
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        await client.get(f"{BASE}?resource_type=rule", headers=_token_headers("admin"))
    assert mock_list.call_args.kwargs.get("resource_type") == "rule"


@pytest.mark.asyncio
async def test_list_audit_logs_filter_from_ts_forwarded(client: AsyncClient) -> None:
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        await client.get(
            f"{BASE}?from_ts=2026-01-01T00:00:00Z",
            headers=_token_headers("admin"),
        )
    from_ts = mock_list.call_args.kwargs.get("from_ts")
    assert from_ts is not None
    assert from_ts.year == 2026


@pytest.mark.asyncio
async def test_list_audit_logs_filter_to_ts_forwarded(client: AsyncClient) -> None:
    mock_list = AsyncMock(return_value=([], 0))
    with patch(f"{MOCK_REPO}.list", new=mock_list):
        await client.get(
            f"{BASE}?to_ts=2026-12-31T23:59:59Z",
            headers=_token_headers("admin"),
        )
    to_ts = mock_list.call_args.kwargs.get("to_ts")
    assert to_ts is not None
    assert to_ts.year == 2026


@pytest.mark.asyncio
async def test_list_audit_logs_custom_page_size(client: AsyncClient) -> None:
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([], 0))):
        resp = await client.get(f"{BASE}?page_size=10&page=2", headers=_token_headers("admin"))
    pg = resp.json()["pagination"]
    assert pg["page"] == 2
    assert pg["page_size"] == 10


# ---------------------------------------------------------------------------
# GET /audit-logs/{id} — single entry
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_audit_log_returns_200(client: AsyncClient) -> None:
    with patch(f"{MOCK_REPO}.get_by_id", new=AsyncMock(return_value=_ENTRY)):
        resp = await client.get(f"{BASE}/{_ENTRY.id}", headers=_token_headers("admin"))
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == _ENTRY.id
    assert data["actor"] == "admin@mxtac.local"
    assert data["action"] == "create"
    assert data["resource_type"] == "rule"


@pytest.mark.asyncio
async def test_get_audit_log_not_found(client: AsyncClient) -> None:
    with patch(f"{MOCK_REPO}.get_by_id", new=AsyncMock(return_value=None)):
        resp = await client.get(f"{BASE}/nonexistent-id", headers=_token_headers("admin"))
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_get_audit_log_details_field(client: AsyncClient) -> None:
    e = _entry(details={"key": "value", "count": 42})
    with patch(f"{MOCK_REPO}.get_by_id", new=AsyncMock(return_value=e)):
        resp = await client.get(f"{BASE}/{e.id}", headers=_token_headers("admin"))
    assert resp.json()["details"] == {"key": "value", "count": 42}


@pytest.mark.asyncio
async def test_get_audit_log_null_optional_fields(client: AsyncClient) -> None:
    e = _entry(resource_id=None, request_ip=None, request_method=None, request_path=None, user_agent=None)
    with patch(f"{MOCK_REPO}.get_by_id", new=AsyncMock(return_value=e)):
        resp = await client.get(f"{BASE}/{e.id}", headers=_token_headers("admin"))
    data = resp.json()
    assert data["resource_id"] is None
    assert data["request_ip"] is None


# ---------------------------------------------------------------------------
# RBAC — admin only
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_viewer_cannot_read_audit_logs(client: AsyncClient) -> None:
    resp = await client.get(BASE, headers=_token_headers("viewer"))
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_analyst_cannot_read_audit_logs(client: AsyncClient) -> None:
    resp = await client.get(BASE, headers=_token_headers("analyst"))
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_hunter_cannot_read_audit_logs(client: AsyncClient) -> None:
    resp = await client.get(BASE, headers=_token_headers("hunter"))
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_engineer_cannot_read_audit_logs(client: AsyncClient) -> None:
    resp = await client.get(BASE, headers=_token_headers("engineer"))
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_admin_can_read_audit_logs(client: AsyncClient) -> None:
    with patch(f"{MOCK_REPO}.list", new=AsyncMock(return_value=([], 0))):
        resp = await client.get(BASE, headers=_token_headers("admin"))
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Unauthenticated
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unauthenticated_list(client: AsyncClient) -> None:
    resp = await client.get(BASE)
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_unauthenticated_get(client: AsyncClient) -> None:
    resp = await client.get(f"{BASE}/some-id")
    assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# AuditLogger.log() DB write integration
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_audit_logger_log_writes_to_db(db_session) -> None:
    """AuditLogger.log() with a session should persist an entry to the DB."""
    from app.services.audit import AuditLogger
    from app.repositories.audit_log_repo import AuditLogRepo

    logger = AuditLogger()
    returned_id = await logger.log(
        actor="test@mxtac.local",
        action="create",
        resource_type="rule",
        resource_id="rule-abc",
        details={"name": "My Rule"},
        session=db_session,
    )
    assert returned_id is not None

    # Commit so we can query
    await db_session.commit()

    entry = await AuditLogRepo.get_by_id(db_session, returned_id)
    assert entry is not None
    assert entry.actor == "test@mxtac.local"
    assert entry.action == "create"
    assert entry.resource_type == "rule"
    assert entry.resource_id == "rule-abc"
    assert entry.details == {"name": "My Rule"}


@pytest.mark.asyncio
async def test_audit_logger_log_without_session_returns_id() -> None:
    """AuditLogger.log() without session still returns a non-None ID."""
    from app.services.audit import AuditLogger

    logger = AuditLogger()
    # No OpenSearch available in test — it should fall through gracefully
    returned_id = await logger.log(
        actor="system",
        action="login",
        resource_type="user",
        resource_id="user-1",
        session=None,
    )
    assert returned_id is not None


# ---------------------------------------------------------------------------
# AuditLogRepo — direct unit tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_audit_log_repo_create_and_list(db_session) -> None:
    from app.repositories.audit_log_repo import AuditLogRepo

    entry = await AuditLogRepo.create(
        db_session,
        actor="alice@mxtac.local",
        action="delete",
        resource_type="connector",
        resource_id="conn-42",
        details={"reason": "decommissioned"},
        request_ip="192.168.1.1",
        request_method="DELETE",
        request_path="/api/v1/connectors/conn-42",
        user_agent="curl/7.68.0",
    )
    await db_session.commit()

    items, total = await AuditLogRepo.list(db_session)
    assert total >= 1
    ids = [e.id for e in items]
    assert entry.id in ids


@pytest.mark.asyncio
async def test_audit_log_repo_filter_by_actor(db_session) -> None:
    from app.repositories.audit_log_repo import AuditLogRepo

    await AuditLogRepo.create(db_session, actor="alice@mxtac.local", action="create", resource_type="rule")
    await AuditLogRepo.create(db_session, actor="bob@mxtac.local", action="update", resource_type="user")
    await db_session.commit()

    items, total = await AuditLogRepo.list(db_session, actor="alice@mxtac.local")
    assert total == 1
    assert items[0].actor == "alice@mxtac.local"


@pytest.mark.asyncio
async def test_audit_log_repo_filter_by_action(db_session) -> None:
    from app.repositories.audit_log_repo import AuditLogRepo

    await AuditLogRepo.create(db_session, actor="a@x.com", action="create", resource_type="rule")
    await AuditLogRepo.create(db_session, actor="a@x.com", action="delete", resource_type="rule")
    await db_session.commit()

    items, total = await AuditLogRepo.list(db_session, action="delete")
    assert total == 1
    assert items[0].action == "delete"


@pytest.mark.asyncio
async def test_audit_log_repo_filter_by_resource_type(db_session) -> None:
    from app.repositories.audit_log_repo import AuditLogRepo

    await AuditLogRepo.create(db_session, actor="a@x.com", action="create", resource_type="rule")
    await AuditLogRepo.create(db_session, actor="a@x.com", action="create", resource_type="user")
    await db_session.commit()

    items, total = await AuditLogRepo.list(db_session, resource_type="rule")
    assert total == 1
    assert items[0].resource_type == "rule"


@pytest.mark.asyncio
async def test_audit_log_repo_get_by_id(db_session) -> None:
    from app.repositories.audit_log_repo import AuditLogRepo

    entry = await AuditLogRepo.create(
        db_session, actor="c@x.com", action="update", resource_type="incident", resource_id="42"
    )
    await db_session.commit()

    found = await AuditLogRepo.get_by_id(db_session, entry.id)
    assert found is not None
    assert found.resource_id == "42"


@pytest.mark.asyncio
async def test_audit_log_repo_get_by_id_not_found(db_session) -> None:
    from app.repositories.audit_log_repo import AuditLogRepo

    found = await AuditLogRepo.get_by_id(db_session, "does-not-exist")
    assert found is None


@pytest.mark.asyncio
async def test_audit_log_repo_pagination(db_session) -> None:
    from app.repositories.audit_log_repo import AuditLogRepo

    for i in range(5):
        await AuditLogRepo.create(
            db_session, actor="a@x.com", action="create", resource_type=f"res{i}"
        )
    await db_session.commit()

    items, total = await AuditLogRepo.list(db_session, skip=0, limit=3)
    assert total == 5
    assert len(items) == 3
