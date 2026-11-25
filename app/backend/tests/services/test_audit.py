"""Unit tests for AuditLogger service — app/services/audit.py.

Coverage:
  - log() request metadata extraction (IP, method, path, user-agent)
  - log() request=None → all metadata fields are None in OS document
  - log() request.client=None → request_ip is None
  - log() document body contains all expected fields
  - log() details=None → 'details' field defaults to {} in OS document
  - log() DB write failure is non-fatal (error logged, OS write still attempted)
  - log() OpenSearch write failure is non-fatal (error logged, DB id returned)
  - log() both DB and OS fail → generated UUID still returned
  - _ensure_client() skips re-init when client already set
  - _ensure_client() ImportError (opensearchpy absent) → client None, warning logged
  - _ensure_client() connection Exception → client None, warning logged
  - close() awaits client.close() when client is initialised
  - close() is a no-op when no client has been initialised
  - get_audit_logger() returns the same singleton instance
  - get_audit_logger() always returns an AuditLogger instance

Not duplicated here (already covered by test_audit_ilm.py):
  - Monthly index format / UTC month / frozen-time tests
  - refresh='true' on OS index call
  - Not targeting events/alerts indices
"""

from __future__ import annotations

import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy import select

from app.models.audit_log import AuditLog
from app.repositories.audit_log_repo import AuditLogRepo
from app.services.audit import AuditLogger, get_audit_logger

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_request(
    *,
    host: str = "10.0.0.1",
    method: str = "POST",
    path: str = "/api/v1/rules",
    user_agent: str = "pytest/1.0",
    client: object = ...,  # sentinel → build a default MagicMock client
) -> MagicMock:
    """Build a minimal FastAPI Request-like mock."""
    req = MagicMock()
    if client is ...:
        req.client = MagicMock()
        req.client.host = host
    else:
        req.client = client
    req.method = method
    req.url = MagicMock()
    req.url.path = path
    req.headers = MagicMock()
    req.headers.get = MagicMock(return_value=user_agent)
    return req


def _make_os_client(*, exc: Exception | None = None) -> MagicMock:
    """Build a minimal OpenSearch async-client mock."""
    client = MagicMock()
    if exc is not None:
        client.index = AsyncMock(side_effect=exc)
    else:
        client.index = AsyncMock(return_value={"_id": "os-doc-id"})
    client.search = AsyncMock(return_value={"hits": {"total": {"value": 0}, "hits": []}})
    client.close = AsyncMock()
    return client


# ---------------------------------------------------------------------------
# log() — request metadata extraction
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_log_extracts_ip_from_request_client() -> None:
    """log() reads request.client.host and writes it as request_ip in the OS document."""
    audit = AuditLogger()
    audit._client = _make_os_client()

    await audit.log(
        actor="u@u.com",
        action="create",
        resource_type="rule",
        request=_make_request(host="192.168.1.99"),
    )

    doc = audit._client.index.call_args.kwargs["body"]
    assert doc["request_ip"] == "192.168.1.99"


@pytest.mark.asyncio
async def test_log_extracts_method_from_request() -> None:
    """log() reads request.method and writes it as request_method in the OS document."""
    audit = AuditLogger()
    audit._client = _make_os_client()

    await audit.log(
        actor="u@u.com",
        action="delete",
        resource_type="rule",
        request=_make_request(method="DELETE"),
    )

    doc = audit._client.index.call_args.kwargs["body"]
    assert doc["request_method"] == "DELETE"


@pytest.mark.asyncio
async def test_log_extracts_path_from_request_url() -> None:
    """log() reads str(request.url.path) and writes it as request_path."""
    audit = AuditLogger()
    audit._client = _make_os_client()

    await audit.log(
        actor="u@u.com",
        action="update",
        resource_type="connector",
        request=_make_request(path="/api/v1/connectors/42"),
    )

    doc = audit._client.index.call_args.kwargs["body"]
    assert doc["request_path"] == "/api/v1/connectors/42"


@pytest.mark.asyncio
async def test_log_extracts_user_agent_from_request_headers() -> None:
    """log() reads the user-agent header and writes it as user_agent."""
    audit = AuditLogger()
    audit._client = _make_os_client()

    await audit.log(
        actor="u@u.com",
        action="create",
        resource_type="rule",
        request=_make_request(user_agent="Mozilla/5.0"),
    )

    doc = audit._client.index.call_args.kwargs["body"]
    assert doc["user_agent"] == "Mozilla/5.0"


@pytest.mark.asyncio
async def test_log_request_none_all_metadata_fields_are_none() -> None:
    """When request=None all request metadata fields are None in the OS document."""
    audit = AuditLogger()
    audit._client = _make_os_client()

    await audit.log(actor="u@u.com", action="login", resource_type="session", request=None)

    doc = audit._client.index.call_args.kwargs["body"]
    assert doc["request_ip"] is None
    assert doc["request_method"] is None
    assert doc["request_path"] is None
    assert doc["user_agent"] is None


@pytest.mark.asyncio
async def test_log_request_client_none_yields_none_ip() -> None:
    """When request.client is None, request_ip is None in the OS document."""
    audit = AuditLogger()
    audit._client = _make_os_client()

    await audit.log(
        actor="u@u.com",
        action="login",
        resource_type="session",
        request=_make_request(client=None),
    )

    doc = audit._client.index.call_args.kwargs["body"]
    assert doc["request_ip"] is None


# ---------------------------------------------------------------------------
# log() — document body field correctness
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_log_document_contains_all_expected_fields() -> None:
    """Document sent to OS includes every mandatory audit field."""
    audit = AuditLogger()
    audit._client = _make_os_client()

    await audit.log(
        actor="admin@mxtac.local",
        action="update",
        resource_type="rule",
        resource_id="rule-123",
        details={"old_severity": "low", "new_severity": "high"},
    )

    doc = audit._client.index.call_args.kwargs["body"]
    for field in (
        "id", "timestamp", "actor", "action", "resource_type",
        "resource_id", "details", "request_ip", "request_method",
        "request_path", "user_agent",
    ):
        assert field in doc, f"Missing field in OS document: {field!r}"


@pytest.mark.asyncio
async def test_log_details_none_defaults_to_empty_dict_in_document() -> None:
    """When details=None the OS document contains 'details': {}."""
    audit = AuditLogger()
    audit._client = _make_os_client()

    await audit.log(actor="u@u.com", action="login", resource_type="session", details=None)

    doc = audit._client.index.call_args.kwargs["body"]
    assert doc["details"] == {}


@pytest.mark.asyncio
async def test_log_document_actor_matches_argument() -> None:
    """Document actor field matches the actor argument passed to log()."""
    audit = AuditLogger()
    audit._client = _make_os_client()

    await audit.log(actor="alice@example.com", action="create", resource_type="rule")

    doc = audit._client.index.call_args.kwargs["body"]
    assert doc["actor"] == "alice@example.com"


@pytest.mark.asyncio
async def test_log_document_action_matches_argument() -> None:
    """Document action field matches the action argument passed to log()."""
    audit = AuditLogger()
    audit._client = _make_os_client()

    await audit.log(actor="u@u.com", action="export", resource_type="rule")

    doc = audit._client.index.call_args.kwargs["body"]
    assert doc["action"] == "export"


@pytest.mark.asyncio
async def test_log_document_resource_id_matches_argument() -> None:
    """Document resource_id field matches the resource_id argument."""
    audit = AuditLogger()
    audit._client = _make_os_client()

    await audit.log(
        actor="u@u.com", action="delete", resource_type="user", resource_id="user-99"
    )

    doc = audit._client.index.call_args.kwargs["body"]
    assert doc["resource_id"] == "user-99"


# ---------------------------------------------------------------------------
# log() — error handling / non-fatal failures
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_log_db_failure_is_non_fatal() -> None:
    """DB write failure does not propagate; log() returns an ID without raising."""
    audit = AuditLogger()
    audit._client = _make_os_client()
    mock_session = MagicMock()

    with patch.object(AuditLogRepo, "create", AsyncMock(side_effect=Exception("DB write error"))):
        result = await audit.log(
            actor="u@u.com", action="create", resource_type="rule", session=mock_session
        )

    assert result is not None


@pytest.mark.asyncio
async def test_log_db_failure_is_logged_at_error_level(caplog) -> None:
    """DB write failure is logged at ERROR level with the exception message."""
    import logging

    audit = AuditLogger()
    audit._client = _make_os_client()
    mock_session = MagicMock()

    with patch.object(AuditLogRepo, "create", AsyncMock(side_effect=Exception("DB write error"))):
        with caplog.at_level(logging.ERROR, logger="app.services.audit"):
            await audit.log(
                actor="u@u.com", action="create", resource_type="rule", session=mock_session
            )

    assert "DB write error" in caplog.text


@pytest.mark.asyncio
async def test_log_os_failure_is_non_fatal() -> None:
    """OpenSearch write failure does not propagate; log() returns an ID."""
    audit = AuditLogger()
    audit._client = _make_os_client(exc=Exception("OS unavailable"))

    result = await audit.log(actor="u@u.com", action="update", resource_type="connector")

    assert result is not None


@pytest.mark.asyncio
async def test_log_os_failure_is_logged_at_error_level(caplog) -> None:
    """OpenSearch write failure is logged at ERROR level."""
    import logging

    audit = AuditLogger()
    audit._client = _make_os_client(exc=Exception("OS write failed"))

    with caplog.at_level(logging.ERROR, logger="app.services.audit"):
        await audit.log(actor="u@u.com", action="update", resource_type="connector")

    assert "OS write failed" in caplog.text


@pytest.mark.asyncio
async def test_log_os_failure_returns_db_doc_id(db_session) -> None:
    """When OS fails but DB succeeds, log() returns the DB-generated ID."""
    audit = AuditLogger()
    audit._client = _make_os_client(exc=Exception("OS down"))

    result = await audit.log(
        actor="u@u.com", action="create", resource_type="rule", session=db_session
    )

    assert result is not None
    # Verify the returned ID actually exists in the DB
    await db_session.commit()
    entry = await db_session.get(AuditLog, result)
    assert entry is not None


@pytest.mark.asyncio
async def test_log_both_db_and_os_fail_returns_generated_uuid() -> None:
    """When both DB and OS fail, log() still returns the pre-generated UUID string."""
    audit = AuditLogger()
    audit._client = _make_os_client(exc=Exception("OS down"))
    mock_session = MagicMock()

    with patch.object(AuditLogRepo, "create", AsyncMock(side_effect=Exception("DB down"))):
        result = await audit.log(
            actor="u@u.com", action="create", resource_type="rule", session=mock_session
        )

    assert result is not None
    assert isinstance(result, str)
    assert len(result) > 0


# ---------------------------------------------------------------------------
# _ensure_client()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ensure_client_skips_reinit_when_client_already_set() -> None:
    """_ensure_client() returns immediately without replacing an existing client."""
    audit = AuditLogger()
    existing = MagicMock()
    audit._client = existing

    await audit._ensure_client()

    assert audit._client is existing


@pytest.mark.asyncio
async def test_ensure_client_import_error_leaves_client_none(caplog) -> None:
    """When opensearchpy is absent, _ensure_client() leaves _client as None and warns."""
    import logging

    audit = AuditLogger()

    with patch.dict(sys.modules, {"opensearchpy": None}):
        with caplog.at_level(logging.WARNING, logger="app.services.audit"):
            await audit._ensure_client()

    assert audit._client is None
    # Warning message should mention opensearch being disabled / not installed
    assert any(
        kw in caplog.text.lower()
        for kw in ("not installed", "disabled", "opensearch")
    )


@pytest.mark.asyncio
async def test_ensure_client_connection_error_leaves_client_none(caplog) -> None:
    """When AsyncOpenSearch constructor raises, _client stays None and a warning is logged."""
    import logging

    audit = AuditLogger()
    mock_module = MagicMock()
    mock_module.AsyncOpenSearch.side_effect = Exception("Connection refused")

    with patch.dict(sys.modules, {"opensearchpy": mock_module}):
        with caplog.at_level(logging.WARNING, logger="app.services.audit"):
            await audit._ensure_client()

    assert audit._client is None
    assert "Connection refused" in caplog.text


# ---------------------------------------------------------------------------
# close()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_close_awaits_client_close_when_client_set() -> None:
    """close() awaits client.close() exactly once when a client is present."""
    audit = AuditLogger()
    mock_client = MagicMock()
    mock_client.close = AsyncMock()
    audit._client = mock_client

    await audit.close()

    mock_client.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_close_is_noop_when_no_client() -> None:
    """close() does not raise when _client is None."""
    audit = AuditLogger()
    # _client is None by default
    await audit.close()  # must not raise


# ---------------------------------------------------------------------------
# get_audit_logger() — singleton
# ---------------------------------------------------------------------------


def test_get_audit_logger_returns_same_instance_on_repeated_calls() -> None:
    """get_audit_logger() is a singleton — multiple calls return the same object."""
    import app.services.audit as audit_module

    original = audit_module._audit_logger
    audit_module._audit_logger = None
    try:
        first = get_audit_logger()
        second = get_audit_logger()
        assert first is second
    finally:
        audit_module._audit_logger = original


def test_get_audit_logger_returns_audit_logger_instance() -> None:
    """get_audit_logger() returns an AuditLogger instance."""
    import app.services.audit as audit_module

    original = audit_module._audit_logger
    audit_module._audit_logger = None
    try:
        instance = get_audit_logger()
        assert isinstance(instance, AuditLogger)
    finally:
        audit_module._audit_logger = original


# ---------------------------------------------------------------------------
# DB write integration (audit_logs table)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_log_with_session_persists_entry_to_db(db_session) -> None:
    """log() with a session persists an entry with the given fields."""
    audit = AuditLogger()
    audit._client = _make_os_client()

    returned_id = await audit.log(
        actor="test@mxtac.local",
        action="create",
        resource_type="rule",
        resource_id="rule-abc",
        details={"name": "My Rule"},
        session=db_session,
    )
    assert returned_id is not None
    await db_session.commit()

    entry = (await db_session.execute(select(AuditLog))).scalars().one()
    assert entry.actor == "test@mxtac.local"
    assert entry.action == "create"
    assert entry.resource_type == "rule"
    assert entry.resource_id == "rule-abc"
    assert entry.details == {"name": "My Rule"}


@pytest.mark.asyncio
async def test_repo_create_persists_request_metadata(db_session) -> None:
    """AuditLogRepo.create() stores the request metadata columns."""
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

    stored = await db_session.get(AuditLog, entry.id)
    assert stored is not None
    assert stored.request_ip == "192.168.1.1"
    assert stored.request_method == "DELETE"
    assert stored.request_path == "/api/v1/connectors/conn-42"
    assert stored.user_agent == "curl/7.68.0"
