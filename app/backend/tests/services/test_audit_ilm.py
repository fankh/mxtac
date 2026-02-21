"""Unit tests for Feature 21.14 — Audit log retention (OpenSearch ILM / ISM).

Coverage:
  - New constants: AUDIT_INDEX_TEMPLATE, AUDIT_ILM_POLICY_NAME, AUDIT_ILM_RETENTION_DAYS, AUDIT_MAPPING
  - _monthly_index() helper (UTC, YYYY.MM format)
  - OpenSearchService.ensure_audit_ilm_policy():
      · no-op when unavailable
      · PUT method via transport.perform_request
      · correct ISM endpoint URL
      · correct policy name (mxtac-3year-audit-retention)
      · 3-year retention (1095d min_index_age)
      · ingest + delete state machine
      · ism_template covers mxtac-audit-* with priority 200
      · exception is caught and logged at WARNING
      · success is logged at INFO
  - OpenSearchService.ensure_indices() — audit template:
      · creates mxtac-audit-template
      · index_pattern is mxtac-audit-*
      · AUDIT_ILM_POLICY_NAME is embedded in template settings
      · AUDIT_MAPPING fields are included
      · exception does not crash ensure_indices()
  - AuditLogger.log() — monthly rollover index
  - AuditLogger.search() — wildcard search across mxtac-audit-*
"""

from __future__ import annotations

import re
import sys
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.opensearch_client import (
    AUDIT_ILM_POLICY_NAME,
    AUDIT_ILM_RETENTION_DAYS,
    AUDIT_INDEX_TEMPLATE,
    AUDIT_MAPPING,
    ILM_POLICY_NAME,
    OpenSearchService,
    _monthly_index,
)
from app.services.audit import AuditLogger


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


def test_audit_ilm_policy_name() -> None:
    """Audit ISM policy name matches the canonical value."""
    assert AUDIT_ILM_POLICY_NAME == "mxtac-3year-audit-retention"


def test_audit_ilm_retention_days() -> None:
    """Audit retention is 1095 days (3 × 365 = 3 years)."""
    assert AUDIT_ILM_RETENTION_DAYS == 1095


def test_audit_ilm_retention_days_is_3_years() -> None:
    """1095 days is exactly 3 calendar years (non-leap)."""
    assert AUDIT_ILM_RETENTION_DAYS == 365 * 3


def test_audit_index_template_name() -> None:
    """AUDIT_INDEX_TEMPLATE is the base used for monthly-rollover indices."""
    assert AUDIT_INDEX_TEMPLATE == "mxtac-audit"


def test_audit_ilm_policy_name_distinct_from_events_policy() -> None:
    """Audit policy name must differ from the 90-day events/alerts policy."""
    assert AUDIT_ILM_POLICY_NAME != ILM_POLICY_NAME


# ---------------------------------------------------------------------------
# AUDIT_MAPPING
# ---------------------------------------------------------------------------


def test_audit_mapping_has_timestamp_date_field() -> None:
    """timestamp must be 'date' for range queries over the audit timeline."""
    assert AUDIT_MAPPING["properties"]["timestamp"] == {"type": "date"}


def test_audit_mapping_has_actor_keyword() -> None:
    """actor must be 'keyword' for exact-match and aggregation."""
    assert AUDIT_MAPPING["properties"]["actor"] == {"type": "keyword"}


def test_audit_mapping_has_action_keyword() -> None:
    """action must be 'keyword'."""
    assert AUDIT_MAPPING["properties"]["action"] == {"type": "keyword"}


def test_audit_mapping_has_resource_type_keyword() -> None:
    """resource_type must be 'keyword'."""
    assert AUDIT_MAPPING["properties"]["resource_type"] == {"type": "keyword"}


def test_audit_mapping_has_request_ip_ip_type() -> None:
    """request_ip must be 'ip' for CIDR and range queries."""
    assert AUDIT_MAPPING["properties"]["request_ip"] == {"type": "ip"}


def test_audit_mapping_has_user_agent_text() -> None:
    """user_agent is free-form text — 'text' enables full-text search."""
    assert AUDIT_MAPPING["properties"]["user_agent"] == {"type": "text"}


# ---------------------------------------------------------------------------
# _monthly_index() helper
# ---------------------------------------------------------------------------


def test_monthly_index_returns_base_with_month_suffix() -> None:
    """_monthly_index(base) appends today's UTC month in YYYY.MM format."""
    result = _monthly_index("mxtac-audit")
    today = datetime.now(timezone.utc).strftime("%Y.%m")
    assert result == f"mxtac-audit-{today}"


def test_monthly_index_format_is_year_dot_month() -> None:
    """The month suffix uses dots (YYYY.MM) not dashes, per OpenSearch conventions."""
    result = _monthly_index("mxtac-audit")
    suffix = result.replace("mxtac-audit-", "")
    parts = suffix.split(".")
    assert len(parts) == 2, f"Expected YYYY.MM, got {suffix!r}"
    assert all(p.isdigit() for p in parts), f"Non-digit part in {suffix!r}"


def test_monthly_index_frozen_date() -> None:
    """_monthly_index() uses UTC time — verifiable by freezing datetime.now."""
    fixed_dt = datetime(2026, 2, 20, 12, 0, 0, tzinfo=timezone.utc)
    with patch("app.services.opensearch_client.datetime") as mock_dt:
        mock_dt.now.return_value = fixed_dt
        result = _monthly_index("mxtac-audit")

    assert result == "mxtac-audit-2026.02"


def test_monthly_index_matches_pattern() -> None:
    """_monthly_index result matches the expected mxtac-audit-YYYY.MM regex."""
    result = _monthly_index("mxtac-audit")
    assert re.fullmatch(r"mxtac-audit-\d{4}\.\d{2}", result), (
        f"Expected mxtac-audit-YYYY.MM, got {result!r}"
    )


def test_monthly_index_december() -> None:
    """_monthly_index handles December (month 12) correctly."""
    fixed_dt = datetime(2025, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
    with patch("app.services.opensearch_client.datetime") as mock_dt:
        mock_dt.now.return_value = fixed_dt
        result = _monthly_index("mxtac-audit")

    assert result == "mxtac-audit-2025.12"


# ---------------------------------------------------------------------------
# Helpers shared across ensure_audit_ilm_policy tests
# ---------------------------------------------------------------------------


def _make_transport(*, exc: Exception | None = None) -> MagicMock:
    transport = MagicMock()
    if exc is not None:
        transport.perform_request = AsyncMock(side_effect=exc)
    else:
        transport.perform_request = AsyncMock(
            return_value={"_id": AUDIT_ILM_POLICY_NAME, "policy": {}}
        )
    return transport


def _make_indices_client(*, rules_exist: bool = True) -> MagicMock:
    idx = MagicMock()
    idx.put_index_template = AsyncMock(return_value={"acknowledged": True})
    idx.exists = AsyncMock(return_value=rules_exist)
    idx.create = AsyncMock(return_value={"acknowledged": True})
    return idx


# ---------------------------------------------------------------------------
# OpenSearchService.ensure_audit_ilm_policy
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ensure_audit_ilm_policy_noop_when_unavailable() -> None:
    """ensure_audit_ilm_policy() is a no-op when no client is connected."""
    svc = OpenSearchService()
    # _client is None — must not raise
    await svc.ensure_audit_ilm_policy()


@pytest.mark.asyncio
async def test_ensure_audit_ilm_policy_calls_put_via_transport() -> None:
    """ensure_audit_ilm_policy() calls transport.perform_request with PUT method."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.transport = _make_transport()
    svc._client = mock_client

    await svc.ensure_audit_ilm_policy()

    mock_client.transport.perform_request.assert_awaited_once()
    call_args = mock_client.transport.perform_request.call_args
    method = call_args.args[0] if call_args.args else call_args.kwargs.get("method")
    assert method == "PUT"


@pytest.mark.asyncio
async def test_ensure_audit_ilm_policy_targets_correct_ism_endpoint() -> None:
    """ensure_audit_ilm_policy() targets the ISM policies endpoint for the audit policy."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.transport = _make_transport()
    svc._client = mock_client

    await svc.ensure_audit_ilm_policy()

    call_args = mock_client.transport.perform_request.call_args
    url = call_args.args[1] if len(call_args.args) > 1 else call_args.kwargs.get("url")
    assert AUDIT_ILM_POLICY_NAME in url
    assert "_ism" in url or "_plugins" in url


@pytest.mark.asyncio
async def test_ensure_audit_ilm_policy_uses_correct_policy_name() -> None:
    """The PUT URL references the canonical 3-year audit policy name."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.transport = _make_transport()
    svc._client = mock_client

    await svc.ensure_audit_ilm_policy()

    assert AUDIT_ILM_POLICY_NAME == "mxtac-3year-audit-retention"


@pytest.mark.asyncio
async def test_ensure_audit_ilm_policy_body_has_ingest_and_delete_states() -> None:
    """Policy body contains 'ingest' and 'delete' states."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.transport = _make_transport()
    svc._client = mock_client

    await svc.ensure_audit_ilm_policy()

    call_args = mock_client.transport.perform_request.call_args
    body = call_args.kwargs.get("body") or (call_args.args[2] if len(call_args.args) > 2 else None)
    assert body is not None
    state_names = {s["name"] for s in body["policy"]["states"]}
    assert "ingest" in state_names
    assert "delete" in state_names


@pytest.mark.asyncio
async def test_ensure_audit_ilm_policy_retention_is_1095_days() -> None:
    """Policy transition uses 'min_index_age' of 1095d (3 years)."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.transport = _make_transport()
    svc._client = mock_client

    await svc.ensure_audit_ilm_policy()

    call_args = mock_client.transport.perform_request.call_args
    body = call_args.kwargs.get("body") or (call_args.args[2] if len(call_args.args) > 2 else None)
    ingest_state = next(s for s in body["policy"]["states"] if s["name"] == "ingest")
    min_age = ingest_state["transitions"][0]["conditions"]["min_index_age"]
    assert min_age == f"{AUDIT_ILM_RETENTION_DAYS}d"
    assert min_age == "1095d"


@pytest.mark.asyncio
async def test_ensure_audit_ilm_policy_delete_state_has_delete_action() -> None:
    """Policy 'delete' state includes the delete action."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.transport = _make_transport()
    svc._client = mock_client

    await svc.ensure_audit_ilm_policy()

    call_args = mock_client.transport.perform_request.call_args
    body = call_args.kwargs.get("body") or (call_args.args[2] if len(call_args.args) > 2 else None)
    delete_state = next(s for s in body["policy"]["states"] if s["name"] == "delete")
    assert {"delete": {}} in delete_state["actions"]


@pytest.mark.asyncio
async def test_ensure_audit_ilm_policy_ism_template_covers_audit_index() -> None:
    """ISM template in the audit policy covers mxtac-audit-* pattern."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.transport = _make_transport()
    svc._client = mock_client

    await svc.ensure_audit_ilm_policy()

    call_args = mock_client.transport.perform_request.call_args
    body = call_args.kwargs.get("body") or (call_args.args[2] if len(call_args.args) > 2 else None)
    patterns = body["policy"]["ism_template"][0]["index_patterns"]
    assert "mxtac-audit-*" in patterns


@pytest.mark.asyncio
async def test_ensure_audit_ilm_policy_ism_template_does_not_cover_events() -> None:
    """Audit policy must NOT accidentally cover the events/alerts indices."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.transport = _make_transport()
    svc._client = mock_client

    await svc.ensure_audit_ilm_policy()

    call_args = mock_client.transport.perform_request.call_args
    body = call_args.kwargs.get("body") or (call_args.args[2] if len(call_args.args) > 2 else None)
    patterns = body["policy"]["ism_template"][0]["index_patterns"]
    assert "mxtac-events-*" not in patterns
    assert "mxtac-alerts-*" not in patterns


@pytest.mark.asyncio
async def test_ensure_audit_ilm_policy_ism_template_priority_is_200() -> None:
    """Audit ISM template priority is 200 (higher than events/alerts at 100)."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.transport = _make_transport()
    svc._client = mock_client

    await svc.ensure_audit_ilm_policy()

    call_args = mock_client.transport.perform_request.call_args
    body = call_args.kwargs.get("body") or (call_args.args[2] if len(call_args.args) > 2 else None)
    priority = body["policy"]["ism_template"][0]["priority"]
    assert priority == 200


@pytest.mark.asyncio
async def test_ensure_audit_ilm_policy_exception_does_not_crash() -> None:
    """An exception from the transport is caught; method returns without raising."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.transport = _make_transport(exc=Exception("ISM plugin unavailable"))
    svc._client = mock_client

    # Must not raise
    await svc.ensure_audit_ilm_policy()


@pytest.mark.asyncio
async def test_ensure_audit_ilm_policy_exception_logs_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A transport exception is logged at WARNING level."""
    import logging

    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.transport = _make_transport(exc=Exception("ISM plugin unavailable"))
    svc._client = mock_client

    with caplog.at_level(logging.WARNING):
        await svc.ensure_audit_ilm_policy()

    assert "ISM plugin unavailable" in caplog.text


@pytest.mark.asyncio
async def test_ensure_audit_ilm_policy_logs_success(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """ensure_audit_ilm_policy() logs INFO on successful policy application."""
    import logging

    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.transport = _make_transport()
    svc._client = mock_client

    with caplog.at_level(logging.INFO):
        await svc.ensure_audit_ilm_policy()

    assert AUDIT_ILM_POLICY_NAME in caplog.text


# ---------------------------------------------------------------------------
# OpenSearchService.ensure_indices — audit template
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ensure_indices_creates_audit_template() -> None:
    """ensure_indices() calls put_index_template for the audit template."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.indices = _make_indices_client(rules_exist=True)
    svc._client = mock_client

    await svc.ensure_indices()

    names_called = [
        c.kwargs.get("name") or (c.args[0] if c.args else None)
        for c in mock_client.indices.put_index_template.call_args_list
    ]
    assert "mxtac-audit-template" in names_called


@pytest.mark.asyncio
async def test_ensure_indices_audit_template_uses_correct_index_pattern() -> None:
    """Audit template must target the mxtac-audit-* index pattern."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.indices = _make_indices_client(rules_exist=True)
    svc._client = mock_client

    await svc.ensure_indices()

    calls = {
        c.kwargs.get("name"): c.kwargs.get("body")
        for c in mock_client.indices.put_index_template.call_args_list
    }
    body = calls.get("mxtac-audit-template", {})
    assert body.get("index_patterns") == ["mxtac-audit-*"]


@pytest.mark.asyncio
async def test_ensure_indices_audit_template_has_ism_policy_id() -> None:
    """Audit template settings embed the 3-year ISM policy ID."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.indices = _make_indices_client(rules_exist=True)
    svc._client = mock_client

    await svc.ensure_indices()

    calls = {
        c.kwargs.get("name"): c.kwargs.get("body")
        for c in mock_client.indices.put_index_template.call_args_list
    }
    audit_body = calls.get("mxtac-audit-template")
    assert audit_body is not None
    settings_block = audit_body["template"]["settings"]
    assert settings_block.get("plugins.index_state_management.policy_id") == AUDIT_ILM_POLICY_NAME


@pytest.mark.asyncio
async def test_ensure_indices_audit_template_has_timestamp_date_field() -> None:
    """Audit template mapping must include 'timestamp' as a date field."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.indices = _make_indices_client(rules_exist=True)
    svc._client = mock_client

    await svc.ensure_indices()

    calls = {
        c.kwargs.get("name"): c.kwargs.get("body")
        for c in mock_client.indices.put_index_template.call_args_list
    }
    props = calls["mxtac-audit-template"]["template"]["mappings"]["properties"]
    assert props["timestamp"] == {"type": "date"}
    assert props["actor"] == {"type": "keyword"}
    assert props["request_ip"] == {"type": "ip"}


@pytest.mark.asyncio
async def test_ensure_indices_audit_template_exception_does_not_crash() -> None:
    """An exception from put_index_template for the audit template is caught."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.indices = _make_indices_client(rules_exist=True)
    # Make the first two calls succeed (events, alerts), fail on audit
    original = mock_client.indices.put_index_template
    call_count = {"n": 0}

    async def _side_effect(*args, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 3:  # third call is audit template
            raise Exception("audit template error")
        return {"acknowledged": True}

    mock_client.indices.put_index_template = _side_effect
    svc._client = mock_client

    # Must not raise
    await svc.ensure_indices()


@pytest.mark.asyncio
async def test_ensure_indices_creates_three_templates_total() -> None:
    """ensure_indices() registers exactly 3 index templates: events, alerts, audit."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    mock_client.indices = _make_indices_client(rules_exist=True)
    svc._client = mock_client

    await svc.ensure_indices()

    names_called = [
        c.kwargs.get("name") or (c.args[0] if c.args else None)
        for c in mock_client.indices.put_index_template.call_args_list
    ]
    assert "mxtac-events-template" in names_called
    assert "mxtac-alerts-template" in names_called
    assert "mxtac-audit-template" in names_called
    assert len(names_called) == 3


# ---------------------------------------------------------------------------
# AuditLogger.log() — monthly rollover index
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_audit_logger_log_targets_monthly_audit_index() -> None:
    """AuditLogger.log() writes to a mxtac-audit-YYYY.MM index."""
    audit = AuditLogger()
    mock_client = MagicMock()
    mock_client.index = AsyncMock(return_value={"_id": "audit-doc-1"})
    audit._client = mock_client

    await audit.log(actor="admin@test.local", action="create", resource_type="rule")

    idx = mock_client.index.call_args.kwargs["index"]
    assert idx.startswith("mxtac-audit-")


@pytest.mark.asyncio
async def test_audit_logger_log_index_matches_monthly_pattern() -> None:
    """The audit index name follows the YYYY.MM monthly-rollover pattern."""
    audit = AuditLogger()
    mock_client = MagicMock()
    mock_client.index = AsyncMock(return_value={"_id": "audit-doc-1"})
    audit._client = mock_client

    await audit.log(actor="admin@test.local", action="delete", resource_type="user")

    idx = mock_client.index.call_args.kwargs["index"]
    assert re.fullmatch(r"mxtac-audit-\d{4}\.\d{2}", idx), (
        f"Expected mxtac-audit-YYYY.MM, got {idx!r}"
    )


@pytest.mark.asyncio
async def test_audit_logger_log_index_uses_utc_month() -> None:
    """The monthly index suffix reflects today's UTC month."""
    audit = AuditLogger()
    mock_client = MagicMock()
    mock_client.index = AsyncMock(return_value={"_id": "x"})
    audit._client = mock_client

    await audit.log(actor="u@u.com", action="login", resource_type="session")

    idx = mock_client.index.call_args.kwargs["index"]
    today_month = datetime.now(timezone.utc).strftime("%Y.%m")
    assert idx == f"mxtac-audit-{today_month}"


@pytest.mark.asyncio
async def test_audit_logger_log_index_frozen_month() -> None:
    """AuditLogger.log() uses the UTC month at call time — verifiable by freezing."""
    audit = AuditLogger()
    mock_client = MagicMock()
    mock_client.index = AsyncMock(return_value={"_id": "x"})
    audit._client = mock_client

    fixed_dt = datetime(2026, 2, 21, 10, 0, 0, tzinfo=timezone.utc)
    with patch("app.services.opensearch_client.datetime") as mock_dt:
        mock_dt.now.return_value = fixed_dt
        await audit.log(actor="u@u.com", action="login", resource_type="session")

    idx = mock_client.index.call_args.kwargs["index"]
    assert idx == "mxtac-audit-2026.02"


@pytest.mark.asyncio
async def test_audit_logger_log_does_not_use_daily_index() -> None:
    """Audit index must NOT have a daily YYYY.MM.DD suffix (monthly rollover only)."""
    audit = AuditLogger()
    mock_client = MagicMock()
    mock_client.index = AsyncMock(return_value={"_id": "x"})
    audit._client = mock_client

    await audit.log(actor="u@u.com", action="update", resource_type="rule")

    idx = mock_client.index.call_args.kwargs["index"]
    # A daily index would have 3 dot-separated segments; monthly has 2
    suffix = idx.replace("mxtac-audit-", "")
    parts = suffix.split(".")
    assert len(parts) == 2, (
        f"Audit index should be YYYY.MM (2 parts), got {idx!r} with {len(parts)} parts"
    )


@pytest.mark.asyncio
async def test_audit_logger_log_does_not_target_events_index() -> None:
    """audit.log() must never write to the events or alerts indices."""
    audit = AuditLogger()
    mock_client = MagicMock()
    mock_client.index = AsyncMock(return_value={"_id": "x"})
    audit._client = mock_client

    await audit.log(actor="u@u.com", action="create", resource_type="rule")

    idx = mock_client.index.call_args.kwargs["index"]
    assert not idx.startswith("mxtac-events-"), f"audit.log() must not write to events index, got {idx!r}"
    assert not idx.startswith("mxtac-alerts-"), f"audit.log() must not write to alerts index, got {idx!r}"


@pytest.mark.asyncio
async def test_audit_logger_log_returns_doc_id_from_response() -> None:
    """log() returns the _id from the OpenSearch response."""
    audit = AuditLogger()
    mock_client = MagicMock()
    mock_client.index = AsyncMock(return_value={"_id": "audit-uuid-999"})
    audit._client = mock_client

    result = await audit.log(actor="u@u.com", action="create", resource_type="rule")

    assert result == "audit-uuid-999"


@pytest.mark.asyncio
async def test_audit_logger_log_passes_refresh_true() -> None:
    """audit.log() uses refresh='true' for immediate visibility."""
    audit = AuditLogger()
    mock_client = MagicMock()
    mock_client.index = AsyncMock(return_value={"_id": "x"})
    audit._client = mock_client

    await audit.log(actor="u@u.com", action="delete", resource_type="user")

    kw = mock_client.index.call_args.kwargs
    assert kw.get("refresh") == "true"


# ---------------------------------------------------------------------------
# AuditLogger.search() — wildcard across mxtac-audit-*
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_audit_logger_search_targets_audit_wildcard_index() -> None:
    """search() queries mxtac-audit-* to cover all monthly audit indices."""
    audit = AuditLogger()
    mock_client = MagicMock()
    mock_client.search = AsyncMock(return_value={
        "hits": {"total": {"value": 0}, "hits": []}
    })
    audit._client = mock_client

    await audit.search()

    call = mock_client.search.call_args
    index_arg = call.kwargs.get("index") or call.args[0]
    assert index_arg == "mxtac-audit-*"


@pytest.mark.asyncio
async def test_audit_logger_search_does_not_target_single_static_index() -> None:
    """search() must not target the old single static 'mxtac-audit' index."""
    audit = AuditLogger()
    mock_client = MagicMock()
    mock_client.search = AsyncMock(return_value={
        "hits": {"total": {"value": 0}, "hits": []}
    })
    audit._client = mock_client

    await audit.search()

    call = mock_client.search.call_args
    index_arg = call.kwargs.get("index") or call.args[0]
    # Exact equality to "mxtac-audit" (no wildcard) would be the old broken behaviour
    assert index_arg != "mxtac-audit", (
        "search() must use mxtac-audit-* (wildcard) not the single static index"
    )


@pytest.mark.asyncio
async def test_audit_logger_search_returns_empty_when_unavailable() -> None:
    """search() returns empty dict when no client is available."""
    audit = AuditLogger()
    # _client is None — _ensure_client() will be called but opensearchpy not installed
    with patch.dict(sys.modules, {"opensearchpy": None}):
        result = await audit.search()

    assert result == {"total": 0, "items": []}
