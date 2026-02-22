"""Tests for feature 8.20 — Rule performance tracking: hit_count / fp_count.

Verifies:

  RuleRepo.increment_hit():
  - Increments hit_count by 1
  - Sets last_hit_at to a non-empty ISO timestamp
  - Multiple calls accumulate the count
  - Targets the correct rule (other rules unchanged)

  RuleRepo.increment_fp():
  - Increments fp_count by 1
  - Multiple calls accumulate the count
  - Does not touch hit_count

  sigma_consumer DB integration:
  - session_factory is called once per rule match
  - RuleRepo.increment_hit is awaited with the correct rule_id
  - No session_factory call when there is no match
  - session_factory failure is silently swallowed (pipeline not blocked)
  - session_factory=None (default) → no DB call attempted
"""

from __future__ import annotations

from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.engine.sigma_engine import SigmaEngine
from app.repositories.rule_repo import RuleRepo
from app.services.sigma_consumer import sigma_consumer


# ---------------------------------------------------------------------------
# DB fixtures — real SQLite in-memory via conftest.db_session
# ---------------------------------------------------------------------------


async def _create_rule(session: AsyncSession, rule_id: str, **kwargs) -> None:
    """Insert a minimal Rule row for testing."""
    await RuleRepo.create(
        session,
        id=rule_id,
        title=kwargs.get("title", f"Rule {rule_id}"),
        content=kwargs.get("content", "title: x\ndetection:\n  condition: selection\n"),
        status="stable",
        level=kwargs.get("level", "medium"),
        enabled=True,
    )


# ---------------------------------------------------------------------------
# RuleRepo.increment_hit
# ---------------------------------------------------------------------------


class TestIncrementHit:
    async def test_hit_count_incremented_by_one(self, db_session: AsyncSession) -> None:
        await _create_rule(db_session, "r-001")

        await RuleRepo.increment_hit(db_session, "r-001")
        await db_session.commit()

        rule = await RuleRepo.get_by_id(db_session, "r-001")
        assert rule is not None
        assert rule.hit_count == 1

    async def test_last_hit_at_is_set(self, db_session: AsyncSession) -> None:
        await _create_rule(db_session, "r-002")

        await RuleRepo.increment_hit(db_session, "r-002")
        await db_session.commit()

        rule = await RuleRepo.get_by_id(db_session, "r-002")
        assert rule is not None
        assert rule.last_hit_at is not None
        assert len(rule.last_hit_at) > 0
        # Verify it parses as an ISO datetime
        parsed = datetime.fromisoformat(rule.last_hit_at)
        assert parsed.year >= 2024

    async def test_multiple_calls_accumulate(self, db_session: AsyncSession) -> None:
        await _create_rule(db_session, "r-003")

        for _ in range(5):
            await RuleRepo.increment_hit(db_session, "r-003")
        await db_session.commit()

        rule = await RuleRepo.get_by_id(db_session, "r-003")
        assert rule is not None
        assert rule.hit_count == 5

    async def test_only_target_rule_affected(self, db_session: AsyncSession) -> None:
        await _create_rule(db_session, "r-target")
        await _create_rule(db_session, "r-other")

        await RuleRepo.increment_hit(db_session, "r-target")
        await db_session.commit()

        other = await RuleRepo.get_by_id(db_session, "r-other")
        assert other is not None
        assert other.hit_count == 0

    async def test_unknown_rule_id_does_not_raise(self, db_session: AsyncSession) -> None:
        """Updating a non-existent rule should silently no-op (UPDATE 0 rows)."""
        await RuleRepo.increment_hit(db_session, "does-not-exist")
        await db_session.commit()  # must not raise


# ---------------------------------------------------------------------------
# RuleRepo.increment_fp
# ---------------------------------------------------------------------------


class TestIncrementFp:
    async def test_fp_count_incremented_by_one(self, db_session: AsyncSession) -> None:
        await _create_rule(db_session, "fp-001")

        await RuleRepo.increment_fp(db_session, "fp-001")
        await db_session.commit()

        rule = await RuleRepo.get_by_id(db_session, "fp-001")
        assert rule is not None
        assert rule.fp_count == 1

    async def test_multiple_fp_calls_accumulate(self, db_session: AsyncSession) -> None:
        await _create_rule(db_session, "fp-002")

        for _ in range(3):
            await RuleRepo.increment_fp(db_session, "fp-002")
        await db_session.commit()

        rule = await RuleRepo.get_by_id(db_session, "fp-002")
        assert rule is not None
        assert rule.fp_count == 3

    async def test_increment_fp_does_not_change_hit_count(self, db_session: AsyncSession) -> None:
        await _create_rule(db_session, "fp-003")

        await RuleRepo.increment_fp(db_session, "fp-003")
        await db_session.commit()

        rule = await RuleRepo.get_by_id(db_session, "fp-003")
        assert rule is not None
        assert rule.hit_count == 0

    async def test_unknown_rule_id_does_not_raise(self, db_session: AsyncSession) -> None:
        await RuleRepo.increment_fp(db_session, "ghost-rule")
        await db_session.commit()


# ---------------------------------------------------------------------------
# Sigma rule YAML fixtures
# ---------------------------------------------------------------------------

_RULE_PS_ENCODED = """\
title: PowerShell Encoded Command
id: rule-ps-encoded-001
status: stable
level: high
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    name: powershell.exe
    cmd_line|contains: -enc
  condition: selection
"""

_RULE_NO_MATCH = """\
title: Unreachable Rule
id: rule-no-match-001
status: experimental
level: low
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    name: this-process-does-not-exist.exe
  condition: selection
"""


# ---------------------------------------------------------------------------
# Event helpers
# ---------------------------------------------------------------------------


from datetime import timezone
from app.services.normalizers.ocsf import (
    Endpoint,
    OCSFCategory,
    OCSFClass,
    OCSFEvent,
    ProcessInfo,
)


def _matching_event_dict() -> dict:
    event = OCSFEvent(
        class_uid=OCSFClass.PROCESS_ACTIVITY,
        class_name="Process Activity",
        category_uid=OCSFCategory.SYSTEM_ACTIVITY,
        time=datetime(2026, 2, 22, 12, 0, 0, tzinfo=timezone.utc),
        severity_id=1,
        metadata_product="windows",
        process=ProcessInfo(name="powershell.exe", cmd_line="powershell -enc abc123"),
        dst_endpoint=Endpoint(hostname="workstation-01", ip="10.0.0.1"),
    )
    return event.model_dump(mode="json")


def _non_matching_event_dict() -> dict:
    event = OCSFEvent(
        class_uid=OCSFClass.PROCESS_ACTIVITY,
        class_name="Process Activity",
        category_uid=OCSFCategory.SYSTEM_ACTIVITY,
        time=datetime(2026, 2, 22, 12, 0, 0, tzinfo=timezone.utc),
        severity_id=1,
        metadata_product="windows",
        process=ProcessInfo(name="notepad.exe", cmd_line="notepad.exe"),
        dst_endpoint=Endpoint(hostname="workstation-01", ip="10.0.0.1"),
    )
    return event.model_dump(mode="json")


def _engine_with_rule(yaml_text: str) -> SigmaEngine:
    engine = SigmaEngine()
    rule = engine.load_rule_yaml(yaml_text)
    assert rule is not None
    engine.add_rule(rule)
    return engine


# ---------------------------------------------------------------------------
# sigma_consumer DB integration
# ---------------------------------------------------------------------------


async def _get_handler(engine: SigmaEngine, session_factory=None):
    """Call sigma_consumer with a mock queue and return (mock_queue, handler)."""
    q = MagicMock()
    q.subscribe = AsyncMock()
    q.publish = AsyncMock()
    await sigma_consumer(q, engine, session_factory=session_factory)
    handler = q.subscribe.call_args.args[2]
    return q, handler


def _make_session_factory():
    """Return a mock session_factory whose context manager yields a mock session."""
    mock_session = MagicMock()
    mock_session.commit = AsyncMock()
    mock_session.execute = AsyncMock()
    mock_session.rollback = AsyncMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    session_factory = MagicMock()
    session_factory.return_value = mock_session
    return session_factory, mock_session


class TestSigmaConsumerHitTracking:
    async def test_session_factory_called_on_match(self) -> None:
        engine = _engine_with_rule(_RULE_PS_ENCODED)
        session_factory, _ = _make_session_factory()
        _, handler = await _get_handler(engine, session_factory=session_factory)

        await handler(_matching_event_dict())

        session_factory.assert_called_once()

    async def test_increment_hit_called_with_correct_rule_id(self) -> None:
        engine = _engine_with_rule(_RULE_PS_ENCODED)
        session_factory, mock_session = _make_session_factory()
        _, handler = await _get_handler(engine, session_factory=session_factory)

        with patch(
            "app.services.sigma_consumer.RuleRepo.increment_hit",
            new_callable=AsyncMock,
        ) as mock_increment:
            await handler(_matching_event_dict())

        mock_increment.assert_awaited_once()
        call_rule_id = mock_increment.call_args.args[1]
        assert call_rule_id == "rule-ps-encoded-001"

    async def test_session_committed_after_match(self) -> None:
        engine = _engine_with_rule(_RULE_PS_ENCODED)
        session_factory, mock_session = _make_session_factory()
        _, handler = await _get_handler(engine, session_factory=session_factory)

        with patch("app.services.sigma_consumer.RuleRepo.increment_hit", new_callable=AsyncMock):
            await handler(_matching_event_dict())

        mock_session.commit.assert_awaited_once()

    async def test_no_session_call_on_no_match(self) -> None:
        engine = _engine_with_rule(_RULE_PS_ENCODED)
        session_factory, _ = _make_session_factory()
        _, handler = await _get_handler(engine, session_factory=session_factory)

        await handler(_non_matching_event_dict())

        session_factory.assert_not_called()

    async def test_session_factory_none_default_no_call(self) -> None:
        """With session_factory=None, no DB calls should occur."""
        engine = _engine_with_rule(_RULE_PS_ENCODED)
        q = MagicMock()
        q.subscribe = AsyncMock()
        q.publish = AsyncMock()
        # Default: session_factory not passed
        await sigma_consumer(q, engine)
        handler = q.subscribe.call_args.args[2]

        with patch("app.services.sigma_consumer.RuleRepo.increment_hit", new_callable=AsyncMock) as mock_incr:
            await handler(_matching_event_dict())

        mock_incr.assert_not_awaited()

    async def test_db_failure_does_not_crash_handler(self) -> None:
        """A session_factory that raises must not propagate to the caller."""
        engine = _engine_with_rule(_RULE_PS_ENCODED)

        def _broken_factory():
            raise RuntimeError("DB is down")

        _, handler = await _get_handler(engine, session_factory=_broken_factory)

        # Must not raise
        await handler(_matching_event_dict())

    async def test_increment_hit_failure_does_not_crash_handler(self) -> None:
        """A failure inside increment_hit must be swallowed."""
        engine = _engine_with_rule(_RULE_PS_ENCODED)
        session_factory, _ = _make_session_factory()
        _, handler = await _get_handler(engine, session_factory=session_factory)

        with patch(
            "app.services.sigma_consumer.RuleRepo.increment_hit",
            new_callable=AsyncMock,
            side_effect=RuntimeError("DB write failed"),
        ):
            await handler(_matching_event_dict())  # must not raise

    async def test_alert_still_published_when_db_fails(self) -> None:
        """DB failure must not suppress the alert publication."""
        engine = _engine_with_rule(_RULE_PS_ENCODED)
        session_factory, _ = _make_session_factory()
        q, handler = await _get_handler(engine, session_factory=session_factory)

        with patch(
            "app.services.sigma_consumer.RuleRepo.increment_hit",
            new_callable=AsyncMock,
            side_effect=RuntimeError("DB write failed"),
        ):
            await handler(_matching_event_dict())

        q.publish.assert_awaited_once()

    async def test_two_matching_rules_produce_two_db_calls(self) -> None:
        engine = SigmaEngine()
        _RULE_MIMIKATZ = """\
title: Mimikatz
id: rule-mimikatz-001
status: stable
level: critical
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    cmd_line|contains: mimikatz
  condition: selection
"""
        for yaml_text in (_RULE_PS_ENCODED, _RULE_MIMIKATZ):
            rule = engine.load_rule_yaml(yaml_text)
            assert rule is not None
            engine.add_rule(rule)

        session_factory, _ = _make_session_factory()
        _, handler = await _get_handler(engine, session_factory=session_factory)

        # Event matching both rules
        event = OCSFEvent(
            class_uid=OCSFClass.PROCESS_ACTIVITY,
            class_name="Process Activity",
            category_uid=OCSFCategory.SYSTEM_ACTIVITY,
            time=datetime(2026, 2, 22, 12, 0, 0, tzinfo=timezone.utc),
            severity_id=1,
            metadata_product="windows",
            process=ProcessInfo(name="powershell.exe", cmd_line="powershell -enc mimikatz"),
            dst_endpoint=Endpoint(hostname="host-01", ip="10.0.0.1"),
        )

        with patch(
            "app.services.sigma_consumer.RuleRepo.increment_hit",
            new_callable=AsyncMock,
        ) as mock_increment:
            await handler(event.model_dump(mode="json"))

        assert mock_increment.await_count == 2
        called_rule_ids = {call.args[1] for call in mock_increment.call_args_list}
        assert called_rule_ids == {"rule-ps-encoded-001", "rule-mimikatz-001"}
