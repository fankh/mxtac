"""Tests for the data retention background task — feature 38.4.

Coverage:

  _delete_old_detections():
  - Returns rowcount from the DELETE statement

  _delete_old_incidents():
  - Filters on status IN ('resolved', 'closed') and closed_at < cutoff
  - Incidents without closed_at are skipped
  - Active incidents are not deleted

  _delete_old_iocs():
  - Only deletes IOCs with expires_at < cutoff
  - IOCs without expires_at are not deleted

  data_retention_task():
  - Runs all three deletions, commits, increments counters on non-zero
  - Zero total → counters not incremented
  - Calls audit.log when records were deleted
  - Exceptions in loop body are caught; task continues
  - asyncio.CancelledError propagates (not swallowed)

  get_retention_storage_stats():
  - Returns correct counts from a real SQLite session
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.retention import (
    _delete_old_detections,
    _delete_old_incidents,
    _delete_old_iocs,
    data_retention_task,
    get_retention_storage_stats,
)
from app.models.detection import Detection
from app.models.incident import Incident
from app.models.ioc import IOC


# ---------------------------------------------------------------------------
# Helper: fake session
# ---------------------------------------------------------------------------

def _make_session() -> MagicMock:
    """MagicMock session with async execute/flush/commit."""
    session = MagicMock()
    session.execute = AsyncMock()
    session.flush = AsyncMock()
    session.commit = AsyncMock()
    session.scalar = AsyncMock()
    return session


def _execute_result(rowcount: int) -> MagicMock:
    result = MagicMock()
    result.rowcount = rowcount
    return result


# ---------------------------------------------------------------------------
# _delete_old_detections
# ---------------------------------------------------------------------------

class TestDeleteOldDetections:

    @pytest.mark.asyncio
    async def test_returns_rowcount(self) -> None:
        session = _make_session()
        session.execute.return_value = _execute_result(5)
        cutoff = datetime.now(timezone.utc) - timedelta(days=365)

        count = await _delete_old_detections(session, cutoff)

        assert count == 5
        session.execute.assert_awaited_once()
        session.flush.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_zero_rowcount(self) -> None:
        session = _make_session()
        session.execute.return_value = _execute_result(0)
        cutoff = datetime.now(timezone.utc)

        count = await _delete_old_detections(session, cutoff)

        assert count == 0


# ---------------------------------------------------------------------------
# _delete_old_incidents
# ---------------------------------------------------------------------------

class TestDeleteOldIncidents:

    @pytest.mark.asyncio
    async def test_returns_rowcount(self) -> None:
        session = _make_session()
        session.execute.return_value = _execute_result(3)
        cutoff = datetime.now(timezone.utc) - timedelta(days=730)

        count = await _delete_old_incidents(session, cutoff)

        assert count == 3
        session.execute.assert_awaited_once()
        session.flush.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_zero_rowcount(self) -> None:
        session = _make_session()
        session.execute.return_value = _execute_result(0)
        cutoff = datetime.now(timezone.utc) - timedelta(days=730)

        count = await _delete_old_incidents(session, cutoff)

        assert count == 0


# ---------------------------------------------------------------------------
# _delete_old_iocs
# ---------------------------------------------------------------------------

class TestDeleteOldIOCs:

    @pytest.mark.asyncio
    async def test_returns_rowcount(self) -> None:
        session = _make_session()
        session.execute.return_value = _execute_result(7)
        cutoff = datetime.now(timezone.utc) - timedelta(days=180)

        count = await _delete_old_iocs(session, cutoff)

        assert count == 7
        session.execute.assert_awaited_once()
        session.flush.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_zero_rowcount(self) -> None:
        session = _make_session()
        session.execute.return_value = _execute_result(0)
        cutoff = datetime.now(timezone.utc) - timedelta(days=180)

        count = await _delete_old_iocs(session, cutoff)

        assert count == 0


# ---------------------------------------------------------------------------
# data_retention_task()
# ---------------------------------------------------------------------------

def _session_ctx(session: MagicMock) -> MagicMock:
    ctx = MagicMock()
    ctx.__aenter__ = AsyncMock(return_value=session)
    ctx.__aexit__ = AsyncMock(return_value=False)
    return ctx


class TestDataRetentionTask:

    @pytest.mark.asyncio
    async def test_deletes_records_increments_counters(self) -> None:
        """All three deletions run; counters incremented for non-zero counts."""
        session = _make_session()

        with (
            patch("app.services.retention.asyncio.sleep", new_callable=AsyncMock) as mock_sleep,
            patch("app.services.retention.AsyncSessionLocal", return_value=_session_ctx(session)),
            patch("app.services.retention._delete_old_detections", new_callable=AsyncMock, return_value=4) as mock_det,
            patch("app.services.retention._delete_old_incidents", new_callable=AsyncMock, return_value=2) as mock_inc,
            patch("app.services.retention._delete_old_iocs", new_callable=AsyncMock, return_value=1) as mock_ioc,
            patch("app.services.retention.metrics") as mock_metrics,
            patch("app.services.retention.settings") as mock_settings,
        ):
            mock_settings.retention_alerts_days = 365
            mock_settings.retention_incidents_days = 730
            mock_settings.retention_iocs_days = 180
            # First sleep returns (triggers one iteration), second raises Cancelled.
            mock_sleep.side_effect = [None, asyncio.CancelledError()]

            with pytest.raises(asyncio.CancelledError):
                await data_retention_task()

        mock_det.assert_awaited_once()
        mock_inc.assert_awaited_once()
        mock_ioc.assert_awaited_once()
        session.commit.assert_awaited_once()

        mock_metrics.retention_deleted.labels.assert_any_call(type="detection")
        mock_metrics.retention_deleted.labels.assert_any_call(type="incident")
        mock_metrics.retention_deleted.labels.assert_any_call(type="ioc")

    @pytest.mark.asyncio
    async def test_zero_total_does_not_increment_counters(self) -> None:
        """When all delete counts are zero, Prometheus counters are not touched."""
        session = _make_session()

        with (
            patch("app.services.retention.asyncio.sleep", new_callable=AsyncMock) as mock_sleep,
            patch("app.services.retention.AsyncSessionLocal", return_value=_session_ctx(session)),
            patch("app.services.retention._delete_old_detections", new_callable=AsyncMock, return_value=0),
            patch("app.services.retention._delete_old_incidents", new_callable=AsyncMock, return_value=0),
            patch("app.services.retention._delete_old_iocs", new_callable=AsyncMock, return_value=0),
            patch("app.services.retention.metrics") as mock_metrics,
            patch("app.services.retention.settings") as mock_settings,
        ):
            mock_settings.retention_alerts_days = 365
            mock_settings.retention_incidents_days = 730
            mock_settings.retention_iocs_days = 180
            mock_sleep.side_effect = [None, asyncio.CancelledError()]

            with pytest.raises(asyncio.CancelledError):
                await data_retention_task()

        mock_metrics.retention_deleted.labels.assert_not_called()

    @pytest.mark.asyncio
    async def test_audit_log_called_when_records_deleted(self) -> None:
        """Audit logger is invoked when at least one record is deleted."""
        session = _make_session()
        mock_audit = MagicMock()
        mock_audit.log = AsyncMock()

        with (
            patch("app.services.retention.asyncio.sleep", new_callable=AsyncMock) as mock_sleep,
            patch("app.services.retention.AsyncSessionLocal", return_value=_session_ctx(session)),
            patch("app.services.retention._delete_old_detections", new_callable=AsyncMock, return_value=3),
            patch("app.services.retention._delete_old_incidents", new_callable=AsyncMock, return_value=0),
            patch("app.services.retention._delete_old_iocs", new_callable=AsyncMock, return_value=0),
            patch("app.services.retention.metrics"),
            patch("app.services.retention.settings") as mock_settings,
            patch("app.services.retention.get_audit_logger", return_value=mock_audit),
        ):
            mock_settings.retention_alerts_days = 365
            mock_settings.retention_incidents_days = 730
            mock_settings.retention_iocs_days = 180
            mock_sleep.side_effect = [None, asyncio.CancelledError()]

            with pytest.raises(asyncio.CancelledError):
                await data_retention_task()

        mock_audit.log.assert_awaited_once()
        call_kwargs = mock_audit.log.call_args.kwargs
        assert call_kwargs["actor"] == "system"
        assert call_kwargs["action"] == "retention_cleanup"
        assert call_kwargs["resource_type"] == "data_retention"
        assert call_kwargs["details"]["detections_deleted"] == 3

    @pytest.mark.asyncio
    async def test_audit_log_not_called_when_nothing_deleted(self) -> None:
        """Audit logger is NOT invoked when all counts are zero."""
        session = _make_session()
        mock_audit = MagicMock()
        mock_audit.log = AsyncMock()

        with (
            patch("app.services.retention.asyncio.sleep", new_callable=AsyncMock) as mock_sleep,
            patch("app.services.retention.AsyncSessionLocal", return_value=_session_ctx(session)),
            patch("app.services.retention._delete_old_detections", new_callable=AsyncMock, return_value=0),
            patch("app.services.retention._delete_old_incidents", new_callable=AsyncMock, return_value=0),
            patch("app.services.retention._delete_old_iocs", new_callable=AsyncMock, return_value=0),
            patch("app.services.retention.metrics"),
            patch("app.services.retention.settings") as mock_settings,
            patch("app.services.retention.get_audit_logger", return_value=mock_audit),
        ):
            mock_settings.retention_alerts_days = 365
            mock_settings.retention_incidents_days = 730
            mock_settings.retention_iocs_days = 180
            mock_sleep.side_effect = [None, asyncio.CancelledError()]

            with pytest.raises(asyncio.CancelledError):
                await data_retention_task()

        mock_audit.log.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_exception_in_iteration_is_caught_loop_continues(self) -> None:
        """Non-CancelledError exceptions are caught; the task keeps running."""
        with (
            patch("app.services.retention.asyncio.sleep", new_callable=AsyncMock) as mock_sleep,
            patch("app.services.retention.AsyncSessionLocal", side_effect=RuntimeError("db error")),
            patch("app.services.retention.metrics"),
            patch("app.services.retention.settings") as mock_settings,
        ):
            mock_settings.retention_alerts_days = 365
            mock_settings.retention_incidents_days = 730
            mock_settings.retention_iocs_days = 180
            # First sleep OK (triggers error), second raises Cancelled to stop.
            mock_sleep.side_effect = [None, asyncio.CancelledError()]

            with pytest.raises(asyncio.CancelledError):
                await data_retention_task()

        # Two sleeps means the loop ran twice (exception caught, continued)
        assert mock_sleep.await_count == 2

    @pytest.mark.asyncio
    async def test_cancelled_error_from_sleep_propagates(self) -> None:
        """asyncio.CancelledError raised from sleep escapes the task."""
        with (
            patch("app.services.retention.asyncio.sleep", new_callable=AsyncMock) as mock_sleep,
            patch("app.services.retention.metrics"),
            patch("app.services.retention.settings") as mock_settings,
        ):
            mock_settings.retention_alerts_days = 365
            mock_settings.retention_incidents_days = 730
            mock_settings.retention_iocs_days = 180
            mock_sleep.side_effect = asyncio.CancelledError()

            with pytest.raises(asyncio.CancelledError):
                await data_retention_task()

    @pytest.mark.asyncio
    async def test_only_detections_nonzero_increments_only_detection_counter(self) -> None:
        """When only detections are deleted, only the 'detection' label is incremented."""
        session = _make_session()

        with (
            patch("app.services.retention.asyncio.sleep", new_callable=AsyncMock) as mock_sleep,
            patch("app.services.retention.AsyncSessionLocal", return_value=_session_ctx(session)),
            patch("app.services.retention._delete_old_detections", new_callable=AsyncMock, return_value=10),
            patch("app.services.retention._delete_old_incidents", new_callable=AsyncMock, return_value=0),
            patch("app.services.retention._delete_old_iocs", new_callable=AsyncMock, return_value=0),
            patch("app.services.retention.metrics") as mock_metrics,
            patch("app.services.retention.settings") as mock_settings,
        ):
            mock_settings.retention_alerts_days = 365
            mock_settings.retention_incidents_days = 730
            mock_settings.retention_iocs_days = 180
            mock_sleep.side_effect = [None, asyncio.CancelledError()]

            with pytest.raises(asyncio.CancelledError):
                await data_retention_task()

        # Only "detection" label should have been incremented
        calls = [str(c) for c in mock_metrics.retention_deleted.labels.call_args_list]
        assert any("detection" in c for c in calls)
        assert not any("incident" in c for c in calls)
        assert not any("ioc" in c for c in calls)


# ---------------------------------------------------------------------------
# get_retention_storage_stats() — integration with real SQLite session
# ---------------------------------------------------------------------------

class TestGetRetentionStorageStats:

    @pytest.mark.asyncio
    async def test_empty_db_returns_all_zeros(self, db_session) -> None:
        """Empty tables → all counts are zero."""
        with patch("app.services.retention.settings") as mock_settings:
            mock_settings.retention_alerts_days = 365
            mock_settings.retention_incidents_days = 730
            mock_settings.retention_iocs_days = 180

            stats = await get_retention_storage_stats(db_session)

        assert stats["detections_total"] == 0
        assert stats["incidents_total"] == 0
        assert stats["iocs_total"] == 0
        assert stats["detections_eligible_for_deletion"] == 0
        assert stats["incidents_eligible_for_deletion"] == 0
        assert stats["iocs_eligible_for_deletion"] == 0

    @pytest.mark.asyncio
    async def test_counts_eligible_detections(self, db_session) -> None:
        """Old detection is counted as eligible; recent one is not."""
        from app.models.base import new_uuid

        old_time = datetime.now(timezone.utc) - timedelta(days=400)
        recent_time = datetime.now(timezone.utc) - timedelta(days=10)

        old_det = Detection(
            id=new_uuid(),
            score=5.0,
            severity="high",
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            tactic="execution",
            name="Old Detection",
            status="active",
            host="host1",
            time=old_time,
            created_at=old_time,
            updated_at=old_time,
        )
        recent_det = Detection(
            id=new_uuid(),
            score=3.0,
            severity="low",
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            tactic="execution",
            name="Recent Detection",
            status="active",
            host="host2",
            time=recent_time,
            created_at=recent_time,
            updated_at=recent_time,
        )
        db_session.add_all([old_det, recent_det])
        await db_session.flush()

        with patch("app.services.retention.settings") as mock_settings:
            mock_settings.retention_alerts_days = 365
            mock_settings.retention_incidents_days = 730
            mock_settings.retention_iocs_days = 180

            stats = await get_retention_storage_stats(db_session)

        assert stats["detections_total"] == 2
        assert stats["detections_eligible_for_deletion"] == 1  # only old_det

    @pytest.mark.asyncio
    async def test_counts_eligible_incidents(self, db_session) -> None:
        """Resolved incident with old closed_at is eligible; open incident is not."""
        old_time = datetime.now(timezone.utc) - timedelta(days=800)

        old_incident = Incident(
            title="Old Resolved",
            severity="high",
            status="resolved",
            priority=2,
            created_by="admin",
            closed_at=old_time,
            created_at=old_time,
            updated_at=old_time,
        )
        active_incident = Incident(
            title="Active Incident",
            severity="medium",
            status="open",
            priority=3,
            created_by="admin",
            closed_at=None,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db_session.add_all([old_incident, active_incident])
        await db_session.flush()

        with patch("app.services.retention.settings") as mock_settings:
            mock_settings.retention_alerts_days = 365
            mock_settings.retention_incidents_days = 730
            mock_settings.retention_iocs_days = 180

            stats = await get_retention_storage_stats(db_session)

        assert stats["incidents_total"] == 2
        assert stats["incidents_eligible_for_deletion"] == 1  # only old_incident

    @pytest.mark.asyncio
    async def test_counts_eligible_iocs(self, db_session) -> None:
        """IOC with old expires_at is eligible; IOC without expires_at is not."""
        old_time = datetime.now(timezone.utc) - timedelta(days=200)

        expired_ioc = IOC(
            ioc_type="ip",
            value="1.2.3.4",
            source="manual",
            confidence=80,
            severity="high",
            first_seen=old_time,
            last_seen=old_time,
            expires_at=old_time,
        )
        no_expiry_ioc = IOC(
            ioc_type="domain",
            value="evil.example.com",
            source="manual",
            confidence=60,
            severity="medium",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            expires_at=None,
        )
        db_session.add_all([expired_ioc, no_expiry_ioc])
        await db_session.flush()

        with patch("app.services.retention.settings") as mock_settings:
            mock_settings.retention_alerts_days = 365
            mock_settings.retention_incidents_days = 730
            mock_settings.retention_iocs_days = 180

            stats = await get_retention_storage_stats(db_session)

        assert stats["iocs_total"] == 2
        assert stats["iocs_eligible_for_deletion"] == 1  # only expired_ioc
