"""
Tests for feature 5.6 / 12.11: Pipeline and OpenSearch wired in main.py startup/shutdown.

Coverage:
  - Startup initialises connectors and alert_mgr state before any external calls
  - Startup sets app.state.queue to the MessageQueue singleton
  - Startup sets app.state.os_client to the OpenSearchService singleton
  - Startup calls os_client.connect() during initialisation  [12.11]
  - Startup calls os_client.ensure_indices() after connect() [12.11]
  - Shutdown calls queue.stop() when queue is present
  - Shutdown calls alert_mgr.close() when alert_mgr is present
  - Shutdown calls os_client.close() when os_client is present
  - Shutdown calls conn.stop() for each connector
  - Shutdown is resilient when state attributes are missing
  - Shutdown continues past a failing connector stop
  - Shutdown continues past a failing queue stop
  - Shutdown continues past a failing alert_mgr close
  - Shutdown continues past a failing os_client close
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.main import app, on_shutdown, on_startup
from app.pipeline.queue import InMemoryQueue, MessageQueue


# ── Startup: state initialisation ────────────────────────────────────────────


class TestStartupStateInit:
    async def test_startup_sets_connectors_to_empty_list_by_default(self) -> None:
        """When DB has no enabled connectors, app.state.connectors is an empty dict."""
        with (
            patch("app.main.seed_database", new_callable=AsyncMock),
            patch("app.main.AsyncSessionLocal") as mock_session_cm,
            patch("app.main.get_opensearch") as mock_get_os,
            patch("app.main.get_queue") as mock_get_queue,
        ):
            # Set up mock queue
            mock_queue = AsyncMock(spec=MessageQueue)
            mock_queue.subscribe = AsyncMock()
            mock_get_queue.return_value = mock_queue

            # Set up mock OpenSearch
            mock_os = AsyncMock()
            mock_get_os.return_value = mock_os

            # Set up mock DB session (no connectors)
            mock_session = AsyncMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=False)
            mock_session.execute = AsyncMock(return_value=MagicMock(scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))))
            mock_session_cm.return_value = mock_session

            await on_startup()

        assert isinstance(app.state.connectors, dict)

    async def test_startup_sets_queue_on_app_state(self) -> None:
        """app.state.queue is set to the queue returned by get_queue()."""
        with (
            patch("app.main.seed_database", new_callable=AsyncMock),
            patch("app.main.AsyncSessionLocal") as mock_session_cm,
            patch("app.main.get_opensearch") as mock_get_os,
            patch("app.main.get_queue") as mock_get_queue,
        ):
            mock_queue = AsyncMock(spec=MessageQueue)
            mock_queue.subscribe = AsyncMock()
            mock_get_queue.return_value = mock_queue

            mock_os = AsyncMock()
            mock_get_os.return_value = mock_os

            mock_session = AsyncMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=False)
            mock_session.execute = AsyncMock(return_value=MagicMock(scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))))
            mock_session_cm.return_value = mock_session

            await on_startup()

        assert app.state.queue is mock_queue

    async def test_startup_sets_os_client_on_app_state(self) -> None:
        """app.state.os_client is set to the client returned by get_opensearch()."""
        with (
            patch("app.main.seed_database", new_callable=AsyncMock),
            patch("app.main.AsyncSessionLocal") as mock_session_cm,
            patch("app.main.get_opensearch") as mock_get_os,
            patch("app.main.get_queue") as mock_get_queue,
        ):
            mock_queue = AsyncMock(spec=MessageQueue)
            mock_queue.subscribe = AsyncMock()
            mock_get_queue.return_value = mock_queue

            mock_os = AsyncMock()
            mock_get_os.return_value = mock_os

            mock_session = AsyncMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=False)
            mock_session.execute = AsyncMock(return_value=MagicMock(scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))))
            mock_session_cm.return_value = mock_session

            await on_startup()

        assert app.state.os_client is mock_os

    async def test_startup_calls_queue_start(self) -> None:
        """queue.start() is awaited exactly once during startup."""
        with (
            patch("app.main.seed_database", new_callable=AsyncMock),
            patch("app.main.AsyncSessionLocal") as mock_session_cm,
            patch("app.main.get_opensearch") as mock_get_os,
            patch("app.main.get_queue") as mock_get_queue,
        ):
            mock_queue = AsyncMock(spec=MessageQueue)
            mock_queue.subscribe = AsyncMock()
            mock_get_queue.return_value = mock_queue

            mock_os = AsyncMock()
            mock_get_os.return_value = mock_os

            mock_session = AsyncMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=False)
            mock_session.execute = AsyncMock(return_value=MagicMock(scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))))
            mock_session_cm.return_value = mock_session

            await on_startup()

        mock_queue.start.assert_called_once()

    async def test_startup_calls_opensearch_connect(self) -> None:
        """os_client.connect() is awaited during startup."""
        with (
            patch("app.main.seed_database", new_callable=AsyncMock),
            patch("app.main.AsyncSessionLocal") as mock_session_cm,
            patch("app.main.get_opensearch") as mock_get_os,
            patch("app.main.get_queue") as mock_get_queue,
        ):
            mock_queue = AsyncMock(spec=MessageQueue)
            mock_queue.subscribe = AsyncMock()
            mock_get_queue.return_value = mock_queue

            mock_os = AsyncMock()
            mock_get_os.return_value = mock_os

            mock_session = AsyncMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=False)
            mock_session.execute = AsyncMock(return_value=MagicMock(scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))))
            mock_session_cm.return_value = mock_session

            await on_startup()

        mock_os.connect.assert_called_once()

    async def test_startup_calls_ensure_indices(self) -> None:
        """os_client.ensure_indices() is awaited after connect() during startup."""
        with (
            patch("app.main.seed_database", new_callable=AsyncMock),
            patch("app.main.AsyncSessionLocal") as mock_session_cm,
            patch("app.main.get_opensearch") as mock_get_os,
            patch("app.main.get_queue") as mock_get_queue,
        ):
            mock_queue = AsyncMock(spec=MessageQueue)
            mock_queue.subscribe = AsyncMock()
            mock_get_queue.return_value = mock_queue

            mock_os = AsyncMock()
            mock_get_os.return_value = mock_os

            mock_session = AsyncMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=False)
            mock_session.execute = AsyncMock(return_value=MagicMock(scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))))
            mock_session_cm.return_value = mock_session

            await on_startup()

        mock_os.ensure_indices.assert_called_once()

    async def test_startup_ensure_indices_called_after_connect(self) -> None:
        """ensure_indices() is always called after connect() — ordering matters."""
        call_order: list[str] = []

        with (
            patch("app.main.seed_database", new_callable=AsyncMock),
            patch("app.main.AsyncSessionLocal") as mock_session_cm,
            patch("app.main.get_opensearch") as mock_get_os,
            patch("app.main.get_queue") as mock_get_queue,
        ):
            mock_queue = AsyncMock(spec=MessageQueue)
            mock_queue.subscribe = AsyncMock()
            mock_get_queue.return_value = mock_queue

            mock_os = AsyncMock()
            mock_os.connect = AsyncMock(side_effect=lambda: call_order.append("connect"))
            mock_os.ensure_indices = AsyncMock(side_effect=lambda: call_order.append("ensure_indices"))
            mock_get_os.return_value = mock_os

            mock_session = AsyncMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=False)
            mock_session.execute = AsyncMock(return_value=MagicMock(scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))))
            mock_session_cm.return_value = mock_session

            await on_startup()

        assert call_order.index("connect") < call_order.index("ensure_indices")


# ── Shutdown: cleanup orchestration ───────────────────────────────────────────


class TestShutdownCleanup:
    async def test_shutdown_calls_queue_stop(self) -> None:
        """Shutdown calls queue.stop() to cancel all consumer tasks."""
        mock_queue = AsyncMock()
        app.state.queue = mock_queue
        app.state.alert_mgr = None
        app.state.os_client = None
        app.state.connectors = {}

        await on_shutdown()

        mock_queue.stop.assert_called_once()

    async def test_shutdown_calls_alert_mgr_close(self) -> None:
        """Shutdown calls alert_mgr.close() to release Valkey connection."""
        mock_queue = AsyncMock()
        mock_alert_mgr = AsyncMock()
        app.state.queue = mock_queue
        app.state.alert_mgr = mock_alert_mgr
        app.state.os_client = None
        app.state.connectors = {}

        await on_shutdown()

        mock_alert_mgr.close.assert_called_once()

    async def test_shutdown_calls_os_client_close(self) -> None:
        """Shutdown calls os_client.close() to release OpenSearch connection."""
        mock_queue = AsyncMock()
        mock_os = AsyncMock()
        app.state.queue = mock_queue
        app.state.alert_mgr = None
        app.state.os_client = mock_os
        app.state.connectors = {}

        await on_shutdown()

        mock_os.close.assert_called_once()

    async def test_shutdown_calls_stop_on_each_connector(self) -> None:
        """Shutdown calls stop() on every connector in app.state.connectors."""
        mock_queue = AsyncMock()
        conn_a = AsyncMock()
        conn_a.config = MagicMock()
        conn_a.config.name = "wazuh-prod"
        conn_b = AsyncMock()
        conn_b.config = MagicMock()
        conn_b.config.name = "zeek-prod"

        app.state.queue = mock_queue
        app.state.alert_mgr = None
        app.state.os_client = None
        app.state.connectors = {"id-a": conn_a, "id-b": conn_b}

        await on_shutdown()

        conn_a.stop.assert_called_once()
        conn_b.stop.assert_called_once()

    async def test_shutdown_skips_queue_stop_when_queue_is_none(self) -> None:
        """If queue was never set or is None, shutdown does not raise."""
        app.state.queue = None
        app.state.alert_mgr = None
        app.state.os_client = None
        app.state.connectors = {}

        await on_shutdown()  # must not raise

    async def test_shutdown_skips_alert_mgr_close_when_none(self) -> None:
        """If AlertManager failed to init (None), shutdown does not raise."""
        mock_queue = AsyncMock()
        app.state.queue = mock_queue
        app.state.alert_mgr = None
        app.state.os_client = None
        app.state.connectors = {}

        await on_shutdown()  # must not raise

    async def test_shutdown_skips_os_close_when_none(self) -> None:
        """If OpenSearch client is None, shutdown does not raise."""
        mock_queue = AsyncMock()
        app.state.queue = mock_queue
        app.state.alert_mgr = None
        app.state.os_client = None
        app.state.connectors = {}

        await on_shutdown()  # must not raise

    async def test_shutdown_is_resilient_to_missing_state_attributes(self) -> None:
        """If state attributes were never set (e.g. startup crashed), shutdown must not raise."""
        # Wipe all relevant attributes
        for attr in ("queue", "alert_mgr", "os_client", "connectors"):
            try:
                delattr(app.state, attr)
            except AttributeError:
                pass

        await on_shutdown()  # must not raise

    async def test_shutdown_continues_after_connector_stop_failure(self) -> None:
        """A connector that raises on stop() must not prevent subsequent cleanup."""
        mock_queue = AsyncMock()
        mock_os = AsyncMock()

        bad_conn = AsyncMock()
        bad_conn.config = MagicMock()
        bad_conn.config.name = "bad-connector"
        bad_conn.stop.side_effect = RuntimeError("connection reset")

        app.state.queue = mock_queue
        app.state.alert_mgr = None
        app.state.os_client = mock_os
        app.state.connectors = {"id-bad": bad_conn}

        await on_shutdown()

        # Despite connector failure, queue and opensearch must still be cleaned up
        mock_queue.stop.assert_called_once()
        mock_os.close.assert_called_once()

    async def test_shutdown_continues_after_queue_stop_failure(self) -> None:
        """A queue.stop() exception must not prevent AlertManager and OpenSearch cleanup."""
        mock_queue = AsyncMock()
        mock_queue.stop.side_effect = RuntimeError("queue error")
        mock_alert_mgr = AsyncMock()
        mock_os = AsyncMock()

        app.state.queue = mock_queue
        app.state.alert_mgr = mock_alert_mgr
        app.state.os_client = mock_os
        app.state.connectors = {}

        await on_shutdown()

        mock_alert_mgr.close.assert_called_once()
        mock_os.close.assert_called_once()

    async def test_shutdown_continues_after_alert_mgr_close_failure(self) -> None:
        """An alert_mgr.close() exception must not prevent OpenSearch cleanup."""
        mock_queue = AsyncMock()
        mock_alert_mgr = AsyncMock()
        mock_alert_mgr.close.side_effect = RuntimeError("valkey gone")
        mock_os = AsyncMock()

        app.state.queue = mock_queue
        app.state.alert_mgr = mock_alert_mgr
        app.state.os_client = mock_os
        app.state.connectors = {}

        await on_shutdown()

        mock_os.close.assert_called_once()

    async def test_shutdown_calls_drain_before_stop(self) -> None:
        """Shutdown drains the queue before stopping it (feature 5.7)."""
        call_order: list[str] = []

        mock_queue = AsyncMock()
        mock_queue.drain = AsyncMock(side_effect=lambda: call_order.append("queue.drain"))
        mock_queue.stop = AsyncMock(side_effect=lambda: call_order.append("queue.stop"))

        app.state.queue = mock_queue
        app.state.alert_mgr = None
        app.state.os_client = None
        app.state.connectors = {}

        await on_shutdown()

        assert "queue.drain" in call_order
        assert "queue.stop" in call_order
        assert call_order.index("queue.drain") < call_order.index("queue.stop")

    async def test_shutdown_full_pipeline_cleanup_order(self) -> None:
        """All cleanup calls happen: connectors → drain → queue.stop → alert_mgr → os_client."""
        call_order: list[str] = []

        mock_queue = AsyncMock()
        mock_queue.drain = AsyncMock(side_effect=lambda: call_order.append("queue.drain"))
        mock_queue.stop = AsyncMock(side_effect=lambda: call_order.append("queue.stop"))

        mock_alert_mgr = AsyncMock()
        mock_alert_mgr.close = AsyncMock(side_effect=lambda: call_order.append("alert_mgr.close"))

        mock_os = AsyncMock()
        mock_os.close = AsyncMock(side_effect=lambda: call_order.append("os.close"))

        conn = AsyncMock()
        conn.config = MagicMock()
        conn.config.name = "wazuh"
        conn.stop = AsyncMock(side_effect=lambda: call_order.append("conn.stop"))

        app.state.queue = mock_queue
        app.state.alert_mgr = mock_alert_mgr
        app.state.os_client = mock_os
        app.state.connectors = {"id-conn": conn}

        await on_shutdown()

        assert call_order == ["conn.stop", "queue.drain", "queue.stop", "alert_mgr.close", "os.close"]

    async def test_shutdown_drain_failure_does_not_prevent_stop(self) -> None:
        """A drain() failure must not prevent queue.stop() from being called."""
        mock_queue = AsyncMock()
        mock_queue.drain.side_effect = RuntimeError("drain error")
        mock_os = AsyncMock()

        app.state.queue = mock_queue
        app.state.alert_mgr = None
        app.state.os_client = mock_os
        app.state.connectors = {}

        await on_shutdown()

        mock_queue.stop.assert_called_once()
        mock_os.close.assert_called_once()


# ── Integration: pipeline subscription wiring ─────────────────────────────────


class TestPipelineSubscriptionWiring:
    async def test_startup_subscribes_normalizer_to_raw_topics(self) -> None:
        """NormalizerPipeline.start() is awaited, which subscribes to raw topics."""
        with (
            patch("app.main.seed_database", new_callable=AsyncMock),
            patch("app.main.AsyncSessionLocal") as mock_session_cm,
            patch("app.main.get_opensearch") as mock_get_os,
            patch("app.main.get_queue") as mock_get_queue,
        ):
            # Use a real InMemoryQueue so subscribe() actually works
            queue = InMemoryQueue()
            await queue.start()
            mock_get_queue.return_value = queue

            mock_os = AsyncMock()
            mock_get_os.return_value = mock_os

            mock_session = AsyncMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=False)
            mock_session.execute = AsyncMock(return_value=MagicMock(scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))))
            mock_session_cm.return_value = mock_session

            await on_startup()

            # Normalizer subscribes to 3 raw topics, sigma to 1, alert_mgr to 1,
            # ws_broadcaster to 1 — total ≥ 5 consumer tasks in the queue
            assert len(queue._tasks) >= 5

            await queue.stop()

    async def test_startup_subscribes_alert_manager_to_alerts_topic(self) -> None:
        """After startup, the queue has a consumer for the mxtac.alerts topic."""
        with (
            patch("app.main.seed_database", new_callable=AsyncMock),
            patch("app.main.AsyncSessionLocal") as mock_session_cm,
            patch("app.main.get_opensearch") as mock_get_os,
            patch("app.main.get_queue") as mock_get_queue,
        ):
            queue = InMemoryQueue()
            await queue.start()
            mock_get_queue.return_value = queue

            mock_os = AsyncMock()
            mock_get_os.return_value = mock_os

            mock_session = AsyncMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=False)
            mock_session.execute = AsyncMock(return_value=MagicMock(scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))))
            mock_session_cm.return_value = mock_session

            await on_startup()

            task_names = {t.get_name() for t in queue._tasks}
            assert any("alert-manager" in name for name in task_names)

            await queue.stop()

    async def test_startup_subscribes_ws_broadcaster_to_enriched_topic(self) -> None:
        """After startup, the queue has a consumer for the mxtac.enriched topic."""
        with (
            patch("app.main.seed_database", new_callable=AsyncMock),
            patch("app.main.AsyncSessionLocal") as mock_session_cm,
            patch("app.main.get_opensearch") as mock_get_os,
            patch("app.main.get_queue") as mock_get_queue,
        ):
            queue = InMemoryQueue()
            await queue.start()
            mock_get_queue.return_value = queue

            mock_os = AsyncMock()
            mock_get_os.return_value = mock_os

            mock_session = AsyncMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=False)
            mock_session.execute = AsyncMock(return_value=MagicMock(scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))))
            mock_session_cm.return_value = mock_session

            await on_startup()

            task_names = {t.get_name() for t in queue._tasks}
            assert any("ws-broadcaster" in name for name in task_names)

            await queue.stop()
