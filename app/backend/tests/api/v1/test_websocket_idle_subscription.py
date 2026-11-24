"""The WebSocket alert subscriber on an idle Valkey subscription.

The asyncio Valkey client has a default socket timeout of 5 seconds, and the
blocking read of ``pubsub.listen()`` uses it.  With that default, a
subscription that receives no message for 5 seconds raises TimeoutError: the
subscriber logged "Valkey subscriber error, reconnecting in 1s" every few
seconds and missed alerts published while it reconnected.

These tests run the real client against a minimal in-process Valkey server
(RESP over TCP) that stays silent for longer than that default.
"""

from __future__ import annotations

import asyncio
import gc
import json
import logging
import weakref
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import app.main as main_module
from app.api.v1.endpoints.websocket import _CHANNEL, DistributedConnectionManager
from app.core.valkey import RULE_RELOAD_CHANNEL, SUBSCRIBER_OPTIONS

# Longer than the client's default socket timeout (5 s)
_IDLE_SECONDS = 5.6


class FakeValkeyServer:
    """Accepts connections, acknowledges SUBSCRIBE and pushes messages on demand."""

    def __init__(self) -> None:
        self.connections = 0
        self.subscribed = asyncio.Event()
        self._writers: dict[str, asyncio.StreamWriter] = {}
        self._server: asyncio.AbstractServer | None = None

    async def __aenter__(self) -> FakeValkeyServer:
        self._server = await asyncio.start_server(self._serve, "127.0.0.1", 0)
        return self

    async def __aexit__(self, *exc: object) -> None:
        for writer in self._writers.values():
            writer.close()
        self._server.close()
        await self._server.wait_closed()

    @property
    def url(self) -> str:
        port = self._server.sockets[0].getsockname()[1]
        return f"redis://127.0.0.1:{port}/0"

    @staticmethod
    def _bulk(*parts: str) -> bytes:
        out = f"*{len(parts)}\r\n"
        for part in parts:
            out += f"${len(part.encode())}\r\n{part}\r\n"
        return out.encode()

    async def _read_command(self, reader: asyncio.StreamReader) -> list[str] | None:
        header = await reader.readline()
        if not header.startswith(b"*"):
            return None
        args = []
        for _ in range(int(header[1:])):
            size = int((await reader.readline())[1:])
            args.append((await reader.readexactly(size + 2))[:-2].decode())
        return args

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.connections += 1
        try:
            while (command := await self._read_command(reader)) is not None:
                if command[0].upper() == "SUBSCRIBE":
                    channel = command[1]
                    self._writers[channel] = writer
                    # Reply: ["subscribe", channel, 1]
                    writer.write(b"*3" + self._bulk("subscribe", channel)[2:] + b":1\r\n")
                    self.subscribed.set()
                else:
                    writer.write(b"+OK\r\n")
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass

    async def publish(self, channel: str, payload: str) -> None:
        writer = self._writers[channel]
        writer.write(self._bulk("message", channel, payload))
        await writer.drain()


def test_subscriber_options_disable_the_read_timeout() -> None:
    assert SUBSCRIBER_OPTIONS["socket_timeout"] is None
    assert SUBSCRIBER_OPTIONS["decode_responses"] is True
    # Connecting is still bounded
    assert SUBSCRIBER_OPTIONS["socket_connect_timeout"]


@pytest.mark.asyncio
async def test_idle_subscription_stays_connected_and_delivers_alerts(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """No error on an idle subscription; an alert published afterwards is delivered."""
    alert = json.dumps({"type": "alert", "data": {"id": "after-idle"}})

    async with FakeValkeyServer() as server:
        manager = DistributedConnectionManager(server.url)
        delivered: list[str] = []

        async def capture(payload: str) -> None:
            delivered.append(payload)

        with (
            patch.object(manager, "_fanout_local", side_effect=capture),
            caplog.at_level(logging.INFO),
        ):
            await manager._ensure_subscriber()
            await asyncio.wait_for(server.subscribed.wait(), timeout=5)

            await asyncio.sleep(_IDLE_SECONDS)      # nothing is published
            assert "Valkey subscriber error" not in caplog.text
            assert server.connections == 1          # no reconnect

            await server.publish(_CHANNEL, alert)
            for _ in range(50):
                if delivered:
                    break
                await asyncio.sleep(0.02)
            await manager.shutdown()

    assert delivered == [alert]
    assert "Valkey subscriber error" not in caplog.text


@pytest.mark.asyncio
async def test_rule_reload_subscriber_survives_an_idle_subscription() -> None:
    """The rule-reload subscriber uses the same options and keeps listening when idle."""
    engine = MagicMock()
    reloaded = asyncio.Event()

    async def reload_from_db(_session: object) -> int:
        reloaded.set()
        return 3

    engine.reload_from_db = reload_from_db

    async with FakeValkeyServer() as server:
        with (
            patch.object(main_module.settings, "valkey_url", server.url),
            patch.object(main_module.app.state, "sigma_engine", engine, create=True),
        ):
            task = asyncio.create_task(main_module._rule_reload_subscriber())
            try:
                await asyncio.wait_for(server.subscribed.wait(), timeout=5)
                await asyncio.sleep(_IDLE_SECONDS)
                assert not task.done(), "the subscriber stopped on an idle subscription"

                await server.publish(RULE_RELOAD_CHANNEL, "reload")
                await asyncio.wait_for(reloaded.wait(), timeout=5)
            finally:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_background_tasks_are_referenced_until_done() -> None:
    """A task that waits without a timeout must not be garbage-collected mid-run.

    The event loop keeps only weak references to tasks.  The rule-reload
    subscriber, started without a reference, was destroyed while pending
    ("Task was destroyed but it is pending!") as soon as it had no read timeout.
    """
    release = asyncio.Event()

    async def wait_for_release() -> None:
        await release.wait()

    task = main_module._spawn(wait_for_release(), name="test-background-task")
    assert task in main_module._background_tasks

    release.set()
    await task
    await asyncio.sleep(0)
    assert task not in main_module._background_tasks


@pytest.mark.asyncio
async def test_spawned_rule_reload_subscriber_survives_garbage_collection() -> None:
    """The subscriber is still running after a garbage collection while it waits."""
    async with FakeValkeyServer() as server:
        with patch.object(main_module.settings, "valkey_url", server.url):
            # Only a weak reference here, like the event loop itself
            ref = weakref.ref(
                main_module._spawn(main_module._rule_reload_subscriber(), name="rule-reload-subscriber")
            )
            await asyncio.wait_for(server.subscribed.wait(), timeout=5)
            gc.collect()
            await asyncio.sleep(0.1)
            task = ref()
            try:
                assert task is not None, "the subscriber task was garbage-collected"
                assert not task.done()
            finally:
                if task is not None:
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_shutdown_cancels_background_tasks_and_clears_the_runtime_state() -> None:
    """After shutdown no background task runs and nothing can start on the stopped queue."""
    cancelled = asyncio.Event()

    async def run_forever() -> None:
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            cancelled.set()
            raise

    task = main_module._spawn(run_forever(), name="test-forever")
    await asyncio.sleep(0)
    queue = MagicMock(drain=AsyncMock(), stop=AsyncMock())
    with (
        patch.object(main_module.app.state, "queue", queue, create=True),
        patch.object(main_module.app.state, "connectors", {}, create=True),
        patch.object(main_module.app.state, "alert_mgr", None, create=True),
        patch.object(main_module.app.state, "os_client", None, create=True),
        patch.object(main_module.app.state, "syslog_receiver", None, create=True),
    ):
        await main_module.on_shutdown()
        assert main_module.app.state.queue is None
        assert main_module.app.state.connectors == {}

    queue.stop.assert_awaited_once()
    assert cancelled.is_set() and task.cancelled()
    assert not main_module._background_tasks
