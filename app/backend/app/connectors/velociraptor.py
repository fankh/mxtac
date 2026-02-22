"""
Velociraptor connector — polls Velociraptor REST API for forensic artifacts.

Velociraptor is an endpoint forensics and incident response platform.
This connector queries the Velociraptor server via its REST/gRPC HTTP frontend
using the VQL (Velociraptor Query Language) query endpoint.

Required config.extra keys:
  api_url: str       — Velociraptor server URL (e.g., "https://velociraptor:8889")
  api_key: str       — Velociraptor API token (from server.config.yaml or API config)

Optional config.extra keys:
  artifacts: list[str]  — Artifact names to collect results for
                          (e.g., ["Windows.System.Pslist", "Linux.Sys.Pslist"]).
                          If empty and no custom vql is set, recent flows metadata
                          is fetched using the default VQL template.
  vql: str              — Custom VQL query string (overrides artifacts when non-empty).
  page_size: int        — Max rows per artifact query. Default: 1000.
  verify_ssl: bool      — SSL certificate verification. Default: True.
  timeout: int          — HTTP request timeout in seconds. Default: 30.
  org_id: str           — Velociraptor org ID for multi-tenant deployments. Default: "".

Feature 6.23: Velociraptor connector — forensic artifacts.
  Polls the Velociraptor VQL endpoint every poll_interval_seconds and publishes
  forensic artifact results to the mxtac.raw.velociraptor topic.
  Supports configurable artifacts list, custom VQL, and timestamp-based
  checkpointing so restarts do not re-ingest historical data.
  The checkpoint timestamp is persisted via checkpoint_callback (registry writes
  it to a JSON state file on disk).
  Exponential backoff (1 s → 60 s cap) is applied after consecutive failures,
  matching the Prowler / OpenCTI connector pattern.

API note:
  The Velociraptor /api/v1/query endpoint returns a streaming NDJSON response.
  Each line is a JSON object where the ``Response`` field contains a
  JSON-encoded array of result rows, and ``log`` fields contain server-side
  log messages (which are skipped).
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta, timezone
from typing import Any, AsyncGenerator

import httpx

from ..core.logging import get_logger
from ..pipeline.queue import Topic
from .base import BaseConnector, ConnectorConfig, ConnectorStatus

logger = get_logger(__name__)

DEFAULT_PAGE_SIZE = 1000
BACKOFF_BASE = 1.0    # seconds — initial delay after a failure
BACKOFF_MAX  = 60.0   # seconds — maximum backoff delay

# VQL template for fetching recent flow metadata when no artifacts are configured
_DEFAULT_VQL_TEMPLATE = (
    "SELECT client_id, flow_id, create_time, artifacts, state "
    "FROM flows() "
    "WHERE create_time > TIMESTAMP(epoch={since_epoch}) "
    "LIMIT {page_size}"
)

# VQL template for collecting results from a specific named artifact
_ARTIFACT_VQL_TEMPLATE = (
    "SELECT *, '{artifact}' AS _artifact_name "
    "FROM source(artifact='{artifact}', start_time=TIMESTAMP(epoch={since_epoch})) "
    "LIMIT {page_size}"
)

# VQL health probe — trivial query that succeeds on any live server
_HEALTH_VQL = "SELECT version() AS version FROM scope()"


class VelociraptorConnector(BaseConnector):
    """Polls Velociraptor REST API and publishes forensic artifact results to mxtac.raw.velociraptor."""

    def __init__(
        self,
        config: ConnectorConfig,
        queue,
        *,
        initial_last_fetched_at: datetime | None = None,
        checkpoint_callback: Callable[[datetime], Awaitable[None]] | None = None,
        status_callback: Callable[[str, str | None], Awaitable[None]] | None = None,
    ) -> None:
        super().__init__(config, queue, status_callback=status_callback)
        self._client: httpx.AsyncClient | None = None
        # Feature 6.23: restore persisted timestamp; default to 1 hour ago on fresh start
        self._last_fetched_at: datetime = (
            initial_last_fetched_at
            if initial_last_fetched_at is not None
            else datetime.now(timezone.utc) - timedelta(hours=1)
        )
        self._checkpoint_callback = checkpoint_callback
        self._backoff_delay: float = BACKOFF_BASE

    @property
    def topic(self) -> str:
        return Topic.RAW_VELOCIRAPTOR

    # ── Connection ─────────────────────────────────────────────────────────────

    async def _connect(self) -> None:
        extra = self.config.extra
        api_url    = extra.get("api_url", "").rstrip("/")
        api_key    = extra.get("api_key", "")
        verify_ssl = extra.get("verify_ssl", True)
        timeout    = extra.get("timeout", 30)
        org_id     = extra.get("org_id", "")

        if not api_url:
            raise ConnectionError("Missing required config key: api_url")
        if not api_key:
            raise ConnectionError("Missing required config key: api_key")

        headers: dict[str, str] = {
            "Grpc-Metadata-Api-Token": api_key,
            "Content-Type": "application/json",
        }
        if org_id:
            headers["Grpc-Metadata-Velociraptor-Org-Id"] = org_id

        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=api_url,
                headers=headers,
                verify=verify_ssl,
                timeout=timeout,
                follow_redirects=True,
            )

        # Health probe — run a trivial VQL query to verify connectivity and auth
        rows: list[dict[str, Any]] = []
        async for row in self._run_vql(_HEALTH_VQL):
            rows.append(row)

        if not rows:
            raise ConnectionError(
                "Velociraptor API returned no response to health probe — "
                "check api_url and api_key configuration"
            )

        logger.info(
            "VelociraptorConnector authenticated url=%s version=%s",
            api_url,
            rows[0].get("version", "unknown"),
        )

    # ── Fetch ──────────────────────────────────────────────────────────────────

    async def _fetch_events(self) -> AsyncGenerator[dict[str, Any], None]:
        if self._client is None:
            return

        extra = self.config.extra
        artifacts: list[str] = extra.get("artifacts", [])
        custom_vql: str      = extra.get("vql", "")
        page_size: int       = extra.get("page_size", DEFAULT_PAGE_SIZE)

        since_epoch = int(self._last_fetched_at.timestamp())

        if custom_vql:
            vql_queries = [custom_vql]
        elif artifacts:
            vql_queries = [
                _ARTIFACT_VQL_TEMPLATE.format(
                    artifact=artifact,
                    since_epoch=since_epoch,
                    page_size=page_size,
                )
                for artifact in artifacts
            ]
        else:
            vql_queries = [
                _DEFAULT_VQL_TEMPLATE.format(
                    since_epoch=since_epoch,
                    page_size=page_size,
                )
            ]

        for vql in vql_queries:
            async for event in self._run_vql(vql):
                yield event

        # Advance checkpoint to now after a complete successful scan
        self._last_fetched_at = datetime.now(timezone.utc)
        if self._checkpoint_callback is not None:
            await self._checkpoint_callback(self._last_fetched_at)

    # ── VQL execution ──────────────────────────────────────────────────────────

    async def _run_vql(self, vql: str) -> AsyncGenerator[dict[str, Any], None]:
        """Execute a VQL query and yield result rows.

        Velociraptor's /api/v1/query endpoint returns a streaming NDJSON response.
        Each line is a JSON object where the ``Response`` field contains a
        JSON-encoded array of result rows.  Lines with only a ``log`` field are
        server-side log messages and are silently skipped.  Lines with an ``error``
        field raise RuntimeError.
        """
        if self._client is None:
            return

        body = {"query": [{"name": "mxtac_poll", "vql": vql}]}

        async with self._client.stream("POST", "/api/v1/query", json=body) as resp:
            resp.raise_for_status()
            async for line in resp.aiter_lines():
                line = line.strip()
                if not line:
                    continue

                try:
                    packet = json.loads(line)
                except json.JSONDecodeError:
                    logger.debug(
                        "VelociraptorConnector: skipping non-JSON line name=%s",
                        self.config.name,
                    )
                    continue

                # Server-side error packet
                error = packet.get("error") or packet.get("Error")
                if error:
                    raise RuntimeError(f"Velociraptor VQL error: {error}")

                # Log / metadata packets have no Response field — skip them
                raw_response = packet.get("Response", "")
                if not raw_response:
                    continue

                try:
                    rows = json.loads(raw_response)
                except json.JSONDecodeError:
                    logger.warning(
                        "VelociraptorConnector: failed to parse Response JSON name=%s",
                        self.config.name,
                    )
                    continue

                for row in rows:
                    if isinstance(row, dict) and row:
                        row["_source"] = "velociraptor"
                        yield row

    # ── Poll loop (exponential backoff) ────────────────────────────────────────

    async def _poll_loop(self) -> None:
        """Poll loop with exponential backoff on failure.

        A successful fetch cycle resets the backoff to BACKOFF_BASE.
        A failed cycle sleeps for the current _backoff_delay, then doubles it
        (capped at BACKOFF_MAX), before the next attempt.  The normal
        poll_interval_seconds sleep is only applied after a *successful* cycle.
        """
        while not self._stop_event.is_set():
            try:
                async for event in self._fetch_events():
                    await self.queue.publish(self.topic, event)
                    self.health.events_total += 1
                    self.health.last_event_at = datetime.now(timezone.utc)
                # Success — reset backoff to base
                self._backoff_delay = BACKOFF_BASE
                await self._update_db_status(ConnectorStatus.ACTIVE.value)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                self.health.errors_total += 1
                self.health.error_message = str(exc)
                logger.error(
                    "VelociraptorConnector fetch error name=%s err=%s backoff=%.1fs",
                    self.config.name,
                    exc,
                    self._backoff_delay,
                )
                await self._update_db_status(ConnectorStatus.ERROR.value, str(exc))
                try:
                    await asyncio.wait_for(
                        asyncio.shield(self._stop_event.wait()),
                        timeout=self._backoff_delay,
                    )
                except asyncio.TimeoutError:
                    pass
                # Increase backoff, capped at maximum
                self._backoff_delay = min(self._backoff_delay * 2, BACKOFF_MAX)
                continue  # skip the normal inter-poll sleep

            # Normal inter-poll sleep (success path only)
            try:
                await asyncio.wait_for(
                    asyncio.shield(self._stop_event.wait()),
                    timeout=self.config.poll_interval_seconds,
                )
            except asyncio.TimeoutError:
                pass

    # ── Cleanup ────────────────────────────────────────────────────────────────

    async def stop(self) -> None:
        await super().stop()
        if self._client is not None:
            await self._client.aclose()
            self._client = None
        logger.info("VelociraptorConnector HTTP client closed name=%s", self.config.name)


class VelociraptorConnectorFactory:
    """Convenience factory from a plain config dict."""

    @staticmethod
    def from_dict(d: dict[str, Any], queue) -> VelociraptorConnector:
        config = ConnectorConfig(
            name=d.get("name", "velociraptor"),
            connector_type="velociraptor",
            enabled=d.get("enabled", True),
            poll_interval_seconds=d.get("poll_interval_seconds", 300),
            extra={
                "api_url":    d["api_url"],
                "api_key":    d["api_key"],
                "artifacts":  d.get("artifacts", []),
                "vql":        d.get("vql", ""),
                "page_size":  d.get("page_size", DEFAULT_PAGE_SIZE),
                "verify_ssl": d.get("verify_ssl", True),
                "timeout":    d.get("timeout", 30),
                "org_id":     d.get("org_id", ""),
            },
        )
        return VelociraptorConnector(config, queue)
