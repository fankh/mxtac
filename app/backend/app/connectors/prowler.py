"""
Prowler connector — polls Prowler REST API for cloud security findings.

Supports AWS, Azure, and GCP providers.

Required config.extra keys:
  api_url: str          — Prowler API base URL (e.g. "https://prowler.example.com")
  api_key: str          — Prowler API key for authentication

Optional config.extra keys:
  providers: list[str]  — Filter by cloud providers (aws, azure, gcp).
                          Default: all providers (no filter).
  severity: list[str]   — Filter by severity (critical, high, medium, low, informational).
                          Default: all severities (no filter).
  status: list[str]     — Filter by finding status (FAIL, PASS, MANUAL).
                          Default: ["FAIL"] — only ingest failed checks.
  verify_ssl: bool      — Whether to verify SSL certificates. Default: True.
  timeout: int          — HTTP request timeout in seconds. Default: 30.

Feature 6.19: Prowler connector — cloud security findings.
  Polls the Prowler REST API every poll_interval_seconds and publishes
  new findings to the mxtac.raw.prowler topic.  Supports filtering by
  cloud provider (aws/azure/gcp), severity, and finding status.
  Checkpoint: the connector records the insertion timestamp of the most-recent
  poll cycle so that restarts do not re-ingest historical data.  The
  timestamp is persisted via checkpoint_callback (registry writes it to a
  JSON state file).
  Exponential backoff (1 s → 60 s cap) is applied after consecutive failures,
  matching the Wazuh connector pattern.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta, timezone
from typing import Any, AsyncGenerator

import httpx

from ..core.logging import get_logger
from ..pipeline.queue import Topic
from .base import BaseConnector, ConnectorConfig, ConnectorStatus

logger = get_logger(__name__)

DEFAULT_PAGE_SIZE = 100
BACKOFF_BASE = 1.0    # seconds — initial delay after a failure
BACKOFF_MAX  = 60.0   # seconds — maximum backoff delay


class ProwlerConnector(BaseConnector):
    """Polls Prowler REST API and publishes cloud security findings to mxtac.raw.prowler."""

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
        # Feature 6.19: restore persisted timestamp; default to 1 hour ago on fresh start
        self._last_fetched_at: datetime = (
            initial_last_fetched_at
            if initial_last_fetched_at is not None
            else datetime.now(timezone.utc) - timedelta(hours=1)
        )
        self._checkpoint_callback = checkpoint_callback
        self._backoff_delay: float = BACKOFF_BASE

    @property
    def topic(self) -> str:
        return Topic.RAW_PROWLER

    # ── Connection ────────────────────────────────────────────────────────────

    async def _connect(self) -> None:
        extra = self.config.extra
        api_url    = extra.get("api_url", "").rstrip("/")
        api_key    = extra.get("api_key", "")
        verify_ssl = extra.get("verify_ssl", True)
        timeout    = extra.get("timeout", 30)

        if not api_url:
            raise ConnectionError("Missing required config key: api_url")
        if not api_key:
            raise ConnectionError("Missing required config key: api_key")

        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=api_url,
                headers={"Authorization": f"Bearer {api_key}"},
                verify=verify_ssl,
                timeout=timeout,
                follow_redirects=True,
            )

        # Verify connectivity — lightweight health probe
        resp = await self._client.get("/api/v1/health")
        resp.raise_for_status()
        logger.info("ProwlerConnector authenticated url=%s", api_url)

    # ── Fetch ─────────────────────────────────────────────────────────────────

    async def _fetch_events(self) -> AsyncGenerator[dict[str, Any], None]:
        if self._client is None:
            return

        extra = self.config.extra

        # Build base query params
        params: dict[str, Any] = {
            "sort": "inserted_at",
            "page[size]": DEFAULT_PAGE_SIZE,
        }

        # Checkpoint filter — only fetch findings inserted since last poll
        since = self._last_fetched_at.strftime("%Y-%m-%dT%H:%M:%SZ")
        params["filter[inserted_at_gte]"] = since

        # Optional cloud provider filter (aws, azure, gcp)
        providers: list[str] = extra.get("providers", [])
        if providers:
            params["filter[provider]"] = ",".join(providers)

        # Optional severity filter
        severities: list[str] = extra.get("severity", [])
        if severities:
            params["filter[severity]"] = ",".join(severities)

        # Finding status filter — default to FAIL only
        statuses: list[str] = extra.get("status", ["FAIL"])
        if statuses:
            params["filter[status]"] = ",".join(statuses)

        page_number = 1
        while True:
            params["page[number]"] = page_number
            resp = await self._client.get("/api/v1/findings", params=params)
            resp.raise_for_status()

            data = resp.json()
            findings: list[dict[str, Any]] = data.get("data", [])

            for finding in findings:
                yield finding

            # Paginate using Prowler's JSON:API pagination metadata
            meta = data.get("meta", {})
            pagination = meta.get("pagination", {})
            total_pages = pagination.get("pages", 1)

            if page_number >= total_pages or not findings:
                break
            page_number += 1

        # Advance checkpoint to now after a successful full scan
        self._last_fetched_at = datetime.now(timezone.utc)
        if self._checkpoint_callback is not None:
            await self._checkpoint_callback(self._last_fetched_at)

    # ── Poll loop (exponential backoff) ───────────────────────────────────────

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
                    "ProwlerConnector fetch error name=%s err=%s backoff=%.1fs",
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

    # ── Cleanup ───────────────────────────────────────────────────────────────

    async def stop(self) -> None:
        await super().stop()
        if self._client is not None:
            await self._client.aclose()
            self._client = None
        logger.info("ProwlerConnector HTTP client closed name=%s", self.config.name)


class ProwlerConnectorFactory:
    """Convenience factory from a plain config dict."""

    @staticmethod
    def from_dict(d: dict[str, Any], queue) -> ProwlerConnector:
        config = ConnectorConfig(
            name=d.get("name", "prowler"),
            connector_type="prowler",
            enabled=d.get("enabled", True),
            poll_interval_seconds=d.get("poll_interval_seconds", 300),
            extra={
                "api_url":    d["api_url"],
                "api_key":    d["api_key"],
                "providers":  d.get("providers", []),
                "severity":   d.get("severity", []),
                "status":     d.get("status", ["FAIL"]),
                "verify_ssl": d.get("verify_ssl", True),
                "timeout":    d.get("timeout", 30),
            },
        )
        return ProwlerConnector(config, queue)
