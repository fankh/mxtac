"""
OpenCTI connector — polls OpenCTI GraphQL API for threat intelligence objects.

Supports Indicators, Malware, Threat Actors, Campaigns, Attack Patterns,
and Vulnerabilities.

Required config.extra keys:
  api_url: str         — OpenCTI base URL (e.g. "https://opencti.example.com")
  api_token: str       — OpenCTI API token for authentication

Optional config.extra keys:
  object_types: list[str]  — Filter by entity type
                             (e.g. ["Indicator", "Malware", "ThreatActor"]).
                             Default: all types (no filter).
  page_size: int           — Number of objects per GraphQL page. Default: 100.
  verify_ssl: bool         — Whether to verify SSL certificates. Default: True.
  timeout: int             — HTTP request timeout in seconds. Default: 30.

Feature 6.20: OpenCTI connector — threat intelligence feed.
  Polls the OpenCTI GraphQL API every poll_interval_seconds and publishes
  new / updated threat intelligence objects to the mxtac.raw.opencti topic.
  Supports filtering by entity type (Indicator, Malware, ThreatActor, etc.).
  Checkpoint: the connector records the timestamp of the most-recent
  poll cycle so that restarts do not re-ingest historical data.  The
  timestamp is persisted via checkpoint_callback (registry writes it to a
  JSON state file).
  Exponential backoff (1 s → 60 s cap) is applied after consecutive failures,
  matching the Prowler connector pattern.
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

# GraphQL query to probe API health
_HEALTH_QUERY = "{ about { version } }"

# GraphQL query to fetch STIX core objects with cursor pagination and timestamp filter
_OBJECTS_QUERY = """
query GetThreatIntelObjects($first: Int!, $after: ID, $filters: FilterGroup) {
  stixCoreObjects(first: $first, after: $after, filters: $filters) {
    pageInfo {
      hasNextPage
      endCursor
    }
    edges {
      node {
        id
        entity_type
        standard_id
        created_at
        updated_at
        ... on Indicator {
          name
          description
          pattern
          pattern_type
          valid_from
          valid_until
          x_opencti_score
        }
        ... on Malware {
          name
          description
          malware_types
          is_family
        }
        ... on ThreatActor {
          name
          description
          threat_actor_types
          sophistication
        }
        ... on Campaign {
          name
          description
          first_seen
          last_seen
        }
        ... on AttackPattern {
          name
          description
          x_mitre_id
          kill_chain_phases {
            kill_chain_name
            phase_name
          }
        }
        ... on Vulnerability {
          name
          description
          x_opencti_cvss_base_score
          x_opencti_cvss_base_severity
        }
      }
    }
  }
}
"""


class OpenCTIConnector(BaseConnector):
    """Polls OpenCTI GraphQL API and publishes threat intelligence objects to mxtac.raw.opencti."""

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
        # Feature 6.20: restore persisted timestamp; default to 1 hour ago on fresh start
        self._last_fetched_at: datetime = (
            initial_last_fetched_at
            if initial_last_fetched_at is not None
            else datetime.now(timezone.utc) - timedelta(hours=1)
        )
        self._checkpoint_callback = checkpoint_callback
        self._backoff_delay: float = BACKOFF_BASE

    @property
    def topic(self) -> str:
        return Topic.RAW_OPENCTI

    # ── Connection ────────────────────────────────────────────────────────────

    async def _connect(self) -> None:
        extra = self.config.extra
        api_url    = extra.get("api_url", "").rstrip("/")
        api_token  = extra.get("api_token", "")
        verify_ssl = extra.get("verify_ssl", True)
        timeout    = extra.get("timeout", 30)

        if not api_url:
            raise ConnectionError("Missing required config key: api_url")
        if not api_token:
            raise ConnectionError("Missing required config key: api_token")

        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=api_url,
                headers={
                    "Authorization": f"Bearer {api_token}",
                    "Content-Type": "application/json",
                },
                verify=verify_ssl,
                timeout=timeout,
                follow_redirects=True,
            )

        # Verify connectivity — lightweight GraphQL health probe
        resp = await self._client.post(
            "/graphql",
            json={"query": _HEALTH_QUERY},
        )
        resp.raise_for_status()
        data = resp.json()
        if "errors" in data:
            raise ConnectionError(f"OpenCTI GraphQL error: {data['errors']}")
        logger.info("OpenCTIConnector authenticated url=%s", api_url)

    # ── Fetch ─────────────────────────────────────────────────────────────────

    async def _fetch_events(self) -> AsyncGenerator[dict[str, Any], None]:
        if self._client is None:
            return

        extra = self.config.extra
        page_size: int = extra.get("page_size", DEFAULT_PAGE_SIZE)

        # Build filter group — always filter by updated_at >= checkpoint
        since = self._last_fetched_at.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        filters: dict[str, Any] = {
            "mode": "and",
            "filterGroups": [],
            "filters": [
                {
                    "key": "updated_at",
                    "operator": "gte",
                    "values": [since],
                    "mode": "or",
                }
            ],
        }

        # Optional entity_type filter
        object_types: list[str] = extra.get("object_types", [])
        if object_types:
            filters["filters"].append(
                {
                    "key": "entity_type",
                    "operator": "eq",
                    "values": object_types,
                    "mode": "or",
                }
            )

        cursor: str | None = None
        while True:
            variables: dict[str, Any] = {"first": page_size, "filters": filters}
            if cursor is not None:
                variables["after"] = cursor

            resp = await self._client.post(
                "/graphql",
                json={"query": _OBJECTS_QUERY, "variables": variables},
            )
            resp.raise_for_status()
            data = resp.json()
            if "errors" in data:
                raise RuntimeError(f"OpenCTI GraphQL error: {data['errors']}")

            result = data.get("data", {}).get("stixCoreObjects", {})
            edges = result.get("edges", [])
            page_info = result.get("pageInfo", {})

            for edge in edges:
                node = edge.get("node", {})
                if node:
                    yield node

            has_next_page = page_info.get("hasNextPage", False)
            cursor = page_info.get("endCursor")

            if not has_next_page or not edges or not cursor:
                break

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
                    "OpenCTIConnector fetch error name=%s err=%s backoff=%.1fs",
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
        logger.info("OpenCTIConnector HTTP client closed name=%s", self.config.name)


class OpenCTIConnectorFactory:
    """Convenience factory from a plain config dict."""

    @staticmethod
    def from_dict(d: dict[str, Any], queue) -> OpenCTIConnector:
        config = ConnectorConfig(
            name=d.get("name", "opencti"),
            connector_type="opencti",
            enabled=d.get("enabled", True),
            poll_interval_seconds=d.get("poll_interval_seconds", 300),
            extra={
                "api_url":      d["api_url"],
                "api_token":    d["api_token"],
                "object_types": d.get("object_types", []),
                "page_size":    d.get("page_size", DEFAULT_PAGE_SIZE),
                "verify_ssl":   d.get("verify_ssl", True),
                "timeout":      d.get("timeout", 30),
            },
        )
        return OpenCTIConnector(config, queue)
