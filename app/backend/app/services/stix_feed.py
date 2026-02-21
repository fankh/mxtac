"""STIX/TAXII feed ingestion service — Feature 29.5.

Implements a minimal TAXII 2.1 HTTP client and STIX 2.1 indicator parser
to ingest threat intelligence from external feeds into the IOC store.

Supported STIX indicator patterns:
  - [ipv4-addr:value = 'x.x.x.x']
  - [domain-name:value = 'evil.com']
  - [url:value = 'http://...']
  - [file:hashes.MD5 = '...']
  - [file:hashes.'SHA-256' = '...']
  - [email-addr:value = 'user@evil.com']
"""

from __future__ import annotations

import asyncio
import re
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from ..core.config import ThreatIntelFeedConfig
from ..core.database import AsyncSessionLocal
from ..core.logging import get_logger
from ..repositories.ioc_repo import IOCRepo

logger = get_logger(__name__)

# TAXII 2.1 media type
_TAXII_MEDIA_TYPE = "application/taxii+json;version=2.1"

# STIX pattern extractors — ordered list of (compiled_regex, ioc_type)
# Each regex captures the indicator value from a STIX pattern clause.
_PATTERN_EXTRACTORS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\[ipv4-addr:value\s*=\s*'([^']+)'", re.IGNORECASE), "ip"),
    (re.compile(r"\[domain-name:value\s*=\s*'([^']+)'", re.IGNORECASE), "domain"),
    (re.compile(r"\[url:value\s*=\s*'([^']+)'", re.IGNORECASE), "url"),
    (re.compile(r"file:hashes\.MD5\s*=\s*'([^']+)'", re.IGNORECASE), "hash_md5"),
    (re.compile(r"file:hashes\.'SHA-256'\s*=\s*'([^']+)'", re.IGNORECASE), "hash_sha256"),
    (re.compile(r"\[email-addr:value\s*=\s*'([^']+)'", re.IGNORECASE), "email"),
]

# Maximum description length stored in the DB (matches IOC.description column usage)
_MAX_DESCRIPTION_LEN = 500


def _confidence_to_severity(confidence: int) -> str:
    """Map STIX confidence (0-100) to MxTac severity string."""
    if confidence >= 76:
        return "critical"
    if confidence >= 51:
        return "high"
    if confidence >= 26:
        return "medium"
    return "low"


def _parse_stix_datetime(value: str | None) -> datetime | None:
    """Parse a STIX RFC 3339 timestamp string to a timezone-aware datetime.

    Returns None when the value is absent or unparseable.
    """
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


class STIXFeedIngester:
    """Ingests STIX 2.1 indicators from a TAXII 2.1 collection into the IOC store.

    Usage::

        ingester = STIXFeedIngester(config)
        created, skipped = await ingester.ingest()
    """

    def __init__(self, config: ThreatIntelFeedConfig) -> None:
        self._config = config
        self._last_poll: datetime | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def ingest(self) -> tuple[int, int]:
        """Poll the TAXII feed, parse STIX bundles, and persist IOCs.

        Returns (created, skipped) counts.
        Returns (0, 0) on poll failure or when there are no parseable indicators.
        Non-fatal: exceptions from the DB layer are logged and re-raised so
        the caller (the poller loop) can decide whether to retry.
        """
        bundle = await self.poll()
        if bundle is None:
            return 0, 0

        iocs = self.parse_bundle(bundle)
        if not iocs:
            logger.info(
                "STIX feed %r: no parseable indicators in bundle",
                self._config.name,
            )
            return 0, 0

        async with AsyncSessionLocal() as session:
            created, skipped = await IOCRepo.bulk_create(session, iocs)
            await session.commit()

        logger.info(
            "STIX feed %r: ingested created=%d skipped=%d",
            self._config.name,
            created,
            skipped,
        )
        return created, skipped

    async def poll(self) -> dict[str, Any] | None:
        """Fetch new STIX objects from the TAXII 2.1 collection since the last poll.

        Uses the ``added_after`` query parameter for incremental polling.
        On the first call, fetches all available objects.

        Returns the raw STIX bundle dict, or None on any HTTP / network error.
        Updates ``_last_poll`` only on success.
        """
        url = self._build_objects_url()
        headers = self._build_headers()

        params: dict[str, str] = {}
        if self._last_poll is not None:
            params["added_after"] = self._last_poll.strftime("%Y-%m-%dT%H:%M:%S.000Z")

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(url, headers=headers, params=params)
                response.raise_for_status()
                bundle: dict[str, Any] = response.json()
                self._last_poll = datetime.now(timezone.utc)
                logger.debug(
                    "STIX feed %r: polled url=%s objects=%d",
                    self._config.name,
                    url,
                    len(bundle.get("objects", [])),
                )
                return bundle
        except httpx.HTTPStatusError as exc:
            logger.warning(
                "STIX feed %r: HTTP error status=%d url=%s",
                self._config.name,
                exc.response.status_code,
                url,
            )
            return None
        except Exception:
            logger.exception(
                "STIX feed %r: poll failed url=%s", self._config.name, url
            )
            return None

    def parse_bundle(self, stix_bundle: dict[str, Any]) -> list[dict]:
        """Extract IOC dicts from a STIX 2.1 bundle.

        Processes only objects of type ``'indicator'``. For each indicator:
        - Extracts all (ioc_type, value) pairs from the STIX ``pattern`` field.
        - Maps STIX ``confidence`` (0-100) → MxTac severity string.
        - Maps ``valid_until`` → ``expires_at``.
        - Sets ``source`` to the feed name.

        Returns a list of dicts suitable for ``IOCRepo.bulk_create()``.
        """
        objects = stix_bundle.get("objects", [])
        now = datetime.now(timezone.utc)
        results: list[dict] = []

        for obj in objects:
            if obj.get("type") != "indicator":
                continue

            pattern: str = obj.get("pattern", "")
            if not pattern:
                continue

            ioc_pairs = self._extract_ioc_pairs(pattern)
            if not ioc_pairs:
                continue

            raw_confidence = obj.get("confidence", 50)
            confidence = min(max(int(raw_confidence), 0), 100)
            severity = _confidence_to_severity(confidence)

            description = obj.get("description") or obj.get("name") or ""
            if description:
                description = description[:_MAX_DESCRIPTION_LEN]
            else:
                description = None

            tags = list(obj.get("labels", []))
            first_seen = _parse_stix_datetime(obj.get("valid_from")) or now
            last_seen = _parse_stix_datetime(obj.get("modified")) or now
            expires_at = _parse_stix_datetime(obj.get("valid_until"))

            for ioc_type, value in ioc_pairs:
                results.append({
                    "ioc_type": ioc_type,
                    "value": value,
                    "source": self._config.name,
                    "confidence": confidence,
                    "severity": severity,
                    "description": description,
                    "tags": tags,
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "expires_at": expires_at,
                    "is_active": True,
                })

        return results

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_objects_url(self) -> str:
        """Construct the TAXII 2.1 objects endpoint URL."""
        base = self._config.taxii_url.rstrip("/")
        return f"{base}/collections/{self._config.collection_id}/objects/"

    def _build_headers(self) -> dict[str, str]:
        """Build HTTP headers for TAXII 2.1 requests."""
        headers: dict[str, str] = {"Accept": _TAXII_MEDIA_TYPE}
        if self._config.api_key:
            headers["Authorization"] = f"Bearer {self._config.api_key}"
        return headers

    def _extract_ioc_pairs(self, pattern: str) -> list[tuple[str, str]]:
        """Parse a STIX pattern string and return (ioc_type, value) pairs."""
        pairs: list[tuple[str, str]] = []
        for regex, ioc_type in _PATTERN_EXTRACTORS:
            for match in regex.finditer(pattern):
                value = match.group(1).strip()
                if value:
                    pairs.append((ioc_type, value))
        return pairs


async def stix_feed_poller(configs: list[ThreatIntelFeedConfig]) -> None:
    """Background task: poll all configured TAXII feeds on their respective intervals.

    The first poll for each feed is triggered immediately on startup (with a
    small per-feed stagger to avoid a thundering herd).  Subsequent polls
    occur after each feed's ``poll_interval`` seconds.

    Runs until cancelled (on shutdown).
    """
    if not configs:
        logger.info("STIX feed poller: no feeds configured, exiting")
        return

    ingesters = [STIXFeedIngester(cfg) for cfg in configs]

    # Stagger initial polls by 5 s per feed to spread DB write load.
    next_poll: list[float] = [time.monotonic() + i * 5.0 for i in range(len(configs))]

    logger.info("STIX feed poller started: %d feed(s)", len(configs))
    for cfg in configs:
        logger.info(
            "  feed=%r taxii_url=%r collection_id=%r interval=%ds",
            cfg.name,
            cfg.taxii_url,
            cfg.collection_id,
            cfg.poll_interval,
        )

    while True:
        try:
            now = time.monotonic()
            for i, ingester in enumerate(ingesters):
                if now >= next_poll[i]:
                    try:
                        await ingester.ingest()
                    except Exception:
                        logger.exception(
                            "STIX feed poller: error in ingester feed=%r",
                            configs[i].name,
                        )
                    next_poll[i] = time.monotonic() + configs[i].poll_interval

            await asyncio.sleep(60)  # check every minute whether any feed is due
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("STIX feed poller: unexpected error in poll loop")
            await asyncio.sleep(60)
