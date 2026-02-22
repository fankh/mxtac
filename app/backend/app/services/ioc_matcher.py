"""IOC Matching Service — feature 29.3.

Maintains an in-memory cache of all active IOCs (refreshed every 5 minutes)
and a per-value Valkey cache to avoid redundant lookups across replicas.

Usage::
    matcher = IOCMatcher(valkey_client)
    matches = await matcher.match_event(host, event_snapshot)
    await matcher.update_hits(matches)
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

import valkey.asyncio as aioredis

from ..core.logging import get_logger

logger = get_logger(__name__)

# In-memory cache TTL: 5 minutes
_MEM_CACHE_TTL: float = 300.0

# Valkey cache TTL: 5 minutes
_VALKEY_TTL: int = 300

# Valkey key prefix for IOC lookups
_VALKEY_PREFIX = "mxtac:ioc:"

# Sentinel stored in Valkey to mark a known cache miss (value is not an IOC)
_VALKEY_MISS = "0"


@dataclass
class IOCMatch:
    """Represents a single matched IOC."""

    ioc_id: int
    ioc_type: str
    value: str
    severity: str
    confidence: int
    source: str
    tags: list[str] = field(default_factory=list)
    description: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ioc_id": self.ioc_id,
            "ioc_type": self.ioc_type,
            "value": self.value,
            "severity": self.severity,
            "confidence": self.confidence,
            "source": self.source,
            "tags": self.tags,
            "description": self.description,
        }


class IOCMatcher:
    """In-memory + Valkey-backed IOC matching service.

    Architecture
    ------------
    1. **In-memory cache** — all active IOCs loaded from PostgreSQL, grouped
       by ``ioc_type → {value → IOCMatch}``.  Refreshed at most every
       ``_MEM_CACHE_TTL`` seconds (5 min) by :meth:`load_active_iocs`.

    2. **Valkey cache** — per-(type, value) lookup result stored with a
       5-minute TTL.  Serves as a warm distributed cache across replicas and
       as a fallback when the in-memory cache is being refreshed.

    Fail-open
    ---------
    All DB and Valkey operations are wrapped in try/except.  Any failure
    results in a graceful degradation (empty matches) rather than blocking
    the alert pipeline.
    """

    def __init__(self, valkey_client: aioredis.Valkey) -> None:
        self._valkey = valkey_client
        # {ioc_type: {value: IOCMatch}}
        self._ioc_map: dict[str, dict[str, IOCMatch]] = {}
        self._cache_loaded_at: float = 0.0

    # ------------------------------------------------------------------
    # In-memory cache
    # ------------------------------------------------------------------

    async def load_active_iocs(self) -> None:
        """Load all active IOCs from DB into the in-memory cache.

        No-op when the cache was refreshed within the last 5 minutes.
        On DB failure, logs the exception and leaves the existing cache intact.
        """
        if time.monotonic() - self._cache_loaded_at < _MEM_CACHE_TTL:
            return

        try:
            from sqlalchemy import select

            from ..core.database import AsyncSessionLocal
            from ..models.ioc import IOC

            async with AsyncSessionLocal() as session:
                result = await session.execute(
                    select(IOC).where(IOC.is_active.is_(True))
                )
                iocs = result.scalars().all()

            ioc_map: dict[str, dict[str, IOCMatch]] = {}
            for ioc in iocs:
                ioc_map.setdefault(ioc.ioc_type, {})[ioc.value] = IOCMatch(
                    ioc_id=ioc.id,
                    ioc_type=ioc.ioc_type,
                    value=ioc.value,
                    severity=ioc.severity,
                    confidence=ioc.confidence,
                    source=ioc.source,
                    tags=ioc.tags or [],
                    description=ioc.description,
                )

            self._ioc_map = ioc_map
            self._cache_loaded_at = time.monotonic()
            total = sum(len(v) for v in ioc_map.values())
            logger.debug("IOCMatcher: loaded %d active IOCs into memory cache", total)

        except Exception:
            logger.exception("IOCMatcher: failed to refresh IOC cache (non-fatal)")

    # ------------------------------------------------------------------
    # Candidate extraction
    # ------------------------------------------------------------------

    def _extract_candidates(
        self, host: str, event_snapshot: dict[str, Any]
    ) -> dict[str, set[str]]:
        """Extract IOC candidate values grouped by type from the alert.

        Supports flat event fields and OCSF nested structures.
        """
        candidates: dict[str, set[str]] = {}

        def _add(ioc_type: str, value: Any) -> None:
            if value and isinstance(value, str):
                v = value.strip()
                if v:
                    candidates.setdefault(ioc_type, set()).add(v)

        snap = event_snapshot or {}

        # Host as both IP and domain (dual extraction)
        _add("ip", host)
        _add("domain", host)

        # Flat event fields (common across connectors)
        _add("ip", snap.get("src_ip"))
        _add("ip", snap.get("dst_ip"))
        _add("domain", snap.get("domain"))
        _add("domain", snap.get("hostname"))
        _add("hash_md5", snap.get("hash_md5"))
        _add("hash_sha256", snap.get("hash_sha256"))
        _add("url", snap.get("url"))

        # OCSF nested fields
        _add("ip", (snap.get("src") or {}).get("ip"))
        _add("ip", (snap.get("dst") or {}).get("ip"))
        _proc = snap.get("process") or {}
        _file = _proc.get("file") or {}
        _add("hash_md5", _file.get("hash_md5"))
        _add("hash_sha256", _file.get("hash_sha256"))

        return candidates

    # ------------------------------------------------------------------
    # Valkey cache helpers
    # ------------------------------------------------------------------

    async def _valkey_get(self, ioc_type: str, value: str) -> IOCMatch | None | str:
        """Check the Valkey cache for a specific (ioc_type, value) pair.

        Returns
        -------
        IOCMatch
            Cached positive hit.
        None
            Cached miss — the value is known to NOT be an active IOC.
        ``"skip"``
            Key not found in cache or Valkey unavailable — caller should
            fall back to the in-memory cache.
        """
        try:
            key = f"{_VALKEY_PREFIX}{ioc_type}:{value}"
            cached = await self._valkey.get(key)
            if cached is None:
                return "skip"  # Not cached yet
            if cached == _VALKEY_MISS:
                return None  # Cached miss
            return IOCMatch(**json.loads(cached))
        except Exception:
            return "skip"  # Valkey unavailable — fall back to in-memory

    async def _valkey_set(
        self, ioc_type: str, value: str, match: IOCMatch | None
    ) -> None:
        """Write IOC lookup result to Valkey with TTL. Non-fatal on error."""
        try:
            key = f"{_VALKEY_PREFIX}{ioc_type}:{value}"
            payload = _VALKEY_MISS if match is None else json.dumps(match.to_dict())
            await self._valkey.set(key, payload, ex=_VALKEY_TTL)
        except Exception:
            pass  # Cache write failure is non-fatal

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def match_event(
        self, host: str, event_snapshot: dict[str, Any]
    ) -> list[IOCMatch]:
        """Match event data against active IOCs and return all matches.

        Lookup order
        ------------
        1. Valkey cache (distributed, shared across replicas)
        2. In-memory cache (local, O(1) dict lookup)

        Deduplication is applied — the same IOC will not appear twice even
        if multiple extracted values map to it.

        Fail-open: returns an empty list on any error.
        """
        await self.load_active_iocs()

        candidates = self._extract_candidates(host, event_snapshot)
        if not candidates:
            return []

        matches: list[IOCMatch] = []
        seen_ids: set[int] = set()

        for ioc_type, values in candidates.items():
            type_map = self._ioc_map.get(ioc_type, {})
            for value in values:
                # 1. Check Valkey cache
                cached = await self._valkey_get(ioc_type, value)
                if cached is None:
                    # Cached miss — skip without hitting in-memory
                    continue
                elif cached == "skip":
                    # Not in cache or Valkey unavailable — check in-memory
                    match: IOCMatch | None = type_map.get(value)
                    await self._valkey_set(ioc_type, value, match)
                else:
                    match = cached  # type: ignore[assignment]

                if match is not None and match.ioc_id not in seen_ids:
                    seen_ids.add(match.ioc_id)
                    matches.append(match)

        return matches

    async def update_hits(self, matches: list[IOCMatch]) -> None:
        """Atomically increment hit_count and last_hit_at for matched IOCs.

        Non-fatal: logs and returns silently on DB error.
        """
        if not matches:
            return
        try:
            from ..core.database import AsyncSessionLocal
            from ..repositories.ioc_repo import IOCRepo

            async with AsyncSessionLocal() as session:
                for match in matches:
                    await IOCRepo.increment_hit(session, match.ioc_id)
                await session.commit()
            logger.debug(
                "IOCMatcher: updated hit counts for %d matched IOCs", len(matches)
            )
        except Exception:
            logger.exception(
                "IOCMatcher: failed to update IOC hit counts (non-fatal)"
            )
