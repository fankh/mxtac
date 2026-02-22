"""
Alert Manager -- deduplication, enrichment, and scoring.

Consumes from mxtac.alerts and publishes to mxtac.enriched.

Deduplication window: same (rule_id, host) within 5 minutes = deduplicated.
Dedup is now backed by Valkey (Redis-compatible) using atomic SET NX EX so
that multiple backend replicas share a single dedup state.

Scoring formula:
    score = base_severity * weight_severity
          + asset_criticality * weight_asset
          + recurrence_bonus
    Normalized to 0-10 range.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

import valkey.asyncio as aioredis

from ..core.config import settings
from ..core.logging import get_logger
from ..core.metrics import alerts_deduplicated, alerts_processed, pipeline_latency
from ..engine.sigma_engine import SigmaAlert, LEVEL_SEVERITY
from ..pipeline.queue import MessageQueue, Topic
from .ioc_matcher import IOCMatcher

if TYPE_CHECKING:
    from .notification_dispatcher import NotificationDispatcher

logger = get_logger(__name__)

# Score weights
W_SEVERITY  = 0.60
W_ASSET     = 0.25
W_RECUR     = 0.15
MAX_SCORE   = 10.0

# Deduplication window in seconds (5 minutes)
DEDUP_WINDOW_SECONDS = 300

# Valkey key prefix for dedup entries
_DEDUP_PREFIX = "mxtac:dedup:"

# GeoIP enrichment — feature 9.8
# Sentinel value set on _geoip_reader when the database is not configured or
# the file cannot be opened. Avoids repeated failed load attempts.
_GEOIP_NOT_AVAILABLE = object()
_GEOIP_CACHE_PREFIX = "mxtac:geoip:"

# Asset criticality defaults — kept for backward-compatibility with scoring tests.
# The actual lookup now uses the CMDB (feature 9.9); these values are no longer
# used by _asset_criticality() but remain importable so existing tests compile.
DEFAULT_ASSET_CRITICALITY: dict[str, float] = {
    "dc":  1.0,   # Domain Controller prefix
    "srv": 0.8,
    "win": 0.6,
    "lin": 0.5,
}

# CMDB criticality scale — maps the Asset.criticality integer (1-5) to the
# 0.0-1.0 float range using the linear formula (criticality - 1) / 4.
# (feature 30.4 / mxtac-9.9)
ASSET_CRITICALITY_SCALE: dict[int, float] = {
    1: 0.00,  # Low          — (1-1)/4
    2: 0.25,  # Medium-Low   — (2-1)/4
    3: 0.50,  # Medium       — (3-1)/4  (also the default when asset not in CMDB)
    4: 0.75,  # High         — (4-1)/4
    5: 1.00,  # Mission-Critical — (5-1)/4
}

# Valkey caching for asset criticality lookups — avoids a DB hit on every alert
# (feature 30.4). Stores the raw integer criticality (1-5) with a 5-minute TTL.
_ASSET_CRIT_CACHE_PREFIX = "mxtac:asset_crit:"
ASSET_CRIT_CACHE_TTL = 300  # 5-minute TTL (seconds)


class AlertManager:
    def __init__(
        self,
        queue: MessageQueue,
        dispatcher: NotificationDispatcher | None = None,
    ) -> None:
        self._queue = queue
        self._dispatcher = dispatcher
        # Valkey client for distributed deduplication (dedup-only, not shared)
        self._valkey: aioredis.Valkey = aioredis.from_url(
            settings.valkey_url, decode_responses=True
        )
        # IOC matcher — separate Valkey client so IOC cache ops don't interfere
        # with the dedup SET NX sequence expected by callers (feature 29.3)
        self._ioc_valkey: aioredis.Valkey = aioredis.from_url(
            settings.valkey_url, decode_responses=True
        )
        self._ioc_matcher = IOCMatcher(self._ioc_valkey)
        # GeoIP mmdb reader — lazy-loaded on first lookup.
        # Set to _GEOIP_NOT_AVAILABLE when the database is missing or not configured.
        self._geoip_reader: Any = None

    async def process(self, alert_dict: dict[str, Any]) -> None:
        """Entry point -- called by queue consumer for each mxtac.alerts message."""
        start_time = time.monotonic()
        try:
            alert = SigmaAlert(
                id=alert_dict.get("id", ""),
                rule_id=alert_dict.get("rule_id", ""),
                rule_title=alert_dict.get("rule_title", ""),
                level=alert_dict.get("level", "medium"),
                severity_id=alert_dict.get("severity_id", 3),
                technique_ids=alert_dict.get("technique_ids", []),
                tactic_ids=alert_dict.get("tactic_ids", []),
                host=alert_dict.get("host", ""),
                time=datetime.fromisoformat(
                    alert_dict.get("time", datetime.now(timezone.utc).isoformat())
                ),
                event_snapshot=alert_dict.get("event_snapshot", {}),
            )

            severity_label = alert.level or "medium"
            alerts_processed.labels(severity=severity_label).inc()

            if await self._is_duplicate(alert):
                alerts_deduplicated.inc()
                logger.debug("AlertManager deduplicated rule_id=%s host=%s", alert.rule_id, alert.host)
                return

            if await self._is_suppressed(alert):
                logger.info(
                    "AlertManager suppressed rule_id=%s host=%s",
                    alert.rule_id, alert.host,
                )
                return

            enriched = await self._enrich(alert)
            scored   = self._score(enriched)

            await self._queue.publish(Topic.ENRICHED, scored)
            logger.info(
                "AlertManager published rule_id=%s host=%s score=%.1f",
                alert.rule_id, alert.host, scored.get("score", 0),
            )

            # Dispatch notifications — after enrichment, before storage (non-fatal)
            if self._dispatcher is not None:
                try:
                    await self._dispatcher.dispatch(scored)
                except Exception:
                    logger.exception(
                        "AlertManager notification dispatch failed (non-fatal) id=%s",
                        scored.get("id"),
                    )

            await self._persist_to_db(scored)
        except Exception:
            logger.exception("AlertManager process error")
        finally:
            pipeline_latency.observe(time.monotonic() - start_time)

    # -- Deduplication (Valkey-backed, distributed) -------------------------

    async def _is_duplicate(self, alert: SigmaAlert) -> bool:
        """Check if this alert is a duplicate using Valkey atomic SET NX EX.

        ``SET key "1" NX EX 300`` atomically:
          - Returns True  (set succeeded) when the key did NOT exist  -> *new* alert
          - Returns None  (set failed)    when the key already exists -> *duplicate*

        The 300-second TTL automatically evicts stale entries, replacing
        the old in-memory expiry sweep.
        """
        key = self._dedup_key(alert)
        try:
            was_set = await self._valkey.set(key, "1", nx=True, ex=DEDUP_WINDOW_SECONDS)
            # was_set is True when the key was newly created (not a duplicate)
            # was_set is None when the key already existed (duplicate)
            return was_set is None
        except Exception:
            logger.exception("Valkey dedup check failed, allowing alert through")
            # Fail-open: if Valkey is unreachable, let the alert through
            return False

    def _dedup_key(self, alert: SigmaAlert) -> str:
        raw = f"{alert.rule_id}|{alert.host}".encode()
        digest = hashlib.md5(raw).hexdigest()  # noqa: S324 (non-crypto use)
        return f"{_DEDUP_PREFIX}{digest}"

    # -- Suppression (whitelist/tuning) ------------------------------------

    async def _is_suppressed(self, alert: SigmaAlert) -> bool:
        """Return True if a matching active suppression rule exists in the DB.

        Fail-open: if the DB is unreachable the alert is allowed through so
        that the pipeline remains available even when PostgreSQL is down.
        """
        try:
            from ..core.database import AsyncSessionLocal
            from ..repositories.suppression_repo import SuppressionRepo
            technique_id = alert.technique_ids[0] if alert.technique_ids else ""
            tactic = alert.tactic_ids[0] if alert.tactic_ids else ""
            async with AsyncSessionLocal() as session:
                matched = await SuppressionRepo.match(
                    session,
                    rule_id_val=alert.rule_id,
                    host_val=alert.host,
                    technique_id_val=technique_id,
                    tactic_val=tactic,
                    severity_val=alert.level,
                )
                if matched:
                    await session.commit()
                    return True
            return False
        except Exception:
            logger.exception(
                "AlertManager suppression check failed (fail-open) rule_id=%s host=%s",
                alert.rule_id, alert.host,
            )
            return False

    # -- Enrichment --------------------------------------------------------

    async def _enrich(self, alert: SigmaAlert) -> dict[str, Any]:
        """Add context that isn't in the raw alert.

        Threat intel enrichment (feature 29.3): IOCMatcher.match_event() looks
        up active IOCs matching IPs, domains, hashes, and URLs extracted from
        the alert.  Matched IOCs are stored in ``threat_intel.matched_iocs`` and
        the score is boosted by +1.5 per match (capped at +3.0).
        """
        # IOC matching — in-memory + Valkey cache (feature 29.3)
        matches = await self._ioc_matcher.match_event(
            alert.host, alert.event_snapshot or {}
        )
        await self._ioc_matcher.update_hits(matches)

        if matches:
            threat_score_boost = round(min(len(matches) * 1.5, 3.0), 1)
            threat_intel: dict[str, Any] | None = {
                "matched_iocs": [m.to_dict() for m in matches],
                "threat_score_boost": threat_score_boost,
            }
        else:
            threat_intel = None

        d = {
            "id":            alert.id,
            "rule_id":       alert.rule_id,
            "rule_title":    alert.rule_title,
            "level":         alert.level,
            "severity_id":   alert.severity_id,
            "technique_ids": alert.technique_ids,
            "tactic_ids":    alert.tactic_ids,
            "host":          alert.host,
            "time":          alert.time.isoformat(),
            "event_snapshot": alert.event_snapshot,
            # Enrichment
            "asset_criticality":  await self._asset_criticality(alert.host),
            "recurrence_count":   await self._get_recurrence_count(alert),
            "threat_intel":       threat_intel,
            "geo_ip":             await self._lookup_geoip(alert),
        }
        return d

    async def _get_recurrence_count(self, alert: SigmaAlert) -> int:
        """Count recent detections for (rule_id, host) in the last 24 hours.

        Non-fatal: returns 0 when the DB is unavailable so scoring degrades
        gracefully rather than blocking the pipeline.
        """
        try:
            from ..core.database import AsyncSessionLocal
            from ..repositories.detection_repo import DetectionRepo
            async with AsyncSessionLocal() as session:
                return await DetectionRepo.count_recent_by_rule_host(
                    session,
                    rule_name=alert.rule_id,
                    host=alert.host,
                )
        except Exception:
            logger.exception(
                "AlertManager recurrence count query failed (non-fatal) rule_id=%s host=%s",
                alert.rule_id, alert.host,
            )
            return 0

    async def _asset_criticality(self, hostname: str) -> float:
        """Look up asset criticality from the CMDB with Valkey read-through cache.

        Maps the Asset.criticality integer (1–5) stored in PostgreSQL to the
        0.0–1.0 float range using the linear formula ``(criticality - 1) / 4``:

            1 → 0.00  (Low)
            2 → 0.25  (Medium-Low)
            3 → 0.50  (Medium — default when the asset is not registered)
            4 → 0.75  (High)
            5 → 1.00  (Mission-Critical)

        Lookup order:
          1. Valkey cache (key: ``mxtac:asset_crit:{hostname}``, TTL 5 min).
          2. AssetRepo.get_criticality() — exact hostname, then IP substring match.
          3. Default criticality (3 → 0.50) when no record is found.

        Fail-open: returns 0.50 on any DB or cache error so the pipeline is
        never blocked by a missing or unreachable CMDB/Valkey.
        (feature 30.4 / mxtac-9.9)
        """
        if not hostname:
            return ASSET_CRITICALITY_SCALE[3]

        cache_key = f"{_ASSET_CRIT_CACHE_PREFIX}{hostname}"

        # Cache read (fail-open: AttributeError, connection error, etc. all caught)
        try:
            cached = await self._valkey.get(cache_key)
            if cached is not None:
                return ASSET_CRITICALITY_SCALE.get(int(cached), 0.5)
        except Exception:
            pass  # Valkey unavailable — fall through to DB

        # DB lookup (fail-open)
        try:
            from ..core.database import AsyncSessionLocal
            from ..repositories.asset_repo import AssetRepo
            async with AsyncSessionLocal() as session:
                db_criticality = await AssetRepo.get_criticality(session, hostname)

            # Cache write (non-fatal — nested try so a Valkey failure doesn't
            # prevent returning the DB-sourced value)
            try:
                await self._valkey.set(
                    cache_key, str(db_criticality), ex=ASSET_CRIT_CACHE_TTL
                )
            except Exception:
                pass

            return ASSET_CRITICALITY_SCALE.get(db_criticality, 0.5)
        except Exception:
            logger.exception(
                "AlertManager CMDB criticality lookup failed (non-fatal) host=%s", hostname
            )
            return 0.5

    # -- GeoIP enrichment (feature 9.8) ------------------------------------

    def _load_geoip_reader(self) -> None:
        """Attempt to open the MaxMind mmdb reader; set _GEOIP_NOT_AVAILABLE on failure.

        Called at most once per AlertManager instance (lazy, on first lookup).
        Sets ``self._geoip_reader`` to either a live ``geoip2.database.Reader``
        or the ``_GEOIP_NOT_AVAILABLE`` sentinel so subsequent calls skip loading.
        """
        db_path = settings.geoip_db_path
        if not db_path:
            logger.debug("GeoIP database path not configured; GeoIP enrichment disabled")
            self._geoip_reader = _GEOIP_NOT_AVAILABLE
            return
        try:
            import geoip2.database  # noqa: PLC0415
            self._geoip_reader = geoip2.database.Reader(db_path)
            logger.info("GeoIP database loaded from %s", db_path)
        except Exception:
            logger.warning(
                "GeoIP database could not be loaded from %s; GeoIP enrichment disabled",
                db_path,
            )
            self._geoip_reader = _GEOIP_NOT_AVAILABLE

    def _collect_public_ips(self, alert: SigmaAlert) -> list[str]:
        """Extract unique globally-routable IPs from alert fields in priority order.

        Checked fields:
          - alert.host (direct host field)
          - event_snapshot: src_ip, dst_ip (flat)
          - event_snapshot: src.ip, dst.ip  (OCSF nested)

        Returns a deduplicated list preserving insertion order. Private, loopback,
        link-local, multicast, and reserved addresses are excluded.
        """
        seen: set[str] = set()
        ips: list[str] = []

        def _try(value: str | None) -> None:
            if not value or not isinstance(value, str):
                return
            v = value.strip()
            if not v or v in seen:
                return
            try:
                addr = ipaddress.ip_address(v)
            except ValueError:
                return
            if (
                addr.is_private
                or addr.is_loopback
                or addr.is_link_local
                or addr.is_multicast
                or addr.is_unspecified
                or addr.is_reserved
            ):
                return
            seen.add(v)
            ips.append(v)

        snap = alert.event_snapshot or {}
        _try(alert.host)
        _try(snap.get("src_ip"))
        _try(snap.get("dst_ip"))
        _try((snap.get("src") or {}).get("ip"))
        _try((snap.get("dst") or {}).get("ip"))
        return ips

    def _geoip_reader_lookup(self, ip: str) -> dict[str, Any] | None:
        """Perform a synchronous mmdb city lookup for *ip*.

        Returns a structured dict on success or None when the IP is not found
        in the database (``AddressNotFoundError``) or any other error occurs.
        """
        try:
            import geoip2.errors  # noqa: PLC0415
            response = self._geoip_reader.city(ip)
            region = (
                response.subdivisions.most_specific.name
                if response.subdivisions
                else None
            )
            return {
                "ip":           ip,
                "country_code": response.country.iso_code or None,
                "country":      response.country.name or None,
                "region":       region or None,
                "city":         response.city.name or None,
                "latitude":     response.location.latitude,
                "longitude":    response.location.longitude,
            }
        except Exception:
            # AddressNotFoundError: IP not in database; others: library / reader errors.
            return None

    async def _geoip_for_ip(self, ip: str) -> dict[str, Any] | None:
        """Return geo data for *ip*, using Valkey as a read-through cache.

        Cache key: ``mxtac:geoip:{ip}``; TTL controlled by ``settings.geoip_cache_ttl``.
        Cache read/write failures are silently ignored so a Valkey outage does not
        block GeoIP enrichment.
        """
        cache_key = f"{_GEOIP_CACHE_PREFIX}{ip}"

        # Cache read
        try:
            cached = await self._valkey.get(cache_key)
            if cached is not None:
                return json.loads(cached)
        except Exception:
            pass  # Cache unavailable — fall through to DB lookup

        # mmdb lookup
        result = self._geoip_reader_lookup(ip)

        # Cache write (non-fatal)
        if result is not None:
            try:
                await self._valkey.set(
                    cache_key,
                    json.dumps(result),
                    ex=settings.geoip_cache_ttl,
                )
            except Exception:
                pass

        return result

    async def _lookup_geoip(self, alert: SigmaAlert) -> dict[str, Any] | None:
        """GeoIP enrichment for the first public IP found in the alert.

        Extracts candidate IP addresses from the alert's host field and
        event_snapshot, skips private/RFC1918 and loopback addresses, and
        queries the MaxMind mmdb database (via Valkey cache) for the first
        public IP that yields a result.

        Returns a dict with ``ip``, ``country_code``, ``country``, ``region``,
        ``city``, ``latitude``, ``longitude`` or ``None`` when no public IP is
        found, the database is not configured, or the lookup fails.

        Fail-open: returns None on any error so the pipeline is never blocked.
        """
        try:
            # Lazy-load the mmdb reader exactly once per instance.
            if self._geoip_reader is None:
                self._load_geoip_reader()
            if self._geoip_reader is _GEOIP_NOT_AVAILABLE:
                return None

            ips = self._collect_public_ips(alert)
            if not ips:
                return None

            for ip in ips:
                result = await self._geoip_for_ip(ip)
                if result is not None:
                    return result

            return None
        except Exception:
            logger.exception(
                "AlertManager GeoIP lookup failed (non-fatal) rule_id=%s host=%s",
                alert.rule_id,
                alert.host,
            )
            return None

    # -- Scoring -----------------------------------------------------------

    def _score(self, enriched: dict[str, Any]) -> dict[str, Any]:
        """Compute a 0-10 risk score and attach to the enriched alert.

        recurrence_bonus is normalized to [0, 1] by capping at 10 occurrences:
            recur_bonus = min(recurrence_count / 10, 1.0)
        10 or more detections of the same (rule_id, host) in the last 24 hours
        yields the full 0.15 recurrence weight.

        threat_score_boost (feature 29.3): +1.5 per matched IOC, capped at +3.0.
        Added on top of the weighted base score before the MAX_SCORE cap.
        """
        severity_norm = (enriched["severity_id"] - 1) / 4   # 0-1
        asset_crit    = enriched.get("asset_criticality", 0.5)
        recur_count   = enriched.get("recurrence_count", 0)
        recur_bonus   = min(recur_count / 10.0, 1.0)        # 0-1

        raw_score = (
            severity_norm * W_SEVERITY
            + asset_crit  * W_ASSET
            + recur_bonus * W_RECUR
        ) * MAX_SCORE

        # IOC threat intel boost (feature 29.3)
        ti = enriched.get("threat_intel")
        threat_boost = ti["threat_score_boost"] if ti else 0.0

        enriched["score"] = round(min(raw_score + threat_boost, MAX_SCORE), 1)
        return enriched

    # -- Persistence -------------------------------------------------------

    async def _update_asset_stats(self, session: Any, hostname: str) -> None:
        """Stamp last_seen_at and increment detection_count for the referenced asset.

        Called within an open DB session after a detection is created.  Uses
        bulk UPDATE so the operation is a no-op (0 rows affected) when the
        hostname does not exist in the assets table.

        Non-fatal: any exception is caught and logged so a CMDB update failure
        never blocks detection persistence. (feature 30.4)
        """
        if not hostname:
            return
        try:
            from ..repositories.asset_repo import AssetRepo
            await AssetRepo.update_last_seen(session, hostname)
            await AssetRepo.increment_detection_count(session, hostname)
        except Exception:
            logger.exception(
                "AlertManager asset stats update failed (non-fatal) host=%s", hostname
            )

    async def _persist_to_db(self, scored: dict[str, Any]) -> None:
        """Persist enriched alert to PostgreSQL. Non-fatal — pipeline continues on error."""
        try:
            from ..core.database import AsyncSessionLocal
            from ..repositories.detection_repo import DetectionRepo
            technique_ids = scored.get("technique_ids") or []
            tactic_ids    = scored.get("tactic_ids") or []
            alert_time    = datetime.fromisoformat(scored["time"])
            async with AsyncSessionLocal() as session:
                await DetectionRepo.create(
                    session,
                    id            = scored["id"],
                    score         = scored["score"],
                    severity      = scored["level"],
                    technique_id  = (technique_ids[0] if technique_ids else "unknown")[:20],
                    technique_name= scored["rule_title"][:255],
                    tactic        = (tactic_ids[0] if tactic_ids else "unknown")[:100],
                    tactic_id     = tactic_ids[0] if tactic_ids else None,
                    name          = scored["rule_title"][:500],
                    host          = scored["host"],
                    time          = alert_time,
                    rule_name     = (scored["rule_id"] or "")[:500] or None,
                )
                await self._correlate_incident(session, scored)
                # Update asset last_seen_at + detection_count (feature 30.4)
                await self._update_asset_stats(session, scored.get("host", ""))
                await session.commit()
            logger.debug("AlertManager persisted detection id=%s", scored["id"])
        except Exception:
            logger.exception(
                "AlertManager DB persistence failed (non-fatal) id=%s", scored.get("id")
            )

    # -- Auto-correlation --------------------------------------------------

    # Severity rank: higher index = higher severity
    _SEVERITY_RANK: dict[str, int] = {
        "low": 0, "medium": 1, "high": 2, "critical": 3,
    }

    async def _correlate_incident(self, session: Any, scored: dict[str, Any]) -> None:
        """Auto-correlate this detection into an incident (feature 26.8).

        Logic:
        1. If auto_create_incident_enabled is False, do nothing.
        2. Look for an open incident with (host, tactic) within correlation_window_seconds.
           If found: append this detection_id to its detection_ids list.
        3. If not found and severity >= auto_create_incident_min_severity: create a new incident.
        """
        if not settings.auto_create_incident_enabled:
            return

        host       = scored.get("host", "")
        tactic_ids = scored.get("tactic_ids") or []
        tactic     = tactic_ids[0] if tactic_ids else ""
        detection_id = scored.get("id", "")
        severity   = scored.get("level", "medium")

        if not host or not tactic or not detection_id:
            return

        from ..repositories.incident_repo import IncidentRepo

        existing = await IncidentRepo.find_open_by_host_tactic(
            session,
            host=host,
            tactic=tactic,
            window_seconds=settings.correlation_window_seconds,
        )

        if existing:
            # Append detection_id if not already present
            ids = list(existing.detection_ids or [])
            if detection_id not in ids:
                ids.append(detection_id)
                existing.detection_ids = ids
            logger.info(
                "AlertManager correlated detection=%s into incident=%s (host=%s tactic=%s)",
                detection_id, existing.id, host, tactic,
            )
            return

        # Check severity threshold for new incident creation
        min_rank = self._SEVERITY_RANK.get(settings.auto_create_incident_min_severity, 2)
        alert_rank = self._SEVERITY_RANK.get(severity, 0)
        if alert_rank < min_rank:
            return

        from ..repositories.incident_repo import IncidentRepo
        technique_ids = scored.get("technique_ids") or []
        await IncidentRepo.create(
            session,
            title        = f"Auto: {scored.get('rule_title', 'Unknown')} on {host}",
            description  = (
                f"Auto-created by alert-to-incident correlation.\n"
                f"Rule: {scored.get('rule_id', '')}\n"
                f"Host: {host}\n"
                f"Tactic: {tactic}"
            ),
            severity     = severity,
            status       = "new",
            priority     = 3,
            created_by   = "system",
            detection_ids= [detection_id],
            technique_ids= technique_ids,
            tactic_ids   = tactic_ids,
            hosts        = [host],
        )
        logger.info(
            "AlertManager created new incident for detection=%s (host=%s tactic=%s severity=%s)",
            detection_id, host, tactic, severity,
        )

    # -- Cleanup -----------------------------------------------------------

    async def close(self) -> None:
        """Close Valkey connections and GeoIP reader."""
        if self._valkey:
            await self._valkey.aclose()
        if self._ioc_valkey:
            await self._ioc_valkey.aclose()
        if (
            self._geoip_reader is not None
            and self._geoip_reader is not _GEOIP_NOT_AVAILABLE
        ):
            self._geoip_reader.close()
