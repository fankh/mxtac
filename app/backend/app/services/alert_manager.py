"""
Alert Manager -- deduplication, enrichment, and scoring.

Consumes from mxtac.alerts and publishes to mxtac.enriched.

Deduplication window: same (rule_id, host) within 5 minutes = deduplicated.
Dedup is now backed by Valkey (Redis-compatible) using atomic SET NX EX so
that multiple backend replicas share a single dedup state.

Scoring formula:
    score = base_severity * weight_severity
          + host_criticality * weight_host
          + recurrence_bonus
    Normalized to 0-10 range.  Every host is weighted as medium criticality.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import time
from datetime import datetime, timezone
from typing import Any

import valkey.asyncio as aioredis

from ..core.config import settings
from ..core.logging import get_logger
from ..core.metrics import alerts_deduplicated, alerts_processed, pipeline_latency
from ..engine.sigma_engine import SigmaAlert, LEVEL_SEVERITY, tactic_name
from ..pipeline.queue import MessageQueue, Topic

logger = get_logger(__name__)

# Score weights
W_SEVERITY  = 0.60
W_HOST      = 0.25
W_RECUR     = 0.15
MAX_SCORE   = 10.0

# Every host is weighted as medium criticality (midpoint of the 0-1 range).
HOST_CRITICALITY = 0.5

# Deduplication window in seconds (5 minutes)
DEDUP_WINDOW_SECONDS = 300

# Valkey key prefix for dedup entries
_DEDUP_PREFIX = "mxtac:dedup:"

# GeoIP enrichment — feature 9.8
# Sentinel value set on _geoip_reader when the database is not configured or
# the file cannot be opened. Avoids repeated failed load attempts.
_GEOIP_NOT_AVAILABLE = object()
_GEOIP_CACHE_PREFIX = "mxtac:geoip:"


class AlertManager:
    def __init__(self, queue: MessageQueue) -> None:
        self._queue = queue
        # Valkey client for distributed deduplication and the GeoIP cache
        self._valkey: aioredis.Valkey = aioredis.from_url(
            settings.valkey_url, decode_responses=True
        )
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

            enriched = await self._enrich(alert)
            scored   = self._score(enriched)

            await self._queue.publish(Topic.ENRICHED, scored)
            logger.info(
                "AlertManager published rule_id=%s host=%s score=%.1f",
                alert.rule_id, alert.host, scored.get("score", 0),
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

    # -- Enrichment --------------------------------------------------------

    async def _enrich(self, alert: SigmaAlert) -> dict[str, Any]:
        """Add context that isn't in the raw alert."""
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
            "recurrence_count":   await self._get_recurrence_count(alert),
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
        """
        severity_norm = (enriched["severity_id"] - 1) / 4   # 0-1
        recur_count   = enriched.get("recurrence_count", 0)
        recur_bonus   = min(recur_count / 10.0, 1.0)        # 0-1

        raw_score = (
            severity_norm      * W_SEVERITY
            + HOST_CRITICALITY * W_HOST
            + recur_bonus      * W_RECUR
        ) * MAX_SCORE

        enriched["score"] = round(min(raw_score, MAX_SCORE), 1)
        return enriched

    # -- Persistence -------------------------------------------------------

    @staticmethod
    def _event_context(snapshot: dict[str, Any]) -> dict[str, str | None]:
        """User, process and log source of the matched event, for the detection row.

        *snapshot* is the flattened event of the alert (``ocsf_to_sigma_flat``).
        A value that is missing or not a scalar is stored as ``None``.
        """
        def text(limit: int, *keys: str) -> str | None:
            for key in keys:
                value = snapshot.get(key)
                if value is None or isinstance(value, (dict, list)):
                    continue
                value = str(value).strip()
                if value:
                    return value[:limit]
            return None

        return {
            "user":       text(255, "actor_user.name"),
            "process":    text(500, "process.cmd_line", "process.path", "process.name"),
            "log_source": text(100, "unmapped.source", "_product"),
        }

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
                    severity      = self._detection_severity(scored["level"]),
                    technique_id  = (technique_ids[0] if technique_ids else "unknown")[:20],
                    technique_name= scored["rule_title"][:255],
                    tactic        = (tactic_name(tactic_ids[0]) if tactic_ids else "unknown")[:100],
                    tactic_id     = tactic_ids[0] if tactic_ids else None,
                    name          = scored["rule_title"][:500],
                    host          = scored["host"],
                    time          = alert_time,
                    rule_name     = (scored["rule_id"] or "")[:500] or None,
                    **self._event_context(scored.get("event_snapshot") or {}),
                )
                await self._correlate_incident(session, scored)
                await session.commit()
            logger.debug("AlertManager persisted detection id=%s", scored["id"])
        except Exception:
            logger.exception(
                "AlertManager DB persistence failed (non-fatal) id=%s", scored.get("id")
            )

    @classmethod
    def _detection_severity(cls, level: str | None) -> str:
        """Map a Sigma rule level to a detection severity.

        Detections have four severities.  The Sigma level ``informational``
        (and any unknown level) is stored as ``low``.
        """
        return level if level in cls._SEVERITY_RANK else "low"

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

        from ..repositories.incident_repo import IncidentRepo, time_to_detect_seconds
        technique_ids = scored.get("technique_ids") or []
        try:
            event_time = datetime.fromisoformat(scored["time"])
        except (KeyError, TypeError, ValueError):
            event_time = None
        await IncidentRepo.create(
            session,
            title        = f"Auto: {scored.get('rule_title', 'Unknown')} on {host}",
            description  = (
                f"Auto-created by alert-to-incident correlation.\n"
                f"Rule: {scored.get('rule_title', 'Unknown')} ({scored.get('rule_id', '')})\n"
                f"Host: {host}\n"
                f"Tactic: {tactic_name(tactic)} ({tactic})"
            ),
            severity     = severity,
            status       = "new",
            priority     = 3,
            created_by   = "system",
            detection_ids= [detection_id],
            technique_ids= technique_ids,
            tactic_ids   = tactic_ids,
            hosts        = [host],
            ttd_seconds  = time_to_detect_seconds(event_time),
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
        if (
            self._geoip_reader is not None
            and self._geoip_reader is not _GEOIP_NOT_AVAILABLE
        ):
            self._geoip_reader.close()
