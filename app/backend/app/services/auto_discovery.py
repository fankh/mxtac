"""Asset auto-discovery — Feature 30.5.

After normalization, extracts hostname and IP information from OCSF events
and upserts asset records into the CMDB.  Supports Wazuh (agent/host),
Zeek conn.log (src/dst IPs), Suricata (src/dst IPs), and MxGuard
heartbeats (hostname + OS + agent_id).

Only internal IPs (RFC 1918 by default) are registered.  Rate-limited to
one upsert per hostname per 5 minutes using a Valkey atomic SET NX EX key.
Failures are caught and logged so the main pipeline is never interrupted.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Any

import valkey.asyncio as aioredis

from ..core.config import settings
from ..core.database import AsyncSessionLocal
from ..core.logging import get_logger
from ..repositories.asset_repo import AssetRepo
from .normalizers.ocsf import OCSFEvent

logger = get_logger(__name__)

# Valkey key prefix for rate-limit tokens
_RATE_LIMIT_PREFIX = "mxtac:autodiscovery:"
# 5-minute rate-limit window (seconds)
_RATE_LIMIT_WINDOW = 300

# Default asset_type for auto-discovered assets
_DEFAULT_ASSET_TYPE = "server"


class AssetDiscovery:
    """Discovers and upserts CMDB assets from normalized OCSF events.

    Instantiate once and inject into :class:`NormalizerPipeline`.  Pass a
    Valkey client (``valkey.asyncio.Valkey``) for distributed rate limiting.
    The internal-network CIDRs are read from ``settings.asset_internal_networks``
    at construction time.
    """

    def __init__(self, valkey_client: aioredis.Valkey) -> None:
        self._valkey = valkey_client
        self._networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for cidr in settings.asset_internal_networks:
            try:
                self._networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                logger.warning(
                    "AssetDiscovery: invalid CIDR in asset_internal_networks: %s", cidr
                )

    # ── Public API ───────────────────────────────────────────────────────────

    def is_internal_ip(self, ip: str) -> bool:
        """Return True if *ip* falls within any configured internal network."""
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in net for net in self._networks)
        except ValueError:
            return False

    async def process_event(self, event: OCSFEvent, source: str) -> None:
        """Extract asset info from *event* and upsert into the CMDB.

        *source* is one of ``"wazuh"``, ``"zeek"``, ``"suricata"``,
        ``"mxguard"``.  Unknown sources are silently ignored.

        All exceptions are caught so that discovery failures never interrupt
        the normalizer pipeline.  When ``settings.asset_auto_discovery`` is
        ``False`` this method is a no-op.
        """
        if not settings.asset_auto_discovery:
            return
        try:
            await self._do_process(event, source)
        except Exception:
            logger.exception(
                "AssetDiscovery.process_event error source=%s", source
            )

    # ── Internal helpers ─────────────────────────────────────────────────────

    async def _do_process(self, event: OCSFEvent, source: str) -> None:
        candidates = self._extract_candidates(event, source)
        if not candidates:
            return

        seen_hostnames: set[str] = set()
        for hostname, ip_addresses, os_name in candidates:
            if not hostname:
                continue
            # Deduplicate within the same event (e.g. src == dst)
            if hostname in seen_hostnames:
                continue
            seen_hostnames.add(hostname)

            if await self._is_rate_limited(hostname):
                logger.debug(
                    "AssetDiscovery rate-limited hostname=%s source=%s",
                    hostname,
                    source,
                )
                continue

            kwargs: dict[str, Any] = {
                "last_seen_at": datetime.now(timezone.utc),
                "asset_type": _DEFAULT_ASSET_TYPE,
            }
            if ip_addresses:
                kwargs["ip_addresses"] = ip_addresses
            if os_name:
                kwargs["os"] = os_name

            async with AsyncSessionLocal() as session:
                await AssetRepo.upsert_by_hostname(session, hostname, **kwargs)
                await session.commit()

            logger.debug(
                "AssetDiscovery upserted hostname=%s ips=%s source=%s",
                hostname,
                ip_addresses,
                source,
            )

    def _extract_candidates(
        self, event: OCSFEvent, source: str
    ) -> list[tuple[str | None, list[str], str | None]]:
        """Return a list of ``(hostname, ip_addresses, os_name)`` tuples.

        Extraction rules per source:

        * **wazuh** — ``dst_endpoint`` (Wazuh agent = monitored host).
          Requires a hostname; IP is included only when internal.
        * **zeek** / **suricata** — both ``src_endpoint`` and
          ``dst_endpoint``; only internal IPs are included.  The hostname
          (if absent) falls back to the IP string so the asset can be
          identified without DNS resolution.
        * **mxguard** — ``dst_endpoint`` (heartbeat from managed endpoint).
          ``agent_id`` is stored via the ``unmapped`` field when present.
        """
        candidates: list[tuple[str | None, list[str], str | None]] = []

        if source == "wazuh":
            ep = event.dst_endpoint
            hostname = ep.hostname
            ip = ep.ip
            os_name = ep.os_name
            if hostname:
                ips = [ip] if ip and self.is_internal_ip(ip) else []
                candidates.append((hostname, ips, os_name))

        elif source in ("zeek", "suricata"):
            for ep in (event.src_endpoint, event.dst_endpoint):
                ip = ep.ip
                if ip and self.is_internal_ip(ip):
                    # Use hostname if known, otherwise identify by IP string
                    hostname = ep.hostname or ip
                    candidates.append((hostname, [ip], ep.os_name))

        elif source == "mxguard":
            ep = event.dst_endpoint
            hostname = ep.hostname
            ip = ep.ip
            os_name = ep.os_name
            if hostname:
                ips = [ip] if ip and self.is_internal_ip(ip) else []
                candidates.append((hostname, ips, os_name))

        return candidates

    async def _is_rate_limited(self, hostname: str) -> bool:
        """Return True if an upsert for *hostname* was performed within the rate window.

        Uses ``SET key "1" NX EX 300`` atomically:
          - Returns True (newly set)  → **not** rate-limited → perform upsert
          - Returns None (key exists) → rate-limited → skip this cycle

        Fail-open: if Valkey is unreachable the upsert is allowed through so
        that asset discovery continues even when Valkey is temporarily down.
        """
        key = f"{_RATE_LIMIT_PREFIX}{hostname}"
        try:
            was_set = await self._valkey.set(
                key, "1", nx=True, ex=_RATE_LIMIT_WINDOW
            )
            # was_set = True  → key newly created → not rate-limited
            # was_set = None  → key already exists → rate-limited
            return was_set is None
        except Exception:
            logger.exception(
                "AssetDiscovery Valkey rate-limit check failed hostname=%s", hostname
            )
            return False  # fail-open: allow upsert
