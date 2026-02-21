"""Event repository — async DB operations for the events table.

Replaces the OpenSearch-based event search with PostgreSQL so the platform
works without a running OpenSearch cluster (dev / single-node deployments).
Full OpenSearch integration is tracked separately in feature 11.5 / 12.x.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.validators import escape_like
from ..models.event import Event


# ── Time parsing ──────────────────────────────────────────────────────────────

_RELATIVE_RE = re.compile(r"^now(?:-(\d+)([smhdwMy]))?$")


def _parse_time(t: str) -> datetime:
    """Convert an OpenSearch-style relative time string to a UTC datetime.

    Supported formats:
    - ``now``        → current UTC timestamp
    - ``now-Nd``     → N days ago  (d = days)
    - ``now-Nh``     → N hours ago (h = hours)
    - ``now-Nm``     → N minutes ago
    - ``now-Nw``     → N weeks ago
    - ISO 8601 strings (e.g. ``2026-01-15T12:00:00Z``)
    """
    m = _RELATIVE_RE.match(t.strip())
    if m:
        now = datetime.now(timezone.utc)
        if m.group(1) is None:
            return now
        n, unit = int(m.group(1)), m.group(2)
        deltas: dict[str, timedelta] = {
            "s": timedelta(seconds=n),
            "m": timedelta(minutes=n),
            "h": timedelta(hours=n),
            "d": timedelta(days=n),
            "w": timedelta(weeks=n),
            "M": timedelta(days=n * 30),
            "y": timedelta(days=n * 365),
        }
        return now - deltas.get(unit, timedelta(0))
    # ISO 8601
    return datetime.fromisoformat(t.replace("Z", "+00:00"))


# ── Field mapping ─────────────────────────────────────────────────────────────

# Maps EventFilter.field names (including OpenSearch-style nested paths) to
# the corresponding SQLAlchemy column on the Event model.
_FIELD_MAP: dict[str, Any] = {
    "severity_id":           Event.severity_id,
    "class_name":            Event.class_name,
    "class_uid":             Event.class_uid,
    "src_ip":                Event.src_ip,
    "dst_ip":                Event.dst_ip,
    "hostname":              Event.hostname,
    "username":              Event.username,
    "process_hash":          Event.process_hash,
    "source":                Event.source,
    # OpenSearch nested-field aliases
    "src_endpoint.ip":       Event.src_ip,
    "dst_endpoint.ip":       Event.dst_ip,
    "dst_endpoint.hostname": Event.hostname,
    "actor_user.name":       Event.username,
    "process.hash_sha256":   Event.process_hash,
}

# Entity-type → Event column(s) for the entity timeline query
_ENTITY_MAP: dict[str, list[Any]] = {
    "ip":   [Event.src_ip, Event.dst_ip],
    "host": [Event.hostname],
    "user": [Event.username],
    "hash": [Event.process_hash],
}


# ── Filter helpers ────────────────────────────────────────────────────────────

def _apply_event_filter(q, field: str, operator: str, value: Any):
    """Return the query with one EventFilter applied (or unchanged if unknown field)."""
    col = _FIELD_MAP.get(field)
    if col is None:
        return q  # Silently skip unknown fields

    if operator == "eq":
        return q.where(col == value)
    if operator == "ne":
        return q.where(col != value)
    if operator == "contains":
        return q.where(col.ilike(f"%{escape_like(str(value))}%", escape="\\"))
    if operator == "gt":
        return q.where(col > value)
    if operator == "lt":
        return q.where(col < value)
    if operator == "gte":
        return q.where(col >= value)
    if operator == "lte":
        return q.where(col <= value)
    return q


# ── Repository ────────────────────────────────────────────────────────────────

class EventRepo:

    @staticmethod
    async def search(
        session: AsyncSession,
        *,
        query: str | None = None,
        filters: list | None = None,          # list[EventFilter] (duck-typed)
        time_from: str = "now-7d",
        time_to: str = "now",
        size: int = 100,
        from_: int = 0,
    ) -> tuple[list[Event], int]:
        """Full-text + filtered search with time range.  Returns (items, total)."""
        t_from = _parse_time(time_from)
        t_to = _parse_time(time_to)

        q = select(Event).where(Event.time >= t_from, Event.time <= t_to)

        # Full-text search across summary, class_name, hostname, username
        if query:
            pattern = f"%{escape_like(query)}%"
            q = q.where(
                Event.summary.ilike(pattern, escape="\\")
                | Event.class_name.ilike(pattern, escape="\\")
                | Event.hostname.ilike(pattern, escape="\\")
                | Event.username.ilike(pattern, escape="\\")
                | Event.src_ip.ilike(pattern, escape="\\")
                | Event.dst_ip.ilike(pattern, escape="\\")
            )

        # Apply structured filters
        for f in filters or []:
            q = _apply_event_filter(q, f.field, f.operator, f.value)

        # Total count (before pagination)
        count_q = select(func.count()).select_from(q.subquery())
        total = await session.scalar(count_q) or 0

        # Sort by event time descending, then paginate
        q = q.order_by(Event.time.desc()).offset(from_).limit(size)

        result = await session.execute(q)
        return list(result.scalars().all()), total

    @staticmethod
    async def get(session: AsyncSession, event_id: str) -> Event | None:
        """Fetch a single event by primary key."""
        result = await session.execute(
            select(Event).where(Event.id == event_id)
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def create(session: AsyncSession, **kwargs) -> Event:
        """Insert a new event row and flush (no commit — caller manages transaction)."""
        evt = Event(**kwargs)
        session.add(evt)
        await session.flush()
        return evt

    @staticmethod
    async def count_by_field(
        session: AsyncSession,
        field: str,
        *,
        time_from: str = "now-7d",
        time_to: str = "now",
        limit: int = 10,
    ) -> list[dict]:
        """Return term counts for *field* within the time window (terms aggregation).

        Returns a list of ``{"key": value, "count": N}`` dicts, sorted by count desc.
        """
        col = _FIELD_MAP.get(field)
        if col is None:
            return []

        t_from = _parse_time(time_from)
        t_to = _parse_time(time_to)

        q = (
            select(col.label("key"), func.count().label("count"))
            .where(Event.time >= t_from, Event.time <= t_to)
            .group_by(col)
            .order_by(func.count().desc())
            .limit(limit)
        )
        rows = await session.execute(q)
        return [{"key": str(r.key) if r.key is not None else "", "count": r.count}
                for r in rows]

    @staticmethod
    async def histogram_by_time(
        session: AsyncSession,
        *,
        interval: str = "1h",
        time_from: str = "now-7d",
        time_to: str = "now",
    ) -> list[dict]:
        """Return event counts grouped by time interval (date_histogram aggregation).

        Bucketing is done in Python after fetching the ``time`` column so the
        method works across SQLite (tests) and PostgreSQL (production) without
        dialect-specific SQL.

        Supported *interval* values: ``1m``, ``1h``, ``1d``, ``1w``, ``1M``
        (and long forms: ``minute``, ``hour``, ``day``, ``week``, ``month``).

        Returns a list of ``{"key": iso_timestamp, "count": N}`` dicts sorted by
        time ascending, ready for time-series charting.
        """
        def _trunc_minute(t: datetime) -> datetime:
            return t.replace(second=0, microsecond=0)

        def _trunc_hour(t: datetime) -> datetime:
            return t.replace(minute=0, second=0, microsecond=0)

        def _trunc_day(t: datetime) -> datetime:
            return t.replace(hour=0, minute=0, second=0, microsecond=0)

        def _trunc_week(t: datetime) -> datetime:
            # Truncate to ISO Monday 00:00:00
            return (t - timedelta(
                days=t.weekday(), hours=t.hour,
                minutes=t.minute, seconds=t.second, microseconds=t.microsecond
            ))

        def _trunc_month(t: datetime) -> datetime:
            return t.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

        _TRUNC: dict[str, Any] = {
            "1m": _trunc_minute, "minute": _trunc_minute,
            "1h": _trunc_hour,   "hour":   _trunc_hour,
            "1d": _trunc_day,    "24h":    _trunc_day,    "day":   _trunc_day,
            "1w": _trunc_week,   "week":   _trunc_week,
            "1M": _trunc_month,  "month":  _trunc_month,
        }
        trunc_fn = _TRUNC.get(interval)
        if trunc_fn is None:
            return []

        t_from = _parse_time(time_from)
        t_to   = _parse_time(time_to)

        q = select(Event.time).where(Event.time >= t_from, Event.time <= t_to)
        rows = await session.execute(q)

        counts: dict[datetime, int] = {}
        for (t,) in rows:
            if t.tzinfo is None:
                t = t.replace(tzinfo=timezone.utc)
            bucket = trunc_fn(t)
            counts[bucket] = counts.get(bucket, 0) + 1

        return [
            {"key": dt.isoformat(), "count": cnt}
            for dt, cnt in sorted(counts.items())
        ]

    @staticmethod
    async def entity_events(
        session: AsyncSession,
        entity_type: str,
        entity_value: str,
        *,
        time_from: str = "now-7d",
        size: int = 200,
    ) -> tuple[list[Event], int]:
        """Return all events involving a specific entity (IP, host, user, hash)."""
        cols = _ENTITY_MAP.get(entity_type, [Event.hostname])
        t_from = _parse_time(time_from)

        conditions = [col == entity_value for col in cols]
        q = (
            select(Event)
            .where(Event.time >= t_from, or_(*conditions))
            .order_by(Event.time.desc())
        )

        count_q = select(func.count()).select_from(q.subquery())
        total = await session.scalar(count_q) or 0

        q = q.limit(size)
        result = await session.execute(q)
        return list(result.scalars().all()), total

    @staticmethod
    async def count(session: AsyncSession) -> int:
        result = await session.scalar(select(func.count()).select_from(Event))
        return result or 0
