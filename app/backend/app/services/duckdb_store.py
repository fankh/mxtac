"""DuckDB embedded event store — feature 20.9.

Provides an embedded OLAP analytics layer for security events without
requiring an external OpenSearch cluster.  DuckDB stores a mirror of
every OCSF-normalised event and answers search / aggregation queries
locally, making the platform fully self-contained.

Architecture
------------
- DuckDB's Python API is synchronous.  All operations run inside a
  single-thread ``ThreadPoolExecutor`` so they never block the asyncio
  event loop and the underlying connection is never accessed from
  multiple threads concurrently.
- Events are written to DuckDB in parallel with PostgreSQL (and
  OpenSearch when enabled) inside ``event_persister``.
- When OpenSearch is unavailable or disabled, the search / aggregate
  API endpoints prefer DuckDB over raw PostgreSQL scans.

Search priority (POST /events/search, POST /events/aggregate):
  1. OpenSearch  — if ``os_client.is_available``
  2. DuckDB      — if ``duckdb_enabled=True`` and ``is_available``
  3. PostgreSQL  — always available as the authoritative store
"""

from __future__ import annotations

import json
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from functools import partial
from typing import Any

from ..core.logging import get_logger

logger = get_logger(__name__)


# ── Time parsing (mirrors event_repo._parse_time) ─────────────────────────────

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
    return datetime.fromisoformat(t.replace("Z", "+00:00"))


# ── Interval → DATE_TRUNC unit mapping for date_histogram ────────────────────

_TRUNC_UNIT: dict[str, str] = {
    "1m":     "minute",
    "minute": "minute",
    "1h":     "hour",
    "hour":   "hour",
    "1d":     "day",
    "24h":    "day",
    "day":    "day",
    "1w":     "week",
    "week":   "week",
    "1M":     "month",
    "month":  "month",
}

# ── Field mapping (mirrors event_repo._FIELD_MAP) ─────────────────────────────
# Maps EventFilter.field names (including OpenSearch nested-path aliases) to
# DuckDB column names in the events table.

_FIELD_MAP: dict[str, str] = {
    "severity_id":           "severity_id",
    "class_name":            "class_name",
    "class_uid":             "class_uid",
    "src_ip":                "src_ip",
    "dst_ip":                "dst_ip",
    "hostname":              "hostname",
    "username":              "username",
    "process_hash":          "process_hash",
    "source":                "source",
    # OpenSearch nested-field aliases
    "src_endpoint.ip":       "src_ip",
    "dst_endpoint.ip":       "dst_ip",
    "dst_endpoint.hostname": "hostname",
    "actor_user.name":       "username",
    "process.hash_sha256":   "process_hash",
}

# ── DDL ───────────────────────────────────────────────────────────────────────

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS events (
    id           VARCHAR PRIMARY KEY,
    event_uid    VARCHAR,
    time         TIMESTAMPTZ,
    class_name   VARCHAR,
    class_uid    INTEGER,
    severity_id  INTEGER,
    src_ip       VARCHAR,
    dst_ip       VARCHAR,
    hostname     VARCHAR,
    username     VARCHAR,
    process_hash VARCHAR,
    source       VARCHAR,
    summary      VARCHAR,
    raw          JSON
)
"""

_CREATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_dkevt_time     ON events (time)",
    "CREATE INDEX IF NOT EXISTS idx_dkevt_source   ON events (source)",
    "CREATE INDEX IF NOT EXISTS idx_dkevt_severity ON events (severity_id)",
    "CREATE INDEX IF NOT EXISTS idx_dkevt_hostname ON events (hostname)",
]


# ── DuckDB store ──────────────────────────────────────────────────────────────


class DuckDBEventStore:
    """Embedded DuckDB analytics store for OCSF security events.

    Thread safety: all synchronous DuckDB operations run in a dedicated
    single-thread ``ThreadPoolExecutor`` so the underlying connection is
    never accessed from multiple threads concurrently.
    """

    def __init__(self, path: str = ":memory:") -> None:
        self._path = path
        self._conn: Any = None          # duckdb.DuckDBPyConnection
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="duckdb")
        self._available = False

    @property
    def is_available(self) -> bool:
        return self._available

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def connect(self) -> None:
        """Open the DuckDB connection and initialise the events schema."""
        try:
            await self._run(self._sync_connect)
            self._available = True
            logger.info("DuckDB event store connected path=%r", self._path)
        except Exception:
            logger.exception("DuckDB connect failed — analytics store unavailable")
            self._available = False

    def _sync_connect(self) -> None:
        import duckdb  # deferred — only fails if duckdb package not installed

        self._conn = duckdb.connect(self._path)
        self._conn.execute(_CREATE_TABLE)
        for idx_sql in _CREATE_INDEXES:
            self._conn.execute(idx_sql)

    async def close(self) -> None:
        """Close the DuckDB connection and shut down the executor thread."""
        try:
            if self._conn is not None:
                await self._run(self._conn.close)
            self._available = False
        except Exception:
            logger.exception("DuckDB close failed")
        finally:
            self._executor.shutdown(wait=False)

    # ── Write ──────────────────────────────────────────────────────────────────

    async def index_event(
        self,
        event_dict: dict[str, Any],
        doc_id: str | None = None,
    ) -> None:
        """Upsert one OCSF event into the DuckDB events table.

        *doc_id* should be the PostgreSQL UUID so both stores share the
        same identifier.  Falls back to the event's own ``id`` field or a
        generated UUID when not provided.
        """
        if not self._available or self._conn is None:
            return
        try:
            await self._run(partial(self._sync_index_event, event_dict, doc_id))
        except Exception:
            logger.exception("DuckDB index_event failed (non-fatal)")

    def _sync_index_event(
        self,
        event_dict: dict[str, Any],
        doc_id: str | None,
    ) -> None:
        import uuid

        src_ep   = event_dict.get("src_endpoint") or {}
        dst_ep   = event_dict.get("dst_endpoint") or {}
        actor    = event_dict.get("actor_user") or {}
        proc     = event_dict.get("process") or {}
        unmapped = event_dict.get("unmapped") or {}
        finding  = event_dict.get("finding_info") or {}

        raw_time = event_dict.get("time")
        if isinstance(raw_time, str):
            try:
                time_val: datetime = datetime.fromisoformat(raw_time)
            except ValueError:
                time_val = datetime.now(timezone.utc)
        elif isinstance(raw_time, datetime):
            time_val = raw_time
        else:
            time_val = datetime.now(timezone.utc)

        summary: str | None = (
            unmapped.get("summary")
            or (finding.get("title") if finding else None)
        )

        row_id = (
            doc_id
            or event_dict.get("id")
            or str(uuid.uuid4())
        )

        self._conn.execute(
            """
            INSERT OR REPLACE INTO events
                (id, event_uid, time, class_name, class_uid, severity_id,
                 src_ip, dst_ip, hostname, username, process_hash, source,
                 summary, raw)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                row_id,
                event_dict.get("metadata_uid"),
                time_val,
                event_dict.get("class_name"),
                event_dict.get("class_uid"),
                event_dict.get("severity_id"),
                src_ep.get("ip"),
                dst_ep.get("ip"),
                src_ep.get("hostname") or dst_ep.get("hostname"),
                actor.get("name"),
                proc.get("hash_sha256"),
                event_dict.get("metadata_product"),
                summary,
                json.dumps(event_dict),
            ],
        )

    # ── Search ─────────────────────────────────────────────────────────────────

    async def search_events(
        self,
        query: str | None = None,
        filters: list[Any] | None = None,
        time_from: str = "now-7d",
        time_to: str = "now",
        size: int = 100,
        from_: int = 0,
    ) -> dict[str, Any]:
        """Full-text + filtered event search with time range.

        Returns ``{"total": int, "items": list[dict]}``.
        """
        if not self._available or self._conn is None:
            return {"total": 0, "items": []}
        try:
            return await self._run(
                partial(
                    self._sync_search,
                    query,
                    filters or [],
                    time_from,
                    time_to,
                    size,
                    from_,
                )
            )
        except Exception:
            logger.exception("DuckDB search_events failed")
            return {"total": 0, "items": []}

    def _sync_search(
        self,
        query: str | None,
        filters: list[Any],
        time_from: str,
        time_to: str,
        size: int,
        from_: int,
    ) -> dict[str, Any]:
        dt_from = _parse_time(time_from)
        dt_to   = _parse_time(time_to)

        conditions: list[str] = ["time >= ? AND time <= ?"]
        params: list[Any] = [dt_from, dt_to]

        # Full-text search across key text fields
        if query:
            like = f"%{query}%"
            conditions.append(
                "(summary ILIKE ? OR hostname ILIKE ? OR username ILIKE ?"
                " OR src_ip ILIKE ? OR dst_ip ILIKE ?)"
            )
            params.extend([like, like, like, like, like])

        # Structured filters
        for f in filters:
            col = _FIELD_MAP.get(f.field)
            if col is None:
                continue
            op  = f.operator
            val = f.value
            if op == "eq":
                conditions.append(f"{col} = ?")
                params.append(val)
            elif op == "ne":
                conditions.append(f"{col} != ?")
                params.append(val)
            elif op == "gt":
                conditions.append(f"{col} > ?")
                params.append(val)
            elif op == "lt":
                conditions.append(f"{col} < ?")
                params.append(val)
            elif op == "gte":
                conditions.append(f"{col} >= ?")
                params.append(val)
            elif op == "lte":
                conditions.append(f"{col} <= ?")
                params.append(val)
            elif op == "contains":
                conditions.append(f"{col} ILIKE ?")
                params.append(f"%{val}%")

        where = " AND ".join(conditions)

        total: int = self._conn.execute(
            f"SELECT COUNT(*) FROM events WHERE {where}",
            params,
        ).fetchone()[0]

        rows = self._conn.execute(
            f"SELECT id, event_uid, time, class_name, class_uid, severity_id,"
            f" src_ip, dst_ip, hostname, username, process_hash, source, summary, raw"
            f" FROM events WHERE {where} ORDER BY time DESC LIMIT ? OFFSET ?",
            params + [size, from_],
        ).fetchall()

        return {"total": total, "items": [_row_to_dict(r) for r in rows]}

    # ── Aggregations ───────────────────────────────────────────────────────────

    async def aggregate(
        self,
        agg_type: str,
        field: str | None = None,
        interval: str = "1h",
        time_from: str = "now-7d",
        time_to: str = "now",
        size: int = 10,
    ) -> list[dict[str, Any]]:
        """Terms or date_histogram aggregation.

        Returns a list of ``{"key": str, "count": int}`` buckets.
        """
        if not self._available or self._conn is None:
            return []
        try:
            return await self._run(
                partial(
                    self._sync_aggregate,
                    agg_type,
                    field,
                    interval,
                    time_from,
                    time_to,
                    size,
                )
            )
        except Exception:
            logger.exception("DuckDB aggregate failed")
            return []

    def _sync_aggregate(
        self,
        agg_type: str,
        field: str | None,
        interval: str,
        time_from: str,
        time_to: str,
        size: int,
    ) -> list[dict[str, Any]]:
        dt_from = _parse_time(time_from)
        dt_to   = _parse_time(time_to)

        if agg_type == "date_histogram":
            trunc = _TRUNC_UNIT.get(interval, "hour")
            sql = (
                f"SELECT DATE_TRUNC('{trunc}', time) AS key, COUNT(*) AS count"
                f" FROM events WHERE time >= ? AND time <= ?"
                f" GROUP BY key ORDER BY key ASC"
            )
            rows = self._conn.execute(sql, [dt_from, dt_to]).fetchall()
            return [
                {
                    "key": r[0].isoformat() if isinstance(r[0], datetime) else str(r[0]),
                    "count": r[1],
                }
                for r in rows
            ]

        # terms aggregation
        col = _FIELD_MAP.get(field or "source", "source")
        sql = (
            f"SELECT {col} AS key, COUNT(*) AS count"
            f" FROM events WHERE time >= ? AND time <= ? AND {col} IS NOT NULL"
            f" GROUP BY key ORDER BY count DESC LIMIT ?"
        )
        rows = self._conn.execute(sql, [dt_from, dt_to, size]).fetchall()
        return [{"key": str(r[0]), "count": r[1]} for r in rows]

    # ── Event count ────────────────────────────────────────────────────────────

    async def total_count(self) -> int:
        """Return total number of events stored in DuckDB."""
        if not self._available or self._conn is None:
            return 0
        try:
            result = await self._run(
                partial(self._conn.execute, "SELECT COUNT(*) FROM events")
            )
            row = result.fetchone()
            return row[0] if row else 0
        except Exception:
            logger.exception("DuckDB total_count failed")
            return 0

    # ── Internal ──────────────────────────────────────────────────────────────

    async def _run(self, fn, *args):
        """Execute *fn* in the dedicated DuckDB thread."""
        loop = __import__("asyncio").get_running_loop()
        if args:
            return await loop.run_in_executor(self._executor, partial(fn, *args))
        return await loop.run_in_executor(self._executor, fn)


# ── Row deserialisation ────────────────────────────────────────────────────────


def _row_to_dict(row: tuple) -> dict[str, Any]:
    """Convert a DuckDB SELECT result row to the standard event response dict."""
    (
        id_, event_uid, time_, class_name, class_uid, severity_id,
        src_ip, dst_ip, hostname, username, process_hash, source, summary, raw_val,
    ) = row

    base: dict[str, Any] = {
        "id":           id_,
        "event_uid":    event_uid,
        "time":         time_.isoformat() if isinstance(time_, datetime) else time_,
        "class_name":   class_name,
        "class_uid":    class_uid,
        "severity_id":  severity_id,
        "src_ip":       src_ip,
        "dst_ip":       dst_ip,
        "hostname":     hostname,
        "username":     username,
        "process_hash": process_hash,
        "source":       source,
        "summary":      summary,
    }

    # Merge the full raw OCSF payload so callers get all fields
    if raw_val:
        try:
            raw = json.loads(raw_val) if isinstance(raw_val, str) else raw_val
            if isinstance(raw, dict):
                base.update(raw)
        except (json.JSONDecodeError, TypeError):
            pass

    return base


# ── Singleton ─────────────────────────────────────────────────────────────────

_instance: DuckDBEventStore | None = None


def get_duckdb() -> DuckDBEventStore:
    """Return the global DuckDB event store instance (created lazily)."""
    global _instance
    if _instance is None:
        from ..core.config import settings

        path = settings.duckdb_path if settings.duckdb_enabled else ":memory:"
        _instance = DuckDBEventStore(path=path)
    return _instance


def get_duckdb_dep() -> DuckDBEventStore:
    """FastAPI dependency — returns the global DuckDB store instance."""
    return get_duckdb()
