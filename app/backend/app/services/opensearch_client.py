"""
OpenSearch event storage service.

Index naming:
  mxtac-events-v2-{YYYY.MM.DD} — event documents (daily rollover); the
                                document is defined in ``event_document.py``
  mxtac-events-{YYYY.MM.DD}   — legacy event indices of earlier versions
                                (nested event only, not searched; their
                                events are re-indexed from PostgreSQL)
  mxtac-alerts-{YYYY.MM.DD}   — enriched alerts
  mxtac-audit-{YYYY.MM}       — audit log entries (monthly rollover, 3-year retention)
  mxtac-rules                 — Sigma rules (single index)

Uses opensearch-py (async client).
"""

from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from typing import Any

try:
    from opensearchpy.exceptions import ConnectionError as OpenSearchConnectionError
except ImportError:   # opensearch-py not installed — OpenSearch storage is disabled
    OpenSearchConnectionError = ConnectionError   # type: ignore[assignment,misc]

from ..core.config import settings
from ..core.logging import get_logger
from .event_document import CMD_LINE_PATH, FILTER_FIELDS, NUMERIC_FIELDS, TEXT_SEARCH_FIELDS

logger = get_logger(__name__)

# Index templates
EVENTS_INDEX_TEMPLATE = "mxtac-events"
# Event documents are written to and searched in the versioned indices only.
# ``mxtac-events-*`` (retention policy, storage metrics) also covers them.
EVENTS_INDEX_PREFIX = f"{EVENTS_INDEX_TEMPLATE}-v2"
# Deepest page of POST /events/search: from_ <= 100000, size <= 1000.
EVENTS_MAX_RESULT_WINDOW = 101_000
# After an event query that could not reach OpenSearch, queries are not sent
# for this many seconds (the caller answers from PostgreSQL).  A request to an
# unreachable cluster takes several seconds to fail; without the pause every
# search would.
QUERY_RETRY_SECONDS = 30.0
# Mapping ``_meta`` key set on a legacy event index after its events were
# re-indexed from PostgreSQL into the versioned indices.
_REINDEXED_META_KEY = "mxtac_reindexed"
ALERTS_INDEX_TEMPLATE = "mxtac-alerts"
AUDIT_INDEX_TEMPLATE = "mxtac-audit"
RULES_INDEX = "mxtac-rules"

# ILM / ISM policy — events & alerts (90-day, legacy name kept for compat)
ILM_POLICY_NAME = "mxtac-90day-retention"
ILM_RETENTION_DAYS = 90

# ILM / ISM policy — audit logs (3-year / 1095-day, legacy name kept for compat)
AUDIT_ILM_POLICY_NAME = "mxtac-3year-audit-retention"
AUDIT_ILM_RETENTION_DAYS = 1095  # 365 × 3

# Per-type ILM policy names — feature 38.2 (hot/warm/delete lifecycle)
EVENTS_ILM_POLICY_NAME = "mxtac-events-ilm"
ALERTS_ILM_POLICY_NAME = "mxtac-alerts-ilm"
AUDIT_TYPE_ILM_POLICY_NAME = "mxtac-audit-ilm"

# Hot-phase durations: indices stay in hot before transitioning to warm
EVENTS_HOT_DAYS = 7
ALERTS_HOT_DAYS = 30
AUDIT_HOT_DAYS = 90

# ---------------------------------------------------------------------------
# Index mapping constants — feature 12.10
#
# Extracted as module-level constants so that:
#   a) ensure_indices() is kept DRY (references these dicts directly), and
#   b) unit tests can assert field types without mocking the OpenSearch client.
#
# Field type decisions:
#   - IP addresses  → "ip"       (enables CIDR and range queries)
#   - Exact strings → "keyword"  (enables aggregations, sorting, exact-match)
#   - Free text     → "text"     (tokenised for full-text search)
#   - Text+keyword  → multi-field with ".keyword" sub-field
#   - Timestamps    → "date"     (ISO-8601 / epoch-millis)
#   - Scores/rates  → "float"    (risk_score, normalised score)
#   - Counters/IDs  → "integer" or "long"
# ---------------------------------------------------------------------------

# Longest string a keyword field indexes.  A Lucene term is limited to 32766
# bytes; 8191 characters stay below it in UTF-8.
_KEYWORD_MAX_CHARS = 8191

#: Mapping body for mxtac-events-v2-* indices (event documents).
#:
#: The document is the event row as the API returns it: the flat fields
#: searches use, plus the nested OCSF event.  Only the fields listed here are
#: indexed (``dynamic: false``); everything else is kept in ``_source`` and
#: returned, but a free-form source field can never break the mapping.
EVENTS_MAPPING: dict[str, Any] = {
    "dynamic": False,
    "properties": {
        # ── Flat fields: the columns of the ``events`` table ─────────────
        # Strings are keywords (exact match, substring match by wildcard,
        # terms aggregation).  Numbers have a keyword sub-field for the
        # ``contains`` operator.
        "id":                     {"type": "keyword"},
        "event_uid":              {"type": "keyword"},
        "time":                   {"type": "date_nanos"},
        "class_name":             {"type": "keyword"},
        "class_uid":              {
            "type": "integer",
            "fields": {"text": {"type": "keyword"}},
        },
        "severity_id":            {
            "type": "integer",
            "fields": {"text": {"type": "keyword"}},
        },
        "src_ip":                 {"type": "keyword"},
        "dst_ip":                 {"type": "keyword"},
        "hostname":               {"type": "keyword"},
        "username":               {"type": "keyword"},
        "process_hash":           {"type": "keyword"},
        "source":                 {"type": "keyword"},
        "summary":                {"type": "keyword", "ignore_above": _KEYWORD_MAX_CHARS},
        # ── Top-level OCSF fields ────────────────────────────────────────
        "metadata_uid":           {"type": "keyword"},
        "severity_name":          {"type": "keyword"},
        "metadata_product":       {"type": "keyword"},
        "metadata_version":       {"type": "keyword"},
        "risk_score_normalized":  {"type": "float"},
        # ── Source endpoint ──────────────────────────────────────────────
        "src_endpoint": {
            "type": "object",
            "properties": {
                "ip":       {"type": "ip"},
                "hostname": {"type": "keyword"},
                "port":     {"type": "integer"},
                "domain":   {"type": "keyword"},
                "os_name":  {"type": "keyword"},
            },
        },
        # ── Destination endpoint ─────────────────────────────────────────
        "dst_endpoint": {
            "type": "object",
            "properties": {
                "ip":       {"type": "ip"},
                "hostname": {"type": "keyword"},
                "port":     {"type": "integer"},
                "domain":   {"type": "keyword"},
                "os_name":  {"type": "keyword"},
            },
        },
        # ── Actor / user context ─────────────────────────────────────────
        "actor_user": {
            "type": "object",
            "properties": {
                "name":          {"type": "keyword"},
                "uid":           {"type": "keyword"},
                "domain":        {"type": "keyword"},
                "email_addr":    {"type": "keyword"},
                "full_name":     {
                    "type": "text",
                    "fields": {"keyword": {"type": "keyword"}},
                },
                "is_privileged": {"type": "boolean"},
            },
        },
        # ── Process context ──────────────────────────────────────────────
        "process": {
            "type": "object",
            "properties": {
                "pid":         {"type": "integer"},
                "name":        {"type": "keyword"},
                "cmd_line":    {"type": "keyword", "ignore_above": _KEYWORD_MAX_CHARS},
                "path":        {"type": "keyword"},
                "parent_pid":  {"type": "integer"},
                "hash_sha256": {"type": "keyword"},
                "hash_sha1":   {"type": "keyword"},
                "hash_md5":    {"type": "keyword"},
            },
        },
        # ── Network traffic details ──────────────────────────────────────
        "network_traffic": {
            "type": "object",
            "properties": {
                "bytes_in":      {"type": "long"},
                "bytes_out":     {"type": "long"},
                "packets_in":    {"type": "long"},
                "packets_out":   {"type": "long"},
                "protocol_name": {"type": "keyword"},
                "protocol_ver":  {"type": "keyword"},
                "direction":     {"type": "keyword"},
            },
        },
        # ── File activity context ────────────────────────────────────────
        "file": {
            "type": "object",
            "properties": {
                "name":          {"type": "keyword"},
                "path":          {"type": "keyword"},
                "type":          {"type": "keyword"},
                "hash_sha256":   {"type": "keyword"},
                "hash_md5":      {"type": "keyword"},
                "size":          {"type": "long"},
                "created_time":  {"type": "date"},
                "modified_time": {"type": "date"},
                "accessed_time": {"type": "date"},
            },
        },
        # ── Finding / detection context ──────────────────────────────────
        "finding_info": {
            "type": "object",
            "properties": {
                "title":    {
                    "type": "text",
                    "fields": {"keyword": {"type": "keyword"}},
                },
                "uid":      {"type": "keyword"},
                "rule_uid": {"type": "keyword"},
            },
        },
        # ── Catch-all buckets (dynamic mapping preserved) ────────────────
        "unmapped": {"type": "object", "enabled": True},
        "raw":      {"type": "object", "enabled": True},
    },
}

#: Mapping body for mxtac-alerts-* indices (enriched detection alerts).
ALERTS_MAPPING: dict[str, Any] = {
    "properties": {
        "rule_id":         {"type": "keyword"},
        "rule_name":       {
            "type": "text",
            "fields": {"keyword": {"type": "keyword"}},
        },
        "severity_name":   {"type": "keyword"},
        "severity_id":     {"type": "integer"},
        "risk_score":      {"type": "float"},
        "detection_count": {"type": "integer"},
        "first_seen":      {"type": "date"},
        "last_seen":       {"type": "date"},
        "time":            {"type": "date"},
        "status":          {"type": "keyword"},
        "assigned_to":     {"type": "keyword"},
        "tags":            {"type": "keyword"},
        "class_name":      {"type": "keyword"},
        "src_endpoint": {
            "type": "object",
            "properties": {
                "ip":       {"type": "ip"},
                "hostname": {"type": "keyword"},
            },
        },
        "dst_endpoint": {
            "type": "object",
            "properties": {
                "ip":       {"type": "ip"},
                "hostname": {"type": "keyword"},
            },
        },
    }
}

#: Mapping body for mxtac-audit-* indices (audit log entries, feature 21.14).
AUDIT_MAPPING: dict[str, Any] = {
    "properties": {
        "id":             {"type": "keyword"},
        "timestamp":      {"type": "date"},
        "actor":          {"type": "keyword"},
        "action":         {"type": "keyword"},
        "resource_type":  {"type": "keyword"},
        "resource_id":    {"type": "keyword"},
        "details":        {"type": "object", "enabled": True},
        "request_ip":     {"type": "ip"},
        "request_method": {"type": "keyword"},
        "request_path":   {"type": "keyword"},
        "user_agent":     {"type": "text"},
    }
}

#: Mapping body for the mxtac-rules static index (Sigma detection rules).
RULES_MAPPING: dict[str, Any] = {
    "properties": {
        "id":          {"type": "keyword"},
        "title":       {
            "type": "text",
            "fields": {"keyword": {"type": "keyword"}},
        },
        "description": {"type": "text"},
        "logsource":   {"type": "object", "enabled": True},
        "detection":   {"type": "object", "enabled": True},
        "tags":        {"type": "keyword"},
        "level":       {"type": "keyword"},
        "status":      {"type": "keyword"},
        "author":      {
            "type": "text",
            "fields": {"keyword": {"type": "keyword"}},
        },
        "date":        {"type": "date"},
        "modified":    {"type": "date"},
        "references":  {"type": "text"},
    }
}

# Maps EventFilter.field names to their OpenSearch document fields: the flat
# fields of the event document, the same ones the PostgreSQL path filters on.
_OS_FIELD_MAP: dict[str, str] = dict(FILTER_FIELDS)

# Document fields matched by the free-text query.
_TEXT_SEARCH_FIELDS: tuple[str, ...] = (*TEXT_SEARCH_FIELDS, ".".join(CMD_LINE_PATH))

_WILDCARD_SPECIAL_RE = re.compile(r"([\\*?])")


class OpenSearchQueryError(Exception):
    """An event query could not be answered by OpenSearch.

    Raised instead of returning an empty result, so that the caller can answer
    from PostgreSQL rather than show "no events".
    """


def _substring_clause(field: str, value: Any) -> dict:
    """Case-insensitive substring match on a keyword field (SQL ``ILIKE '%v%'``)."""
    escaped = _WILDCARD_SPECIAL_RE.sub(r"\\\1", str(value))
    return {"wildcard": {field: {"value": f"*{escaped}*", "case_insensitive": True}}}


def filter_to_dsl(field: str, operator: str, value: Any) -> dict | None:
    """Convert an EventFilter (field, operator, value) to an OpenSearch DSL clause.

    The clauses select the same events as ``EventRepo`` does in SQL: ``eq`` is
    an exact match, ``contains`` a case-insensitive substring, and ``ne`` only
    matches events that have a value in the field (SQL ``<>`` semantics).

    Returns ``None`` if the field is unknown or operator is unsupported, so the
    caller can skip the clause instead of sending a malformed query.
    """
    os_field = _OS_FIELD_MAP.get(field)
    if os_field is None:
        return None

    if operator == "eq":
        return {"term": {os_field: value}}
    if operator == "ne":
        return {
            "bool": {
                "must":     [{"exists": {"field": os_field}}],
                "must_not": [{"term": {os_field: value}}],
            }
        }
    if operator == "contains":
        if os_field in NUMERIC_FIELDS:
            os_field = f"{os_field}.text"   # keyword copy of the number
        return _substring_clause(os_field, value)
    if operator == "gt":
        return {"range": {os_field: {"gt": value}}}
    if operator == "lt":
        return {"range": {os_field: {"lt": value}}}
    if operator == "gte":
        return {"range": {os_field: {"gte": value}}}
    if operator == "lte":
        return {"range": {os_field: {"lte": value}}}
    return None


def build_event_query(
    query: str | None,
    filters: list[dict] | None,
    time_from: str,
    time_to: str,
) -> dict:
    """Build the OpenSearch query for an event search.

    *query* is free text: a case-insensitive substring of the summary, class
    name, host, user, addresses or process command line — the same match the
    PostgreSQL path makes with ``ILIKE``.  *filters* are clauses from
    :func:`filter_to_dsl`.
    """
    must_clauses: list[dict] = []
    if query:
        must_clauses.append({
            "bool": {
                "should": [_substring_clause(f, query) for f in _TEXT_SEARCH_FIELDS],
                "minimum_should_match": 1,
            }
        })
    if filters:
        must_clauses.extend(filters)
    must_clauses.append({"range": {"time": {"gte": time_from, "lte": time_to}}})
    return {"bool": {"must": must_clauses}}


def _daily_index(base: str) -> str:
    return f"{base}-{datetime.now(timezone.utc).strftime('%Y.%m.%d')}"


def _monthly_index(base: str) -> str:
    """Return a monthly-rollover index name ``{base}-YYYY.MM`` (UTC).

    Used for audit indices which roll over monthly rather than daily.
    With a 3-year retention policy this caps the total number of audit
    indices at 36, compared to 1 095 if daily rollover were used.
    """
    return f"{base}-{datetime.now(timezone.utc).strftime('%Y.%m')}"


class OpenSearchService:
    """Async wrapper around opensearch-py for MxTac event storage."""

    def __init__(self) -> None:
        self._client = None
        self._skip_queries_until = 0.0   # time.monotonic() value

    @property
    def is_available(self) -> bool:
        """True when a live OpenSearch connection is established."""
        return self._client is not None

    async def connect(self) -> None:
        try:
            from opensearchpy import AsyncOpenSearch  # type: ignore[import-untyped]
            url = getattr(settings, "opensearch_url", "http://localhost:9200")
            self._client = AsyncOpenSearch(
                hosts=[url],
                http_auth=getattr(settings, "opensearch_http_auth", None),
                http_compress=True,
                use_ssl=url.startswith("https"),
                verify_certs=False,
                ssl_show_warn=False,
            )
            info = await self._client.info()
            logger.info("OpenSearch connected version=%s", info.get("version", {}).get("number"))
        except ImportError:
            logger.warning("opensearch-py not installed — OpenSearch storage disabled")
            self._client = None
        except Exception as exc:
            logger.warning("OpenSearch connection failed: %s", exc)
            self._client = None

    async def _query(self, what: str, body: dict[str, Any]) -> dict[str, Any]:
        """Run an event query.  Raises :class:`OpenSearchQueryError` on failure.

        When OpenSearch cannot be reached, the next queries fail at once for
        ``QUERY_RETRY_SECONDS``, without a request to OpenSearch.
        """
        if time.monotonic() < self._skip_queries_until:
            raise OpenSearchQueryError("OpenSearch is skipped after a connection failure")
        try:
            return await self._client.search(index=f"{EVENTS_INDEX_PREFIX}-*", body=body)
        except Exception as exc:
            logger.error("OpenSearch %s failed: %s", what, exc)
            if isinstance(exc, OpenSearchConnectionError):
                self._skip_queries_until = time.monotonic() + QUERY_RETRY_SECONDS
            raise OpenSearchQueryError(str(exc)) from exc

    async def index_event(self, event: dict[str, Any], doc_id: str | None = None) -> str | None:
        """Index an event document. Returns document ID or None.

        *event* is the document built by ``event_document.event_to_dict``.
        Pass ``doc_id`` to use the PostgreSQL UUID as the OpenSearch document ID
        so that both stores share the same identifier.
        """
        if self._client is None:
            return None
        idx = _daily_index(EVENTS_INDEX_PREFIX)
        try:
            resp = await self._client.index(
                index=idx, body=event, id=doc_id, refresh="false"
            )
            return resp.get("_id")
        except Exception as exc:
            logger.error("OpenSearch index_event failed: %s", exc)
            return None

    async def index_alert(self, alert: dict[str, Any]) -> str | None:
        """Index an enriched alert. Returns document ID or None."""
        if self._client is None:
            return None
        idx = _daily_index(ALERTS_INDEX_TEMPLATE)
        try:
            resp = await self._client.index(index=idx, body=alert, refresh="true")
            return resp.get("_id")
        except Exception as exc:
            logger.error("OpenSearch index_alert failed: %s", exc)
            return None

    async def search_events(
        self,
        query: str | None = None,
        filters: list[dict] | None = None,
        time_from: str = "now-7d",
        time_to: str = "now",
        size: int = 100,
        from_: int = 0,
    ) -> dict[str, Any]:
        """Free-text + filtered event search. Returns OpenSearch hits dict.

        The newest events come first; events with the same time are ordered by
        ID, as on the PostgreSQL path.  Raises :class:`OpenSearchQueryError`
        when the query fails.
        """
        if self._client is None:
            return {"hits": {"total": {"value": 0}, "hits": []}}

        body = {
            "query": build_event_query(query, filters, time_from, time_to),
            "sort":  [{"time": {"order": "desc"}}, {"id": {"order": "desc"}}],
            "size":  size,
            "from":  from_,
            "track_total_hits": True,
        }

        return await self._query("search_events", body)

    # ── Aggregation interval mapping ──────────────────────────────────────────
    _CALENDAR_INTERVALS: dict[str, str] = {
        "1m": "minute", "minute": "minute",
        "1h": "hour",   "hour":   "hour",
        "1d": "day",    "24h":    "day",    "day":   "day",
        "1w": "week",   "week":   "week",
        "1M": "month",  "month":  "month",
    }

    async def aggregate(
        self,
        agg_type: str,
        *,
        field: str | None = None,
        interval: str = "1h",
        time_from: str = "now-7d",
        time_to: str = "now",
        size: int = 10,
    ) -> list[dict]:
        """Run a terms or date_histogram aggregation over the events index.

        - ``agg_type="terms"`` groups by *field* value; returns buckets sorted by
          count descending: ``[{"key": value, "count": N}, ...]``.  Events
          without a value are counted under the key ``""``.
        - ``agg_type="date_histogram"`` buckets events by *interval*; returns
          buckets sorted by time ascending: ``[{"key": iso_ts, "count": N}, ...]``.

        The buckets have the same keys and order as those of ``EventRepo``.

        Returns an empty list when the client is unavailable or when a required
        parameter is missing/unknown.  Raises :class:`OpenSearchQueryError`
        when the query fails.
        """
        if self._client is None:
            return []

        base_query: dict[str, Any] = {
            "size": 0,
            "query": {"range": {"time": {"gte": time_from, "lte": time_to}}},
        }

        if agg_type == "terms":
            os_field = _OS_FIELD_MAP.get(field or "")
            if not os_field:
                logger.warning("aggregate(terms): unknown field %r — returning []", field)
                return []
            body = {
                **base_query,
                "aggs": {
                    "terms_agg": {
                        "terms": {
                            "field": os_field,
                            "size":  size,
                            "order": [{"_count": "desc"}, {"_key": "asc"}],
                        }
                    },
                    "missing_agg": {"missing": {"field": os_field}},
                },
            }
            resp = await self._query("aggregate(terms)", body)
            aggs = resp.get("aggregations", {})
            buckets = [
                {"key": str(b["key"]), "count": b["doc_count"]}
                for b in aggs.get("terms_agg", {}).get("buckets", [])
            ]
            # Events without a value: one bucket with an empty key, placed
            # after the buckets of the same or a higher count
            missing = aggs.get("missing_agg", {}).get("doc_count", 0)
            if missing:
                pos = sum(1 for b in buckets if b["count"] >= missing)
                buckets.insert(pos, {"key": "", "count": missing})
            return buckets[:size]

        if agg_type == "date_histogram":
            cal_interval = self._CALENDAR_INTERVALS.get(interval)
            if cal_interval is None:
                logger.warning("aggregate(date_histogram): unknown interval %r — returning []", interval)
                return []
            body = {
                **base_query,
                "aggs": {
                    "histogram_agg": {
                        "date_histogram": {
                            "field":             "time",
                            "calendar_interval": cal_interval,
                            "min_doc_count":     1,
                            "order":             {"_key": "asc"},
                        }
                    }
                },
            }
            resp = await self._query("aggregate(date_histogram)", body)
            raw = resp.get("aggregations", {}).get("histogram_agg", {}).get("buckets", [])
            # Bucket key: start of the interval in UTC, ISO 8601 (``key`` is epoch millis)
            return [
                {
                    "key": datetime.fromtimestamp(b["key"] / 1000, tz=timezone.utc).isoformat(),
                    "count": b["doc_count"],
                }
                for b in raw
            ]

        logger.warning("aggregate: unsupported agg_type %r — returning []", agg_type)
        return []

    async def get_event(self, event_id: str, index: str | None = None) -> dict | None:
        if self._client is None:
            return None
        idx = index or f"{EVENTS_INDEX_PREFIX}-*"
        try:
            resp = await self._client.get(index=idx, id=event_id)
            return resp.get("_source")
        except Exception:
            return None

    # ── Re-indexing from PostgreSQL ───────────────────────────────────────────

    async def legacy_event_indices(self) -> list[str]:
        """Names of the event indices of earlier versions not yet re-indexed.

        Those indices (``mxtac-events-YYYY.MM.DD``) hold the nested event
        without the flat fields and are not searched.  An index is marked in
        its mapping ``_meta`` once its events have been re-indexed.
        """
        if self._client is None:
            return []
        try:
            mappings = await self._client.indices.get_mapping(
                index=f"{EVENTS_INDEX_TEMPLATE}-*,-{EVENTS_INDEX_PREFIX}-*",
                params={"ignore_unavailable": "true", "allow_no_indices": "true"},
            )
        except Exception as exc:
            logger.warning("OpenSearch legacy_event_indices failed: %s", exc)
            return []
        return sorted(
            name for name, body in mappings.items()
            if not ((body.get("mappings") or {}).get("_meta") or {}).get(_REINDEXED_META_KEY)
        )

    async def mark_legacy_indices_reindexed(self, names: list[str]) -> None:
        """Record in the mapping ``_meta`` of *names* that their events were re-indexed."""
        if self._client is None:
            return
        for name in names:
            await self._client.indices.put_mapping(
                index=name, body={"_meta": {_REINDEXED_META_KEY: True}}
            )

    async def missing_event_ids(self, ids: list[str]) -> set[str]:
        """Return the IDs from *ids* that have no document in the event indices."""
        if self._client is None or not ids:
            return set()
        resp = await self._client.search(
            index=f"{EVENTS_INDEX_PREFIX}-*",
            body={
                "query": {"ids": {"values": ids}},
                "size": len(ids),
                "_source": False,
            },
            params={"ignore_unavailable": "true", "allow_no_indices": "true"},
        )
        found = {hit["_id"] for hit in resp.get("hits", {}).get("hits", [])}
        return set(ids) - found

    async def bulk_index_events(self, events: list[dict[str, Any]]) -> int:
        """Index event documents in one request (document ID = ``event["id"]``).

        Returns the number of documents indexed.
        """
        if self._client is None or not events:
            return 0
        idx = _daily_index(EVENTS_INDEX_PREFIX)
        body: list[dict[str, Any]] = []
        for event in events:
            body.append({"index": {"_index": idx, "_id": event["id"]}})
            body.append(event)
        resp = await self._client.bulk(body=body, params={"refresh": "true"})
        failed = [
            item["index"] for item in resp.get("items", [])
            if item.get("index", {}).get("error")
        ]
        if failed:
            logger.error(
                "OpenSearch bulk_index_events: %d of %d documents failed, first error: %s",
                len(failed), len(events), failed[0]["error"],
            )
        return len(events) - len(failed)

    async def upsert_rule(self, rule: dict[str, Any]) -> None:
        if self._client is None:
            return
        try:
            await self._client.index(
                index=RULES_INDEX,
                id=rule["id"],
                body=rule,
                refresh="true",
            )
        except Exception as exc:
            logger.error("OpenSearch upsert_rule failed: %s", exc)

    async def ensure_indices(self) -> None:
        """Create index templates for events/alerts and ensure the rules index exists.

        Uses ``indices.put_index_template`` for the daily-rollover indices so that
        every new ``mxtac-events-v2-YYYY.MM.DD`` / ``mxtac-alerts-YYYY.MM.DD`` index
        inherits the correct field mappings automatically.  The static
        ``mxtac-rules`` index is created directly if it does not yet exist.

        Safe to call multiple times — templates are idempotent (PUT) and the
        rules-index creation is guarded by an existence check.  If no client is
        available this method is a no-op.
        """
        if self._client is None:
            return

        # ── mxtac-events-v2-* index template ──────────────────────────────────
        try:
            await self._client.indices.put_index_template(
                name="mxtac-events-template",
                body={
                    "index_patterns": [f"{EVENTS_INDEX_PREFIX}-*"],
                    "template": {
                        "settings": {
                            "number_of_shards": 3,
                            "number_of_replicas": 1,
                            "plugins.index_state_management.policy_id": EVENTS_ILM_POLICY_NAME,
                            # A value that does not fit its mapped type (a
                            # non-numeric port, a date out of range) must not
                            # keep the whole event out of the index.
                            "index.mapping.ignore_malformed": True,
                            # The search endpoint pages up to from_=100000, size=1000.
                            "index.max_result_window": EVENTS_MAX_RESULT_WINDOW,
                        },
                        "mappings": EVENTS_MAPPING,
                    },
                },
            )
            logger.info("Applied index template: mxtac-events-template")
        except Exception as exc:
            logger.warning("ensure_indices: events template failed: %s", exc)

        # ── mxtac-alerts-* index template ─────────────────────────────────────
        try:
            await self._client.indices.put_index_template(
                name="mxtac-alerts-template",
                body={
                    "index_patterns": [f"{ALERTS_INDEX_TEMPLATE}-*"],
                    "template": {
                        "settings": {
                            "number_of_shards": 3,
                            "number_of_replicas": 1,
                            "plugins.index_state_management.policy_id": ALERTS_ILM_POLICY_NAME,
                        },
                        "mappings": ALERTS_MAPPING,
                    },
                },
            )
            logger.info("Applied index template: mxtac-alerts-template")
        except Exception as exc:
            logger.warning("ensure_indices: alerts template failed: %s", exc)

        # ── mxtac-audit-* index template (feature 38.2: 3-year retention) ──────
        try:
            await self._client.indices.put_index_template(
                name="mxtac-audit-template",
                body={
                    "index_patterns": [f"{AUDIT_INDEX_TEMPLATE}-*"],
                    "template": {
                        "settings": {
                            "number_of_shards": 1,
                            "number_of_replicas": 1,
                            "plugins.index_state_management.policy_id": AUDIT_TYPE_ILM_POLICY_NAME,
                        },
                        "mappings": AUDIT_MAPPING,
                    },
                },
            )
            logger.info("Applied index template: mxtac-audit-template")
        except Exception as exc:
            logger.warning("ensure_indices: audit template failed: %s", exc)

        # ── mxtac-rules (single static index) ─────────────────────────────────
        try:
            exists = await self._client.indices.exists(index=RULES_INDEX)
            if not exists:
                await self._client.indices.create(
                    index=RULES_INDEX,
                    body={
                        "settings": {
                            "number_of_shards": 1,
                            "number_of_replicas": 1,
                        },
                        "mappings": RULES_MAPPING,
                    },
                )
                logger.info("Created rules index: %s", RULES_INDEX)
            else:
                logger.debug("Rules index already exists: %s", RULES_INDEX)
        except Exception as exc:
            logger.warning("ensure_indices: rules index failed: %s", exc)

    async def ensure_ilm_policy(self) -> None:
        """Create or update the ISM policy that enforces 90-day index retention.

        Creates an OpenSearch ISM (Index State Management) policy named
        ``mxtac-90day-retention`` that automatically deletes
        ``mxtac-events-*`` and ``mxtac-alerts-*`` indices after 90 days.

        The policy body uses two states:
        - ``ingest`` — the initial state; transitions to ``delete`` once the
          index reaches ``ILM_RETENTION_DAYS`` days old.
        - ``delete`` — removes the index.

        The ``ism_template`` section auto-attaches the policy to every new
        index whose name matches the events or alerts wildcard patterns, so no
        additional per-index configuration is required.

        This operation is idempotent — a PUT on an existing policy updates it.
        If the ISM plugin is unavailable (e.g. a minimal OpenSearch build) the
        failure is logged at WARNING level and startup continues normally.
        """
        if self._client is None:
            return

        policy_body = {
            "policy": {
                "description": (
                    f"Delete MxTac event/alert indices after {ILM_RETENTION_DAYS} days."
                ),
                "default_state": "ingest",
                "states": [
                    {
                        "name": "ingest",
                        "actions": [],
                        "transitions": [
                            {
                                "state_name": "delete",
                                "conditions": {
                                    "min_index_age": f"{ILM_RETENTION_DAYS}d"
                                },
                            }
                        ],
                    },
                    {
                        "name": "delete",
                        "actions": [{"delete": {}}],
                        "transitions": [],
                    },
                ],
                "ism_template": [
                    {
                        "index_patterns": [
                            f"{EVENTS_INDEX_TEMPLATE}-*",
                            f"{ALERTS_INDEX_TEMPLATE}-*",
                        ],
                        "priority": 100,
                    }
                ],
            }
        }

        try:
            await self._client.transport.perform_request(
                "PUT",
                f"/_plugins/_ism/policies/{ILM_POLICY_NAME}",
                body=policy_body,
            )
            logger.info(
                "Applied ISM policy: %s (retention=%dd)",
                ILM_POLICY_NAME,
                ILM_RETENTION_DAYS,
            )
        except Exception as exc:
            logger.warning("ensure_ilm_policy: ISM policy creation failed: %s", exc)

    async def ensure_audit_ilm_policy(self) -> None:
        """Create or update the ISM policy that enforces 3-year audit log retention.

        Creates an OpenSearch ISM (Index State Management) policy named
        ``mxtac-3year-audit-retention`` that automatically deletes
        ``mxtac-audit-*`` monthly indices after 1 095 days (3 years).

        This satisfies regulatory retention requirements (SOC 2, HIPAA, etc.)
        that mandate a minimum 3-year audit trail — while keeping the number
        of live audit indices bounded at 36 (one per calendar month).

        Policy state machine:
        - ``ingest`` — initial state; transitions to ``delete`` once the
          index reaches ``AUDIT_ILM_RETENTION_DAYS`` days old.
        - ``delete`` — removes the index.

        The ``ism_template`` section auto-attaches the policy to every new
        ``mxtac-audit-YYYY.MM`` index so no per-index configuration is needed.

        This operation is idempotent — a PUT on an existing policy updates it.
        If the ISM plugin is unavailable the failure is logged at WARNING level
        and startup continues normally.
        """
        if self._client is None:
            return

        policy_body = {
            "policy": {
                "description": (
                    f"Delete MxTac audit indices after {AUDIT_ILM_RETENTION_DAYS} days"
                    f" ({AUDIT_ILM_RETENTION_DAYS // 365} years)."
                ),
                "default_state": "ingest",
                "states": [
                    {
                        "name": "ingest",
                        "actions": [],
                        "transitions": [
                            {
                                "state_name": "delete",
                                "conditions": {
                                    "min_index_age": f"{AUDIT_ILM_RETENTION_DAYS}d"
                                },
                            }
                        ],
                    },
                    {
                        "name": "delete",
                        "actions": [{"delete": {}}],
                        "transitions": [],
                    },
                ],
                "ism_template": [
                    {
                        "index_patterns": [f"{AUDIT_INDEX_TEMPLATE}-*"],
                        "priority": 200,
                    }
                ],
            }
        }

        try:
            await self._client.transport.perform_request(
                "PUT",
                f"/_plugins/_ism/policies/{AUDIT_ILM_POLICY_NAME}",
                body=policy_body,
            )
            logger.info(
                "Applied ISM policy: %s (retention=%dd)",
                AUDIT_ILM_POLICY_NAME,
                AUDIT_ILM_RETENTION_DAYS,
            )
        except Exception as exc:
            logger.warning("ensure_audit_ilm_policy: ISM policy creation failed: %s", exc)

    async def ensure_ilm_policies(self) -> None:
        """Create or update all three ILM policies with hot → warm → delete phases.

        Feature 38.2 — replaces the legacy single-policy approach with per-type
        policies that include a force_merge step in the warm phase to reduce
        segment count and storage pressure before eventual deletion.

        Policy schedule (days from index creation):
          Events: hot 0–7d → warm 7–90d (force_merge) → delete at 90d
          Alerts: hot 0–30d → warm 30–365d (force_merge) → delete at 365d
          Audit:  hot 0–90d → warm 90–1095d (force_merge) → delete at 1095d

        Retention values are read from settings so operators can override them
        without code changes. Safe to call multiple times (idempotent PUT).
        """
        if self._client is None:
            return

        events_delete = settings.opensearch_events_retention_days
        alerts_delete = settings.opensearch_alerts_retention_days
        audit_delete = settings.opensearch_audit_retention_days

        policies = [
            {
                "name": EVENTS_ILM_POLICY_NAME,
                "description": (
                    f"MxTac events: hot {EVENTS_HOT_DAYS}d → warm (force_merge)"
                    f" → delete at {events_delete}d"
                ),
                "hot_days": EVENTS_HOT_DAYS,
                "delete_days": events_delete,
                "index_patterns": [f"{EVENTS_INDEX_TEMPLATE}-*"],
                "priority": 100,
            },
            {
                "name": ALERTS_ILM_POLICY_NAME,
                "description": (
                    f"MxTac alerts: hot {ALERTS_HOT_DAYS}d → warm (force_merge)"
                    f" → delete at {alerts_delete}d"
                ),
                "hot_days": ALERTS_HOT_DAYS,
                "delete_days": alerts_delete,
                "index_patterns": [f"{ALERTS_INDEX_TEMPLATE}-*"],
                "priority": 100,
            },
            {
                "name": AUDIT_TYPE_ILM_POLICY_NAME,
                "description": (
                    f"MxTac audit: hot {AUDIT_HOT_DAYS}d → warm (force_merge)"
                    f" → delete at {audit_delete}d ({audit_delete // 365} years)"
                ),
                "hot_days": AUDIT_HOT_DAYS,
                "delete_days": audit_delete,
                "index_patterns": [f"{AUDIT_INDEX_TEMPLATE}-*"],
                "priority": 200,
            },
        ]

        for pol in policies:
            policy_body = {
                "policy": {
                    "description": pol["description"],
                    "default_state": "hot",
                    "states": [
                        {
                            "name": "hot",
                            "actions": [],
                            "transitions": [
                                {
                                    "state_name": "warm",
                                    "conditions": {
                                        "min_index_age": f"{pol['hot_days']}d"
                                    },
                                }
                            ],
                        },
                        {
                            "name": "warm",
                            "actions": [
                                {"force_merge": {"max_num_segments": 1}}
                            ],
                            "transitions": [
                                {
                                    "state_name": "delete",
                                    "conditions": {
                                        "min_index_age": f"{pol['delete_days']}d"
                                    },
                                }
                            ],
                        },
                        {
                            "name": "delete",
                            "actions": [{"delete": {}}],
                            "transitions": [],
                        },
                    ],
                    "ism_template": [
                        {
                            "index_patterns": pol["index_patterns"],
                            "priority": pol["priority"],
                        }
                    ],
                }
            }
            try:
                await self._client.transport.perform_request(
                    "PUT",
                    f"/_plugins/_ism/policies/{pol['name']}",
                    body=policy_body,
                )
                logger.info(
                    "Applied ISM policy: %s (hot=%dd warm→delete=%dd)",
                    pol["name"],
                    pol["hot_days"],
                    pol["delete_days"],
                )
            except Exception as exc:
                logger.warning(
                    "ensure_ilm_policies: failed to apply %s: %s", pol["name"], exc
                )

    async def get_storage_metrics(self) -> dict[str, Any]:
        """Query OpenSearch for index storage size and per-day event counts.

        Returns a dict with:
          ``index_sizes``  — mapping of index-pattern label → total bytes
          ``events_per_day`` — mapping of date string (YYYY-MM-DD) → doc count

        Returns empty structures when the client is unavailable or queries fail.
        """
        if self._client is None:
            return {"index_sizes": {}, "events_per_day": {}}

        index_sizes: dict[str, int] = {}

        # ── Index storage sizes ────────────────────────────────────────────────
        for label, pattern in [
            ("events", f"{EVENTS_INDEX_TEMPLATE}-*"),
            ("alerts", f"{ALERTS_INDEX_TEMPLATE}-*"),
            ("audit", f"{AUDIT_INDEX_TEMPLATE}-*"),
        ]:
            try:
                stats = await self._client.indices.stats(index=pattern, metric="store")
                total_bytes = (
                    stats.get("_all", {})
                    .get("total", {})
                    .get("store", {})
                    .get("size_in_bytes", 0)
                )
                index_sizes[label] = total_bytes
            except Exception as exc:
                logger.debug("get_storage_metrics: stats failed for %s: %s", pattern, exc)
                index_sizes[label] = 0

        # ── Per-day event counts ───────────────────────────────────────────────
        events_per_day: dict[str, int] = {}
        try:
            stats = await self._client.indices.stats(
                index=f"{EVENTS_INDEX_PREFIX}-*", metric="docs"
            )
            indices_data = stats.get("indices", {})
            for index_name, index_stat in indices_data.items():
                # Extract date from index name: mxtac-events-v2-YYYY.MM.DD → YYYY-MM-DD
                suffix = index_name.removeprefix(f"{EVENTS_INDEX_PREFIX}-")
                # Convert YYYY.MM.DD → YYYY-MM-DD
                if len(suffix) == 10 and suffix.count(".") == 2:
                    date_str = suffix.replace(".", "-")
                    doc_count = (
                        index_stat.get("total", {})
                        .get("docs", {})
                        .get("count", 0)
                    )
                    events_per_day[date_str] = doc_count
        except Exception as exc:
            logger.debug("get_storage_metrics: per-day query failed: %s", exc)

        return {"index_sizes": index_sizes, "events_per_day": events_per_day}

    # ── Snapshot management — feature 38.3 ───────────────────────────────────

    async def create_snapshot_repo(self, name: str, path: str) -> bool:
        """Register a filesystem snapshot repository in OpenSearch.

        Uses the ``fs`` repository type with compression enabled.  Safe to
        call multiple times — a PUT on an existing repository is idempotent.
        The ``path`` must be listed in ``path.repo`` in OpenSearch's config.

        Returns ``True`` on success, ``False`` when the client is unavailable
        or the request fails.
        """
        if self._client is None:
            return False
        try:
            await self._client.snapshot.create_repository(
                repository=name,
                body={
                    "type": "fs",
                    "settings": {
                        "location": path,
                        "compress": True,
                    },
                },
            )
            logger.info("Snapshot repository registered: %s -> %s", name, path)
            return True
        except Exception as exc:
            logger.error("create_snapshot_repo failed: %s", exc)
            return False

    async def create_snapshot(self, repo: str, name: str) -> dict[str, Any] | None:
        """Initiate a snapshot of all mxtac-* indices (non-blocking).

        Returns the raw OpenSearch response dict on success, or ``None`` when
        the client is unavailable or the API call fails.  The snapshot runs
        asynchronously in the cluster; callers should poll ``list_snapshots``
        to check for completion.
        """
        if self._client is None:
            return None
        try:
            resp = await self._client.snapshot.create(
                repository=repo,
                snapshot=name,
                body={
                    "indices": "mxtac-*",
                    "ignore_unavailable": True,
                    "include_global_state": False,
                },
                params={"wait_for_completion": "false"},
            )
            logger.info("Snapshot initiated: %s/%s", repo, name)
            return resp
        except Exception as exc:
            logger.error("create_snapshot failed: %s", exc)
            return None

    async def list_snapshots(self, repo: str) -> list[dict[str, Any]]:
        """List all snapshots in *repo* with their status and size.

        Returns a list of dicts with keys:
          ``name``, ``state``, ``start_time``, ``end_time``,
          ``duration_millis``, ``indices``, ``size_bytes``,
          ``shards_total``, ``shards_successful``, ``shards_failed``.

        Returns an empty list when the client is unavailable, the repository
        does not exist, or the query fails.
        """
        if self._client is None:
            return []
        try:
            resp = await self._client.snapshot.get(
                repository=repo,
                snapshot="_all",
            )
            result = []
            for s in resp.get("snapshots", []):
                # ``stats.total.size_in_bytes`` is only present during IN_PROGRESS
                # snapshots; default to 0 for completed / failed snapshots.
                size_bytes = (
                    s.get("stats", {}).get("total", {}).get("size_in_bytes", 0)
                )
                result.append({
                    "name": s.get("snapshot", ""),
                    "state": s.get("state", ""),
                    "start_time": s.get("start_time", ""),
                    "end_time": s.get("end_time", ""),
                    "duration_millis": s.get("duration_in_millis", 0),
                    "indices": s.get("indices", []),
                    "size_bytes": size_bytes,
                    "shards_total": s.get("shards", {}).get("total", 0),
                    "shards_successful": s.get("shards", {}).get("successful", 0),
                    "shards_failed": s.get("shards", {}).get("failed", 0),
                })
            return result
        except Exception as exc:
            logger.error("list_snapshots failed: %s", exc)
            return []

    async def restore_snapshot(self, repo: str, name: str) -> bool:
        """Restore all mxtac-* indices from *name* in *repo* (non-blocking).

        Runs asynchronously in the cluster.  Returns ``True`` when the
        restore request is accepted, ``False`` on failure.
        """
        if self._client is None:
            return False
        try:
            await self._client.snapshot.restore(
                repository=repo,
                snapshot=name,
                body={
                    "indices": "mxtac-*",
                    "ignore_unavailable": True,
                    "include_global_state": False,
                },
                params={"wait_for_completion": "false"},
            )
            logger.info("Snapshot restore initiated: %s/%s", repo, name)
            return True
        except Exception as exc:
            logger.error("restore_snapshot failed: %s", exc)
            return False

    async def delete_snapshot(self, repo: str, name: str) -> bool:
        """Delete a single snapshot from the repository.

        Returns ``True`` on success or ``False`` when the client is
        unavailable / the deletion fails.
        """
        if self._client is None:
            return False
        try:
            await self._client.snapshot.delete(repository=repo, snapshot=name)
            logger.info("Deleted snapshot: %s/%s", repo, name)
            return True
        except Exception as exc:
            logger.error("delete_snapshot failed: %s", exc)
            return False

    async def close(self) -> None:
        if self._client:
            await self._client.close()


# ── Singleton ─────────────────────────────────────────────────────────────────
_opensearch: OpenSearchService | None = None


def get_opensearch() -> OpenSearchService:
    global _opensearch
    if _opensearch is None:
        _opensearch = OpenSearchService()
    return _opensearch


def get_opensearch_dep() -> OpenSearchService:
    """FastAPI dependency — returns the singleton OpenSearch client.

    The client's ``is_available`` property indicates whether a live connection
    exists.  Endpoints should fall back to PostgreSQL when it is ``False``.
    """
    return get_opensearch()
