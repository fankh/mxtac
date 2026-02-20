"""
OpenSearch event storage service.

Index naming:
  mxtac-events-{YYYY.MM.DD}   — OCSF-normalized events (daily rollover)
  mxtac-alerts-{YYYY.MM.DD}   — enriched alerts
  mxtac-rules                 — Sigma rules (single index)

Uses opensearch-py (async client).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ..core.config import settings
from ..core.logging import get_logger

logger = get_logger(__name__)

# Index templates
EVENTS_INDEX_TEMPLATE = "mxtac-events"
ALERTS_INDEX_TEMPLATE = "mxtac-alerts"
RULES_INDEX = "mxtac-rules"

# ILM / ISM policy
ILM_POLICY_NAME = "mxtac-90day-retention"
ILM_RETENTION_DAYS = 90

# Maps EventFilter.field names to their OpenSearch document field paths.
# Flat column aliases (e.g. "src_ip") are mapped to the nested OCSF paths
# used in the indexed document; nested paths pass through unchanged.
_OS_FIELD_MAP: dict[str, str] = {
    "severity_id":           "severity_id",
    "class_name":            "class_name",
    "class_uid":             "class_uid",
    "src_ip":                "src_endpoint.ip",
    "dst_ip":                "dst_endpoint.ip",
    "hostname":              "src_endpoint.hostname",
    "username":              "actor_user.name",
    "process_hash":          "process.hash_sha256",
    "source":                "metadata_product",
    # OpenSearch nested-path aliases pass through unchanged
    "src_endpoint.ip":       "src_endpoint.ip",
    "dst_endpoint.ip":       "dst_endpoint.ip",
    "dst_endpoint.hostname": "dst_endpoint.hostname",
    "actor_user.name":       "actor_user.name",
    "process.hash_sha256":   "process.hash_sha256",
}


def filter_to_dsl(field: str, operator: str, value: Any) -> dict | None:
    """Convert an EventFilter (field, operator, value) to an OpenSearch DSL clause.

    Returns ``None`` if the field is unknown or operator is unsupported, so the
    caller can skip the clause instead of sending a malformed query.
    """
    os_field = _OS_FIELD_MAP.get(field)
    if os_field is None:
        return None

    if operator == "eq":
        return {"term": {os_field: value}}
    if operator == "ne":
        return {"bool": {"must_not": [{"term": {os_field: value}}]}}
    if operator == "contains":
        return {"wildcard": {os_field: f"*{value}*"}}
    if operator == "gt":
        return {"range": {os_field: {"gt": value}}}
    if operator == "lt":
        return {"range": {os_field: {"lt": value}}}
    if operator == "gte":
        return {"range": {os_field: {"gte": value}}}
    if operator == "lte":
        return {"range": {os_field: {"lte": value}}}
    return None


def _daily_index(base: str) -> str:
    return f"{base}-{datetime.now(timezone.utc).strftime('%Y.%m.%d')}"


class OpenSearchService:
    """Async wrapper around opensearch-py for MxTac event storage."""

    def __init__(self) -> None:
        self._client = None

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

    async def index_event(self, event: dict[str, Any], doc_id: str | None = None) -> str | None:
        """Index a normalized OCSF event. Returns document ID or None.

        Pass ``doc_id`` to use the PostgreSQL UUID as the OpenSearch document ID
        so that both stores share the same identifier.
        """
        if self._client is None:
            return None
        idx = _daily_index(EVENTS_INDEX_TEMPLATE)
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
        """Full-text + filtered event search. Returns OpenSearch hits dict."""
        if self._client is None:
            return {"hits": {"total": {"value": 0}, "hits": []}}

        must_clauses = []
        if query:
            must_clauses.append({"query_string": {"query": query}})
        if filters:
            must_clauses.extend(filters)

        must_clauses.append({
            "range": {
                "time": {"gte": time_from, "lte": time_to}
            }
        })

        body = {
            "query": {"bool": {"must": must_clauses}},
            "sort":  [{"time": {"order": "desc"}}],
            "size":  size,
            "from":  from_,
        }

        try:
            resp = await self._client.search(
                index=f"{EVENTS_INDEX_TEMPLATE}-*",
                body=body,
            )
            return resp
        except Exception as exc:
            logger.error("OpenSearch search_events failed: %s", exc)
            return {"hits": {"total": {"value": 0}, "hits": []}}

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
          count descending: ``[{"key": value, "count": N}, ...]``.
        - ``agg_type="date_histogram"`` buckets events by *interval*; returns
          buckets sorted by time ascending: ``[{"key": iso_ts, "count": N}, ...]``.

        Returns an empty list when the client is unavailable, when a required
        parameter is missing/unknown, or on any OpenSearch error.
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
                            "order": {"_count": "desc"},
                        }
                    }
                },
            }
            try:
                resp = await self._client.search(
                    index=f"{EVENTS_INDEX_TEMPLATE}-*", body=body
                )
                raw = resp.get("aggregations", {}).get("terms_agg", {}).get("buckets", [])
                return [{"key": str(b["key"]), "count": b["doc_count"]} for b in raw]
            except Exception as exc:
                logger.error("OpenSearch aggregate(terms) failed: %s", exc)
                return []

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
            try:
                resp = await self._client.search(
                    index=f"{EVENTS_INDEX_TEMPLATE}-*", body=body
                )
                raw = resp.get("aggregations", {}).get("histogram_agg", {}).get("buckets", [])
                return [{"key": b.get("key_as_string", ""), "count": b["doc_count"]} for b in raw]
            except Exception as exc:
                logger.error("OpenSearch aggregate(date_histogram) failed: %s", exc)
                return []

        logger.warning("aggregate: unsupported agg_type %r — returning []", agg_type)
        return []

    async def get_event(self, event_id: str, index: str | None = None) -> dict | None:
        if self._client is None:
            return None
        idx = index or f"{EVENTS_INDEX_TEMPLATE}-*"
        try:
            resp = await self._client.get(index=idx, id=event_id)
            return resp.get("_source")
        except Exception:
            return None

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
        every new ``mxtac-events-YYYY.MM.DD`` / ``mxtac-alerts-YYYY.MM.DD`` index
        inherits the correct field mappings automatically.  The static
        ``mxtac-rules`` index is created directly if it does not yet exist.

        Safe to call multiple times — templates are idempotent (PUT) and the
        rules-index creation is guarded by an existence check.  If no client is
        available this method is a no-op.
        """
        if self._client is None:
            return

        # ── mxtac-events-* index template ─────────────────────────────────────
        try:
            await self._client.indices.put_index_template(
                name="mxtac-events-template",
                body={
                    "index_patterns": [f"{EVENTS_INDEX_TEMPLATE}-*"],
                    "template": {
                        "settings": {
                            "number_of_shards": 3,
                            "number_of_replicas": 1,
                            "plugins.index_state_management.policy_id": ILM_POLICY_NAME,
                        },
                        "mappings": {
                            "properties": {
                                "metadata_uid":     {"type": "keyword"},
                                "time":             {"type": "date"},
                                "class_name":       {"type": "keyword"},
                                "class_uid":        {"type": "integer"},
                                "severity_id":      {"type": "integer"},
                                "metadata_product": {"type": "keyword"},
                                "metadata_version": {"type": "keyword"},
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
                                "actor_user": {
                                    "type": "object",
                                    "properties": {
                                        "name":          {"type": "keyword"},
                                        "uid":           {"type": "keyword"},
                                        "domain":        {"type": "keyword"},
                                        "is_privileged": {"type": "boolean"},
                                    },
                                },
                                "process": {
                                    "type": "object",
                                    "properties": {
                                        "pid":         {"type": "integer"},
                                        "name":        {"type": "keyword"},
                                        "cmd_line":    {"type": "text"},
                                        "path":        {"type": "keyword"},
                                        "parent_pid":  {"type": "integer"},
                                        "hash_sha256": {"type": "keyword"},
                                    },
                                },
                                "network_traffic": {"type": "object", "enabled": True},
                                "file":            {"type": "object", "enabled": True},
                                "finding_info":    {"type": "object", "enabled": True},
                                "unmapped":        {"type": "object", "enabled": True},
                                "raw":             {"type": "object", "enabled": True},
                            }
                        },
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
                            "plugins.index_state_management.policy_id": ILM_POLICY_NAME,
                        },
                        "mappings": {
                            "properties": {
                                "rule_id":         {"type": "keyword"},
                                "rule_name":       {
                                    "type": "text",
                                    "fields": {"keyword": {"type": "keyword"}},
                                },
                                "severity_name":   {"type": "keyword"},
                                "risk_score":      {"type": "float"},
                                "detection_count": {"type": "integer"},
                                "first_seen":      {"type": "date"},
                                "last_seen":       {"type": "date"},
                                "status":          {"type": "keyword"},
                                "assigned_to":     {"type": "keyword"},
                                "tags":            {"type": "keyword"},
                                "time":            {"type": "date"},
                                "class_name":      {"type": "keyword"},
                                "severity_id":     {"type": "integer"},
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
                        },
                    },
                },
            )
            logger.info("Applied index template: mxtac-alerts-template")
        except Exception as exc:
            logger.warning("ensure_indices: alerts template failed: %s", exc)

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
                        "mappings": {
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
                                "author":      {"type": "text"},
                                "date":        {"type": "date"},
                                "modified":    {"type": "date"},
                                "references":  {"type": "text"},
                            }
                        },
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
