"""
OpenSearch event storage service.

Index naming:
  mxtac-events-{YYYY.MM.DD}   — OCSF-normalized events (daily rollover)
  mxtac-alerts-{YYYY.MM.DD}   — enriched alerts
  mxtac-audit-{YYYY.MM}       — audit log entries (monthly rollover, 3-year retention)
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

#: Mapping body for mxtac-events-* indices (OCSF-normalised security events).
EVENTS_MAPPING: dict[str, Any] = {
    "properties": {
        # ── Top-level OCSF fields ────────────────────────────────────────
        "metadata_uid":           {"type": "keyword"},
        "time":                   {"type": "date"},
        "class_name":             {"type": "keyword"},
        "class_uid":              {"type": "integer"},
        "severity_id":            {"type": "integer"},
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
                "cmd_line":    {"type": "text"},
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
    }
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
            # Use simple_query_string instead of query_string to prevent Lucene
            # injection attacks (field boosting bypass, regex patterns, etc.).
            # simple_query_string supports +/-/|/"" operators but not field:value
            # or _source:* overrides, making it safe for user-supplied input.
            must_clauses.append({
                "simple_query_string": {
                    "query": query,
                    "fields": ["summary", "class_name", "hostname", "username"],
                    "default_operator": "AND",
                }
            })
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
                            "plugins.index_state_management.policy_id": EVENTS_ILM_POLICY_NAME,
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
                index=f"{EVENTS_INDEX_TEMPLATE}-*", metric="docs"
            )
            indices_data = stats.get("indices", {})
            for index_name, index_stat in indices_data.items():
                # Extract date from index name: mxtac-events-YYYY.MM.DD → YYYY-MM-DD
                suffix = index_name.removeprefix(f"{EVENTS_INDEX_TEMPLATE}-")
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
