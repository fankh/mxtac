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
