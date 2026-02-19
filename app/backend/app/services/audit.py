"""
Audit Logger — structured audit trail stored in OpenSearch.

Index: mxtac-audit

Every admin/security-relevant action is recorded with:
  - actor (who)
  - action (what)
  - resource_type + resource_id (on what)
  - details (free-form context)
  - request metadata (IP, user-agent, method, path)
  - timestamp
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import Request

from ..core.config import settings
from ..core.logging import get_logger

logger = get_logger(__name__)

AUDIT_INDEX = "mxtac-audit"


class AuditLogger:
    """Writes audit log entries to OpenSearch."""

    def __init__(self) -> None:
        self._client = None

    async def _ensure_client(self) -> None:
        """Lazy-init the OpenSearch async client."""
        if self._client is not None:
            return
        try:
            from opensearchpy import AsyncOpenSearch  # type: ignore[import-untyped]

            url = settings.opensearch_url
            self._client = AsyncOpenSearch(
                hosts=[url],
                http_compress=True,
                use_ssl=url.startswith("https"),
                verify_certs=False,
                ssl_show_warn=False,
            )
        except ImportError:
            logger.warning("opensearch-py not installed — audit logging disabled")
        except Exception as exc:
            logger.warning("AuditLogger OpenSearch connection failed: %s", exc)

    async def _ensure_index(self) -> None:
        """Create the audit index with proper mappings if it does not exist."""
        if self._client is None:
            return
        try:
            exists = await self._client.indices.exists(index=AUDIT_INDEX)
            if not exists:
                mapping = {
                    "settings": {
                        "number_of_shards": 1,
                        "number_of_replicas": 1,
                    },
                    "mappings": {
                        "properties": {
                            "id":            {"type": "keyword"},
                            "timestamp":     {"type": "date"},
                            "actor":         {"type": "keyword"},
                            "action":        {"type": "keyword"},
                            "resource_type": {"type": "keyword"},
                            "resource_id":   {"type": "keyword"},
                            "details":       {"type": "object", "enabled": True},
                            "request_ip":    {"type": "ip"},
                            "request_method": {"type": "keyword"},
                            "request_path":  {"type": "keyword"},
                            "user_agent":    {"type": "text"},
                        }
                    },
                }
                await self._client.indices.create(index=AUDIT_INDEX, body=mapping)
                logger.info("Created audit index: %s", AUDIT_INDEX)
        except Exception as exc:
            logger.warning("AuditLogger ensure_index failed: %s", exc)

    async def log(
        self,
        actor: str,
        action: str,
        resource_type: str,
        resource_id: str = "",
        details: dict[str, Any] | None = None,
        request: Request | None = None,
    ) -> str | None:
        """
        Write an audit log entry to OpenSearch.

        Args:
            actor: Identity of the user performing the action (e.g. email).
            action: Action verb (e.g. "create", "update", "delete", "login").
            resource_type: Type of resource acted upon (e.g. "rule", "connector", "user").
            resource_id: Identifier of the specific resource.
            details: Arbitrary context dict for the action.
            request: FastAPI Request object (for IP, method, path, user-agent).

        Returns:
            The document ID of the audit entry, or None on failure.
        """
        await self._ensure_client()
        if self._client is None:
            logger.debug("Audit log skipped (no OpenSearch client): actor=%s action=%s", actor, action)
            return None

        await self._ensure_index()

        doc_id = str(uuid.uuid4())
        doc: dict[str, Any] = {
            "id":            doc_id,
            "timestamp":     datetime.now(timezone.utc).isoformat(),
            "actor":         actor,
            "action":        action,
            "resource_type": resource_type,
            "resource_id":   resource_id,
            "details":       details or {},
        }

        # Extract request metadata
        if request is not None:
            doc["request_ip"] = request.client.host if request.client else None
            doc["request_method"] = request.method
            doc["request_path"] = str(request.url.path)
            doc["user_agent"] = request.headers.get("user-agent", "")

        try:
            resp = await self._client.index(
                index=AUDIT_INDEX,
                id=doc_id,
                body=doc,
                refresh="true",
            )
            logger.info(
                "Audit: actor=%s action=%s resource=%s/%s",
                actor, action, resource_type, resource_id,
            )
            return resp.get("_id")
        except Exception as exc:
            logger.error("AuditLogger write failed: %s", exc)
            return None

    async def search(
        self,
        actor: str | None = None,
        action: str | None = None,
        resource_type: str | None = None,
        time_from: str = "now-7d",
        time_to: str = "now",
        size: int = 50,
        from_: int = 0,
    ) -> dict[str, Any]:
        """
        Query audit log entries with optional filters.

        Returns:
            Dict with 'total' and 'items' keys.
        """
        await self._ensure_client()
        if self._client is None:
            return {"total": 0, "items": []}

        must_clauses: list[dict[str, Any]] = []

        if actor:
            must_clauses.append({"term": {"actor": actor}})
        if action:
            must_clauses.append({"term": {"action": action}})
        if resource_type:
            must_clauses.append({"term": {"resource_type": resource_type}})

        must_clauses.append({
            "range": {"timestamp": {"gte": time_from, "lte": time_to}}
        })

        body = {
            "query": {"bool": {"must": must_clauses}},
            "sort":  [{"timestamp": {"order": "desc"}}],
            "size":  size,
            "from":  from_,
        }

        try:
            resp = await self._client.search(index=AUDIT_INDEX, body=body)
            hits = resp.get("hits", {})
            return {
                "total": hits.get("total", {}).get("value", 0),
                "items": [h.get("_source", {}) for h in hits.get("hits", [])],
            }
        except Exception as exc:
            logger.error("AuditLogger search failed: %s", exc)
            return {"total": 0, "items": []}

    async def close(self) -> None:
        if self._client:
            await self._client.close()


# ── Singleton ────────────────────────────────────────────────────────────────
_audit_logger: AuditLogger | None = None


def get_audit_logger() -> AuditLogger:
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger
