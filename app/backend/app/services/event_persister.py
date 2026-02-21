"""Event persister — triple-write normalized events to PostgreSQL, DuckDB,
and OpenSearch.

Subscribes to ``mxtac.normalized`` and for each OCSF event:
  1. Extracts flat fields and persists a row to PostgreSQL (via EventRepo).
  2. Mirrors the full OCSF dict to DuckDB (if enabled) using the PostgreSQL
     UUID as the row ID so both stores share the same identifier.
  3. Indexes the full OCSF dict to OpenSearch (if a client is available),
     again using the PostgreSQL UUID as the document ID.

All three operations are non-fatal: a failure in any store is logged and the
pipeline continues.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from ..core.logging import get_logger
from ..pipeline.queue import MessageQueue, Topic
from ..services.duckdb_store import DuckDBEventStore
from ..services.opensearch_client import OpenSearchService

logger = get_logger(__name__)


def _extract_event_fields(event_dict: dict[str, Any]) -> dict[str, Any]:
    """Extract flat PostgreSQL-column fields from an OCSF event dict.

    The OCSF dict is produced by ``OCSFEvent.model_dump(mode="json")``, so
    nested objects are plain dicts and ``time`` is an ISO-8601 string.
    """
    src_ep = event_dict.get("src_endpoint") or {}
    dst_ep = event_dict.get("dst_endpoint") or {}
    actor  = event_dict.get("actor_user") or {}
    proc   = event_dict.get("process") or {}
    unmapped = event_dict.get("unmapped") or {}
    finding  = event_dict.get("finding_info") or {}

    # Parse ISO time string → datetime for SQLAlchemy DateTime column
    raw_time = event_dict.get("time")
    if isinstance(raw_time, str):
        time_val: datetime = datetime.fromisoformat(raw_time)
    elif isinstance(raw_time, datetime):
        time_val = raw_time
    else:
        time_val = datetime.utcnow()

    # summary: prefer unmapped.summary, then finding_info.title
    summary: str | None = (
        unmapped.get("summary")
        or (finding.get("title") if finding else None)
    )

    return {
        "event_uid":    event_dict.get("metadata_uid"),
        "time":         time_val,
        "class_name":   event_dict.get("class_name"),
        "class_uid":    event_dict.get("class_uid"),
        "severity_id":  event_dict.get("severity_id"),
        "src_ip":       src_ep.get("ip"),
        "dst_ip":       dst_ep.get("ip"),
        "hostname":     src_ep.get("hostname") or dst_ep.get("hostname"),
        "username":     actor.get("name"),
        "process_hash": proc.get("hash_sha256"),
        "source":       event_dict.get("metadata_product"),
        "summary":      summary,
        "raw":          event_dict,
    }


async def event_persister(
    queue: MessageQueue,
    os_client: OpenSearchService,
    duckdb_store: DuckDBEventStore | None = None,
) -> None:
    """Subscribe to ``mxtac.normalized`` and persist each event.

    Writes to:
      1. PostgreSQL (authoritative store, always attempted)
      2. DuckDB     (embedded analytics, when *duckdb_store* is provided
                     and ``duckdb_store.is_available`` is True)
      3. OpenSearch (optional full-text search, when available)
    """

    async def _handle(event_dict: dict[str, Any]) -> None:
        pg_id: str | None = None

        # 1. Persist to PostgreSQL (authoritative store)
        try:
            from ..core.database import AsyncSessionLocal
            from ..repositories.event_repo import EventRepo

            fields = _extract_event_fields(event_dict)
            async with AsyncSessionLocal() as session:
                evt = await EventRepo.create(session, **fields)
                await session.commit()
                pg_id = evt.id
            logger.debug("EventPersister persisted to PG id=%s", pg_id)
        except Exception:
            logger.exception("EventPersister PostgreSQL write failed (non-fatal)")

        # 2. Mirror to DuckDB analytics store (if enabled and available)
        try:
            if duckdb_store is not None and duckdb_store.is_available:
                await duckdb_store.index_event(event_dict, doc_id=pg_id)
                logger.debug("EventPersister mirrored to DuckDB id=%s", pg_id)
        except Exception:
            logger.exception("EventPersister DuckDB write failed (non-fatal)")

        # 3. Index to OpenSearch using the PostgreSQL UUID as document ID
        try:
            if os_client.is_available:
                doc = {**event_dict}
                if pg_id:
                    doc["id"] = pg_id
                await os_client.index_event(doc, doc_id=pg_id)
                logger.debug("EventPersister indexed to OpenSearch id=%s", pg_id)
        except Exception:
            logger.exception("EventPersister OpenSearch index failed (non-fatal)")

    await queue.subscribe(Topic.NORMALIZED, "event-persister", _handle)
    logger.info("EventPersister subscribed to %s", Topic.NORMALIZED)
