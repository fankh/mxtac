"""Event persister — write normalized events to PostgreSQL and OpenSearch.

Subscribes to ``mxtac.normalized`` and for each OCSF event:
  1. Extracts flat fields and persists a row to PostgreSQL (via EventRepo),
     under the event ID the normalizer pipeline assigned (``EVENT_ID_KEY``).
  2. Indexes the event document of that row (``event_document.event_to_dict``:
     the flat fields plus the full OCSF dict) to OpenSearch, if a client is
     available, using the PostgreSQL UUID as the document ID.

Both operations are non-fatal: a failure in either store is logged and the
pipeline continues.

``reindex_legacy_events`` copies the events of an installation whose
OpenSearch indices were written by an earlier version (nested OCSF dict only)
from PostgreSQL into the current indices.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select

from ..core.database import AsyncSessionLocal
from ..core.logging import get_logger
from ..models.base import new_uuid
from ..models.event import Event
from ..pipeline.queue import MessageQueue, Topic
from ..repositories.event_repo import EventRepo
from ..services.event_document import event_to_dict
from ..services.normalizers.ocsf import EVENT_ID_KEY
from ..services.opensearch_client import ILM_RETENTION_DAYS, OpenSearchService

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
        # The pipeline's event ID travels next to the payload, not inside it.
        "raw":          {k: v for k, v in event_dict.items() if k != EVENT_ID_KEY},
    }


async def event_persister(queue: MessageQueue, os_client: OpenSearchService) -> None:
    """Subscribe to ``mxtac.normalized`` and persist each event.

    Writes to:
      1. PostgreSQL (authoritative store, always attempted)
      2. OpenSearch (optional full-text search, when available)
    """

    async def _handle(event_dict: dict[str, Any]) -> None:
        fields: dict[str, Any] | None = None
        doc: dict[str, Any] | None = None
        # The ID the normalizer pipeline assigned; detections refer to it.
        event_id = event_dict.get(EVENT_ID_KEY) or new_uuid()

        # 1. Persist to PostgreSQL (authoritative store)
        try:
            fields = _extract_event_fields(event_dict)
            async with AsyncSessionLocal() as session:
                evt = await EventRepo.create(session, id=event_id, **fields)
                await session.commit()
                doc = event_to_dict(evt)
            logger.debug("EventPersister persisted to PG id=%s", doc["id"])
        except Exception:
            logger.exception("EventPersister PostgreSQL write failed (non-fatal)")

        # 2. Index the same document to OpenSearch, with the PostgreSQL UUID
        #    as document ID
        try:
            if os_client.is_available:
                if doc is None and fields is not None:
                    # No row was written: index the document under the same ID
                    doc = event_to_dict(Event(id=event_id, **fields))
                if doc is not None:
                    await os_client.index_event(doc, doc_id=doc["id"])
                    logger.debug("EventPersister indexed to OpenSearch id=%s", doc["id"])
        except Exception:
            logger.exception("EventPersister OpenSearch index failed (non-fatal)")

    await queue.subscribe(Topic.NORMALIZED, "event-persister", _handle)
    logger.info("EventPersister subscribed to %s", Topic.NORMALIZED)


_REINDEX_BATCH_SIZE = 500


async def reindex_legacy_events(os_client: OpenSearchService) -> int:
    """Re-index events from PostgreSQL after an upgrade from the old index shape.

    Earlier versions indexed the nested OCSF dict into ``mxtac-events-YYYY.MM.DD``.
    Those indices are no longer searched.  When such an index exists, the events
    of the retention period are read from PostgreSQL (the authoritative store)
    and every event that has no document in the current indices is indexed, so
    that a search on OpenSearch returns the same rows as PostgreSQL.  The legacy
    indices are then marked as re-indexed; they are left in place and expire
    under the retention policy.

    Safe to run again after an interruption: events already indexed are skipped.
    Returns the number of events indexed.
    """
    if not os_client.is_available:
        return 0
    legacy = await os_client.legacy_event_indices()
    if not legacy:
        return 0
    logger.info("Re-indexing events from PostgreSQL (legacy indices: %s)", ", ".join(legacy))

    cutoff = datetime.now(timezone.utc) - timedelta(days=ILM_RETENTION_DAYS)
    indexed = 0
    last_id = ""
    while True:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(Event)
                .where(Event.created_at >= cutoff, Event.id > last_id)
                .order_by(Event.id)
                .limit(_REINDEX_BATCH_SIZE)
            )
            docs = {e.id: event_to_dict(e) for e in result.scalars()}
        if not docs:
            break
        last_id = max(docs)
        missing = await os_client.missing_event_ids(list(docs))
        indexed += await os_client.bulk_index_events([docs[i] for i in sorted(missing)])

    await os_client.mark_legacy_indices_reindexed(legacy)
    logger.info("Re-indexed %d events from PostgreSQL", indexed)
    return indexed
