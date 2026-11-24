"""The event document — one shape for an event everywhere it is read.

An event is stored twice: as a row of the ``events`` table (PostgreSQL, the
authoritative store) and as a document in the ``mxtac-events-v2-*`` indices
(OpenSearch, the search index).  Both stores hold the same document: the flat
columns of the row, with the full normalized event merged on top.  The event
endpoints return this document, so a search answers with the same rows from
either store.

This module is the single definition of that document and of the fields that
searches use.  ``EventRepo`` (SQL), ``opensearch_client`` (OpenSearch DSL) and
``query_builder`` (Lucene) all take their field names from here.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from ..models.event import Event

#: Filter field name (as accepted by the events endpoint) → flat field of the
#: event document.  The nested OCSF paths are accepted as aliases.
FILTER_FIELDS: dict[str, str] = {
    "severity_id":           "severity_id",
    "class_name":            "class_name",
    "class_uid":             "class_uid",
    "src_ip":                "src_ip",
    "dst_ip":                "dst_ip",
    "hostname":              "hostname",
    "username":              "username",
    "process_hash":          "process_hash",
    "source":                "source",
    # Nested OCSF aliases
    "src_endpoint.ip":       "src_ip",
    "dst_endpoint.ip":       "dst_ip",
    "dst_endpoint.hostname": "hostname",
    "actor_user.name":       "username",
    "process.hash_sha256":   "process_hash",
}

#: Flat fields that hold a number (all other filter fields hold a string).
NUMERIC_FIELDS = frozenset({"severity_id", "class_uid"})

#: Flat fields matched by the free-text query (case-insensitive substring).
TEXT_SEARCH_FIELDS: tuple[str, ...] = (
    "summary", "class_name", "hostname", "username", "src_ip", "dst_ip",
)

#: Path of the process command line inside the document; the free-text query
#: matches it too.  It has no column of its own in the ``events`` table.
CMD_LINE_PATH: tuple[str, str] = ("process", "cmd_line")


def event_to_dict(e: Event) -> dict[str, Any]:
    """Serialize an Event row to the event document (JSON-safe dict)."""
    doc: dict[str, Any] = {
        "id":           e.id,
        "event_uid":    e.event_uid,
        "time":         e.time.isoformat() if isinstance(e.time, datetime) else e.time,
        "class_name":   e.class_name,
        "class_uid":    e.class_uid,
        "severity_id":  e.severity_id,
        "src_ip":       e.src_ip,
        "dst_ip":       e.dst_ip,
        "hostname":     e.hostname,
        "username":     e.username,
        "process_hash": e.process_hash,
        "source":       e.source,
        "summary":      e.summary,
    }
    # Merge the full normalized event on top so callers get all OCSF fields
    if e.raw:
        doc.update(e.raw)
    return doc
