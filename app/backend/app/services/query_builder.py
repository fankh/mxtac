"""Lucene DSL query builder — converts EventFilter params to a Lucene query string.

This module provides :func:`build_lucene_query` which serialises a
:class:`~app.api.v1.endpoints.events.SearchRequest` (text query + structured
filters + time range) into a single Lucene query string compatible with the
OpenSearch ``query_string`` DSL.

Lucene syntax produced:

============  =============================================
Operator      Lucene clause
============  =============================================
``eq``        ``field:value``
``ne``        ``NOT field:value``
``contains``  ``field:*value*``  (wildcard)
``gt``        ``field:{value TO *}``  (exclusive lower)
``lt``        ``field:{* TO value}``  (exclusive upper)
``gte``       ``field:[value TO *]``  (inclusive lower)
``lte``       ``field:[* TO value]``  (inclusive upper)
============  =============================================

All clauses are joined with ``AND``.  The time window is appended as a
``time:[<from> TO <to>]`` range clause.  When no constraints are provided the
query defaults to ``"*"`` (match all).

Examples::

    >>> from app.services.query_builder import build_lucene_query
    >>> build_lucene_query("mimikatz", [], "now-1h", "now")
    'mimikatz AND time:[now-1h TO now]'
"""

from __future__ import annotations

import re
from typing import Any

# ---------------------------------------------------------------------------
# Field mapping
# ---------------------------------------------------------------------------

# Maps EventFilter.field names to the Lucene field paths used in queries.
# Mirrors _OS_FIELD_MAP in opensearch_client.py so Lucene queries align with
# the actual OpenSearch document field structure.
_LUCENE_FIELD_MAP: dict[str, str] = {
    "severity_id":           "severity_id",
    "class_name":            "class_name",
    "class_uid":             "class_uid",
    "src_ip":                "src_endpoint.ip",
    "dst_ip":                "dst_endpoint.ip",
    "hostname":              "src_endpoint.hostname",
    "username":              "actor_user.name",
    "process_hash":          "process.hash_sha256",
    "source":                "metadata_product",
    # Nested-path aliases pass through unchanged
    "src_endpoint.ip":       "src_endpoint.ip",
    "dst_endpoint.ip":       "dst_endpoint.ip",
    "dst_endpoint.hostname": "dst_endpoint.hostname",
    "actor_user.name":       "actor_user.name",
    "process.hash_sha256":   "process.hash_sha256",
}

# ---------------------------------------------------------------------------
# Escaping helpers
# ---------------------------------------------------------------------------

# Lucene special characters that must be backslash-escaped inside a plain term
# (per the Lucene query parser spec). Note: '*' and '?' are intentionally
# omitted so wildcard expressions are preserved.
_LUCENE_SPECIAL_RE = re.compile(r'([+\-!(){}[\]^"~?:\\/]|&&|\|\|)')


def _escape_term(value: str) -> str:
    """Backslash-escape Lucene special characters in *value*.

    Wildcards (``*``) are left intact so that callers constructing wildcard
    queries can embed them freely.
    """
    return _LUCENE_SPECIAL_RE.sub(r"\\\1", value)


def _format_value(value: Any) -> str:
    """Return a Lucene-safe string for a plain (non-wildcard) term.

    Strings containing whitespace are wrapped in double-quotes (phrase query).
    All other values are escaped character-by-character.
    """
    s = str(value)
    if " " in s:
        inner = s.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{inner}"'
    return _escape_term(s)


# ---------------------------------------------------------------------------
# Single-filter clause builder
# ---------------------------------------------------------------------------


def _filter_to_lucene(field: str, operator: str, value: Any) -> str | None:
    """Convert a single EventFilter triple to a Lucene query clause.

    Returns ``None`` when *field* is unknown or *operator* is unsupported so
    callers can skip the clause rather than producing a malformed query.

    Args:
        field:    EventFilter field name (flat alias or OCSF nested path).
        operator: One of ``eq``, ``ne``, ``contains``, ``gt``, ``lt``,
                  ``gte``, ``lte``.
        value:    Filter value (scalar — string, int, float).

    Returns:
        A Lucene query clause string, or ``None``.
    """
    lucene_field = _LUCENE_FIELD_MAP.get(field)
    if lucene_field is None:
        return None

    if operator == "eq":
        return f"{lucene_field}:{_format_value(value)}"

    if operator == "ne":
        return f"NOT {lucene_field}:{_format_value(value)}"

    if operator == "contains":
        # Wildcard query — pass the value through verbatim (mirrors OpenSearch
        # wildcard query semantics; '-' and other chars inside *…* are literals).
        return f"{lucene_field}:*{value}*"

    if operator == "gt":
        return f"{lucene_field}:{{{value} TO *}}"

    if operator == "lt":
        return f"{lucene_field}:{{* TO {value}}}"

    if operator == "gte":
        return f"{lucene_field}:[{value} TO *]"

    if operator == "lte":
        return f"{lucene_field}:[* TO {value}]"

    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build_lucene_query(
    query: str | None,
    filters: list,  # list[EventFilter] (duck-typed: .field, .operator, .value)
    time_from: str = "now-7d",
    time_to: str = "now",
) -> str:
    """Build a Lucene query string from a :class:`SearchRequest`.

    The output is compatible with the OpenSearch ``query_string`` DSL and can
    be pasted directly into OpenSearch Dashboards / Kibana Dev Tools.

    Clause ordering:
    1. Free-text *query* (passed through verbatim — may contain Lucene syntax).
    2. Structured filter clauses (one per EventFilter, unknown fields skipped).
    3. Time-range clause (``time:[<from> TO <to>]``).

    All clauses are joined with ``AND``.  Returns ``"*"`` when no constraints
    are provided (match-all).

    Args:
        query:      Optional free-text search string.  Callers may embed Lucene
                    operators (``AND``, ``OR``, ``NOT``, field prefixes …).
        filters:    Sequence of objects with ``field``, ``operator``, and
                    ``value`` attributes — typically
                    :class:`~app.api.v1.endpoints.events.EventFilter` instances.
        time_from:  Start of time window.  Accepts OpenSearch relative formats
                    (``now-7d``, ``now-1h``) or ISO 8601 strings.
        time_to:    End of time window (default ``"now"``).

    Returns:
        Lucene query string ready for ``query_string.query``.
    """
    clauses: list[str] = []

    # 1. Free-text query
    if query and query.strip():
        clauses.append(query.strip())

    # 2. Structured filters
    for f in filters:
        clause = _filter_to_lucene(f.field, f.operator, f.value)
        if clause is not None:
            clauses.append(clause)

    # 3. Time range
    t_from = (time_from or "now-7d").strip()
    t_to = (time_to or "now").strip()
    clauses.append(f"time:[{t_from} TO {t_to}]")

    return " AND ".join(clauses) if clauses else "*"
