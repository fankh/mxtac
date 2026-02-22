"""OCSF → Sigma flat event mapper.

Sigma rules reference Windows/Sysmon-style field names (CommandLine, Image,
DestinationIp, …).  This module translates OCSF event fields into a flat dict
that the _Condition evaluator can match against — per logsource category.

Usage::

    from app.engine.field_mapper import ocsf_to_sigma_flat

    flat = ocsf_to_sigma_flat(event, rule.logsource)
    matched = rule._matcher.matches(flat)
"""

from __future__ import annotations

from typing import Any

from ..services.normalizers.ocsf import OCSFEvent


# ── Per-category Sigma field name → OCSF attribute path ──────────────────────
#
# Paths use dot-notation.  Leading segment is an OCSFEvent attribute; nested
# Pydantic sub-models are traversed via getattr, plain dicts via key lookup.

_PROCESS_CREATION_MAP: dict[str, str] = {
    "CommandLine":      "process.cmd_line",
    "Image":            "process.path",
    "OriginalFileName": "process.name",
    "ProcessId":        "process.pid",
    "ParentImage":      "process.parent_name",
    "ParentProcessId":  "process.parent_pid",
    "User":             "actor_user.name",
    "Hashes":           "process.hash_sha256",
}

_NETWORK_CONNECTION_MAP: dict[str, str] = {
    "SourceIp":            "src_endpoint.ip",
    "SourcePort":          "src_endpoint.port",
    "SourceHostname":      "src_endpoint.hostname",
    "DestinationIp":       "dst_endpoint.ip",
    "DestinationPort":     "dst_endpoint.port",
    "DestinationHostname": "dst_endpoint.hostname",
    "Image":               "process.path",
    "User":                "actor_user.name",
}

_DNS_QUERY_MAP: dict[str, str] = {
    "QueryName":    "network_traffic.query",
    "QueryType":    "network_traffic.query_type",
    "QueryResults": "network_traffic.answers",
    "Image":        "process.path",
    "User":         "actor_user.name",
}

_AUTHENTICATION_MAP: dict[str, str] = {
    "TargetUserName":   "actor_user.name",
    "TargetUserSid":    "actor_user.uid",
    "TargetDomainName": "actor_user.domain",
    "IpAddress":        "src_endpoint.ip",
    "WorkstationName":  "src_endpoint.hostname",
}

_FILE_ACTIVITY_MAP: dict[str, str] = {
    "TargetFilename": "file.path",
    "FileName":       "file.name",
    "Image":          "process.path",
    "CommandLine":    "process.cmd_line",
    "User":           "actor_user.name",
}

# Map from Sigma logsource category → field alias map
CATEGORY_MAPS: dict[str, dict[str, str]] = {
    "process_creation":   _PROCESS_CREATION_MAP,
    "network_connection": _NETWORK_CONNECTION_MAP,
    "dns_query":          _DNS_QUERY_MAP,
    "authentication":     _AUTHENTICATION_MAP,
    "file_access":        _FILE_ACTIVITY_MAP,
    "file_change":        _FILE_ACTIVITY_MAP,
    "file_delete":        _FILE_ACTIVITY_MAP,
    "file_event":         _FILE_ACTIVITY_MAP,
}


def _get_nested(obj: Any, path: str) -> Any:
    """Dot-notation attribute / key traversal for Pydantic models and dicts."""
    val = obj
    for part in path.split("."):
        if val is None:
            return None
        if isinstance(val, dict):
            val = val.get(part)
        else:
            val = getattr(val, part, None)
    return val


def ocsf_to_sigma_flat(
    event: OCSFEvent,
    logsource: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Convert an OCSFEvent to a flat dict with Sigma-compatible field names.

    The result contains five layers:

    1. **Common fields** (always present):
       - ``_product``  — lowercase ``metadata_product``
       - ``_category`` — ``class_uid`` as string

    2. **OCSF dot-notation paths** — rules that reference OCSF paths directly
       (e.g. ``process.cmd_line``, ``src_endpoint.ip``) still work unchanged.

    3. **ProcessInfo short names** — flattened from ``event.process`` so rules
       can reference ``name``, ``cmd_line``, ``pid`` etc. without a prefix.

    4. **Endpoint short names** — from ``event.src_endpoint`` (``hostname``,
       ``ip``, ``port``, ``domain``); added with *setdefault* so dot-notation
       keys take precedence if the same name appears in both.

    5. **Category-specific Sigma aliases** — canonical Windows/Sysmon-style
       field names (``CommandLine``, ``Image``, ``DestinationIp`` …) derived
       from ``logsource["category"]``.  Only non-``None`` values are emitted.

    Args:
        event:      Normalized OCSF event.
        logsource:  Sigma rule ``logsource`` dict (may contain ``category``,
                    ``product``, ``service``).  Pass ``None`` to skip category
                    aliases.

    Returns:
        Flat ``str → Any`` dict suitable for ``_Condition.matches()``.
    """
    flat: dict[str, Any] = {}

    # ── 1. Common ─────────────────────────────────────────────────────────────
    flat["_product"]  = event.metadata_product.lower()
    flat["_category"] = str(event.class_uid)

    # ── 2. OCSF dot-notation paths ────────────────────────────────────────────
    proc = event.process
    flat["process.cmd_line"]    = proc.cmd_line
    flat["process.name"]        = proc.name
    flat["process.path"]        = proc.path
    flat["process.pid"]         = proc.pid
    flat["process.parent_name"] = proc.parent_name
    flat["process.parent_pid"]  = proc.parent_pid
    flat["process.hash_sha256"] = proc.hash_sha256

    src = event.src_endpoint
    flat["src_endpoint.ip"]       = src.ip
    flat["src_endpoint.hostname"] = src.hostname
    flat["src_endpoint.port"]     = src.port
    flat["src_endpoint.domain"]   = src.domain

    dst = event.dst_endpoint
    flat["dst_endpoint.ip"]       = dst.ip
    flat["dst_endpoint.hostname"] = dst.hostname
    flat["dst_endpoint.port"]     = dst.port
    flat["dst_endpoint.domain"]   = dst.domain

    user = event.actor_user
    flat["actor_user.name"]   = user.name
    flat["actor_user.uid"]    = user.uid
    flat["actor_user.domain"] = user.domain

    for k, v in event.network_traffic.items():
        flat[f"network_traffic.{k}"] = v

    for k, v in event.file.items():
        flat[f"file.{k}"] = v

    # ── 3. ProcessInfo short names (backwards-compat: name, cmd_line, …) ─────
    for k, v in proc.model_dump().items():
        flat.setdefault(k, v)

    # ── 4. src_endpoint short names (backwards-compat: hostname, ip, …) ──────
    for k, v in src.model_dump().items():
        flat.setdefault(k, v)

    # ── 5. Category-specific Sigma aliases ────────────────────────────────────
    category = (logsource or {}).get("category", "").lower()
    for sigma_name, ocsf_path in CATEGORY_MAPS.get(category, {}).items():
        val = _get_nested(event, ocsf_path)
        if val is not None:
            flat[sigma_name] = val

    return flat
