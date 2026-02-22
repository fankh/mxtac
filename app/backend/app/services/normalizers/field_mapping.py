"""Feature 7.15 — Custom field mapping config per connector.

Allows per-connector YAML/dict overrides for OCSF field mappings.

Connectors can include a ``field_mapping`` key in their ``config_json`` (stored in DB).
This key holds either:

  * A YAML **string** (multi-line, stored as-is) containing a ``field_mappings`` dict:

    .. code-block:: yaml

        field_mappings:
          src_endpoint.ip: data.client_ip
          dst_endpoint.hostname: agent.server_name
          actor_user.name: data.user.username

  * A **plain dict** with the same structure:

    .. code-block:: json

        {"field_mappings": {"src_endpoint.ip": "data.client_ip"}}

  * A **flat dict** where every key is already an OCSF field path (shorthand):

    .. code-block:: json

        {"src_endpoint.ip": "data.client_ip"}

Field path syntax
-----------------
Both source and destination paths use dot-notation to traverse nested dicts.

  ``src_endpoint.ip``  →  ``event_dict["src_endpoint"]["ip"]``
  ``data.win.eventdata.commandLine``  →  ``raw["data"]["win"]["eventdata"]["commandLine"]``

If a source path resolves to ``None`` or is absent the override is silently skipped
(the default normalizer value is kept).  The OCSFEvent is re-validated via Pydantic
after all overrides are applied, so type errors on the destination field will surface
as ``ValidationError`` and be handled by the pipeline's existing DLQ logic.
"""

from __future__ import annotations

from typing import Any

import yaml
from pydantic import BaseModel

from .ocsf import OCSFEvent


# ── Path helpers ──────────────────────────────────────────────────────────────

def _get_nested(obj: dict[str, Any], path: str) -> Any:
    """Extract a value from a nested dict using dot-path notation.

    Returns ``None`` if any intermediate key is missing or not a dict.
    """
    current: Any = obj
    for part in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
        if current is None:
            return None
    return current


def _set_nested(obj: dict[str, Any], path: str, value: Any) -> None:
    """Set a value in a nested dict using dot-path notation.

    Intermediate dicts are created automatically if missing.
    """
    parts = path.split(".")
    current = obj
    for part in parts[:-1]:
        if part not in current or not isinstance(current[part], dict):
            current[part] = {}
        current = current[part]
    current[parts[-1]] = value


# ── Main config model ─────────────────────────────────────────────────────────

class FieldMappingConfig(BaseModel):
    """Custom field mapping overrides for a single connector instance.

    Each entry in ``field_mappings`` maps an OCSF destination field path to a
    source field path in the raw (pre-normalisation) event dict.

    Example::

        FieldMappingConfig(field_mappings={
            "src_endpoint.ip": "data.client_ip",
            "dst_endpoint.hostname": "agent.server_name",
        })
    """

    field_mappings: dict[str, str] = {}

    # ── Factory ───────────────────────────────────────────────────────────────

    @classmethod
    def from_config(cls, data: Any) -> "FieldMappingConfig":
        """Build a ``FieldMappingConfig`` from a connector config value.

        *data* may be:

        * ``None`` / falsy → empty (no-op) config
        * ``str``          → YAML string; must contain a ``field_mappings`` key
        * ``dict``         → either ``{"field_mappings": {...}}`` or a flat mapping

        Invalid / unparseable values are silently ignored (returns empty config).
        """
        if not data:
            return cls()

        if isinstance(data, str):
            try:
                parsed = yaml.safe_load(data) or {}
            except yaml.YAMLError:
                return cls()
            if not isinstance(parsed, dict):
                return cls()
            mappings = parsed.get("field_mappings", {})
            if isinstance(mappings, dict):
                return cls(field_mappings=mappings)
            return cls()

        if isinstance(data, dict):
            # Support both {"field_mappings": {...}} and flat {"ocsf.path": "src.path"}
            if "field_mappings" in data and isinstance(data["field_mappings"], dict):
                return cls(field_mappings=data["field_mappings"])
            # Flat format — every key assumed to be an OCSF path
            flat = {k: v for k, v in data.items() if isinstance(k, str) and isinstance(v, str)}
            return cls(field_mappings=flat)

        return cls()

    # ── Application ──────────────────────────────────────────────────────────

    def apply(self, event: OCSFEvent, raw: dict[str, Any]) -> OCSFEvent:
        """Apply field mapping overrides to an already-normalised ``OCSFEvent``.

        For each ``(ocsf_path, source_path)`` pair:

        1. Resolve ``source_path`` against ``raw``.
        2. If the value is not ``None``, write it to ``ocsf_path`` in the event dict.
        3. Re-validate the event via Pydantic (raises ``ValidationError`` on type
           mismatch — this is handled upstream by the normaliser pipeline).

        Returns the original ``event`` unchanged when ``field_mappings`` is empty.
        """
        if not self.field_mappings:
            return event

        event_dict = event.model_dump()
        changed = False

        for ocsf_path, source_path in self.field_mappings.items():
            value = _get_nested(raw, source_path)
            if value is not None:
                _set_nested(event_dict, ocsf_path, value)
                changed = True

        if not changed:
            return event

        return OCSFEvent.model_validate(event_dict)

    @property
    def is_empty(self) -> bool:
        """True when no overrides are configured (no-op)."""
        return not self.field_mappings
