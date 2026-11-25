"""MITRE ATT&CK Enterprise technique names.

The names come from a table bundled with the backend
(``app/data/attack_techniques.json``), generated from the official ATT&CK STIX
data by ``scripts/gen_attack_techniques.py``.  The file states the ATT&CK
version and the retrieval date; revoked and deprecated techniques are left
out.  ATT&CK is (c) The MITRE Corporation, see the NOTICE file at the
repository root.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "attack_techniques.json"


@lru_cache(maxsize=1)
def _table() -> dict[str, Any]:
    return json.loads(DATA_FILE.read_text(encoding="utf-8"))


def attack_version() -> str:
    """ATT&CK release the bundled table was generated from, for example ``20.1``."""
    return _table()["attack_version"]


def attack_retrieved() -> str:
    """Date (ISO) the ATT&CK data of the bundled table was downloaded."""
    return _table()["retrieved"]


@lru_cache(maxsize=1)
def technique_names() -> dict[str, str]:
    """Technique ID -> display name for every technique and sub-technique.

    A sub-technique is named as on attack.mitre.org, with its parent in front
    (``T1003.001`` -> ``OS Credential Dumping: LSASS Memory``): several
    sub-techniques share a short name (``Local Accounts``, ``Windows`` ...).
    """
    raw: dict[str, str] = _table()["techniques"]
    names: dict[str, str] = {}
    for technique_id, name in raw.items():
        parent = raw.get(technique_id.partition(".")[0]) if "." in technique_id else None
        names[technique_id] = f"{parent}: {name}" if parent else name
    return names


def technique_name(technique_id: str | None) -> str | None:
    """Display name of *technique_id*, or None when the table does not know it
    (not an Enterprise technique, revoked, deprecated or newer than the table)."""
    if not technique_id:
        return None
    return technique_names().get(technique_id.strip().upper())


def resolve_technique_name(technique_id: str | None, stored: str | None) -> str:
    """Technique name to show for a detection.

    The bundled table wins.  For an ID it does not know, the stored value is
    kept (rows written before the table existed hold the rule title there),
    and without one the ID itself is returned.
    """
    return technique_name(technique_id) or stored or technique_id or ""
