"""ATT&CK tactic tables and Sigma ``attack.*`` tag parsing.

Kept apart from :mod:`app.engine.sigma_engine` so the repositories can use the
tactic names without importing the engine, which itself imports the
repositories.
"""

from __future__ import annotations

import re
from typing import overload

_TECHNIQUE_TAG_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
_TACTIC_ID_TAG_RE = re.compile(r"^attack\.(ta\d{4})$", re.IGNORECASE)

# Tactic names as written in Sigma tags (``attack.credential-access`` or
# ``attack.credential_access``), normalised to underscores.
TACTIC_NAME_TO_ID: dict[str, str] = {
    "reconnaissance":       "TA0043",
    "resource_development": "TA0042",
    "initial_access":       "TA0001",
    "execution":            "TA0002",
    "persistence":          "TA0003",
    "privilege_escalation": "TA0004",
    "defense_evasion":      "TA0005",
    "credential_access":    "TA0006",
    "discovery":            "TA0007",
    "lateral_movement":     "TA0008",
    "collection":           "TA0009",
    "exfiltration":         "TA0010",
    "command_and_control":  "TA0011",
    "impact":               "TA0040",
}


# Tactic names as shown in the UI and stored in ``Detection.tactic``.
TACTIC_ID_TO_NAME: dict[str, str] = {
    "TA0043": "Reconnaissance",
    "TA0042": "Resource Development",
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
}


@overload
def tactic_name(tactic: str) -> str: ...
@overload
def tactic_name(tactic: None) -> None: ...
@overload
def tactic_name(tactic: str | None) -> str | None: ...


def tactic_name(tactic: str | None) -> str | None:
    """Return the tactic name for a tactic ID (``TA0006`` → ``Credential Access``).

    ``Detection.tactic`` holds the name.  Rows written before the pipeline
    stored names hold the ID instead, so readers pass the column through this
    function.  Any other value (a name, ``unknown``, ``None``) is returned
    unchanged.
    """
    if tactic is None:
        return None
    return TACTIC_ID_TO_NAME.get(tactic.strip().upper(), tactic)


def parse_attack_tags(tags: list[str]) -> tuple[list[str], list[str]]:
    """Return ``(technique_ids, tactic_ids)`` from Sigma ``attack.*`` tags."""
    techniques: list[str] = []
    tactics: list[str] = []
    for tag in tags:
        tag = str(tag).strip()
        if m := _TACTIC_ID_TAG_RE.match(tag):
            tactic = m.group(1).upper()
        elif m := _TECHNIQUE_TAG_RE.match(tag):
            technique = m.group(1).upper()
            if technique not in techniques:
                techniques.append(technique)
            continue
        elif tag.lower().startswith("attack."):
            name = tag[len("attack."):].lower().replace("-", "_")
            tactic = TACTIC_NAME_TO_ID.get(name)
        else:
            tactic = None
        if tactic and tactic not in tactics:
            tactics.append(tactic)
    return techniques, tactics
