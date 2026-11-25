"""Generate the table of bundled Sigma rules in docs/sigma-engine.md.

Usage (from the repository root, with the backend dependencies installed):

    python scripts/gen_rule_table.py            # print the table
    python scripts/gen_rule_table.py --write    # replace the table in docs/sigma-engine.md

The table is built from the YAML files in app/backend/sigma_rules/. ATT&CK tags
are parsed with the same function the Sigma engine uses. The "Applies to"
column is derived from each rule's logsource, following the selection logic in
app/backend/app/engine/sigma_engine.py.
"""
import logging
import os
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "app" / "backend" / "sigma_rules"
DOC = REPO_ROOT / "docs" / "sigma-engine.md"
START = "<!-- bundled-rules:start -->"
END = "<!-- bundled-rules:end -->"

os.environ.setdefault("SQLITE_MODE", "true")
sys.path.insert(0, str(REPO_ROOT / "app" / "backend"))
logging.disable(logging.CRITICAL)

from app.engine.sigma_engine import TACTIC_NAME_TO_ID, parse_attack_tags  # noqa: E402

TACTIC_NAMES = {
    tactic_id: name.replace("_", " ").title().replace(" And ", " and ")
    for name, tactic_id in TACTIC_NAME_TO_ID.items()
}

CATEGORY_EVENTS = {
    "process_creation": "process events",
    "network_connection": "network connection events",
    "dns_query": "DNS events",
    "authentication": "authentication events",
}
HOST_SOURCES = "Wazuh, syslog, webhook"


def applies_to(logsource: dict) -> str:
    product = str(logsource.get("product") or "").lower()
    category = str(logsource.get("category") or "").lower()
    service = str(logsource.get("service") or "").lower()
    events = CATEGORY_EVENTS.get(category, "events")
    if product in ("zeek", "suricata"):
        text = f"{product.title()} {events}"
    elif product:
        text = f"{events.capitalize()} from {product.title()} hosts ({HOST_SOURCES})"
    elif category:
        text = f"{events[0].upper()}{events[1:]} from any source"
    else:
        text = "Every event"
    if service:
        text += f", service `{service}`"
    return text


def build_table() -> str:
    rows = []
    for path in sorted(RULES_DIR.glob("*.y*ml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        techniques, tactics = parse_attack_tags(doc.get("tags") or [])
        rows.append(
            "| `%s` | %s | %s | %s | %s | %s |"
            % (
                path.name,
                doc.get("title", "Untitled"),
                doc.get("level", "medium"),
                ", ".join(techniques) or "-",
                ", ".join(TACTIC_NAMES.get(t, t) for t in tactics) or "-",
                applies_to(doc.get("logsource") or {}),
            )
        )
    header = [
        "| File | Title | Level | Technique | Tactic | Applies to |",
        "|------|-------|-------|-----------|--------|------------|",
    ]
    return "\n".join(header + rows)


def main() -> None:
    table = build_table()
    if "--write" not in sys.argv:
        print(table)
        return
    text = DOC.read_text(encoding="utf-8")
    start, end = text.index(START), text.index(END)
    text = text[: start + len(START)] + "\n" + table + "\n" + text[end:]
    DOC.write_text(text, encoding="utf-8", newline="\n")
    print("updated", DOC.relative_to(REPO_ROOT), "-", table.count("\n") - 1, "rules")


if __name__ == "__main__":
    main()
