#!/usr/bin/env python3
"""Generate the bundled ATT&CK technique name table.

Reads the MITRE ATT&CK Enterprise STIX bundle and writes
``app/backend/app/data/attack_techniques.json``: technique and sub-technique
ID -> name, without revoked and deprecated entries.

    python scripts/gen_attack_techniques.py 20.1               # download that release
    python scripts/gen_attack_techniques.py 20.1 bundle.json   # use a local copy of it
    python scripts/gen_attack_techniques.py --check            # the table is well-formed

The bundle does not state its ATT&CK version, so the version is an argument and
the download is taken from the release tag of that version in mitre/cti.

The names are (c) The MITRE Corporation and are reproduced under the ATT&CK
terms of use; see the NOTICE file at the repository root.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from datetime import date
from pathlib import Path

# Release tag "ATT&CK-v<version>" of https://github.com/mitre/cti
SOURCE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v{version}"
    "/enterprise-attack/enterprise-attack.json"
)
VERSION_RE = re.compile(r"^\d+\.\d+$")
OUTPUT = Path(__file__).resolve().parent.parent / "app/backend/app/data/attack_techniques.json"
TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
NOTICE = (
    "(c) The MITRE Corporation. This work is reproduced and distributed with the "
    "permission of The MITRE Corporation."
)


def _technique_sort_key(technique_id: str) -> tuple[int, int]:
    base, _, sub = technique_id[1:].partition(".")
    return int(base), int(sub or -1)


def build_table(bundle: dict, version: str, retrieved: str) -> dict:
    """Technique table from a STIX bundle, with its provenance first."""
    techniques: dict[str, str] = {}
    for obj in bundle["objects"]:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        for ref in obj.get("external_references", []):
            technique_id = ref.get("external_id", "")
            if ref.get("source_name") == "mitre-attack" and TECHNIQUE_ID_RE.match(technique_id):
                if technique_id in techniques:
                    raise ValueError(f"{technique_id} appears twice in the bundle")
                techniques[technique_id] = obj["name"].strip()
    return {
        "source": "MITRE ATT&CK Enterprise",
        "source_url": SOURCE_URL.format(version=version),
        "attack_version": version,
        "retrieved": retrieved,
        "notice": NOTICE,
        "generated_by": "scripts/gen_attack_techniques.py",
        "techniques": {
            technique_id: techniques[technique_id]
            for technique_id in sorted(techniques, key=_technique_sort_key)
        },
    }


def check_table(table: dict) -> list[str]:
    """Problems of a generated table; empty when it is well-formed."""
    problems = []
    for key in ("source", "source_url", "attack_version", "retrieved", "notice", "techniques"):
        if not table.get(key):
            problems.append(f"missing {key}")
    techniques = table.get("techniques") or {}
    for technique_id, name in techniques.items():
        if not TECHNIQUE_ID_RE.match(technique_id):
            problems.append(f"bad technique ID {technique_id!r}")
        if not isinstance(name, str) or not name.strip():
            problems.append(f"{technique_id} has no name")
        parent = technique_id.partition(".")[0]
        if parent != technique_id and parent not in techniques:
            problems.append(f"{technique_id} has no parent technique {parent}")
    if list(techniques) != sorted(techniques, key=_technique_sort_key):
        problems.append("techniques are not sorted by ID")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("version", nargs="?", help="ATT&CK release, for example 20.1")
    parser.add_argument("bundle", nargs="?", help="local copy of that release's enterprise-attack.json")
    parser.add_argument("--retrieved", default=date.today().isoformat(),
                        help="date the bundle was downloaded (default: today)")
    parser.add_argument("--check", action="store_true",
                        help="only verify the table that is already in the repository")
    args = parser.parse_args()

    if args.check:
        problems = check_table(json.loads(OUTPUT.read_text(encoding="utf-8")))
        for problem in problems:
            print(problem, file=sys.stderr)
        return 1 if problems else 0

    if not args.version or not VERSION_RE.match(args.version):
        parser.error("give the ATT&CK release to bundle, for example 20.1")
    if args.bundle:
        bundle = json.loads(Path(args.bundle).read_text(encoding="utf-8"))
    else:
        url = SOURCE_URL.format(version=args.version)
        with urllib.request.urlopen(url, timeout=300) as response:  # noqa: S310 (fixed https host)
            bundle = json.load(response)

    table = build_table(bundle, args.version, args.retrieved)
    problems = check_table(table)
    if problems:
        print("\n".join(problems), file=sys.stderr)
        return 1
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_bytes((json.dumps(table, indent=1, ensure_ascii=False) + "\n").encode("utf-8"))
    print(f"ATT&CK v{table['attack_version']}: {len(table['techniques'])} techniques -> {OUTPUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
