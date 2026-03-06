"""
Project-specific codebase rules checker.

Loads rules from {project_root}/.agent-scheduler/lint-rules.yaml and checks
files against them using regex/string matching (zero API cost).

Two entry points:
  - check_all(project_root)   → LintAgent: scan entire codebase
  - check_files(project_root, file_list) → VerifierAgent: scan only specific files
"""

import fnmatch
import logging
import re
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

RULES_FILE = ".agent-scheduler/lint-rules.yaml"

# Supported check types
CHECK_TYPES = {
    "must_contain",
    "must_not_contain",
    "must_match",
    "must_not_match",
    "filename_must_match",
}


def _load_rules(project_root: Path) -> list[dict]:
    """Load rules from the project's lint-rules.yaml. Returns [] if missing."""
    rules_path = project_root / RULES_FILE
    if not rules_path.exists():
        return []
    try:
        with open(rules_path) as f:
            data = yaml.safe_load(f)
        rules = data.get("rules", []) if isinstance(data, dict) else []
        # Validate each rule has required fields
        valid = []
        for r in rules:
            if not isinstance(r, dict):
                continue
            if not r.get("name") or not r.get("glob"):
                logger.warning(f"Skipping rule missing name/glob: {r}")
                continue
            check_keys = CHECK_TYPES & set(r.keys())
            if not check_keys:
                logger.warning(f"Skipping rule '{r['name']}' — no check type found")
                continue
            valid.append(r)
        return valid
    except Exception as e:
        logger.error(f"Failed to load rules from {rules_path}: {e}")
        return []


def _glob_files(project_root: Path, pattern: str, exclude: str | None = None) -> list[Path]:
    """Collect files matching a glob pattern under project_root."""
    files = list(project_root.glob(pattern))
    if exclude:
        files = [
            f for f in files
            if not fnmatch.fnmatch(str(f.relative_to(project_root)), exclude)
            and not fnmatch.fnmatch(f.name, exclude)
        ]
    return [f for f in files if f.is_file()]


def _check_rule(rule: dict, file_path: Path) -> dict | None:
    """
    Check a single rule against a single file.
    Returns a violation dict if the rule is violated, else None.
    """
    name = rule["name"]
    severity = rule.get("severity", "error")

    # filename_must_match — checks basename only, no file content needed
    if "filename_must_match" in rule:
        pattern = rule["filename_must_match"]
        if not re.search(pattern, file_path.name):
            return {
                "rule": name,
                "file": str(file_path),
                "severity": severity,
                "detail": f"Filename '{file_path.name}' does not match /{pattern}/",
            }
        return None

    # Read file content for content-based checks
    try:
        content = file_path.read_text(errors="replace")
    except Exception as e:
        return {
            "rule": name,
            "file": str(file_path),
            "severity": severity,
            "detail": f"Cannot read file: {e}",
        }

    lines = content.splitlines()

    if "must_contain" in rule:
        needle = rule["must_contain"]
        if needle not in content:
            return {
                "rule": name,
                "file": str(file_path),
                "severity": severity,
                "detail": f"File must contain '{needle}' but does not",
            }

    if "must_not_contain" in rule:
        needle = rule["must_not_contain"]
        if needle in content:
            # Find first occurrence line number
            for i, line in enumerate(lines, 1):
                if needle in line:
                    return {
                        "rule": name,
                        "file": str(file_path),
                        "severity": severity,
                        "detail": f"File must not contain '{needle}' (line {i})",
                    }

    if "must_match" in rule:
        pattern = rule["must_match"]
        try:
            regex = re.compile(pattern)
        except re.error as e:
            return {
                "rule": name,
                "file": str(file_path),
                "severity": "warning",
                "detail": f"Invalid regex '{pattern}': {e}",
            }
        if not any(regex.search(line) for line in lines):
            return {
                "rule": name,
                "file": str(file_path),
                "severity": severity,
                "detail": f"No line matches /{pattern}/",
            }

    if "must_not_match" in rule:
        pattern = rule["must_not_match"]
        try:
            regex = re.compile(pattern)
        except re.error as e:
            return {
                "rule": name,
                "file": str(file_path),
                "severity": "warning",
                "detail": f"Invalid regex '{pattern}': {e}",
            }
        for i, line in enumerate(lines, 1):
            if regex.search(line):
                return {
                    "rule": name,
                    "file": str(file_path),
                    "severity": severity,
                    "detail": f"Line {i} matches forbidden /{pattern}/",
                }

    return None


def _run_checks(project_root: Path, files_filter: list[str] | None = None) -> list[dict]:
    """
    Core check runner.

    If files_filter is None, scan all files matching each rule's glob.
    If files_filter is provided, only check those files against applicable rules.
    """
    rules = _load_rules(project_root)
    if not rules:
        return []

    violations = []

    for rule in rules:
        pattern = rule["glob"]
        exclude = rule.get("exclude_glob")

        if files_filter is not None:
            # Only check files from the filter list that match this rule's glob
            candidates = []
            for f in files_filter:
                p = Path(f)
                if not p.is_absolute():
                    p = project_root / p
                if p.is_file() and fnmatch.fnmatch(str(p.relative_to(project_root)), pattern):
                    if exclude and (
                        fnmatch.fnmatch(str(p.relative_to(project_root)), exclude)
                        or fnmatch.fnmatch(p.name, exclude)
                    ):
                        continue
                    candidates.append(p)
        else:
            candidates = _glob_files(project_root, pattern, exclude)

        for file_path in candidates:
            violation = _check_rule(rule, file_path)
            if violation:
                # Make path relative for readability
                try:
                    violation["file"] = str(file_path.relative_to(project_root))
                except ValueError:
                    pass
                violations.append(violation)

    return violations


def check_all(project_root: str | Path) -> dict:
    """
    LintAgent entry point: scan entire codebase against all rules.

    Returns:
        {
            "errors": int,
            "warnings": int,
            "violations": [...],
            "detail": str,
        }
    """
    root = Path(project_root)
    violations = _run_checks(root)

    errors = sum(1 for v in violations if v["severity"] == "error")
    warnings = sum(1 for v in violations if v["severity"] == "warning")

    return {
        "tool": "project_rules",
        "errors": errors,
        "warnings": warnings,
        "violations": violations[:50],  # Cap for reporting
        "detail": f"{errors} errors, {warnings} warnings from project rules",
    }


def check_files(project_root: str | Path, file_list: list[str]) -> dict:
    """
    VerifierAgent entry point: check specific files against applicable rules.

    Returns:
        {
            "pass": bool,     (True if no errors — warnings don't block)
            "errors": int,
            "warnings": int,
            "violations": [...],
            "detail": str,
        }
    """
    root = Path(project_root)
    violations = _run_checks(root, files_filter=file_list)

    errors = sum(1 for v in violations if v["severity"] == "error")
    warnings = sum(1 for v in violations if v["severity"] == "warning")

    return {
        "check": "project_rules",
        "pass": errors == 0,
        "errors": errors,
        "warnings": warnings,
        "violations": violations[:20],
        "detail": f"Rules: {errors} errors, {warnings} warnings"
            if violations else "All project rules passed",
    }
