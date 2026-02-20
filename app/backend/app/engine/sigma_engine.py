"""
Sigma Detection Engine — pySigma-based rule evaluation.

Pipeline:
  1. Load Sigma YAML rules from disk (or DB)
  2. Compile each rule to a callable matcher
  3. For each incoming OCSF event:
     a. Look up applicable rules by logsource
     b. Evaluate each rule against the event
     c. Yield Detection objects for matches

Usage:
    engine = SigmaEngine()
    await engine.load_rules_from_dir("/opt/mxtac/rules")
    async for alert in engine.evaluate(ocsf_event):
        await queue.publish(Topic.ALERTS, alert.dict())
"""

from __future__ import annotations

import re
import yaml
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncGenerator
from uuid import uuid4

from ..core.logging import get_logger
from ..services.normalizers.ocsf import OCSFEvent

logger = get_logger(__name__)


# ── Rule data structures ─────────────────────────────────────────────────────

@dataclass
class SigmaRule:
    id: str
    title: str
    description: str
    status: str                         # stable, test, experimental
    level: str                          # critical, high, medium, low, informational
    logsource: dict[str, str]
    detection: dict[str, Any]
    tags: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    enabled: bool = True

    # Parsed ATT&CK tags
    technique_ids: list[str] = field(default_factory=list)
    tactic_ids:    list[str] = field(default_factory=list)

    # Compiled condition (set by SigmaEngine)
    _matcher: Any = field(default=None, repr=False)


LEVEL_SEVERITY: dict[str, int] = {
    "critical": 5,
    "high":     4,
    "medium":   3,
    "low":      2,
    "informational": 1,
}


@dataclass
class SigmaAlert:
    """A fired Sigma rule match."""
    id: str = field(default_factory=lambda: str(uuid4()))
    rule_id: str = ""
    rule_title: str = ""
    level: str = "medium"
    severity_id: int = 3
    technique_ids: list[str] = field(default_factory=list)
    tactic_ids:    list[str] = field(default_factory=list)
    host: str = ""
    time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    event_snapshot: dict[str, Any] = field(default_factory=dict)


# ── Condition evaluator ──────────────────────────────────────────────────────

class _Condition:
    """
    Evaluates a single Sigma detection block against a flat event dict.
    Supports: keywords, field modifiers (contains, startswith, endswith, re)
    """

    def __init__(self, detection: dict[str, Any]) -> None:
        self._detection = detection
        self._condition = detection.get("condition", "selection")

    def matches(self, event: dict[str, Any]) -> bool:
        """Return True if the detection condition matches the event."""
        named_results: dict[str, bool] = {}

        for name, criterion in self._detection.items():
            if name == "condition":
                continue
            named_results[name] = self._eval_selection(criterion, event)

        return self._eval_condition(self._condition, named_results)

    def _eval_selection(self, criterion: Any, event: dict[str, Any]) -> bool:
        """Evaluate one named selection block."""
        if isinstance(criterion, list):
            # OR of keyword strings
            return any(self._value_in_event(kw, event) for kw in criterion)
        if isinstance(criterion, dict):
            # AND of field matchers
            return all(
                self._field_matches(field_expr, values, event)
                for field_expr, values in criterion.items()
            )
        # Simple scalar keyword
        return self._value_in_event(str(criterion), event)

    def _field_matches(self, field_expr: str, values: Any, event: dict[str, Any]) -> bool:
        """Match field|modifier(s) against values."""
        parts     = field_expr.split("|")
        field_key = parts[0]
        modifiers = parts[1:] if len(parts) > 1 else []

        field_val = self._get_field(field_key, event)
        if field_val is None:
            return False

        field_str = str(field_val).lower()
        value_list = values if isinstance(values, list) else [values]

        def _check_one(v: Any) -> bool:
            vs = str(v).lower()
            if "contains" in modifiers:  return vs in field_str
            if "startswith" in modifiers: return field_str.startswith(vs)
            if "endswith" in modifiers:   return field_str.endswith(vs)
            if "re" in modifiers:
                try:
                    return bool(re.search(v, field_str, re.IGNORECASE))
                except re.error:
                    return False
            if "base64" in modifiers:
                import base64
                try:
                    decoded = base64.b64decode(v).decode(errors="replace").lower()
                    return decoded in field_str
                except Exception:
                    return False
            if "cidr" in modifiers:
                return self._cidr_match(field_str, vs)
            # Default: exact match
            return vs == field_str

        # all/any modifier
        if "all" in modifiers:
            return all(_check_one(v) for v in value_list)
        return any(_check_one(v) for v in value_list)

    def _get_field(self, field_key: str, event: dict[str, Any]) -> Any:
        """Support dot-notation lookup (e.g. process.cmd_line)."""
        parts = field_key.split(".")
        val   = event
        for part in parts:
            if isinstance(val, dict):
                val = val.get(part)
            else:
                return None
        return val

    def _value_in_event(self, keyword: str, event: dict[str, Any]) -> bool:
        """Check if keyword appears in any event value."""
        kw = keyword.lower()
        return any(kw in str(v).lower() for v in self._flatten_values(event))

    def _flatten_values(self, d: Any, depth: int = 0) -> list[Any]:
        if depth > 5:
            return []
        if isinstance(d, dict):
            result = []
            for v in d.values():
                result.extend(self._flatten_values(v, depth + 1))
            return result
        if isinstance(d, list):
            result = []
            for v in d:
                result.extend(self._flatten_values(v, depth + 1))
            return result
        return [d]

    def _eval_condition(self, condition: str, results: dict[str, bool]) -> bool:
        """Parse simple Sigma condition expressions: 'selection', 'not filter', 'A and B', etc."""
        condition = condition.strip()

        # Single name
        if condition in results:
            return results[condition]

        # NOT
        if condition.startswith("not "):
            return not self._eval_condition(condition[4:], results)

        # AND / OR with precedence (AND binds tighter)
        if " or " in condition:
            return any(
                self._eval_condition(part.strip(), results)
                for part in condition.split(" or ")
            )
        if " and " in condition:
            return all(
                self._eval_condition(part.strip(), results)
                for part in condition.split(" and ")
            )

        # Parentheses (simple)
        if condition.startswith("(") and condition.endswith(")"):
            return self._eval_condition(condition[1:-1], results)

        # Count-based (1 of them / all of them / 1 of pattern*)
        # "them" is a Sigma keyword meaning all named selections (equivalent to *)
        if condition.startswith("1 of "):
            pattern = condition[5:].strip()
            if pattern == "them":
                pattern = "*"
            regex = re.compile(pattern.replace("*", ".*"), re.IGNORECASE)
            return any(v for k, v in results.items() if regex.match(k))
        if condition.startswith("all of "):
            pattern = condition[7:].strip()
            if pattern == "them":
                pattern = "*"
            regex = re.compile(pattern.replace("*", ".*"), re.IGNORECASE)
            matched_keys = [k for k in results if regex.match(k)]
            if not matched_keys:
                return False
            return all(results.get(k, False) for k in matched_keys)

        return False

    def _cidr_match(self, ip: str, cidr: str) -> bool:
        """Simple CIDR check without external deps."""
        try:
            import ipaddress
            return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
        except Exception:
            return False


# ── Engine ───────────────────────────────────────────────────────────────────

class SigmaEngine:
    """
    Loads, indexes, and evaluates Sigma rules against OCSF events.

    Rules are indexed by logsource (category, product, service) to
    avoid evaluating every rule for every event.
    """

    def __init__(self) -> None:
        self._rules: dict[str, SigmaRule] = {}
        self._index: dict[str, list[SigmaRule]] = {}  # logsource_key → rules

    # ── Loading ──────────────────────────────────────────────────────────────

    def load_rule_yaml(self, yaml_text: str) -> SigmaRule | None:
        """Parse a single Sigma YAML string into a SigmaRule."""
        try:
            doc = yaml.safe_load(yaml_text)
            if not isinstance(doc, dict):
                return None

            rule = SigmaRule(
                id=str(doc.get("id", str(uuid4()))),
                title=doc.get("title", "Untitled"),
                description=doc.get("description", ""),
                status=doc.get("status", "experimental"),
                level=doc.get("level", "medium"),
                logsource=doc.get("logsource", {}),
                detection=doc.get("detection", {}),
                tags=doc.get("tags", []),
                references=doc.get("references", []),
            )

            # Extract ATT&CK tags  (attack.tXXXX techniques, attack.taXXXX tactics)
            # Check tactic prefix first — "attack.ta" is a subset of "attack.t"
            for tag in rule.tags:
                tl = tag.lower()
                if tl.startswith("attack.ta"):
                    rule.tactic_ids.append(tag.split(".", 1)[1].upper())
                elif tl.startswith("attack.t"):
                    rule.technique_ids.append(tag.split(".", 1)[1].upper())

            rule._matcher = _Condition(rule.detection)
            return rule
        except Exception:
            logger.exception("Failed to parse Sigma rule yaml")
            return None

    async def load_rules_from_dir(self, directory: str) -> int:
        """Load all .yml / .yaml files from a directory tree."""
        loaded = 0
        for path in Path(directory).rglob("*.y*ml"):
            try:
                rule = self.load_rule_yaml(path.read_text())
                if rule:
                    self.add_rule(rule)
                    loaded += 1
            except Exception:
                logger.warning("Skipping rule file path=%s", path)
        logger.info("SigmaEngine loaded rules count=%d from=%s", loaded, directory)
        return loaded

    def add_rule(self, rule: SigmaRule) -> None:
        self._rules[rule.id] = rule
        for key in self._logsource_keys(rule.logsource):
            self._index.setdefault(key, []).append(rule)

    def remove_rule(self, rule_id: str) -> None:
        """Remove a rule from the engine and all index entries."""
        rule = self._rules.pop(rule_id, None)
        if rule is None:
            return
        for key in self._logsource_keys(rule.logsource):
            lst = self._index.get(key)
            if lst is not None:
                self._index[key] = [r for r in lst if r.id != rule_id]

    def upsert_rule(self, rule: SigmaRule) -> None:
        """Add or replace a rule (removes existing index entries first)."""
        if rule.id in self._rules:
            self.remove_rule(rule.id)
        self.add_rule(rule)

    async def load_rules_from_db(self, session: Any) -> int:
        """Load all rules from the database into the engine.

        Uses upsert_rule so DB state overrides any disk-loaded rules with the
        same ID. The rule's enabled flag is taken from the DB record.
        """
        from ..repositories.rule_repo import RuleRepo
        db_rules = await RuleRepo.list(session)
        loaded = 0
        for db_rule in db_rules:
            if not db_rule.content:
                continue
            sigma_rule = self.load_rule_yaml(db_rule.content)
            if sigma_rule:
                sigma_rule.enabled = db_rule.enabled
                self.upsert_rule(sigma_rule)
                loaded += 1
        logger.info("SigmaEngine loaded rules from DB count=%d", loaded)
        return loaded

    # ── Evaluation ────────────────────────────────────────────────────────────

    async def evaluate(self, event: OCSFEvent) -> AsyncGenerator[SigmaAlert, None]:
        """Yield SigmaAlert for each matching rule."""
        flat_event = event.model_dump()
        flat_event["_product"]  = event.metadata_product.lower()
        # Flatten process fields for direct field matching
        flat_event.update(event.process.model_dump())
        flat_event.update(event.src_endpoint.model_dump())

        candidate_rules = self._get_candidates(event)

        for rule in candidate_rules:
            if not rule.enabled:
                continue
            try:
                if rule._matcher.matches(flat_event):
                    yield SigmaAlert(
                        rule_id=rule.id,
                        rule_title=rule.title,
                        level=rule.level,
                        severity_id=LEVEL_SEVERITY.get(rule.level, 3),
                        technique_ids=rule.technique_ids,
                        tactic_ids=rule.tactic_ids,
                        host=event.dst_endpoint.hostname or event.dst_endpoint.ip or "",
                        time=event.time,
                        event_snapshot=flat_event,
                    )
            except Exception:
                logger.debug("Rule eval error rule_id=%s", rule.id)

    def _get_candidates(self, event: OCSFEvent) -> list[SigmaRule]:
        """Return rules applicable to this event based on logsource."""
        product = event.metadata_product.lower()
        results: list[SigmaRule] = []

        # Product-level rules
        results.extend(self._index.get(f"product:{product}", []))

        # Category-based rules (e.g. process_creation, network_connection)
        if event.class_uid == 1007:   # Process Activity
            results.extend(self._index.get("category:process_creation", []))
        elif event.class_uid == 4001: # Network Activity
            results.extend(self._index.get("category:network_connection", []))
        elif event.class_uid == 4003: # DNS
            results.extend(self._index.get("category:dns_query", []))
        elif event.class_uid == 3002: # Authentication
            results.extend(self._index.get("category:authentication", []))

        # Global rules (no logsource filter)
        results.extend(self._index.get("*", []))

        # Deduplicate
        seen = set()
        unique = []
        for r in results:
            if r.id not in seen:
                seen.add(r.id)
                unique.append(r)
        return unique

    def _logsource_keys(self, logsource: dict) -> list[str]:
        keys = []
        if product := logsource.get("product"):
            keys.append(f"product:{product.lower()}")
        if category := logsource.get("category"):
            keys.append(f"category:{category.lower()}")
        if service := logsource.get("service"):
            keys.append(f"service:{service.lower()}")
        if not keys:
            keys = ["*"]
        return keys

    # ── Stats ─────────────────────────────────────────────────────────────────

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def get_rules(self, enabled_only: bool = False) -> list[dict]:
        rules = self._rules.values()
        if enabled_only:
            rules = (r for r in rules if r.enabled)
        return [
            {
                "id":            r.id,
                "title":         r.title,
                "level":         r.level,
                "status":        r.status,
                "enabled":       r.enabled,
                "technique_ids": r.technique_ids,
                "tactic_ids":    r.tactic_ids,
                "logsource":     r.logsource,
            }
            for r in rules
        ]
