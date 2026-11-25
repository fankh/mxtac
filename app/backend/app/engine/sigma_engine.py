"""
Sigma Detection Engine — evaluates a subset of the Sigma specification.

Pipeline:
  1. Load Sigma YAML rules (from the ``rules`` database table)
  2. Compile each rule to a callable matcher
  3. For each incoming OCSF event:
     a. Look up applicable rules by logsource
     b. Evaluate each rule against the event
     c. Yield SigmaAlert objects for matches

Supported detection syntax:
  - selections: map of fields (AND), list of maps (OR), list of keywords (OR)
  - value modifiers: contains, startswith, endswith, all, re, cidr, base64
  - wildcards ``*`` and ``?`` in plain string values, case-insensitive matching
  - conditions: and / or / not / parentheses, ``1 of``, ``<n> of``, ``all of``
    with ``them`` or a wildcard selection pattern

A rule that uses anything else (aggregations, ``timeframe``, correlation
rules, unknown modifiers) is rejected with :class:`SigmaRuleError` instead of
being loaded and silently never matching.

Usage:
    engine = SigmaEngine()
    await engine.load_rules_from_db(session)
    async for alert in engine.evaluate(ocsf_event):
        await queue.publish(Topic.ALERTS, alert.dict())
"""

from __future__ import annotations

import base64
import ipaddress
import re
from collections.abc import AsyncGenerator, Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any
from uuid import uuid4

import yaml

from ..core.logging import get_logger
from ..core.metrics import rule_matches as _rule_matches_counter
from ..repositories.rule_repo import RuleRepo
from ..services.normalizers.ocsf import OCSFClass, OCSFEvent
from .attack_tags import TACTIC_ID_TO_NAME as TACTIC_ID_TO_NAME
from .attack_tags import TACTIC_NAME_TO_ID as TACTIC_NAME_TO_ID
from .attack_tags import parse_attack_tags
from .attack_tags import tactic_name as tactic_name
from .field_mapper import ocsf_to_sigma_flat

logger = get_logger(__name__)

Matcher = Callable[[dict[str, Any]], bool]


class SigmaRuleError(ValueError):
    """The rule is not valid Sigma or uses syntax this engine does not support."""


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
    time: datetime = field(default_factory=lambda: datetime.now(UTC))
    event_snapshot: dict[str, Any] = field(default_factory=dict)
    # ID of the stored event that matched (assigned by the normalizer pipeline;
    # filled in by the Sigma consumer, None for an event without one).
    event_id: str | None = None


# ── Field lookup ─────────────────────────────────────────────────────────────

def _get_field(event: dict[str, Any], key: str) -> Any:
    """Look up *key* as a literal key first, then as a dot-separated path."""
    if key in event:
        return event[key]
    val: Any = event
    for part in key.split("."):
        if not isinstance(val, dict):
            return None
        val = val.get(part)
    return val


def _flatten_values(value: Any, depth: int = 0) -> list[Any]:
    """All scalar values of a nested dict / list (used by keyword selections)."""
    if depth > 5:
        return []
    if isinstance(value, dict):
        value = list(value.values())
    if isinstance(value, list):
        return [leaf for item in value for leaf in _flatten_values(item, depth + 1)]
    return [value]


# ── Value matchers ───────────────────────────────────────────────────────────
# A value matcher takes one scalar field value and returns True on a match.

ValueMatcher = Callable[[Any], bool]

_SUPPORTED_MODIFIERS = frozenset(
    {"contains", "startswith", "endswith", "all", "re", "cidr", "base64"}
)
_STRING_MODES = ("contains", "startswith", "endswith")
_WILDCARD_TOKEN_RE = re.compile(r"\\([*?\\])|([*?])")


def _parse_wildcards(value: str) -> tuple[str, re.Pattern[str] | None]:
    """Split a Sigma string into ``(literal, regex)``.

    ``*`` and ``?`` are wildcards unless escaped with a backslash; ``\\\\`` is
    a literal backslash.  *regex* is ``None`` when the value has no wildcards,
    in which case *literal* is the unescaped, lower-cased string.
    """
    literal: list[str] = []
    pattern: list[str] = []
    has_wildcard = False
    pos = 0
    for m in _WILDCARD_TOKEN_RE.finditer(value):
        chunk = value[pos:m.start()]
        literal.append(chunk)
        pattern.append(re.escape(chunk))
        if m.group(1):                       # escaped character
            literal.append(m.group(1))
            pattern.append(re.escape(m.group(1)))
        else:
            has_wildcard = True
            pattern.append(".*" if m.group(2) == "*" else ".")
        pos = m.end()
    literal.append(value[pos:])
    pattern.append(re.escape(value[pos:]))
    if not has_wildcard:
        return "".join(literal).lower(), None
    return "", re.compile("".join(pattern), re.IGNORECASE | re.DOTALL)


def _string_matcher(value: Any, mode: str | None) -> ValueMatcher:
    """Case-insensitive string comparison with ``*`` / ``?`` wildcard support."""
    literal, regex = _parse_wildcards(str(value))

    if regex is not None:
        prefix = "" if mode in (None, "startswith") else ".*"
        suffix = "" if mode in (None, "endswith") else ".*"
        full = re.compile(f"{prefix}(?:{regex.pattern}){suffix}", regex.flags)
        return lambda fv: full.fullmatch(str(fv)) is not None

    if mode == "contains":
        return lambda fv: literal in str(fv).lower()
    if mode == "startswith":
        return lambda fv: str(fv).lower().startswith(literal)
    if mode == "endswith":
        return lambda fv: str(fv).lower().endswith(literal)
    return lambda fv: str(fv).lower() == literal


def _base64_matcher(value: Any, mode: str | None) -> ValueMatcher:
    """Compare against the base64 encoding of *value* (case-sensitive)."""
    encoded = base64.b64encode(str(value).encode("utf-8")).decode("ascii")
    if mode == "contains":
        return lambda fv: encoded in str(fv)
    if mode == "startswith":
        return lambda fv: str(fv).startswith(encoded)
    if mode == "endswith":
        return lambda fv: str(fv).endswith(encoded)
    return lambda fv: str(fv) == encoded


def _regex_matcher(value: Any, field_expr: str) -> ValueMatcher:
    try:
        pattern = re.compile(str(value), re.IGNORECASE)
    except re.error as exc:
        raise SigmaRuleError(
            f"invalid regular expression in '{field_expr}': {exc}"
        ) from exc
    return lambda fv: pattern.search(str(fv)) is not None


def _cidr_matcher(value: Any, field_expr: str) -> ValueMatcher:
    try:
        network = ipaddress.ip_network(str(value), strict=False)
    except ValueError as exc:
        raise SigmaRuleError(f"invalid CIDR network in '{field_expr}': {value}") from exc

    def _match(fv: Any) -> bool:
        try:
            return ipaddress.ip_address(str(fv)) in network
        except ValueError:
            return False

    return _match


def _compile_field(field_expr: str, values: Any) -> Matcher:
    """Compile one ``field|modifier: value(s)`` entry of a selection."""
    key, *modifiers = str(field_expr).split("|")
    unknown = [m for m in modifiers if m not in _SUPPORTED_MODIFIERS]
    if unknown:
        raise SigmaRuleError(
            f"unsupported modifier '{unknown[0]}' in '{field_expr}' "
            f"(supported: {', '.join(sorted(_SUPPORTED_MODIFIERS))})"
        )
    mode = next((m for m in _STRING_MODES if m in modifiers), None)
    value_list = values if isinstance(values, list) else [values]
    if not value_list:
        raise SigmaRuleError(f"'{field_expr}' has an empty value list")

    matchers: list[ValueMatcher] = []
    for value in value_list:
        if isinstance(value, dict | list):
            raise SigmaRuleError(f"'{field_expr}' has a nested value; expected a scalar or a list of scalars")
        if value is None:
            matchers.append(lambda fv: fv is None)
        elif "re" in modifiers:
            matchers.append(_regex_matcher(value, field_expr))
        elif "cidr" in modifiers:
            matchers.append(_cidr_matcher(value, field_expr))
        elif "base64" in modifiers:
            matchers.append(_base64_matcher(value, mode))
        else:
            matchers.append(_string_matcher(value, mode))

    matches_null = any(value is None for value in value_list)
    combine = all if "all" in modifiers else any

    def _match(event: dict[str, Any]) -> bool:
        fv = _get_field(event, key)
        if fv is None:
            return matches_null
        candidates = fv if isinstance(fv, list | tuple) else (fv,)
        return combine(any(m(c) for c in candidates) for m in matchers)

    return _match


def _compile_keywords(keywords: list[Any]) -> Matcher:
    """Keyword search: any keyword matches any value of the event."""
    matchers = [_string_matcher(kw, "contains") for kw in keywords]

    def _match(event: dict[str, Any]) -> bool:
        values = [v for v in _flatten_values(event) if v is not None]
        return any(m(v) for m in matchers for v in values)

    return _match


def _compile_map(selection: dict[str, Any]) -> Matcher:
    """A map of fields: every field must match."""
    if not selection:
        raise SigmaRuleError("empty selection")
    field_matchers = [_compile_field(fe, vals) for fe, vals in selection.items()]
    if len(field_matchers) == 1:
        return field_matchers[0]
    return lambda event: all(m(event) for m in field_matchers)


def _compile_selection(name: str, selection: Any) -> Matcher:
    try:
        if isinstance(selection, dict):
            return _compile_map(selection)
        if isinstance(selection, list):
            if not selection:
                raise SigmaRuleError("empty selection")
            if all(isinstance(item, dict) for item in selection):
                alternatives = [_compile_map(item) for item in selection]
                return lambda event: any(m(event) for m in alternatives)
            if any(isinstance(item, dict | list) for item in selection):
                raise SigmaRuleError("a list selection must contain only maps or only keywords")
            return _compile_keywords(selection)
        if selection is None:
            raise SigmaRuleError("empty selection")
        return _compile_keywords([selection])
    except SigmaRuleError as exc:
        raise SigmaRuleError(f"selection '{name}': {exc}") from exc


# ── Condition parser ─────────────────────────────────────────────────────────
#
#   expr     := and_expr ( "or" and_expr )*
#   and_expr := not_expr ( "and" not_expr )*
#   not_expr := "not" not_expr | primary
#   primary  := "(" expr ")" | quantifier "of" target | selection_name
#   quantifier := "all" | <integer>
#   target   := "them" | selection_name_pattern (may contain "*")

_CONDITION_TOKEN_RE = re.compile(r"\s*(\(|\)|[^\s()]+)")


class _ConditionParser:
    def __init__(self, condition: str, selections: dict[str, Matcher]) -> None:
        if "|" in condition:
            raise SigmaRuleError(
                "aggregation expressions ('| count() ...', '| near ...') are not supported"
            )
        self._condition = condition
        self._selections = selections
        self._tokens = _CONDITION_TOKEN_RE.findall(condition)
        self._pos = 0

    def parse(self) -> Matcher:
        if not self._tokens:
            raise SigmaRuleError("empty condition")
        matcher = self._parse_or()
        if self._peek() is not None:
            raise self._error(f"unexpected '{self._peek()}'")
        return matcher

    # ── helpers ──────────────────────────────────────────────────────────────

    def _error(self, message: str) -> SigmaRuleError:
        return SigmaRuleError(f"condition '{self._condition}': {message}")

    def _peek(self, offset: int = 0) -> str | None:
        index = self._pos + offset
        return self._tokens[index] if index < len(self._tokens) else None

    def _peek_keyword(self, offset: int = 0) -> str | None:
        token = self._peek(offset)
        return token.lower() if token is not None else None

    def _next(self) -> str:
        token = self._peek()
        if token is None:
            raise self._error("unexpected end of condition")
        self._pos += 1
        return token

    # ── grammar ──────────────────────────────────────────────────────────────

    def _parse_or(self) -> Matcher:
        operands = [self._parse_and()]
        while self._peek_keyword() == "or":
            self._next()
            operands.append(self._parse_and())
        if len(operands) == 1:
            return operands[0]
        return lambda event: any(m(event) for m in operands)

    def _parse_and(self) -> Matcher:
        operands = [self._parse_not()]
        while self._peek_keyword() == "and":
            self._next()
            operands.append(self._parse_not())
        if len(operands) == 1:
            return operands[0]
        return lambda event: all(m(event) for m in operands)

    def _parse_not(self) -> Matcher:
        if self._peek_keyword() == "not":
            self._next()
            operand = self._parse_not()
            return lambda event: not operand(event)
        return self._parse_primary()

    def _parse_primary(self) -> Matcher:
        token = self._next()
        if token == "(":
            matcher = self._parse_or()
            if self._peek() != ")":
                raise self._error("missing ')'")
            self._next()
            return matcher
        if token == ")":
            raise self._error("unexpected ')'")
        if self._peek_keyword() == "of" and (token.lower() == "all" or token.isdigit()):
            self._next()
            return self._parse_quantifier(token.lower())
        if token.lower() in ("and", "or", "of"):
            raise self._error(f"unexpected '{token}'")
        if token not in self._selections:
            raise self._error(f"unknown selection '{token}'")
        return self._selections[token]

    def _parse_quantifier(self, quantifier: str) -> Matcher:
        target = self._next()
        if target in ("(", ")"):
            raise self._error(f"expected 'them' or a selection pattern after '{quantifier} of'")
        pattern = "*" if target.lower() == "them" else target.lower()
        matched = [
            m for name, m in self._selections.items() if fnmatchcase(name.lower(), pattern)
        ]
        if not matched:
            raise self._error(f"'{target}' does not match any selection")
        if quantifier == "all":
            return lambda event: all(m(event) for m in matched)
        minimum = int(quantifier)
        if minimum == 1:
            return lambda event: any(m(event) for m in matched)
        return lambda event: sum(1 for m in matched if m(event)) >= minimum


class _Condition:
    """Compiled ``detection`` block of a Sigma rule.

    Selections and the condition expression are compiled once at construction
    time; :meth:`matches` only runs the resulting closures.  Raises
    :class:`SigmaRuleError` for invalid or unsupported syntax.
    """

    def __init__(self, detection: dict[str, Any]) -> None:
        if not isinstance(detection, dict):
            raise SigmaRuleError("'detection' must be a mapping")
        if "timeframe" in detection:
            raise SigmaRuleError("'timeframe' (time-based aggregation) is not supported")

        selections = {
            str(name): _compile_selection(str(name), selection)
            for name, selection in detection.items()
            if name != "condition"
        }
        if not selections:
            raise SigmaRuleError("'detection' has no selections")

        condition = detection.get("condition", "selection")
        conditions = condition if isinstance(condition, list) else [condition]
        if not conditions or not all(isinstance(c, str) for c in conditions):
            raise SigmaRuleError("'condition' must be a string or a list of strings")
        alternatives = [_ConditionParser(c, selections).parse() for c in conditions]

        if len(alternatives) == 1:
            self.matches: Matcher = alternatives[0]
        else:
            self.matches = lambda event: any(m(event) for m in alternatives)


# ── Logsource matching ───────────────────────────────────────────────────────

# OCSF class → Sigma logsource categories the event can satisfy.
_CLASS_CATEGORIES: dict[int, frozenset[str]] = {
    OCSFClass.PROCESS_ACTIVITY: frozenset({"process_creation"}),
    OCSFClass.NETWORK_ACTIVITY: frozenset({"network_connection", "firewall"}),
    OCSFClass.DNS_ACTIVITY:     frozenset({"dns_query", "dns"}),
    OCSFClass.AUTHENTICATION:   frozenset({"authentication"}),
    OCSFClass.HTTP_ACTIVITY:    frozenset({"webserver", "proxy"}),
    OCSFClass.FILE_ACTIVITY:    frozenset(
        {"file_event", "file_access", "file_change", "file_delete"}
    ),
}

# Sources that describe network traffic, not a host: they never satisfy an
# operating-system product such as ``windows`` or ``linux``.
_NETWORK_PRODUCTS = frozenset({"zeek", "suricata"})
_OS_PRODUCTS = frozenset({"windows", "linux", "macos"})
_OS_NAME_HINTS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("windows", ("windows",)),
    ("macos", ("macos", "mac os", "darwin")),
    ("linux", (
        "linux", "ubuntu", "debian", "centos", "red hat", "rhel", "fedora",
        "suse", "amazon", "alpine", "arch", "rocky", "alma", "oracle",
    )),
)


def _os_product(event: OCSFEvent) -> str | None:
    """Operating-system product of the event's host, when the event names it."""
    os_name = (event.dst_endpoint.os_name or event.src_endpoint.os_name or "").lower()
    if not os_name:
        return None
    for product, hints in _OS_NAME_HINTS:
        if any(hint in os_name for hint in hints):
            return product
    return None


def _event_products(event: OCSFEvent) -> frozenset[str]:
    """Sigma ``logsource.product`` values this event satisfies.

    Always the source itself (``wazuh``, ``zeek``, ``syslog`` …).  Host-based
    sources also satisfy the operating system of the host; when the event does
    not say which one, any OS product is accepted and the rule's field
    conditions decide.
    """
    source = event.metadata_product.lower()
    if source in _NETWORK_PRODUCTS or source in _OS_PRODUCTS:
        return frozenset({source})
    os_product = _os_product(event)
    return frozenset({source, os_product}) if os_product else _OS_PRODUCTS | {source}


def _event_services(event: OCSFEvent) -> frozenset[str]:
    """Sigma ``logsource.service`` values named by the normalizer (may be empty)."""
    hint = event.unmapped.get("service")
    if not hint:
        return frozenset()
    hints = hint if isinstance(hint, list) else [hint]
    return frozenset(str(h).lower() for h in hints)


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

    def parse_rule_yaml(self, yaml_text: str) -> SigmaRule:
        """Parse and compile a single Sigma YAML document.

        Raises :class:`SigmaRuleError` with a message suitable for the user
        when the rule is invalid or uses unsupported syntax.
        """
        try:
            doc = yaml.safe_load(yaml_text)
        except yaml.YAMLError as exc:
            raise SigmaRuleError(f"YAML parse error: {exc}") from exc
        if not isinstance(doc, dict):
            raise SigmaRuleError("rule must be a YAML mapping")
        if "correlation" in doc:
            raise SigmaRuleError("correlation rules are not supported")

        logsource = doc.get("logsource") or {}
        if not isinstance(logsource, dict):
            raise SigmaRuleError("'logsource' must be a mapping")
        tags = doc.get("tags") or []
        if not isinstance(tags, list):
            raise SigmaRuleError("'tags' must be a list")

        rule = SigmaRule(
            id=str(doc.get("id", str(uuid4()))),
            title=doc.get("title", "Untitled"),
            description=doc.get("description", ""),
            status=doc.get("status", "experimental"),
            level=doc.get("level", "medium"),
            logsource=logsource,
            detection=doc.get("detection", {}),
            tags=tags,
            references=doc.get("references", []),
        )
        rule.technique_ids, rule.tactic_ids = parse_attack_tags(tags)
        rule._matcher = _Condition(rule.detection)
        return rule

    def load_rule_yaml(self, yaml_text: str) -> SigmaRule | None:
        """Like :meth:`parse_rule_yaml` but returns ``None`` for a bad rule."""
        try:
            return self.parse_rule_yaml(yaml_text)
        except SigmaRuleError as exc:
            logger.warning("Sigma rule rejected: %s", exc)
            return None
        except Exception:
            logger.exception("Failed to parse Sigma rule yaml")
            return None

    async def load_rules_from_dir(self, directory: str) -> int:
        """Load all .yml / .yaml files from a directory tree."""
        loaded = 0
        for path in Path(directory).rglob("*.y*ml"):
            try:
                rule = self.load_rule_yaml(path.read_text(encoding="utf-8"))
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

        The ``rules`` table is the single source of truth: bundled rule files
        are imported into it at startup (see ``services/bundled_rules.py``).
        The rule's enabled flag is taken from the DB record.
        """
        db_rules = await RuleRepo.list(session)
        loaded = 0
        for db_rule in db_rules:
            if not db_rule.content:
                continue
            sigma_rule = self.load_rule_yaml(db_rule.content)
            if sigma_rule:
                # The table's primary key identifies the rule everywhere else
                # (API, hit counters), also when the YAML carries no id.
                sigma_rule.id = db_rule.id
                sigma_rule.enabled = db_rule.enabled
                self.upsert_rule(sigma_rule)
                loaded += 1
        logger.info("SigmaEngine loaded rules from DB count=%d", loaded)
        return loaded

    async def reload_from_db(self, session: Any) -> int:
        """Hot-reload: clear all in-memory rules then reload from DB.

        Unlike load_rules_from_db (which upserts), this method first clears
        the engine state entirely so that rules deleted from the DB are also
        removed from the engine.  Use this for admin-triggered full reloads.
        """
        self._rules.clear()
        self._index.clear()
        count = await self.load_rules_from_db(session)
        logger.info("SigmaEngine hot-reload complete rules=%d", count)
        return count

    # ── Evaluation ────────────────────────────────────────────────────────────

    async def evaluate(self, event: OCSFEvent) -> AsyncGenerator[SigmaAlert, None]:
        """Yield SigmaAlert for each matching rule."""
        candidate_rules = self._get_candidates(event)

        for rule in candidate_rules:
            if not rule.enabled:
                continue
            try:
                flat_event = ocsf_to_sigma_flat(event, rule.logsource)
                if rule._matcher.matches(flat_event):
                    _rule_matches_counter.labels(rule_id=rule.id, level=rule.level).inc()
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
        """Return the rules whose logsource applies to this event.

        ``product``, ``category`` and ``service`` are each optional in a rule;
        every one that is present must be satisfied by the event:

        - product  — the source (``wazuh``, ``zeek``, ``suricata``, ``syslog`` …)
          or the host operating system (see :func:`_event_products`)
        - category — derived from the OCSF class (see ``_CLASS_CATEGORIES``)
        - service  — one of the services the normalizer names in
          ``unmapped["service"]``; ignored when the event names none
        """
        products = _event_products(event)
        categories = _CLASS_CATEGORIES.get(event.class_uid, frozenset())
        services = _event_services(event)

        keys = ["*"]
        keys += [f"product:{p}" for p in products]
        keys += [f"category:{c}" for c in categories]
        keys += [f"service:{s}" for s in services]

        seen: set[str] = set()
        candidates: list[SigmaRule] = []
        for key in keys:
            for rule in self._index.get(key, ()):
                if rule.id in seen:
                    continue
                seen.add(rule.id)
                logsource = rule.logsource
                product = str(logsource.get("product") or "").lower()
                category = str(logsource.get("category") or "").lower()
                service = str(logsource.get("service") or "").lower()
                if product and product not in products:
                    continue
                if category and category not in categories:
                    continue
                if service and services and service not in services:
                    continue
                candidates.append(rule)
        return candidates

    def _logsource_keys(self, logsource: dict[str, Any]) -> list[str]:
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

    def get_rules(self, enabled_only: bool = False) -> list[dict[str, Any]]:
        rules: Iterable[SigmaRule] = self._rules.values()
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
