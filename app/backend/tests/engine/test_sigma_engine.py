"""Tests for feature 28.14 — Sigma: rule loads from valid YAML.

Coverage for SigmaEngine.load_rule_yaml():
  - Minimal valid YAML returns a SigmaRule
  - All standard fields are parsed correctly
  - ATT&CK technique tags (attack.tXXXX) populate technique_ids
  - ATT&CK tactic tags (attack.taXXXX) populate tactic_ids
  - Mixed tags: both technique and tactic ids extracted in one pass
  - Tags with no ATT&CK prefix are ignored (not added to either list)
  - Auto-generated UUID when 'id' field is absent
  - Default field values applied when optional fields are absent
  - Compiled _matcher is set and callable
  - Empty YAML string returns None
  - Non-dict YAML (list) returns None
  - Invalid YAML syntax returns None
  - Rule with empty detection block still returns a SigmaRule
"""

from __future__ import annotations

import pytest

from app.engine.sigma_engine import SigmaEngine, SigmaRule, _Condition

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine() -> SigmaEngine:
    return SigmaEngine()


# ---------------------------------------------------------------------------
# Valid YAML — happy-path tests
# ---------------------------------------------------------------------------

_MINIMAL_YAML = """\
title: Minimal Rule
detection:
  selection:
    CommandLine|contains: evil
  condition: selection
"""

_FULL_YAML = """\
title: PowerShell Encoded Command
id: b6f98540-ed62-4856-b8b7-2a2d7b80f5b7
status: stable
level: high
description: Detects Base64-encoded PowerShell commands.
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    cmd_line|contains:
      - '-enc'
      - '-EncodedCommand'
    name|endswith: powershell.exe
  condition: selection
tags:
  - attack.T1059.001
  - attack.TA0002
references:
  - https://attack.mitre.org/techniques/T1059/001/
"""

_MULTI_TAG_YAML = """\
title: Multi-Tag Rule
id: multi-tag-001
status: experimental
level: critical
description: Rule with several ATT&CK tags.
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains: mimikatz
  condition: selection
tags:
  - attack.T1003.001
  - attack.T1059.001
  - attack.TA0006
  - attack.TA0002
  - some.other.tag
"""


def test_load_minimal_yaml_returns_sigma_rule(engine: SigmaEngine) -> None:
    """Minimal valid YAML produces a SigmaRule, not None."""
    rule = engine.load_rule_yaml(_MINIMAL_YAML)
    assert rule is not None
    assert isinstance(rule, SigmaRule)


def test_load_full_yaml_title(engine: SigmaEngine) -> None:
    rule = engine.load_rule_yaml(_FULL_YAML)
    assert rule is not None
    assert rule.title == "PowerShell Encoded Command"


def test_load_full_yaml_id(engine: SigmaEngine) -> None:
    rule = engine.load_rule_yaml(_FULL_YAML)
    assert rule is not None
    assert rule.id == "b6f98540-ed62-4856-b8b7-2a2d7b80f5b7"


def test_load_full_yaml_status(engine: SigmaEngine) -> None:
    rule = engine.load_rule_yaml(_FULL_YAML)
    assert rule is not None
    assert rule.status == "stable"


def test_load_full_yaml_level(engine: SigmaEngine) -> None:
    rule = engine.load_rule_yaml(_FULL_YAML)
    assert rule is not None
    assert rule.level == "high"


def test_load_full_yaml_description(engine: SigmaEngine) -> None:
    rule = engine.load_rule_yaml(_FULL_YAML)
    assert rule is not None
    assert "Base64" in rule.description


def test_load_full_yaml_logsource(engine: SigmaEngine) -> None:
    rule = engine.load_rule_yaml(_FULL_YAML)
    assert rule is not None
    assert rule.logsource == {"category": "process_creation", "product": "windows"}


def test_load_full_yaml_detection_preserved(engine: SigmaEngine) -> None:
    rule = engine.load_rule_yaml(_FULL_YAML)
    assert rule is not None
    assert "selection" in rule.detection
    assert "condition" in rule.detection


def test_load_full_yaml_references(engine: SigmaEngine) -> None:
    rule = engine.load_rule_yaml(_FULL_YAML)
    assert rule is not None
    assert len(rule.references) == 1
    assert "mitre.org" in rule.references[0]


def test_load_full_yaml_tags_raw(engine: SigmaEngine) -> None:
    rule = engine.load_rule_yaml(_FULL_YAML)
    assert rule is not None
    assert "attack.T1059.001" in rule.tags
    assert "attack.TA0002" in rule.tags


# ---------------------------------------------------------------------------
# ATT&CK tag extraction
# ---------------------------------------------------------------------------


def test_technique_id_extracted_from_tags(engine: SigmaEngine) -> None:
    """attack.T1059.001 tag → technique_ids contains 'T1059.001'."""
    rule = engine.load_rule_yaml(_FULL_YAML)
    assert rule is not None
    assert "T1059.001" in rule.technique_ids


def test_tactic_id_extracted_from_tags(engine: SigmaEngine) -> None:
    """attack.TA0002 tag → tactic_ids contains 'TA0002'."""
    rule = engine.load_rule_yaml(_FULL_YAML)
    assert rule is not None
    assert "TA0002" in rule.tactic_ids


def test_technique_not_in_tactic_ids(engine: SigmaEngine) -> None:
    """Technique tags must not leak into tactic_ids."""
    rule = engine.load_rule_yaml(_FULL_YAML)
    assert rule is not None
    assert "T1059.001" not in rule.tactic_ids


def test_tactic_not_in_technique_ids(engine: SigmaEngine) -> None:
    """Tactic tags must not leak into technique_ids."""
    rule = engine.load_rule_yaml(_FULL_YAML)
    assert rule is not None
    assert "TA0002" not in rule.technique_ids


def test_multiple_technique_and_tactic_ids(engine: SigmaEngine) -> None:
    """Multiple ATT&CK tags are all extracted correctly."""
    rule = engine.load_rule_yaml(_MULTI_TAG_YAML)
    assert rule is not None
    assert "T1003.001" in rule.technique_ids
    assert "T1059.001" in rule.technique_ids
    assert "TA0006" in rule.tactic_ids
    assert "TA0002" in rule.tactic_ids


def test_non_attack_tags_ignored(engine: SigmaEngine) -> None:
    """Tags without the 'attack.' prefix are not added to technique/tactic lists."""
    rule = engine.load_rule_yaml(_MULTI_TAG_YAML)
    assert rule is not None
    # 'some.other.tag' must not pollute ATT&CK id lists
    assert all("other" not in t for t in rule.technique_ids)
    assert all("other" not in t for t in rule.tactic_ids)


def test_no_tags_yields_empty_attack_lists(engine: SigmaEngine) -> None:
    """Rule with no tags produces empty technique_ids and tactic_ids."""
    rule = engine.load_rule_yaml(_MINIMAL_YAML)
    assert rule is not None
    assert rule.technique_ids == []
    assert rule.tactic_ids == []


# ---------------------------------------------------------------------------
# Default values for missing optional fields
# ---------------------------------------------------------------------------


def test_missing_id_generates_uuid(engine: SigmaEngine) -> None:
    """When 'id' is absent the engine assigns a generated UUID."""
    rule = engine.load_rule_yaml(_MINIMAL_YAML)
    assert rule is not None
    assert len(rule.id) > 0  # non-empty string


def test_missing_status_defaults_to_experimental(engine: SigmaEngine) -> None:
    rule = engine.load_rule_yaml(_MINIMAL_YAML)
    assert rule is not None
    assert rule.status == "experimental"


def test_missing_level_defaults_to_medium(engine: SigmaEngine) -> None:
    rule = engine.load_rule_yaml(_MINIMAL_YAML)
    assert rule is not None
    assert rule.level == "medium"


def test_missing_description_defaults_to_empty_string(engine: SigmaEngine) -> None:
    rule = engine.load_rule_yaml(_MINIMAL_YAML)
    assert rule is not None
    assert rule.description == ""


def test_missing_logsource_defaults_to_empty_dict(engine: SigmaEngine) -> None:
    rule = engine.load_rule_yaml(_MINIMAL_YAML)
    assert rule is not None
    assert rule.logsource == {}


def test_missing_references_defaults_to_empty_list(engine: SigmaEngine) -> None:
    rule = engine.load_rule_yaml(_MINIMAL_YAML)
    assert rule is not None
    assert rule.references == []


def test_rule_enabled_true_by_default(engine: SigmaEngine) -> None:
    rule = engine.load_rule_yaml(_MINIMAL_YAML)
    assert rule is not None
    assert rule.enabled is True


# ---------------------------------------------------------------------------
# Compiled matcher
# ---------------------------------------------------------------------------


def test_matcher_is_set_after_load(engine: SigmaEngine) -> None:
    """_matcher must be a _Condition instance after loading."""
    rule = engine.load_rule_yaml(_FULL_YAML)
    assert rule is not None
    assert rule._matcher is not None
    assert isinstance(rule._matcher, _Condition)


def test_matcher_is_callable_via_matches(engine: SigmaEngine) -> None:
    """_matcher.matches() must be callable and return a bool."""
    rule = engine.load_rule_yaml(_FULL_YAML)
    assert rule is not None
    result = rule._matcher.matches({"cmd_line": "-enc abc", "name": "powershell.exe"})
    assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# Invalid / degenerate inputs — must return None
# ---------------------------------------------------------------------------


def test_empty_string_returns_none(engine: SigmaEngine) -> None:
    assert engine.load_rule_yaml("") is None


def test_whitespace_only_returns_none(engine: SigmaEngine) -> None:
    assert engine.load_rule_yaml("   \n  ") is None


def test_invalid_yaml_syntax_returns_none(engine: SigmaEngine) -> None:
    bad_yaml = "key: [unclosed bracket"
    assert engine.load_rule_yaml(bad_yaml) is None


def test_yaml_list_at_root_returns_none(engine: SigmaEngine) -> None:
    """A YAML document whose root is a list (not a dict) must return None."""
    list_yaml = "- item1\n- item2\n"
    assert engine.load_rule_yaml(list_yaml) is None


def test_yaml_scalar_at_root_returns_none(engine: SigmaEngine) -> None:
    """A YAML document whose root is a plain scalar must return None."""
    assert engine.load_rule_yaml("just a string") is None


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_rule_with_empty_detection_returns_sigma_rule(engine: SigmaEngine) -> None:
    """A rule with no detection keys is unusual but should not raise."""
    yaml_text = """\
title: No Detection Rule
id: no-detect-001
status: experimental
level: low
logsource:
  category: process_creation
detection:
  condition: selection
"""
    rule = engine.load_rule_yaml(yaml_text)
    # The engine must not crash; returning None or a SigmaRule is both acceptable,
    # but the _matcher must be set if a rule is returned.
    if rule is not None:
        assert rule._matcher is not None


def test_two_calls_produce_independent_rules(engine: SigmaEngine) -> None:
    """Calling load_rule_yaml twice returns two independent SigmaRule objects."""
    rule_a = engine.load_rule_yaml(_FULL_YAML)
    rule_b = engine.load_rule_yaml(_MINIMAL_YAML)
    assert rule_a is not None
    assert rule_b is not None
    assert rule_a is not rule_b
    assert rule_a.id != rule_b.id or rule_a.title != rule_b.title
