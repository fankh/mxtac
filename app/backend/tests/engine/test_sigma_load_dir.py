"""Tests for feature 8.3 — Load rules from YAML directory.

Coverage for SigmaEngine.load_rules_from_dir():

  Happy-path loading:
  - Empty directory returns 0 and engine has no rules
  - Single valid .yml file returns count 1 and engine has 1 rule
  - Single valid .yaml extension is also discovered (not just .yml)
  - Three valid files in the same directory returns 3
  - Rules are accessible via get_rules() after loading
  - rule_count matches the return value

  Recursive directory scanning:
  - Files in a single subdirectory are discovered
  - Files nested two levels deep are discovered
  - Files at root and in a subdirectory both count toward total

  Error tolerance:
  - Invalid YAML syntax is skipped; other valid files still load
  - YAML file whose root is not a dict is skipped
  - Non-YAML extensions (.txt, .json, .log) are ignored
  - A directory containing only invalid files returns 0

  Rule content integrity:
  - Loaded rules have _matcher set (not None)
  - Loaded rules default to enabled=True
  - Rule title is preserved from YAML
  - Rule level is preserved from YAML
  - Rule logsource is preserved from YAML
  - ATT&CK technique tags are extracted into technique_ids
  - ATT&CK tactic tags are extracted into tactic_ids

  Accumulation:
  - Two successive calls to load_rules_from_dir accumulate rules across both dirs

  Non-existent path:
  - Non-existent directory returns 0 (Python 3.13 rglob returns empty for missing paths)
  - Engine stays empty when pointed at a non-existent directory
"""

from __future__ import annotations

import pytest
from pathlib import Path
from typing import Any

from app.engine.sigma_engine import SigmaEngine, SigmaRule, _Condition


# ---------------------------------------------------------------------------
# YAML fixtures
# ---------------------------------------------------------------------------

_RULE_A = """\
title: Rule Alpha
id: rule-alpha-001
status: stable
level: high
description: Detects alpha pattern.
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    cmd_line|contains: alpha
  condition: selection
tags:
  - attack.T1059.001
  - attack.TA0002
references:
  - https://attack.mitre.org/techniques/T1059/001/
"""

_RULE_B = """\
title: Rule Beta
id: rule-beta-002
status: experimental
level: medium
description: Detects beta pattern.
logsource:
  category: network_connection
  product: linux
detection:
  selection:
    dst_port: 4444
  condition: selection
tags:
  - attack.T1071
"""

_RULE_C = """\
title: Rule Gamma
id: rule-gamma-003
status: test
level: critical
description: Detects gamma pattern.
logsource:
  category: authentication
detection:
  selection:
    event_type: failed_login
  condition: selection
tags:
  - attack.T1110
  - attack.TA0006
"""

_RULE_YAML_EXT = """\
title: Rule YAML Extension
id: rule-yaml-ext-004
status: stable
level: low
description: Rule with .yaml extension.
logsource:
  category: process_creation
detection:
  selection:
    name|endswith: .sh
  condition: selection
"""

_INVALID_YAML = "key: [unclosed bracket"

_NON_DICT_YAML = "- item1\n- item2\n"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write(tmp_path: Path, filename: str, content: str) -> Path:
    """Write a file in tmp_path and return its path."""
    p = tmp_path / filename
    p.write_text(content, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Happy-path loading
# ---------------------------------------------------------------------------


class TestLoadRulesFromDirHappyPath:
    async def test_empty_directory_returns_zero(self, tmp_path: Path) -> None:
        engine = SigmaEngine()
        count = await engine.load_rules_from_dir(str(tmp_path))
        assert count == 0

    async def test_empty_directory_engine_has_no_rules(self, tmp_path: Path) -> None:
        engine = SigmaEngine()
        await engine.load_rules_from_dir(str(tmp_path))
        assert engine.rule_count == 0

    async def test_single_yml_file_returns_one(self, tmp_path: Path) -> None:
        _write(tmp_path, "rule_a.yml", _RULE_A)
        engine = SigmaEngine()
        count = await engine.load_rules_from_dir(str(tmp_path))
        assert count == 1

    async def test_single_yml_engine_rule_count_is_one(self, tmp_path: Path) -> None:
        _write(tmp_path, "rule_a.yml", _RULE_A)
        engine = SigmaEngine()
        await engine.load_rules_from_dir(str(tmp_path))
        assert engine.rule_count == 1

    async def test_yaml_extension_is_discovered(self, tmp_path: Path) -> None:
        """Files ending in .yaml (not just .yml) must be loaded."""
        _write(tmp_path, "rule.yaml", _RULE_YAML_EXT)
        engine = SigmaEngine()
        count = await engine.load_rules_from_dir(str(tmp_path))
        assert count == 1

    async def test_three_valid_files_returns_three(self, tmp_path: Path) -> None:
        _write(tmp_path, "rule_a.yml", _RULE_A)
        _write(tmp_path, "rule_b.yml", _RULE_B)
        _write(tmp_path, "rule_c.yml", _RULE_C)
        engine = SigmaEngine()
        count = await engine.load_rules_from_dir(str(tmp_path))
        assert count == 3

    async def test_three_valid_files_rule_count_matches(self, tmp_path: Path) -> None:
        _write(tmp_path, "rule_a.yml", _RULE_A)
        _write(tmp_path, "rule_b.yml", _RULE_B)
        _write(tmp_path, "rule_c.yml", _RULE_C)
        engine = SigmaEngine()
        count = await engine.load_rules_from_dir(str(tmp_path))
        assert engine.rule_count == count

    async def test_get_rules_contains_loaded_rules(self, tmp_path: Path) -> None:
        _write(tmp_path, "rule_a.yml", _RULE_A)
        _write(tmp_path, "rule_b.yml", _RULE_B)
        engine = SigmaEngine()
        await engine.load_rules_from_dir(str(tmp_path))
        rules = engine.get_rules()
        assert len(rules) == 2

    async def test_get_rules_ids_match_yaml_ids(self, tmp_path: Path) -> None:
        _write(tmp_path, "rule_a.yml", _RULE_A)
        _write(tmp_path, "rule_b.yml", _RULE_B)
        engine = SigmaEngine()
        await engine.load_rules_from_dir(str(tmp_path))
        rule_ids = {r["id"] for r in engine.get_rules()}
        assert "rule-alpha-001" in rule_ids
        assert "rule-beta-002" in rule_ids

    async def test_yml_and_yaml_extensions_both_loaded(self, tmp_path: Path) -> None:
        _write(tmp_path, "rule_a.yml", _RULE_A)
        _write(tmp_path, "rule_b.yaml", _RULE_YAML_EXT)
        engine = SigmaEngine()
        count = await engine.load_rules_from_dir(str(tmp_path))
        assert count == 2


# ---------------------------------------------------------------------------
# Recursive directory scanning
# ---------------------------------------------------------------------------


class TestLoadRulesFromDirRecursive:
    async def test_file_in_subdirectory_is_discovered(self, tmp_path: Path) -> None:
        sub = tmp_path / "windows"
        sub.mkdir()
        _write(sub, "rule_a.yml", _RULE_A)
        engine = SigmaEngine()
        count = await engine.load_rules_from_dir(str(tmp_path))
        assert count == 1

    async def test_file_two_levels_deep_is_discovered(self, tmp_path: Path) -> None:
        nested = tmp_path / "windows" / "process"
        nested.mkdir(parents=True)
        _write(nested, "rule_a.yml", _RULE_A)
        engine = SigmaEngine()
        count = await engine.load_rules_from_dir(str(tmp_path))
        assert count == 1

    async def test_files_at_root_and_subdir_both_count(self, tmp_path: Path) -> None:
        sub = tmp_path / "network"
        sub.mkdir()
        _write(tmp_path, "rule_a.yml", _RULE_A)
        _write(sub, "rule_b.yml", _RULE_B)
        engine = SigmaEngine()
        count = await engine.load_rules_from_dir(str(tmp_path))
        assert count == 2

    async def test_deep_nested_rules_are_accessible_in_engine(self, tmp_path: Path) -> None:
        deep = tmp_path / "a" / "b" / "c"
        deep.mkdir(parents=True)
        _write(deep, "rule_c.yml", _RULE_C)
        engine = SigmaEngine()
        await engine.load_rules_from_dir(str(tmp_path))
        assert engine.rule_count == 1

    async def test_multiple_subdirs_all_discovered(self, tmp_path: Path) -> None:
        for sub_name, rule in [("win", _RULE_A), ("linux", _RULE_B), ("auth", _RULE_C)]:
            sub = tmp_path / sub_name
            sub.mkdir()
            _write(sub, "rule.yml", rule)
        engine = SigmaEngine()
        count = await engine.load_rules_from_dir(str(tmp_path))
        assert count == 3


# ---------------------------------------------------------------------------
# Error tolerance
# ---------------------------------------------------------------------------


class TestLoadRulesFromDirErrorTolerance:
    async def test_invalid_yaml_is_skipped(self, tmp_path: Path) -> None:
        _write(tmp_path, "bad.yml", _INVALID_YAML)
        engine = SigmaEngine()
        count = await engine.load_rules_from_dir(str(tmp_path))
        assert count == 0

    async def test_invalid_yaml_does_not_crash(self, tmp_path: Path) -> None:
        _write(tmp_path, "bad.yml", _INVALID_YAML)
        engine = SigmaEngine()
        # Must not raise
        await engine.load_rules_from_dir(str(tmp_path))

    async def test_invalid_yaml_skipped_valid_files_still_load(self, tmp_path: Path) -> None:
        _write(tmp_path, "bad.yml", _INVALID_YAML)
        _write(tmp_path, "good.yml", _RULE_A)
        engine = SigmaEngine()
        count = await engine.load_rules_from_dir(str(tmp_path))
        assert count == 1

    async def test_non_dict_root_yaml_is_skipped(self, tmp_path: Path) -> None:
        _write(tmp_path, "list.yml", _NON_DICT_YAML)
        engine = SigmaEngine()
        count = await engine.load_rules_from_dir(str(tmp_path))
        assert count == 0

    async def test_non_dict_skipped_valid_still_loads(self, tmp_path: Path) -> None:
        _write(tmp_path, "list.yml", _NON_DICT_YAML)
        _write(tmp_path, "rule_b.yml", _RULE_B)
        engine = SigmaEngine()
        count = await engine.load_rules_from_dir(str(tmp_path))
        assert count == 1

    async def test_txt_extension_is_ignored(self, tmp_path: Path) -> None:
        _write(tmp_path, "rule.txt", _RULE_A)
        engine = SigmaEngine()
        count = await engine.load_rules_from_dir(str(tmp_path))
        assert count == 0

    async def test_json_extension_is_ignored(self, tmp_path: Path) -> None:
        _write(tmp_path, "rule.json", '{"title": "test"}')
        engine = SigmaEngine()
        count = await engine.load_rules_from_dir(str(tmp_path))
        assert count == 0

    async def test_log_extension_is_ignored(self, tmp_path: Path) -> None:
        _write(tmp_path, "engine.log", _RULE_A)
        engine = SigmaEngine()
        count = await engine.load_rules_from_dir(str(tmp_path))
        assert count == 0

    async def test_only_invalid_files_returns_zero(self, tmp_path: Path) -> None:
        _write(tmp_path, "bad1.yml", _INVALID_YAML)
        _write(tmp_path, "bad2.yml", _NON_DICT_YAML)
        engine = SigmaEngine()
        count = await engine.load_rules_from_dir(str(tmp_path))
        assert count == 0

    async def test_only_invalid_files_engine_empty(self, tmp_path: Path) -> None:
        _write(tmp_path, "bad.yml", _INVALID_YAML)
        engine = SigmaEngine()
        await engine.load_rules_from_dir(str(tmp_path))
        assert engine.rule_count == 0

    async def test_mixed_valid_and_invalid_correct_count(self, tmp_path: Path) -> None:
        _write(tmp_path, "rule_a.yml", _RULE_A)
        _write(tmp_path, "bad.yml", _INVALID_YAML)
        _write(tmp_path, "rule_b.yml", _RULE_B)
        _write(tmp_path, "list.yml", _NON_DICT_YAML)
        engine = SigmaEngine()
        count = await engine.load_rules_from_dir(str(tmp_path))
        assert count == 2


# ---------------------------------------------------------------------------
# Rule content integrity
# ---------------------------------------------------------------------------


class TestLoadRulesFromDirContentIntegrity:
    async def test_loaded_rule_has_matcher_set(self, tmp_path: Path) -> None:
        _write(tmp_path, "rule_a.yml", _RULE_A)
        engine = SigmaEngine()
        await engine.load_rules_from_dir(str(tmp_path))
        rule_info = engine.get_rules()[0]
        rule_id = rule_info["id"]
        # Access internal rules dict to inspect _matcher
        rule = engine._rules[rule_id]
        assert rule._matcher is not None

    async def test_loaded_rule_matcher_is_condition_instance(self, tmp_path: Path) -> None:
        _write(tmp_path, "rule_a.yml", _RULE_A)
        engine = SigmaEngine()
        await engine.load_rules_from_dir(str(tmp_path))
        rule = engine._rules["rule-alpha-001"]
        assert isinstance(rule._matcher, _Condition)

    async def test_loaded_rule_enabled_is_true_by_default(self, tmp_path: Path) -> None:
        _write(tmp_path, "rule_a.yml", _RULE_A)
        engine = SigmaEngine()
        await engine.load_rules_from_dir(str(tmp_path))
        rule = engine._rules["rule-alpha-001"]
        assert rule.enabled is True

    async def test_loaded_rule_title_preserved(self, tmp_path: Path) -> None:
        _write(tmp_path, "rule_a.yml", _RULE_A)
        engine = SigmaEngine()
        await engine.load_rules_from_dir(str(tmp_path))
        rule = engine._rules["rule-alpha-001"]
        assert rule.title == "Rule Alpha"

    async def test_loaded_rule_level_preserved(self, tmp_path: Path) -> None:
        _write(tmp_path, "rule_a.yml", _RULE_A)
        engine = SigmaEngine()
        await engine.load_rules_from_dir(str(tmp_path))
        rule = engine._rules["rule-alpha-001"]
        assert rule.level == "high"

    async def test_loaded_rule_status_preserved(self, tmp_path: Path) -> None:
        _write(tmp_path, "rule_a.yml", _RULE_A)
        engine = SigmaEngine()
        await engine.load_rules_from_dir(str(tmp_path))
        rule = engine._rules["rule-alpha-001"]
        assert rule.status == "stable"

    async def test_loaded_rule_logsource_preserved(self, tmp_path: Path) -> None:
        _write(tmp_path, "rule_a.yml", _RULE_A)
        engine = SigmaEngine()
        await engine.load_rules_from_dir(str(tmp_path))
        rule = engine._rules["rule-alpha-001"]
        assert rule.logsource == {"category": "process_creation", "product": "windows"}

    async def test_loaded_rule_technique_ids_extracted(self, tmp_path: Path) -> None:
        _write(tmp_path, "rule_a.yml", _RULE_A)
        engine = SigmaEngine()
        await engine.load_rules_from_dir(str(tmp_path))
        rule = engine._rules["rule-alpha-001"]
        assert "T1059.001" in rule.technique_ids

    async def test_loaded_rule_tactic_ids_extracted(self, tmp_path: Path) -> None:
        _write(tmp_path, "rule_a.yml", _RULE_A)
        engine = SigmaEngine()
        await engine.load_rules_from_dir(str(tmp_path))
        rule = engine._rules["rule-alpha-001"]
        assert "TA0002" in rule.tactic_ids

    async def test_technique_not_in_tactic_ids(self, tmp_path: Path) -> None:
        _write(tmp_path, "rule_a.yml", _RULE_A)
        engine = SigmaEngine()
        await engine.load_rules_from_dir(str(tmp_path))
        rule = engine._rules["rule-alpha-001"]
        assert "T1059.001" not in rule.tactic_ids

    async def test_tactic_not_in_technique_ids(self, tmp_path: Path) -> None:
        _write(tmp_path, "rule_a.yml", _RULE_A)
        engine = SigmaEngine()
        await engine.load_rules_from_dir(str(tmp_path))
        rule = engine._rules["rule-alpha-001"]
        assert "TA0002" not in rule.technique_ids

    async def test_multiple_technique_ids_all_extracted(self, tmp_path: Path) -> None:
        _write(tmp_path, "rule_c.yml", _RULE_C)
        engine = SigmaEngine()
        await engine.load_rules_from_dir(str(tmp_path))
        rule = engine._rules["rule-gamma-003"]
        assert "T1110" in rule.technique_ids

    async def test_multiple_tactic_ids_all_extracted(self, tmp_path: Path) -> None:
        _write(tmp_path, "rule_c.yml", _RULE_C)
        engine = SigmaEngine()
        await engine.load_rules_from_dir(str(tmp_path))
        rule = engine._rules["rule-gamma-003"]
        assert "TA0006" in rule.tactic_ids

    async def test_rule_with_no_tags_has_empty_technique_ids(self, tmp_path: Path) -> None:
        no_tags_yaml = """\
title: No Tags Rule
id: rule-no-tags-005
status: experimental
level: low
detection:
  selection:
    field: value
  condition: selection
"""
        _write(tmp_path, "no_tags.yml", no_tags_yaml)
        engine = SigmaEngine()
        await engine.load_rules_from_dir(str(tmp_path))
        rule = engine._rules["rule-no-tags-005"]
        assert rule.technique_ids == []
        assert rule.tactic_ids == []

    async def test_get_rules_returns_dicts_with_expected_keys(self, tmp_path: Path) -> None:
        _write(tmp_path, "rule_a.yml", _RULE_A)
        engine = SigmaEngine()
        await engine.load_rules_from_dir(str(tmp_path))
        rules = engine.get_rules()
        assert len(rules) == 1
        rule_dict = rules[0]
        expected_keys = {"id", "title", "level", "status", "enabled", "technique_ids", "tactic_ids", "logsource"}
        assert expected_keys.issubset(rule_dict.keys())


# ---------------------------------------------------------------------------
# Accumulation across multiple load calls
# ---------------------------------------------------------------------------


class TestLoadRulesFromDirAccumulation:
    async def test_two_successive_calls_accumulate_rules(self, tmp_path: Path) -> None:
        dir_a = tmp_path / "dir_a"
        dir_b = tmp_path / "dir_b"
        dir_a.mkdir()
        dir_b.mkdir()
        _write(dir_a, "rule_a.yml", _RULE_A)
        _write(dir_b, "rule_b.yml", _RULE_B)
        engine = SigmaEngine()
        count_a = await engine.load_rules_from_dir(str(dir_a))
        count_b = await engine.load_rules_from_dir(str(dir_b))
        assert count_a == 1
        assert count_b == 1
        assert engine.rule_count == 2

    async def test_return_value_reflects_only_current_call(self, tmp_path: Path) -> None:
        dir_a = tmp_path / "dir_a"
        dir_b = tmp_path / "dir_b"
        dir_a.mkdir()
        dir_b.mkdir()
        _write(dir_a, "rule_a.yml", _RULE_A)
        _write(dir_b, "rule_b.yml", _RULE_B)
        _write(dir_b, "rule_c.yml", _RULE_C)
        engine = SigmaEngine()
        await engine.load_rules_from_dir(str(dir_a))
        count_b = await engine.load_rules_from_dir(str(dir_b))
        # Second call only loaded 2 files — return value is per-call, not cumulative
        assert count_b == 2

    async def test_loading_same_dir_twice_does_not_double_rule_count(self, tmp_path: Path) -> None:
        """Same rule ID loaded twice goes into _rules dict once (upsert by key)."""
        _write(tmp_path, "rule_a.yml", _RULE_A)
        engine = SigmaEngine()
        await engine.load_rules_from_dir(str(tmp_path))
        await engine.load_rules_from_dir(str(tmp_path))
        # _rules dict is keyed by id — same id cannot appear twice
        assert engine.rule_count == 1


# ---------------------------------------------------------------------------
# Non-existent directory
# ---------------------------------------------------------------------------
# In Python 3.13, Path.rglob() on a non-existent path returns an empty
# iterator rather than raising, so load_rules_from_dir gracefully returns 0.


class TestLoadRulesFromDirNonExistent:
    async def test_nonexistent_directory_returns_zero(self) -> None:
        """A path that does not exist on disk returns 0 (no rules loaded)."""
        engine = SigmaEngine()
        count = await engine.load_rules_from_dir("/nonexistent/path/xyzzy_mxtac_test")
        assert count == 0

    async def test_nonexistent_directory_engine_unchanged(self) -> None:
        """Engine stays empty when pointed at a non-existent directory."""
        engine = SigmaEngine()
        await engine.load_rules_from_dir("/nonexistent/path/xyzzy_mxtac_test")
        assert engine.rule_count == 0


# ---------------------------------------------------------------------------
# Integration: load from real sigma_rules directory
# ---------------------------------------------------------------------------


class TestLoadRulesFromDirRealRules:
    async def test_real_sigma_rules_dir_loads_successfully(self) -> None:
        """Load from the actual sigma_rules directory in the project."""
        import os
        # Navigate to the sigma_rules directory relative to the backend root
        backend_root = Path(__file__).parent.parent.parent
        sigma_rules_dir = backend_root / "sigma_rules"
        if not sigma_rules_dir.exists():
            pytest.skip("sigma_rules directory not found")
        engine = SigmaEngine()
        count = await engine.load_rules_from_dir(str(sigma_rules_dir))
        assert count > 0

    async def test_real_sigma_rules_all_have_matchers(self) -> None:
        """Every rule loaded from disk must have a compiled _matcher."""
        backend_root = Path(__file__).parent.parent.parent
        sigma_rules_dir = backend_root / "sigma_rules"
        if not sigma_rules_dir.exists():
            pytest.skip("sigma_rules directory not found")
        engine = SigmaEngine()
        await engine.load_rules_from_dir(str(sigma_rules_dir))
        for rule in engine._rules.values():
            assert rule._matcher is not None, f"Rule {rule.id!r} has no _matcher"

    async def test_real_sigma_rules_all_enabled_by_default(self) -> None:
        """Rules loaded from disk default to enabled=True."""
        backend_root = Path(__file__).parent.parent.parent
        sigma_rules_dir = backend_root / "sigma_rules"
        if not sigma_rules_dir.exists():
            pytest.skip("sigma_rules directory not found")
        engine = SigmaEngine()
        await engine.load_rules_from_dir(str(sigma_rules_dir))
        for rule in engine._rules.values():
            assert rule.enabled is True, f"Rule {rule.id!r} should be enabled by default"
