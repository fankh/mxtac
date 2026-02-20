"""Unit tests for the Lucene DSL query builder (feature 11.6).

Tests cover:
  - _filter_to_lucene()  — per-operator clause generation
  - build_lucene_query() — full query assembly from SearchRequest parts
  - Field mapping (flat aliases → OCSF nested paths)
  - Lucene special-character escaping
  - Edge cases (empty inputs, unknown fields, unsupported operators)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from app.services.query_builder import (
    _filter_to_lucene,
    build_lucene_query,
)


# ---------------------------------------------------------------------------
# Test helper — mimics EventFilter without importing the FastAPI schema
# ---------------------------------------------------------------------------


@dataclass
class _Filter:
    """Duck-typed stand-in for EventFilter used by build_lucene_query."""
    field: str
    operator: str
    value: Any


# ---------------------------------------------------------------------------
# _filter_to_lucene — single clause tests
# ---------------------------------------------------------------------------


class TestFilterToLucene:
    """Tests for the _filter_to_lucene internal helper."""

    def test_eq_integer(self) -> None:
        assert _filter_to_lucene("severity_id", "eq", 4) == "severity_id:4"

    def test_eq_string(self) -> None:
        assert _filter_to_lucene("class_name", "eq", "Network Activity") == (
            'class_name:"Network Activity"'
        )

    def test_eq_string_no_spaces(self) -> None:
        assert _filter_to_lucene("source", "eq", "wazuh") == "metadata_product:wazuh"

    def test_ne_integer(self) -> None:
        assert _filter_to_lucene("severity_id", "ne", 1) == "NOT severity_id:1"

    def test_ne_string(self) -> None:
        result = _filter_to_lucene("class_name", "ne", "DNS Activity")
        assert result == 'NOT class_name:"DNS Activity"'

    def test_contains(self) -> None:
        result = _filter_to_lucene("hostname", "contains", "dc-")
        # hostname → src_endpoint.hostname
        assert result == "src_endpoint.hostname:*dc-*"

    def test_contains_field_mapping(self) -> None:
        result = _filter_to_lucene("username", "contains", "admin")
        # username → actor_user.name
        assert result == "actor_user.name:*admin*"

    def test_gt(self) -> None:
        result = _filter_to_lucene("severity_id", "gt", 3)
        assert result == "severity_id:{3 TO *}"

    def test_lt(self) -> None:
        result = _filter_to_lucene("severity_id", "lt", 5)
        assert result == "severity_id:{* TO 5}"

    def test_gte(self) -> None:
        result = _filter_to_lucene("severity_id", "gte", 3)
        assert result == "severity_id:[3 TO *]"

    def test_lte(self) -> None:
        result = _filter_to_lucene("severity_id", "lte", 4)
        assert result == "severity_id:[* TO 4]"

    def test_flat_alias_src_ip(self) -> None:
        """Flat column alias 'src_ip' maps to 'src_endpoint.ip'."""
        result = _filter_to_lucene("src_ip", "eq", "10.0.0.1")
        assert result == "src_endpoint.ip:10.0.0.1"

    def test_flat_alias_dst_ip(self) -> None:
        result = _filter_to_lucene("dst_ip", "eq", "10.0.0.2")
        assert result == "dst_endpoint.ip:10.0.0.2"

    def test_flat_alias_process_hash(self) -> None:
        result = _filter_to_lucene("process_hash", "eq", "abc123")
        assert result == "process.hash_sha256:abc123"

    def test_nested_path_passthrough(self) -> None:
        """Nested OCSF paths pass through unchanged."""
        result = _filter_to_lucene("actor_user.name", "eq", "root")
        assert result == "actor_user.name:root"

    def test_nested_path_dst_hostname(self) -> None:
        result = _filter_to_lucene("dst_endpoint.hostname", "contains", "srv")
        assert result == "dst_endpoint.hostname:*srv*"

    def test_unknown_field_returns_none(self) -> None:
        assert _filter_to_lucene("nonexistent_field", "eq", "value") is None

    def test_unsupported_operator_returns_none(self) -> None:
        assert _filter_to_lucene("severity_id", "fuzzy", 3) is None

    def test_special_chars_escaped_in_eq(self) -> None:
        """Lucene special characters in values are escaped."""
        result = _filter_to_lucene("hostname", "eq", "host:prod")
        # colon must be escaped
        assert result == r"src_endpoint.hostname:host\:prod"

    def test_special_chars_escaped_in_ne(self) -> None:
        result = _filter_to_lucene("class_name", "ne", "proc(exec)")
        # parens must be escaped
        assert result == r"NOT class_name:proc\(exec\)"

    def test_phrase_query_with_spaces(self) -> None:
        """Values containing spaces produce a phrase query (double-quoted)."""
        result = _filter_to_lucene("class_name", "eq", "Endpoint Activity")
        assert result == 'class_name:"Endpoint Activity"'

    def test_contains_preserves_wildcard_in_value(self) -> None:
        """A '*' inside a contains value is passed through as a wildcard."""
        result = _filter_to_lucene("hostname", "contains", "srv*01")
        assert result == "src_endpoint.hostname:*srv*01*"


# ---------------------------------------------------------------------------
# build_lucene_query — full query assembly
# ---------------------------------------------------------------------------


class TestBuildLuceneQuery:
    """Tests for the public build_lucene_query() function."""

    def test_match_all_when_no_constraints(self) -> None:
        """Empty query + empty filters → '*' (match-all) plus time range."""
        result = build_lucene_query(None, [])
        # Time range clause is always appended
        assert result == "time:[now-7d TO now]"

    def test_none_query_empty_filters_default_time(self) -> None:
        result = build_lucene_query(None, [], "now-7d", "now")
        assert result == "time:[now-7d TO now]"

    def test_text_query_only(self) -> None:
        result = build_lucene_query("mimikatz", [], "now-1h", "now")
        assert result == "mimikatz AND time:[now-1h TO now]"

    def test_text_query_stripped(self) -> None:
        """Leading/trailing whitespace in query is stripped."""
        result = build_lucene_query("  mimikatz  ", [], "now-1h", "now")
        assert result == "mimikatz AND time:[now-1h TO now]"

    def test_empty_string_query_ignored(self) -> None:
        result = build_lucene_query("", [_Filter("severity_id", "eq", 4)], "now-1d", "now")
        assert result == "severity_id:4 AND time:[now-1d TO now]"

    def test_whitespace_only_query_ignored(self) -> None:
        result = build_lucene_query("   ", [], "now-7d", "now")
        assert result == "time:[now-7d TO now]"

    def test_single_filter_eq(self) -> None:
        filters = [_Filter("severity_id", "eq", 4)]
        result = build_lucene_query(None, filters, "now-7d", "now")
        assert result == "severity_id:4 AND time:[now-7d TO now]"

    def test_single_filter_contains(self) -> None:
        filters = [_Filter("hostname", "contains", "dc-")]
        result = build_lucene_query(None, filters, "now-24h", "now")
        assert result == "src_endpoint.hostname:*dc-* AND time:[now-24h TO now]"

    def test_multiple_filters_joined_with_and(self) -> None:
        filters = [
            _Filter("severity_id", "gte", 3),
            _Filter("src_ip", "eq", "10.0.0.1"),
        ]
        result = build_lucene_query(None, filters, "now-7d", "now")
        assert result == (
            "severity_id:[3 TO *] AND src_endpoint.ip:10.0.0.1 AND time:[now-7d TO now]"
        )

    def test_query_and_filters_combined(self) -> None:
        filters = [_Filter("class_name", "eq", "Process Activity")]
        result = build_lucene_query("powershell", filters, "now-2d", "now")
        assert result == (
            'powershell AND class_name:"Process Activity" AND time:[now-2d TO now]'
        )

    def test_lucene_query_with_operators_passed_through(self) -> None:
        """Free-text query containing Lucene operators is preserved verbatim."""
        result = build_lucene_query(
            "mimikatz OR credential_dump", [], "now-7d", "now"
        )
        assert result == "mimikatz OR credential_dump AND time:[now-7d TO now]"

    def test_unknown_field_filter_skipped(self) -> None:
        """Filters with unknown fields are silently skipped."""
        filters = [
            _Filter("nonexistent_field", "eq", "value"),
            _Filter("severity_id", "eq", 5),
        ]
        result = build_lucene_query(None, filters, "now-7d", "now")
        assert result == "severity_id:5 AND time:[now-7d TO now]"

    def test_unsupported_operator_filter_skipped(self) -> None:
        """Filters with unsupported operators are silently skipped."""
        filters = [_Filter("severity_id", "fuzzy", 4)]
        result = build_lucene_query(None, filters, "now-7d", "now")
        assert result == "time:[now-7d TO now]"

    def test_all_filters_skipped_produces_time_range(self) -> None:
        filters = [_Filter("bad_field", "eq", "x")]
        result = build_lucene_query(None, filters, "now-7d", "now")
        assert result == "time:[now-7d TO now]"

    def test_custom_time_range(self) -> None:
        result = build_lucene_query(None, [], "now-30d", "now-1d")
        assert result == "time:[now-30d TO now-1d]"

    def test_iso8601_time_range(self) -> None:
        result = build_lucene_query(
            None, [], "2026-01-01T00:00:00Z", "2026-01-31T23:59:59Z"
        )
        assert result == "time:[2026-01-01T00:00:00Z TO 2026-01-31T23:59:59Z]"

    def test_ne_operator(self) -> None:
        filters = [_Filter("source", "ne", "wazuh")]
        result = build_lucene_query(None, filters, "now-1d", "now")
        assert result == "NOT metadata_product:wazuh AND time:[now-1d TO now]"

    def test_gt_and_lte_range(self) -> None:
        filters = [
            _Filter("severity_id", "gt", 2),
            _Filter("severity_id", "lte", 5),
        ]
        result = build_lucene_query(None, filters, "now-7d", "now")
        assert result == (
            "severity_id:{2 TO *} AND severity_id:[* TO 5] AND time:[now-7d TO now]"
        )

    def test_complex_hunt_query(self) -> None:
        """Realistic hunting scenario: free text + multiple filters + time."""
        filters = [
            _Filter("severity_id", "gte", 4),
            _Filter("hostname", "contains", "workstation"),
            _Filter("class_name", "eq", "Process Activity"),
        ]
        result = build_lucene_query(
            "lsass", filters, "now-24h", "now"
        )
        assert result == (
            "lsass"
            " AND severity_id:[4 TO *]"
            " AND src_endpoint.hostname:*workstation*"
            ' AND class_name:"Process Activity"'
            " AND time:[now-24h TO now]"
        )
