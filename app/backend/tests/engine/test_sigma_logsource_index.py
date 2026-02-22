"""Tests for feature 8.5 — Index rules by logsource (product/category/service).

Coverage for SigmaEngine logsource indexing:

_logsource_keys():
  - product only → ["product:windows"]
  - category only → ["category:process_creation"]
  - service only → ["service:syslog"]
  - product + category → both keys
  - product + category + service → all three keys
  - empty logsource → ["*"]
  - keys are lowercase-normalized from mixed-case input

add_rule():
  - rule stored in _rules dict by id
  - rule appears in product index bucket
  - rule appears in category index bucket
  - rule with product+category stored in both buckets
  - global rule (empty logsource) stored under "*"
  - multiple rules accumulate in same index bucket
  - rule_count increments correctly

remove_rule():
  - rule removed from _rules
  - rule removed from a single product bucket
  - rule removed from both product+category buckets
  - removing non-existent id is a no-op (no exception)
  - other rules in same bucket are preserved after removal

upsert_rule():
  - new rule (no prior id) is added like add_rule
  - existing rule replaced: old removed, new added
  - rule_count unchanged after replacing an existing rule
  - index reflects updated logsource fields after upsert
  - rule with changed logsource key is re-indexed correctly

_get_candidates():
  - process_creation rule matched by class_uid=1007 event
  - network_connection rule matched by class_uid=4001 event
  - dns_query rule matched by class_uid=4003 event
  - authentication rule matched by class_uid=3002 event
  - product rule matched by matching metadata_product
  - product rule NOT returned for mismatched product
  - global ("*") rule returned for any event
  - rule indexed by product+category appears only once (deduplication)
  - empty engine yields empty candidates
  - class_uid with no category mapping returns product and global only
  - disabled rule still appears in candidates (filtering is done in evaluate)
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.engine.sigma_engine import SigmaEngine, SigmaRule, _Condition
from app.services.normalizers.ocsf import (
    OCSFCategory,
    OCSFClass,
    OCSFEvent,
    ProcessInfo,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_rule(
    rule_id: str,
    *,
    product: str | None = None,
    category: str | None = None,
    service: str | None = None,
    enabled: bool = True,
) -> SigmaRule:
    """Build a minimal SigmaRule with the given logsource fields."""
    logsource: dict[str, str] = {}
    if product is not None:
        logsource["product"] = product
    if category is not None:
        logsource["category"] = category
    if service is not None:
        logsource["service"] = service

    detection = {"selection": {"name": "test.exe"}, "condition": "selection"}
    rule = SigmaRule(
        id=rule_id,
        title=f"Test Rule {rule_id}",
        description="",
        status="experimental",
        level="medium",
        logsource=logsource,
        detection=detection,
        enabled=enabled,
    )
    rule._matcher = _Condition(detection)
    return rule


def _make_event(
    class_uid: int,
    category_uid: int,
    class_name: str,
    metadata_product: str = "windows",
) -> OCSFEvent:
    """Build a minimal OCSFEvent for candidate-lookup tests."""
    return OCSFEvent(
        class_uid=class_uid,
        class_name=class_name,
        category_uid=category_uid,
        time=datetime.now(timezone.utc),
        severity_id=1,
        metadata_product=metadata_product,
        process=ProcessInfo(name="test.exe"),
    )


def _process_event(metadata_product: str = "windows") -> OCSFEvent:
    return _make_event(
        OCSFClass.PROCESS_ACTIVITY,
        OCSFCategory.SYSTEM_ACTIVITY,
        "Process Activity",
        metadata_product=metadata_product,
    )


def _network_event(metadata_product: str = "windows") -> OCSFEvent:
    return _make_event(
        OCSFClass.NETWORK_ACTIVITY,
        OCSFCategory.NETWORK,
        "Network Activity",
        metadata_product=metadata_product,
    )


def _dns_event(metadata_product: str = "windows") -> OCSFEvent:
    return _make_event(
        OCSFClass.DNS_ACTIVITY,
        OCSFCategory.NETWORK,
        "DNS Activity",
        metadata_product=metadata_product,
    )


def _auth_event(metadata_product: str = "windows") -> OCSFEvent:
    return _make_event(
        OCSFClass.AUTHENTICATION,
        OCSFCategory.IAM,
        "Authentication",
        metadata_product=metadata_product,
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine() -> SigmaEngine:
    return SigmaEngine()


# ---------------------------------------------------------------------------
# _logsource_keys() — key generation
# ---------------------------------------------------------------------------

def test_logsource_keys_product_only(engine: SigmaEngine) -> None:
    """product only → single key 'product:{value}'."""
    keys = engine._logsource_keys({"product": "windows"})
    assert keys == ["product:windows"]


def test_logsource_keys_category_only(engine: SigmaEngine) -> None:
    """category only → single key 'category:{value}'."""
    keys = engine._logsource_keys({"category": "process_creation"})
    assert keys == ["category:process_creation"]


def test_logsource_keys_service_only(engine: SigmaEngine) -> None:
    """service only → single key 'service:{value}'."""
    keys = engine._logsource_keys({"service": "syslog"})
    assert keys == ["service:syslog"]


def test_logsource_keys_product_and_category(engine: SigmaEngine) -> None:
    """product + category → two keys in order."""
    keys = engine._logsource_keys({"product": "windows", "category": "process_creation"})
    assert "product:windows" in keys
    assert "category:process_creation" in keys
    assert len(keys) == 2


def test_logsource_keys_product_category_service(engine: SigmaEngine) -> None:
    """product + category + service → all three keys."""
    keys = engine._logsource_keys(
        {"product": "linux", "category": "authentication", "service": "sshd"}
    )
    assert "product:linux" in keys
    assert "category:authentication" in keys
    assert "service:sshd" in keys
    assert len(keys) == 3


def test_logsource_keys_empty_logsource_returns_global(engine: SigmaEngine) -> None:
    """Empty logsource dict → ['*'] (global bucket)."""
    keys = engine._logsource_keys({})
    assert keys == ["*"]


def test_logsource_keys_lowercase_normalization(engine: SigmaEngine) -> None:
    """Mixed-case logsource values are lowercased in keys."""
    keys = engine._logsource_keys({"product": "Windows", "category": "Process_Creation"})
    assert "product:windows" in keys
    assert "category:process_creation" in keys


def test_logsource_keys_uppercase_input(engine: SigmaEngine) -> None:
    """Fully uppercase logsource values are lowercased."""
    keys = engine._logsource_keys({"product": "LINUX"})
    assert keys == ["product:linux"]


def test_logsource_keys_returns_list(engine: SigmaEngine) -> None:
    """_logsource_keys always returns a list."""
    result = engine._logsource_keys({"product": "windows"})
    assert isinstance(result, list)


# ---------------------------------------------------------------------------
# add_rule() — indexing
# ---------------------------------------------------------------------------

def test_add_rule_stored_in_rules(engine: SigmaEngine) -> None:
    """add_rule stores the rule in _rules by its id."""
    rule = _make_rule("r1", product="windows")
    engine.add_rule(rule)
    assert "r1" in engine._rules
    assert engine._rules["r1"] is rule


def test_add_rule_increments_rule_count(engine: SigmaEngine) -> None:
    """rule_count reflects the number of added rules."""
    assert engine.rule_count == 0
    engine.add_rule(_make_rule("r1", product="windows"))
    assert engine.rule_count == 1
    engine.add_rule(_make_rule("r2", product="linux"))
    assert engine.rule_count == 2


def test_add_rule_product_bucket(engine: SigmaEngine) -> None:
    """Rule with product logsource appears in 'product:{value}' index bucket."""
    rule = _make_rule("r1", product="windows")
    engine.add_rule(rule)
    assert rule in engine._index.get("product:windows", [])


def test_add_rule_category_bucket(engine: SigmaEngine) -> None:
    """Rule with category logsource appears in 'category:{value}' index bucket."""
    rule = _make_rule("r1", category="process_creation")
    engine.add_rule(rule)
    assert rule in engine._index.get("category:process_creation", [])


def test_add_rule_service_bucket(engine: SigmaEngine) -> None:
    """Rule with service logsource appears in 'service:{value}' index bucket."""
    rule = _make_rule("r1", service="syslog")
    engine.add_rule(rule)
    assert rule in engine._index.get("service:syslog", [])


def test_add_rule_product_and_category_both_buckets(engine: SigmaEngine) -> None:
    """Rule with product+category appears in both index buckets."""
    rule = _make_rule("r1", product="windows", category="process_creation")
    engine.add_rule(rule)
    assert rule in engine._index.get("product:windows", [])
    assert rule in engine._index.get("category:process_creation", [])


def test_add_rule_empty_logsource_goes_to_global_bucket(engine: SigmaEngine) -> None:
    """Rule with empty logsource is stored under '*' (global)."""
    rule = _make_rule("r1")  # no product/category/service
    engine.add_rule(rule)
    assert rule in engine._index.get("*", [])


def test_add_rule_not_in_wrong_bucket(engine: SigmaEngine) -> None:
    """Rule with product:windows must not appear in product:linux bucket."""
    rule = _make_rule("r1", product="windows")
    engine.add_rule(rule)
    assert rule not in engine._index.get("product:linux", [])


def test_add_multiple_rules_same_product_bucket(engine: SigmaEngine) -> None:
    """Multiple rules with the same product accumulate in the same bucket."""
    r1 = _make_rule("r1", product="windows")
    r2 = _make_rule("r2", product="windows")
    engine.add_rule(r1)
    engine.add_rule(r2)
    bucket = engine._index.get("product:windows", [])
    assert r1 in bucket
    assert r2 in bucket


def test_add_multiple_rules_different_products(engine: SigmaEngine) -> None:
    """Rules for different products go into separate buckets."""
    r_win = _make_rule("r1", product="windows")
    r_lin = _make_rule("r2", product="linux")
    engine.add_rule(r_win)
    engine.add_rule(r_lin)
    assert r_win in engine._index.get("product:windows", [])
    assert r_lin in engine._index.get("product:linux", [])
    assert r_win not in engine._index.get("product:linux", [])
    assert r_lin not in engine._index.get("product:windows", [])


# ---------------------------------------------------------------------------
# remove_rule() — index cleanup
# ---------------------------------------------------------------------------

def test_remove_rule_deletes_from_rules(engine: SigmaEngine) -> None:
    """remove_rule removes the rule from _rules."""
    rule = _make_rule("r1", product="windows")
    engine.add_rule(rule)
    engine.remove_rule("r1")
    assert "r1" not in engine._rules


def test_remove_rule_decrements_rule_count(engine: SigmaEngine) -> None:
    """rule_count decreases after removing a rule."""
    engine.add_rule(_make_rule("r1", product="windows"))
    assert engine.rule_count == 1
    engine.remove_rule("r1")
    assert engine.rule_count == 0


def test_remove_rule_clears_product_bucket(engine: SigmaEngine) -> None:
    """remove_rule removes the rule from its product index bucket."""
    rule = _make_rule("r1", product="windows")
    engine.add_rule(rule)
    engine.remove_rule("r1")
    assert rule not in engine._index.get("product:windows", [])


def test_remove_rule_clears_category_bucket(engine: SigmaEngine) -> None:
    """remove_rule removes the rule from its category index bucket."""
    rule = _make_rule("r1", category="process_creation")
    engine.add_rule(rule)
    engine.remove_rule("r1")
    assert rule not in engine._index.get("category:process_creation", [])


def test_remove_rule_clears_all_buckets(engine: SigmaEngine) -> None:
    """Rule with product+category is removed from both buckets."""
    rule = _make_rule("r1", product="windows", category="process_creation")
    engine.add_rule(rule)
    engine.remove_rule("r1")
    assert rule not in engine._index.get("product:windows", [])
    assert rule not in engine._index.get("category:process_creation", [])


def test_remove_nonexistent_rule_is_noop(engine: SigmaEngine) -> None:
    """Removing a rule id that was never added does not raise."""
    engine.remove_rule("does-not-exist")  # must not raise


def test_remove_rule_preserves_other_rules_in_bucket(engine: SigmaEngine) -> None:
    """Removing one rule leaves other rules in the same bucket intact."""
    r1 = _make_rule("r1", product="windows")
    r2 = _make_rule("r2", product="windows")
    engine.add_rule(r1)
    engine.add_rule(r2)
    engine.remove_rule("r1")
    bucket = engine._index.get("product:windows", [])
    assert r1 not in bucket
    assert r2 in bucket


def test_remove_rule_global_bucket(engine: SigmaEngine) -> None:
    """Global rule (empty logsource) is removed from '*' bucket."""
    rule = _make_rule("r1")
    engine.add_rule(rule)
    engine.remove_rule("r1")
    assert rule not in engine._index.get("*", [])


# ---------------------------------------------------------------------------
# upsert_rule() — add-or-replace semantics
# ---------------------------------------------------------------------------

def test_upsert_adds_new_rule(engine: SigmaEngine) -> None:
    """upsert_rule on a new id adds the rule like add_rule."""
    rule = _make_rule("r1", product="windows")
    engine.upsert_rule(rule)
    assert "r1" in engine._rules
    assert engine.rule_count == 1


def test_upsert_replaces_existing_rule(engine: SigmaEngine) -> None:
    """upsert_rule on an existing id replaces it; rule_count stays the same."""
    rule_v1 = _make_rule("r1", product="windows")
    engine.upsert_rule(rule_v1)
    rule_v2 = _make_rule("r1", product="linux")   # same id, different product
    engine.upsert_rule(rule_v2)
    assert engine.rule_count == 1
    assert engine._rules["r1"] is rule_v2


def test_upsert_removes_old_logsource_key(engine: SigmaEngine) -> None:
    """After upsert, the old logsource bucket no longer contains the rule."""
    rule_v1 = _make_rule("r1", product="windows")
    engine.upsert_rule(rule_v1)
    rule_v2 = _make_rule("r1", product="linux")
    engine.upsert_rule(rule_v2)
    # old bucket must be empty
    assert rule_v1 not in engine._index.get("product:windows", [])
    assert rule_v2 not in engine._index.get("product:windows", [])


def test_upsert_adds_to_new_logsource_key(engine: SigmaEngine) -> None:
    """After upsert, the updated rule appears under its new logsource bucket."""
    rule_v1 = _make_rule("r1", product="windows")
    engine.upsert_rule(rule_v1)
    rule_v2 = _make_rule("r1", product="linux")
    engine.upsert_rule(rule_v2)
    assert rule_v2 in engine._index.get("product:linux", [])


def test_upsert_same_logsource_replaces_rule_object(engine: SigmaEngine) -> None:
    """Upserting with the same logsource replaces the rule object in the bucket."""
    rule_v1 = _make_rule("r1", product="windows")
    engine.upsert_rule(rule_v1)
    rule_v2 = _make_rule("r1", product="windows")  # same product, new object
    engine.upsert_rule(rule_v2)
    bucket = engine._index.get("product:windows", [])
    # Only one entry for this id
    assert sum(1 for r in bucket if r.id == "r1") == 1
    assert rule_v2 in bucket
    assert rule_v1 not in bucket


# ---------------------------------------------------------------------------
# _get_candidates() — fast candidate lookup
# ---------------------------------------------------------------------------

def test_get_candidates_empty_engine(engine: SigmaEngine) -> None:
    """Empty engine returns no candidates for any event."""
    event = _process_event()
    candidates = engine._get_candidates(event)
    assert candidates == []


def test_get_candidates_process_creation_by_class_uid(engine: SigmaEngine) -> None:
    """Rule with category:process_creation is a candidate for class_uid=1007 events."""
    rule = _make_rule("r1", category="process_creation")
    engine.add_rule(rule)
    event = _process_event()   # class_uid=1007
    candidates = engine._get_candidates(event)
    assert rule in candidates


def test_get_candidates_network_connection_by_class_uid(engine: SigmaEngine) -> None:
    """Rule with category:network_connection is a candidate for class_uid=4001 events."""
    rule = _make_rule("r1", category="network_connection")
    engine.add_rule(rule)
    event = _network_event()   # class_uid=4001
    candidates = engine._get_candidates(event)
    assert rule in candidates


def test_get_candidates_dns_query_by_class_uid(engine: SigmaEngine) -> None:
    """Rule with category:dns_query is a candidate for class_uid=4003 events."""
    rule = _make_rule("r1", category="dns_query")
    engine.add_rule(rule)
    event = _dns_event()   # class_uid=4003
    candidates = engine._get_candidates(event)
    assert rule in candidates


def test_get_candidates_authentication_by_class_uid(engine: SigmaEngine) -> None:
    """Rule with category:authentication is a candidate for class_uid=3002 events."""
    rule = _make_rule("r1", category="authentication")
    engine.add_rule(rule)
    event = _auth_event()   # class_uid=3002
    candidates = engine._get_candidates(event)
    assert rule in candidates


def test_get_candidates_product_match(engine: SigmaEngine) -> None:
    """Rule indexed by product is a candidate when event metadata_product matches."""
    rule = _make_rule("r1", product="windows")
    engine.add_rule(rule)
    event = _process_event(metadata_product="windows")
    candidates = engine._get_candidates(event)
    assert rule in candidates


def test_get_candidates_product_mismatch(engine: SigmaEngine) -> None:
    """Rule for product:windows is NOT a candidate when event product is 'linux'."""
    rule = _make_rule("r1", product="windows")
    engine.add_rule(rule)
    event = _process_event(metadata_product="linux")
    candidates = engine._get_candidates(event)
    assert rule not in candidates


def test_get_candidates_product_case_insensitive(engine: SigmaEngine) -> None:
    """Product lookup is case-insensitive — 'Windows' event matches 'windows' rule."""
    rule = _make_rule("r1", product="windows")
    engine.add_rule(rule)
    # OCSFEvent.metadata_product="Windows" → lowercased to "windows" in _get_candidates
    event = _process_event(metadata_product="Windows")
    candidates = engine._get_candidates(event)
    assert rule in candidates


def test_get_candidates_global_rule_always_returned(engine: SigmaEngine) -> None:
    """Rule with empty logsource ('*' bucket) is returned for any event."""
    global_rule = _make_rule("global-1")  # no product/category/service
    engine.add_rule(global_rule)
    for event in [_process_event(), _network_event(), _dns_event(), _auth_event()]:
        candidates = engine._get_candidates(event)
        assert global_rule in candidates


def test_get_candidates_global_rule_returned_for_unknown_product(engine: SigmaEngine) -> None:
    """Global rule is also returned for events with an unusual product."""
    global_rule = _make_rule("global-1")
    engine.add_rule(global_rule)
    event = _process_event(metadata_product="zeek")
    candidates = engine._get_candidates(event)
    assert global_rule in candidates


def test_get_candidates_deduplication(engine: SigmaEngine) -> None:
    """Rule indexed under both product and category appears only once in candidates."""
    rule = _make_rule("r1", product="windows", category="process_creation")
    engine.add_rule(rule)
    event = _process_event(metadata_product="windows")  # class_uid=1007
    candidates = engine._get_candidates(event)
    assert candidates.count(rule) == 1


def test_get_candidates_dedup_preserves_all_unique_rules(engine: SigmaEngine) -> None:
    """Deduplication removes duplicates but keeps all distinct rules."""
    r1 = _make_rule("r1", product="windows", category="process_creation")
    r2 = _make_rule("r2", product="windows")
    engine.add_rule(r1)
    engine.add_rule(r2)
    event = _process_event(metadata_product="windows")
    candidates = engine._get_candidates(event)
    assert r1 in candidates
    assert r2 in candidates
    # Verify no duplicate ids
    ids = [r.id for r in candidates]
    assert len(ids) == len(set(ids))


def test_get_candidates_unmapped_class_uid_returns_product_and_global(engine: SigmaEngine) -> None:
    """class_uid with no category mapping yields product + global rules only."""
    product_rule = _make_rule("r1", product="windows")
    global_rule = _make_rule("r2")
    category_rule = _make_rule("r3", category="process_creation")
    engine.add_rule(product_rule)
    engine.add_rule(global_rule)
    engine.add_rule(category_rule)

    # Use an unmapped class_uid (e.g. 1001 = File Activity — not in _get_candidates mapping)
    event = _make_event(
        OCSFClass.FILE_ACTIVITY,
        OCSFCategory.SYSTEM_ACTIVITY,
        "File Activity",
        metadata_product="windows",
    )
    candidates = engine._get_candidates(event)
    assert product_rule in candidates
    assert global_rule in candidates
    # process_creation rule not returned — no category mapping for FILE_ACTIVITY
    assert category_rule not in candidates


def test_get_candidates_disabled_rule_still_returned(engine: SigmaEngine) -> None:
    """_get_candidates returns disabled rules (evaluate() is responsible for filtering)."""
    rule = _make_rule("r1", product="windows", enabled=False)
    engine.add_rule(rule)
    event = _process_event(metadata_product="windows")
    candidates = engine._get_candidates(event)
    assert rule in candidates


def test_get_candidates_process_creation_rule_not_matched_by_network_event(engine: SigmaEngine) -> None:
    """category:process_creation rule is NOT a candidate for network_connection events."""
    rule = _make_rule("r1", category="process_creation")
    engine.add_rule(rule)
    event = _network_event()  # class_uid=4001, not 1007
    candidates = engine._get_candidates(event)
    assert rule not in candidates


def test_get_candidates_multiple_matching_rules(engine: SigmaEngine) -> None:
    """All matching rules from multiple buckets are returned together."""
    r_product = _make_rule("r-product", product="windows")
    r_category = _make_rule("r-category", category="process_creation")
    r_global = _make_rule("r-global")
    engine.add_rule(r_product)
    engine.add_rule(r_category)
    engine.add_rule(r_global)

    event = _process_event(metadata_product="windows")
    candidates = engine._get_candidates(event)
    assert r_product in candidates
    assert r_category in candidates
    assert r_global in candidates


def test_get_candidates_returns_list(engine: SigmaEngine) -> None:
    """_get_candidates always returns a list."""
    event = _process_event()
    result = engine._get_candidates(event)
    assert isinstance(result, list)
