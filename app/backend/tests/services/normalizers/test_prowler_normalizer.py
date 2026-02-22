"""Tests for ProwlerNormalizer — Feature 35.1: Prowler connector — cloud security findings.

Coverage:
  - PROWLER_SEVERITY_MAP: all documented severity levels (critical→5, high→4,
    medium→3, low→2, informational→1, info→1)
  - normalize(): class_uid is COMPLIANCE_FINDING (2003)
  - normalize(): class_name is "Compliance Finding"
  - normalize(): category_uid is FINDINGS (2)
  - normalize(): metadata_product is "Prowler"
  - normalize(): metadata_uid set from finding id field
  - normalize(): severity_id mapped from severity string
  - normalize(): severity from check_metadata.Severity fallback
  - normalize(): unknown severity maps to 0
  - normalize(): check_id extracted from top-level check_id field
  - normalize(): check_id falls back to check_metadata.CheckID
  - normalize(): check_title from check_metadata.CheckTitle
  - normalize(): check_title falls back to check_id when CheckTitle absent
  - normalize(): finding_info.title equals check_title
  - normalize(): finding_info.analytic.uid equals check_id
  - normalize(): finding_info.analytic.type_id is 1 (Rule)
  - normalize(): src_endpoint.uid set from account_uid
  - normalize(): src_endpoint.hostname set from provider
  - normalize(): src_endpoint.domain set from region
  - normalize(): missing account/region/provider → None endpoint fields
  - normalize(): raw field preserved in OCSFEvent.raw
  - normalize(): unmapped contains status, status_extended, provider, region,
    account_uid, resource_uid, resource_name, resource_type
  - normalize(): unmapped.service populated from check_metadata.ServiceName
  - normalize(): unmapped omits keys with None values
  - normalize(): time parsed from inserted_at ISO string
  - normalize(): time defaults to now when inserted_at is missing
  - normalize(): time defaults to now when inserted_at is invalid

ATT&CK mapping (_lookup_attack / _build_attacks):
  - Known check_id returns single AttackInfo with correct tech + tactic
  - iam_root_account_mfa_enabled → T1078.004 / TA0001 (Initial Access)
  - iam_user_mfa_enabled → T1078 / TA0001
  - s3_bucket_public_read_prohibition → T1530 / TA0009
  - s3_bucket_public_write_prohibition → T1530 / TA0009
  - cloudtrail_enabled → T1562.008 / TA0005
  - ec2_securitygroup_allow_all_ingress_traffic → T1190 / TA0001
  - guardduty_is_enabled → T1562 / TA0005
  - iam_access_key_rotation → T1528 / TA0006
  - Unknown check_id returns empty attacks list
  - Sub-technique ID (e.g. T1078.004) has sub_technique set to "004"
  - Non-sub-technique (e.g. T1530) has sub_technique=None
  - Prefix fallback: iam_custom_check → T1078 / TA0004
  - Prefix fallback: s3_custom_check → T1530 / TA0009
  - Prefix fallback: cloudtrail_custom_check → T1562.008 / TA0005
  - Exact match takes priority over prefix

Full round-trip:
  - Realistic AWS FAIL finding produces valid OCSFEvent with all fields
  - Azure finding produces correct provider in src_endpoint.hostname
  - GCP finding produces correct provider in src_endpoint.hostname
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.services.normalizers.ocsf import OCSFCategory, OCSFClass
from app.services.normalizers.prowler import (
    PROWLER_SEVERITY_MAP,
    ProwlerNormalizer,
    _lookup_attack,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def normalizer() -> ProwlerNormalizer:
    return ProwlerNormalizer()


@pytest.fixture
def aws_finding() -> dict:
    """Realistic Prowler AWS FAIL finding from REST API."""
    return {
        "id": "prowler-aws-s3-bucket-public-read-us-east-1-123456789012-my-bucket",
        "check_id": "s3_bucket_public_read_prohibition",
        "check_metadata": {
            "CheckID": "s3_bucket_public_read_prohibition",
            "CheckTitle": "S3 Bucket Should Not Have Public Read Access",
            "ServiceName": "s3",
            "Severity": "critical",
        },
        "status": "FAIL",
        "status_extended": "S3 Bucket my-bucket has public read access.",
        "severity": "critical",
        "resource_uid": "arn:aws:s3:::my-bucket",
        "resource_name": "my-bucket",
        "resource_type": "AWS::S3::Bucket",
        "region": "us-east-1",
        "account_uid": "123456789012",
        "provider": "aws",
        "inserted_at": "2024-01-15T08:30:00Z",
    }


@pytest.fixture
def azure_finding() -> dict:
    """Minimal Prowler Azure finding."""
    return {
        "id": "prowler-azure-iam-mfa-001",
        "check_id": "iam_user_mfa_enabled",
        "check_metadata": {
            "CheckTitle": "MFA Should Be Enabled for All Users",
            "ServiceName": "iam",
            "Severity": "high",
        },
        "status": "FAIL",
        "severity": "high",
        "region": "eastus",
        "account_uid": "azure-subscription-001",
        "provider": "azure",
        "inserted_at": "2024-02-01T12:00:00Z",
    }


@pytest.fixture
def gcp_finding() -> dict:
    """Minimal Prowler GCP finding."""
    return {
        "id": "prowler-gcp-cloudtrail-001",
        "check_id": "cloudtrail_enabled",
        "check_metadata": {
            "CheckTitle": "Cloud Audit Logging Should Be Configured",
            "ServiceName": "logging",
            "Severity": "medium",
        },
        "status": "FAIL",
        "severity": "medium",
        "region": "us-central1",
        "account_uid": "my-gcp-project",
        "provider": "gcp",
        "inserted_at": "2024-03-10T06:45:00Z",
    }


# ── PROWLER_SEVERITY_MAP ───────────────────────────────────────────────────────


class TestProwlerSeverityMap:
    def test_critical_maps_to_5(self) -> None:
        assert PROWLER_SEVERITY_MAP["critical"] == 5

    def test_high_maps_to_4(self) -> None:
        assert PROWLER_SEVERITY_MAP["high"] == 4

    def test_medium_maps_to_3(self) -> None:
        assert PROWLER_SEVERITY_MAP["medium"] == 3

    def test_low_maps_to_2(self) -> None:
        assert PROWLER_SEVERITY_MAP["low"] == 2

    def test_informational_maps_to_1(self) -> None:
        assert PROWLER_SEVERITY_MAP["informational"] == 1

    def test_info_maps_to_1(self) -> None:
        assert PROWLER_SEVERITY_MAP["info"] == 1


# ── OCSF class / category ─────────────────────────────────────────────────────


class TestProwlerOCSFClass:
    def test_class_uid_is_compliance_finding(self, normalizer, aws_finding) -> None:
        event = normalizer.normalize(aws_finding)
        assert event.class_uid == OCSFClass.COMPLIANCE_FINDING

    def test_class_uid_is_2003(self, normalizer, aws_finding) -> None:
        event = normalizer.normalize(aws_finding)
        assert event.class_uid == 2003

    def test_class_name_is_compliance_finding(self, normalizer, aws_finding) -> None:
        event = normalizer.normalize(aws_finding)
        assert event.class_name == "Compliance Finding"

    def test_category_uid_is_findings(self, normalizer, aws_finding) -> None:
        event = normalizer.normalize(aws_finding)
        assert event.category_uid == OCSFCategory.FINDINGS

    def test_category_uid_is_2(self, normalizer, aws_finding) -> None:
        event = normalizer.normalize(aws_finding)
        assert event.category_uid == 2

    def test_metadata_product_is_prowler(self, normalizer, aws_finding) -> None:
        event = normalizer.normalize(aws_finding)
        assert event.metadata_product == "Prowler"


# ── metadata_uid ──────────────────────────────────────────────────────────────


class TestProwlerMetadataUid:
    def test_metadata_uid_from_id_field(self, normalizer, aws_finding) -> None:
        event = normalizer.normalize(aws_finding)
        assert event.metadata_uid == aws_finding["id"]

    def test_metadata_uid_none_when_id_missing(self, normalizer) -> None:
        raw = {"check_id": "some_check", "severity": "low"}
        event = normalizer.normalize(raw)
        assert event.metadata_uid is None


# ── Severity mapping ──────────────────────────────────────────────────────────


class TestProwlerSeverityMapping:
    @pytest.mark.parametrize(
        "sev_str,expected_id",
        [
            ("critical",      5),
            ("high",          4),
            ("medium",        3),
            ("low",           2),
            ("informational", 1),
            ("info",          1),
        ],
    )
    def test_severity_string_maps_to_severity_id(
        self, normalizer, sev_str, expected_id
    ) -> None:
        raw = {"check_id": "test_check", "severity": sev_str}
        event = normalizer.normalize(raw)
        assert event.severity_id == expected_id

    def test_unknown_severity_maps_to_0(self, normalizer) -> None:
        raw = {"check_id": "test_check", "severity": "bogus"}
        event = normalizer.normalize(raw)
        assert event.severity_id == 0

    def test_missing_severity_maps_to_0(self, normalizer) -> None:
        raw = {"check_id": "test_check"}
        event = normalizer.normalize(raw)
        assert event.severity_id == 0

    def test_severity_from_check_metadata_fallback(self, normalizer) -> None:
        raw = {
            "check_id": "test_check",
            "check_metadata": {"Severity": "high"},
            # no top-level "severity"
        }
        event = normalizer.normalize(raw)
        assert event.severity_id == 4

    def test_top_level_severity_takes_priority_over_metadata(self, normalizer) -> None:
        raw = {
            "check_id": "test_check",
            "severity": "low",
            "check_metadata": {"Severity": "critical"},
        }
        event = normalizer.normalize(raw)
        assert event.severity_id == 2  # "low"


# ── check_id / check_title extraction ─────────────────────────────────────────


class TestProwlerCheckExtraction:
    def test_check_id_from_top_level(self, normalizer) -> None:
        raw = {"check_id": "s3_bucket_public_read_prohibition", "severity": "critical"}
        event = normalizer.normalize(raw)
        assert event.finding_info.analytic.uid == "s3_bucket_public_read_prohibition"

    def test_check_id_falls_back_to_metadata_CheckID(self, normalizer) -> None:
        raw = {
            "check_metadata": {"CheckID": "iam_mfa_check"},
            "severity": "high",
        }
        event = normalizer.normalize(raw)
        assert event.finding_info.analytic.uid == "iam_mfa_check"

    def test_check_id_defaults_to_unknown_when_absent(self, normalizer) -> None:
        raw = {"severity": "low"}
        event = normalizer.normalize(raw)
        assert event.finding_info.analytic.uid == "unknown"

    def test_check_title_from_check_metadata_CheckTitle(self, normalizer, aws_finding) -> None:
        event = normalizer.normalize(aws_finding)
        assert event.finding_info.title == "S3 Bucket Should Not Have Public Read Access"

    def test_check_title_falls_back_to_check_id(self, normalizer) -> None:
        raw = {"check_id": "my_custom_check", "severity": "medium"}
        event = normalizer.normalize(raw)
        assert event.finding_info.title == "my_custom_check"

    def test_analytic_type_id_is_1(self, normalizer, aws_finding) -> None:
        event = normalizer.normalize(aws_finding)
        assert event.finding_info.analytic.type_id == 1


# ── src_endpoint ──────────────────────────────────────────────────────────────


class TestProwlerEndpoint:
    def test_src_endpoint_uid_from_account_uid(self, normalizer, aws_finding) -> None:
        event = normalizer.normalize(aws_finding)
        assert event.src_endpoint.uid == "123456789012"

    def test_src_endpoint_hostname_from_provider(self, normalizer, aws_finding) -> None:
        event = normalizer.normalize(aws_finding)
        assert event.src_endpoint.hostname == "aws"

    def test_src_endpoint_domain_from_region(self, normalizer, aws_finding) -> None:
        event = normalizer.normalize(aws_finding)
        assert event.src_endpoint.domain == "us-east-1"

    def test_azure_provider_in_hostname(self, normalizer, azure_finding) -> None:
        event = normalizer.normalize(azure_finding)
        assert event.src_endpoint.hostname == "azure"

    def test_gcp_provider_in_hostname(self, normalizer, gcp_finding) -> None:
        event = normalizer.normalize(gcp_finding)
        assert event.src_endpoint.hostname == "gcp"

    def test_missing_account_uid_yields_none(self, normalizer) -> None:
        raw = {"check_id": "test", "severity": "low"}
        event = normalizer.normalize(raw)
        assert event.src_endpoint.uid is None

    def test_missing_provider_yields_none(self, normalizer) -> None:
        raw = {"check_id": "test", "severity": "low"}
        event = normalizer.normalize(raw)
        assert event.src_endpoint.hostname is None

    def test_missing_region_yields_none(self, normalizer) -> None:
        raw = {"check_id": "test", "severity": "low"}
        event = normalizer.normalize(raw)
        assert event.src_endpoint.domain is None


# ── raw + unmapped ────────────────────────────────────────────────────────────


class TestProwlerUnmapped:
    def test_raw_field_preserved(self, normalizer, aws_finding) -> None:
        event = normalizer.normalize(aws_finding)
        assert event.raw == aws_finding

    def test_unmapped_contains_status(self, normalizer, aws_finding) -> None:
        event = normalizer.normalize(aws_finding)
        assert event.unmapped["status"] == "FAIL"

    def test_unmapped_contains_status_extended(self, normalizer, aws_finding) -> None:
        event = normalizer.normalize(aws_finding)
        assert "status_extended" in event.unmapped

    def test_unmapped_contains_provider(self, normalizer, aws_finding) -> None:
        event = normalizer.normalize(aws_finding)
        assert event.unmapped["provider"] == "aws"

    def test_unmapped_contains_region(self, normalizer, aws_finding) -> None:
        event = normalizer.normalize(aws_finding)
        assert event.unmapped["region"] == "us-east-1"

    def test_unmapped_contains_account_uid(self, normalizer, aws_finding) -> None:
        event = normalizer.normalize(aws_finding)
        assert event.unmapped["account_uid"] == "123456789012"

    def test_unmapped_contains_resource_uid(self, normalizer, aws_finding) -> None:
        event = normalizer.normalize(aws_finding)
        assert event.unmapped["resource_uid"] == "arn:aws:s3:::my-bucket"

    def test_unmapped_contains_resource_name(self, normalizer, aws_finding) -> None:
        event = normalizer.normalize(aws_finding)
        assert event.unmapped["resource_name"] == "my-bucket"

    def test_unmapped_contains_resource_type(self, normalizer, aws_finding) -> None:
        event = normalizer.normalize(aws_finding)
        assert event.unmapped["resource_type"] == "AWS::S3::Bucket"

    def test_unmapped_contains_service_from_metadata(self, normalizer, aws_finding) -> None:
        event = normalizer.normalize(aws_finding)
        assert event.unmapped["service"] == "s3"

    def test_unmapped_omits_none_values(self, normalizer) -> None:
        raw = {"check_id": "test", "status": "FAIL"}
        event = normalizer.normalize(raw)
        # Keys not present in raw should not appear in unmapped
        assert "resource_uid" not in event.unmapped
        assert "region" not in event.unmapped

    def test_unmapped_no_service_when_metadata_absent(self, normalizer) -> None:
        raw = {"check_id": "test", "status": "FAIL", "severity": "low"}
        event = normalizer.normalize(raw)
        assert "service" not in event.unmapped


# ── time parsing ──────────────────────────────────────────────────────────────


class TestProwlerTimeParsing:
    def test_time_parsed_from_inserted_at(self, normalizer, aws_finding) -> None:
        event = normalizer.normalize(aws_finding)
        assert event.time == datetime(2024, 1, 15, 8, 30, 0, tzinfo=timezone.utc)

    def test_time_defaults_to_now_when_inserted_at_missing(self, normalizer) -> None:
        before = datetime.now(timezone.utc)
        raw = {"check_id": "test", "severity": "low"}
        event = normalizer.normalize(raw)
        after = datetime.now(timezone.utc)
        assert before <= event.time <= after

    def test_time_defaults_to_now_when_inserted_at_invalid(self, normalizer) -> None:
        before = datetime.now(timezone.utc)
        raw = {"check_id": "test", "severity": "low", "inserted_at": "not-a-date"}
        event = normalizer.normalize(raw)
        after = datetime.now(timezone.utc)
        assert before <= event.time <= after


# ── ATT&CK mapping ────────────────────────────────────────────────────────────


class TestProwlerAttackLookup:
    def test_unknown_check_id_returns_none(self) -> None:
        assert _lookup_attack("completely_unknown_check") is None

    @pytest.mark.parametrize(
        "check_id,expected_tech,expected_tac",
        [
            ("iam_root_account_mfa_enabled",             "T1078.004", "TA0001"),
            ("iam_root_mfa_enabled",                     "T1078.004", "TA0001"),
            ("iam_user_mfa_enabled",                     "T1078",     "TA0001"),
            ("iam_user_mfa_enabled_console_access",      "T1078",     "TA0001"),
            ("s3_bucket_public_read_prohibition",        "T1530",     "TA0009"),
            ("s3_bucket_public_write_prohibition",       "T1530",     "TA0009"),
            ("cloudtrail_enabled",                       "T1562.008", "TA0005"),
            ("cloudtrail_multi_region_enabled",          "T1562.008", "TA0005"),
            ("ec2_securitygroup_allow_all_ingress_traffic", "T1190",  "TA0001"),
            ("guardduty_is_enabled",                     "T1562",     "TA0005"),
            ("iam_access_key_rotation",                  "T1528",     "TA0006"),
            ("iam_policy_no_administrative_privileges",  "T1078",     "TA0004"),
        ],
    )
    def test_known_check_id_returns_correct_attack(
        self, check_id, expected_tech, expected_tac
    ) -> None:
        result = _lookup_attack(check_id)
        assert result is not None
        tech_uid, _, tac_uid, _ = result
        assert tech_uid == expected_tech
        assert tac_uid == expected_tac


class TestProwlerBuildAttacks:
    def test_unknown_check_id_produces_empty_attacks(self, normalizer) -> None:
        raw = {"check_id": "completely_unknown_xyz", "severity": "low"}
        event = normalizer.normalize(raw)
        assert event.finding_info.attacks == []

    def test_known_check_id_produces_one_attack(self, normalizer, aws_finding) -> None:
        event = normalizer.normalize(aws_finding)
        assert len(event.finding_info.attacks) == 1

    def test_sub_technique_set_for_dotted_uid(self, normalizer) -> None:
        raw = {
            "check_id": "iam_root_account_mfa_enabled",
            "severity": "critical",
        }
        event = normalizer.normalize(raw)
        attack = event.finding_info.attacks[0]
        # T1078.004 → sub_technique="004"
        assert attack.technique.sub_technique == "004"

    def test_no_sub_technique_for_plain_uid(self, normalizer, aws_finding) -> None:
        # s3_bucket_public_read_prohibition → T1530 (no dot)
        event = normalizer.normalize(aws_finding)
        attack = event.finding_info.attacks[0]
        assert attack.technique.sub_technique is None

    def test_tactic_name_and_uid_populated(self, normalizer, aws_finding) -> None:
        event = normalizer.normalize(aws_finding)
        attack = event.finding_info.attacks[0]
        assert attack.tactic.uid == "TA0009"
        assert attack.tactic.name == "Collection"

    def test_technique_uid_populated(self, normalizer, aws_finding) -> None:
        event = normalizer.normalize(aws_finding)
        attack = event.finding_info.attacks[0]
        assert attack.technique.uid == "T1530"

    def test_prefix_fallback_iam_custom(self, normalizer) -> None:
        raw = {"check_id": "iam_custom_obscure_check", "severity": "medium"}
        event = normalizer.normalize(raw)
        # Should hit the iam_ prefix → T1078 / TA0004
        attacks = event.finding_info.attacks
        assert len(attacks) == 1
        assert attacks[0].technique.uid == "T1078"
        assert attacks[0].tactic.uid == "TA0004"

    def test_prefix_fallback_s3_custom(self, normalizer) -> None:
        raw = {"check_id": "s3_encryption_at_rest", "severity": "medium"}
        event = normalizer.normalize(raw)
        attacks = event.finding_info.attacks
        assert len(attacks) == 1
        assert attacks[0].technique.uid == "T1530"

    def test_prefix_fallback_cloudtrail_custom(self, normalizer) -> None:
        raw = {"check_id": "cloudtrail_custom_check", "severity": "high"}
        event = normalizer.normalize(raw)
        attacks = event.finding_info.attacks
        assert len(attacks) == 1
        assert attacks[0].technique.uid == "T1562.008"

    def test_exact_match_beats_prefix(self, normalizer) -> None:
        # iam_root_account_mfa_enabled is an exact match → T1078.004
        # iam_ prefix would yield T1078 — verify exact wins
        raw = {"check_id": "iam_root_account_mfa_enabled", "severity": "critical"}
        event = normalizer.normalize(raw)
        assert event.finding_info.attacks[0].technique.uid == "T1078.004"


# ── Full round-trip ───────────────────────────────────────────────────────────


class TestProwlerRoundTrip:
    def test_aws_finding_produces_valid_ocsf_event(self, normalizer, aws_finding) -> None:
        event = normalizer.normalize(aws_finding)
        assert event.class_uid == 2003
        assert event.class_name == "Compliance Finding"
        assert event.category_uid == 2
        assert event.metadata_product == "Prowler"
        assert event.metadata_uid == aws_finding["id"]
        assert event.severity_id == 5
        assert event.src_endpoint.uid == "123456789012"
        assert event.src_endpoint.hostname == "aws"
        assert event.src_endpoint.domain == "us-east-1"
        assert event.finding_info.title == "S3 Bucket Should Not Have Public Read Access"
        assert event.finding_info.analytic.uid == "s3_bucket_public_read_prohibition"
        assert len(event.finding_info.attacks) == 1
        assert event.raw == aws_finding

    def test_azure_finding_produces_valid_ocsf_event(self, normalizer, azure_finding) -> None:
        event = normalizer.normalize(azure_finding)
        assert event.class_uid == 2003
        assert event.severity_id == 4
        assert event.src_endpoint.hostname == "azure"
        assert event.src_endpoint.domain == "eastus"

    def test_gcp_finding_produces_valid_ocsf_event(self, normalizer, gcp_finding) -> None:
        event = normalizer.normalize(gcp_finding)
        assert event.class_uid == 2003
        assert event.severity_id == 3
        assert event.src_endpoint.hostname == "gcp"

    def test_model_dump_produces_json_serializable_dict(self, normalizer, aws_finding) -> None:
        event = normalizer.normalize(aws_finding)
        dumped = event.model_dump(mode="json")
        assert isinstance(dumped, dict)
        assert dumped["class_uid"] == 2003
        assert dumped["metadata_product"] == "Prowler"
