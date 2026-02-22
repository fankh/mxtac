"""
Prowler → OCSF normalizer.

Prowler finding structure (REST API v3+):
{
  "id": "prowler-aws-s3-bucket-public-read-...",
  "check_id": "s3_bucket_public_read_prohibition",
  "check_metadata": {
    "CheckID": "s3_bucket_public_read_prohibition",
    "CheckTitle": "S3 Bucket Should Not Have Public Read Access",
    "ServiceName": "s3",
    "Severity": "critical"
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
  "inserted_at": "2024-01-15T08:30:00Z"
}

Maps to OCSF ComplianceFinding (class_uid 2003, category_uid 2 — Findings).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .ocsf import (
    Analytic,
    AttackInfo,
    AttackTactic,
    AttackTechnique,
    Endpoint,
    FindingInfo,
    OCSFCategory,
    OCSFClass,
    OCSFEvent,
    SEVERITY_MAP,
)

# Prowler severity string → OCSF severity_id
# "informational" maps to 1 (Informational); not in the standard SEVERITY_MAP alias
PROWLER_SEVERITY_MAP: dict[str, int] = {
    "critical":      5,
    "high":          4,
    "medium":        3,
    "low":           2,
    "informational": 1,
    "info":          1,
}

# check_id prefix/exact → (tech_uid, tech_name, tac_uid, tac_name)
# Covers the most common Prowler checks that have a direct ATT&CK mapping.
# Lookup order: exact match first, then prefix match (longest prefix wins).
_CHECK_ATTACK: dict[str, tuple[str, str, str, str]] = {
    # ── IAM / Credential Access ───────────────────────────────────────────────
    "iam_root_account_mfa_enabled":
        ("T1078.004", "Valid Accounts: Cloud Accounts", "TA0001", "Initial Access"),
    "iam_root_mfa_enabled":
        ("T1078.004", "Valid Accounts: Cloud Accounts", "TA0001", "Initial Access"),
    "iam_user_mfa_enabled_console_access":
        ("T1078",     "Valid Accounts",                 "TA0001", "Initial Access"),
    "iam_user_mfa_enabled":
        ("T1078",     "Valid Accounts",                 "TA0001", "Initial Access"),
    "iam_access_key_rotation":
        ("T1528",     "Steal Application Access Token", "TA0006", "Credential Access"),
    "iam_access_key_no_user_not_used":
        ("T1528",     "Steal Application Access Token", "TA0006", "Credential Access"),
    "iam_policy_no_administrative_privileges":
        ("T1078",     "Valid Accounts",                 "TA0004", "Privilege Escalation"),
    "iam_policy_attached_only_to_groups_or_roles":
        ("T1078",     "Valid Accounts",                 "TA0004", "Privilege Escalation"),
    # ── S3 / Data Exposure ───────────────────────────────────────────────────
    "s3_bucket_public_read_prohibition":
        ("T1530",     "Data from Cloud Storage Object", "TA0009", "Collection"),
    "s3_bucket_public_write_prohibition":
        ("T1530",     "Data from Cloud Storage Object", "TA0009", "Collection"),
    "s3_bucket_publicly_accessible":
        ("T1530",     "Data from Cloud Storage Object", "TA0009", "Collection"),
    # ── CloudTrail / Logging — Defense Evasion ────────────────────────────────
    "cloudtrail_enabled":
        ("T1562.008", "Disable or Modify Cloud Logs",   "TA0005", "Defense Evasion"),
    "cloudtrail_multi_region_enabled":
        ("T1562.008", "Disable or Modify Cloud Logs",   "TA0005", "Defense Evasion"),
    "cloudtrail_s3_dataevents_read_enabled":
        ("T1562.008", "Disable or Modify Cloud Logs",   "TA0005", "Defense Evasion"),
    "cloudtrail_s3_dataevents_write_enabled":
        ("T1562.008", "Disable or Modify Cloud Logs",   "TA0005", "Defense Evasion"),
    "cloudwatch_log_metric_filter_unauthorized_api_calls":
        ("T1562.008", "Disable or Modify Cloud Logs",   "TA0005", "Defense Evasion"),
    # ── EC2 / Network Exposure — Initial Access ───────────────────────────────
    "ec2_securitygroup_allow_all_ingress_traffic":
        ("T1190",     "Exploit Public-Facing Application", "TA0001", "Initial Access"),
    "ec2_securitygroup_allow_all_ingress_tcp_udp_traffic":
        ("T1190",     "Exploit Public-Facing Application", "TA0001", "Initial Access"),
    "ec2_securitygroup_default_restrict_traffic":
        ("T1190",     "Exploit Public-Facing Application", "TA0001", "Initial Access"),
    # ── GuardDuty / Security Services — Impair Defenses ──────────────────────
    "guardduty_is_enabled":
        ("T1562",     "Impair Defenses",                "TA0005", "Defense Evasion"),
    "securityhub_enabled":
        ("T1562",     "Impair Defenses",                "TA0005", "Defense Evasion"),
    # ── Cross-account / Trusted Relationships ────────────────────────────────
    "iam_role_cross_account_readonlyaccess_policy":
        ("T1199",     "Trusted Relationship",           "TA0001", "Initial Access"),
}

# Prefix-based fallback table (evaluated only when exact match fails)
_CHECK_ATTACK_PREFIXES: list[tuple[str, tuple[str, str, str, str]]] = sorted(
    [
        ("iam_root_",          ("T1078.004", "Valid Accounts: Cloud Accounts", "TA0001", "Initial Access")),
        ("iam_user_",          ("T1078",     "Valid Accounts",                 "TA0001", "Initial Access")),
        ("iam_access_key_",    ("T1528",     "Steal Application Access Token", "TA0006", "Credential Access")),
        ("iam_policy_",        ("T1078",     "Valid Accounts",                 "TA0004", "Privilege Escalation")),
        ("iam_",               ("T1078",     "Valid Accounts",                 "TA0004", "Privilege Escalation")),
        ("s3_bucket_public",   ("T1530",     "Data from Cloud Storage Object", "TA0009", "Collection")),
        ("s3_",                ("T1530",     "Data from Cloud Storage Object", "TA0009", "Collection")),
        ("cloudtrail_",        ("T1562.008", "Disable or Modify Cloud Logs",   "TA0005", "Defense Evasion")),
        ("cloudwatch_",        ("T1562.008", "Disable or Modify Cloud Logs",   "TA0005", "Defense Evasion")),
        ("ec2_securitygroup_", ("T1190",     "Exploit Public-Facing Application", "TA0001", "Initial Access")),
        ("guardduty_",         ("T1562",     "Impair Defenses",                "TA0005", "Defense Evasion")),
    ],
    key=lambda x: -len(x[0]),  # longest prefix first
)


def _lookup_attack(check_id: str) -> tuple[str, str, str, str] | None:
    """Return (tech_uid, tech_name, tac_uid, tac_name) for a Prowler check_id, or None."""
    entry = _CHECK_ATTACK.get(check_id)
    if entry:
        return entry
    for prefix, attack in _CHECK_ATTACK_PREFIXES:
        if check_id.startswith(prefix):
            return attack
    return None


class ProwlerNormalizer:
    """Transforms a Prowler REST API finding dict into an OCSFEvent."""

    def normalize(self, raw: dict[str, Any]) -> OCSFEvent:
        meta = raw.get("check_metadata", {})

        # Resolve check identifier and title from both top-level and nested fields
        check_id    = raw.get("check_id") or meta.get("CheckID", "unknown")
        check_title = meta.get("CheckTitle") or check_id

        # Severity — prefer top-level "severity"; fall back to check_metadata.Severity
        sev_str     = (raw.get("severity") or meta.get("Severity") or "").lower()
        severity_id = PROWLER_SEVERITY_MAP.get(sev_str, 0)

        # ATT&CK mapping from check_id
        attacks = self._build_attacks(check_id)

        # Finding info
        finding = FindingInfo(
            title=check_title,
            severity_id=severity_id,
            attacks=attacks,
            analytic=Analytic(
                uid=check_id,
                name=check_title,
                type_id=1,
            ),
        )

        # Cloud endpoint — encode account + provider + region as endpoint fields
        provider   = raw.get("provider", "")
        region     = raw.get("region", "")
        account_id = raw.get("account_uid", "")
        src = Endpoint(
            uid=account_id or None,
            hostname=provider or None,
            domain=region or None,
        )

        # Collect Prowler-specific fields in unmapped for full traceability
        unmapped: dict[str, Any] = {}
        for key in (
            "status", "status_extended", "provider", "region",
            "account_uid", "resource_uid", "resource_name", "resource_type",
        ):
            val = raw.get(key)
            if val is not None:
                unmapped[key] = val
        service = meta.get("ServiceName")
        if service:
            unmapped["service"] = service

        return OCSFEvent(
            class_uid=OCSFClass.COMPLIANCE_FINDING,
            class_name="Compliance Finding",
            category_uid=OCSFCategory.FINDINGS,
            time=self._parse_time(raw.get("inserted_at")),
            severity_id=severity_id,
            metadata_product="Prowler",
            metadata_uid=raw.get("id"),
            src_endpoint=src,
            finding_info=finding,
            raw=raw,
            unmapped=unmapped,
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _build_attacks(self, check_id: str) -> list[AttackInfo]:
        entry = _lookup_attack(check_id)
        if entry is None:
            return []
        tech_uid, tech_name, tac_uid, tac_name = entry
        sub = tech_uid.split(".", 1)[1] if "." in tech_uid else None
        return [
            AttackInfo(
                tactic=AttackTactic(uid=tac_uid, name=tac_name),
                technique=AttackTechnique(uid=tech_uid, name=tech_name, sub_technique=sub),
            )
        ]

    def _parse_time(self, ts: str | None) -> datetime:
        if not ts:
            return datetime.now(timezone.utc)
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return datetime.now(timezone.utc)
