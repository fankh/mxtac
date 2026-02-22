"""
OCSF (Open Cybersecurity Schema Framework) event model.
Based on OCSF 1.1.0 — https://schema.ocsf.io/

We implement the subset relevant to security detections:
  - Network Activity (class_uid: 4001)
  - Process Activity (class_uid: 1007)
  - File Activity (class_uid: 1001)
  - Security Finding (class_uid: 2001)
  - Authentication (class_uid: 3002)
  - DNS Activity (class_uid: 4003)
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field


# ── Shared sub-objects ───────────────────────────────────────────────────────

class Endpoint(BaseModel):
    uid: str | None = None      # Unique identifier (e.g., Wazuh agent.id)
    hostname: str | None = None
    ip: str | None = None
    port: int | None = None
    domain: str | None = None
    os_name: str | None = None


class ProcessInfo(BaseModel):
    pid: int | None = None
    name: str | None = None
    cmd_line: str | None = None
    path: str | None = None
    parent_pid: int | None = None
    parent_name: str | None = None
    hash_sha256: str | None = None


class UserInfo(BaseModel):
    name: str | None = None
    uid: str | None = None
    domain: str | None = None
    is_privileged: bool | None = None


class AttackInfo(BaseModel):
    tactic: AttackTactic | None = None
    technique: AttackTechnique | None = None


class AttackTactic(BaseModel):
    name: str
    uid: str   # e.g. "TA0002"


class AttackTechnique(BaseModel):
    name: str
    uid: str   # e.g. "T1059.001"
    sub_technique: str | None = None


class FindingInfo(BaseModel):
    title: str
    analytic: Analytic | None = None
    attacks: list[AttackInfo] = Field(default_factory=list)
    severity_id: int = 1   # 0=Unknown 1=Informational 2=Low 3=Medium 4=High 5=Critical


class Analytic(BaseModel):
    uid: str | None = None      # rule ID
    name: str | None = None     # rule name
    type_id: int = 1            # 1=Rule 2=Behavioral 3=Statistical


# ── OCSF severity mapping ────────────────────────────────────────────────────

SEVERITY_MAP = {
    "critical": 5,
    "high":     4,
    "medium":   3,
    "low":      2,
    "info":     1,
    "unknown":  0,
}

SEVERITY_ID_TO_NAME = {v: k for k, v in SEVERITY_MAP.items()}


# ── Main OCSF event model ────────────────────────────────────────────────────

class OCSFEvent(BaseModel):
    """
    Normalized OCSF event. A common envelope used throughout the MxTac pipeline.
    """
    # Required OCSF fields
    class_uid: int                  # e.g. 4001 (Network), 1007 (Process), 2001 (Finding)
    class_name: str                 # human-readable class name
    category_uid: int               # e.g. 4 (Network), 1 (System), 2 (Findings)
    time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    severity_id: int = 1

    # Source metadata
    metadata_product: str           # "Wazuh", "Zeek", "Suricata", etc.
    metadata_version: str = "1.1.0"
    metadata_uid: str | None = None  # raw event ID from source

    # Endpoint info
    src_endpoint: Endpoint = Field(default_factory=Endpoint)
    dst_endpoint: Endpoint = Field(default_factory=Endpoint)

    # Identity
    actor_user: UserInfo = Field(default_factory=UserInfo)

    # Process context
    process: ProcessInfo = Field(default_factory=ProcessInfo)

    # Network context
    network_traffic: dict[str, Any] = Field(default_factory=dict)

    # File context
    file: dict[str, Any] = Field(default_factory=dict)

    # ATT&CK + finding (for Security Finding class)
    finding_info: FindingInfo | None = None

    # Raw event for traceability
    raw: dict[str, Any] = Field(default_factory=dict)

    # Free-form extension fields
    unmapped: dict[str, Any] = Field(default_factory=dict)

    @property
    def severity_name(self) -> str:
        return SEVERITY_ID_TO_NAME.get(self.severity_id, "unknown")


# ── OCSF class constants ─────────────────────────────────────────────────────

class OCSFClass:
    FILE_ACTIVITY       = 1001
    PROCESS_ACTIVITY    = 1007
    SECURITY_FINDING    = 2001
    COMPLIANCE_FINDING  = 2003
    AUTHENTICATION      = 3002
    NETWORK_ACTIVITY    = 4001
    DNS_ACTIVITY        = 4003
    HTTP_ACTIVITY       = 4002

class OCSFCategory:
    SYSTEM_ACTIVITY     = 1
    FINDINGS            = 2
    IAM                 = 3
    NETWORK             = 4
