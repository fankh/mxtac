"""Idempotent database seeder.

On first run (no users) exactly one account is created: ``admin@mxtac.local``
with a one-time bootstrap password that must be changed at first sign-in.
The password is ``INITIAL_ADMIN_PASSWORD`` when set, otherwise a random one
that is written once to the startup log.

Demo accounts for the other roles and demo detections, connectors, rules and
incidents are fabricated sample rows and are only written when explicitly
requested (``SEED_DEMO_DATA=true``).
"""

from __future__ import annotations

import json
import secrets
import string
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.config import settings
from ..core.logging import get_logger
from ..core.security import hash_password
from ..core.validators import validate_password_policy
from ..models.connector import Connector
from ..models.detection import Detection
from ..models.incident import Incident
from ..models.rule import Rule
from ..models.user import User

logger = get_logger(__name__)

ADMIN_EMAIL = "admin@mxtac.local"

# Demo-only accounts (SEED_DEMO_DATA=true): one per remaining role.
_DEMO_ACCOUNTS = [
    ("analyst@mxtac.local", "Default Analyst", "analyst"),
    ("hunter@mxtac.local", "Threat Hunter", "hunter"),
    ("engineer@mxtac.local", "Security Engineer", "engineer"),
]

_GENERATED_PASSWORD_LENGTH = 24
_GENERATED_PASSWORD_ALPHABET = string.ascii_letters + string.digits


def generate_initial_password() -> str:
    """Return a random 24-character password that satisfies the password policy.

    Letters and digits only (about 143 bits of entropy) so it survives log
    formats and copy/paste unchanged.  Candidates that miss a character class
    or contain a run of 4 identical characters are discarded and redrawn.
    """
    while True:
        candidate = "".join(
            secrets.choice(_GENERATED_PASSWORD_ALPHABET) for _ in range(_GENERATED_PASSWORD_LENGTH)
        )
        try:
            return validate_password_policy(candidate)
        except ValueError:
            continue


def _announce_initial_password(password: str, *, generated: bool) -> None:
    """Tell the operator how to sign in for the first time.

    A generated password is written to the log exactly once, at WARNING level.
    This is the only place a password is ever logged: it is a one-time
    bootstrap credential that the account is forced to replace at first
    sign-in.  A password supplied through INITIAL_ADMIN_PASSWORD is never logged.
    """
    if generated:
        logger.warning(
            "INITIAL ADMIN PASSWORD (generated, shown only once): email=%s password=%s "
            "- sign in and set a new password now; it cannot be used for anything else.",
            ADMIN_EMAIL,
            password,
        )
    else:
        logger.info(
            "Initial admin account %s uses the password from INITIAL_ADMIN_PASSWORD; "
            "it must be changed at first sign-in.",
            ADMIN_EMAIL,
        )


async def seed_database(session: AsyncSession, *, demo_data: bool = False) -> None:
    """Idempotent seed — only runs if the users table is empty.

    Always creates the single bootstrap admin account.  With
    ``demo_data=True`` it also inserts demo accounts for the other roles and
    sample (invented) detections, connectors, rules and incidents.  Every
    seeded account has ``must_change_password=True``.
    """

    # Check if data exists
    user_count = await session.scalar(select(func.count()).select_from(User))
    if user_count and user_count > 0:
        logger.info("Database already seeded (%d users), skipping", user_count)
        return

    logger.info("Seeding database (demo data: %s)...", "on" if demo_data else "off")

    # ── Users ────────────────────────────────────────────────────────────────
    initial_password = settings.initial_admin_password
    generated = not initial_password
    if generated:
        initial_password = generate_initial_password()
    else:
        # Settings already rejects a weak value at startup; checked again here
        # so the seeder can never store a password that violates the policy.
        validate_password_policy(initial_password)
    hashed = hash_password(initial_password)

    accounts = [(ADMIN_EMAIL, "Admin", "admin")]
    if demo_data:
        accounts += _DEMO_ACCOUNTS
    users = [
        User(
            email=email,
            hashed_password=hashed,
            full_name=full_name,
            role=role,
            is_active=True,
            must_change_password=True,
        )
        for email, full_name, role in accounts
    ]
    session.add_all(users)

    if not demo_data:
        await session.commit()
        logger.info("Database seeded: %d users (no demo data)", len(users))
        _announce_initial_password(initial_password, generated=generated)
        return

    # ── Demo data (opt-in) — everything below is invented sample content ─────

    # ── Detections ───────────────────────────────────────────────────────────
    detections = [
        Detection(
            id="DET-2026-00847",
            score=9.0, severity="critical",
            technique_id="T1003.006", technique_name="DCSync",
            name="DCSync via DRSUAPI GetNCChanges",
            host="DC-PROD-01", tactic="Credential Access",
            status="active",
            time=datetime(2026, 2, 19, 14, 21, 7, tzinfo=timezone.utc),
            user="CORP\\svc-backup", process="lsass.exe (PID: 4)",
            rule_name="win_dcsync_replication", log_source="Elastic SIEM · Windows Security",
            event_id="4662", occurrence_count=14,
            description="DCSync attack detected. Account CORP\\svc-backup invoked DRSUAPI replication from DC-PROD-01.",
            cvss_v3=8.8, confidence=96, tactic_id="TA0006",
            assigned_to="J. Smith", priority="P1 Urgent",
        ),
        Detection(
            id="DET-2026-00846",
            score=9.2, severity="critical",
            technique_id="T1055.001", technique_name="Process Injection",
            name="Process Injection via DLL",
            host="WS-PROD-114", tactic="Defense Evasion",
            status="active",
            time=datetime(2026, 2, 19, 14, 28, 0, tzinfo=timezone.utc),
            rule_name="win_process_injection_dll", log_source="Elastic SIEM",
            occurrence_count=3, cvss_v3=8.5, confidence=91, tactic_id="TA0005",
            assigned_to="K. Lee", priority="P1 Urgent",
        ),
        Detection(
            id="DET-2026-00845",
            score=8.7, severity="high",
            technique_id="T1558.003", technique_name="Kerberoasting",
            name="Kerberoasting — SPN Enumeration",
            host="SRV-AUTH-07", tactic="Credential Access",
            status="investigating",
            time=datetime(2026, 2, 19, 14, 9, 0, tzinfo=timezone.utc),
            rule_name="win_kerberoasting", log_source="MS Sentinel",
            occurrence_count=7, cvss_v3=8.1, confidence=88, tactic_id="TA0006",
            assigned_to="M. Park", priority="P2 High",
        ),
        Detection(
            id="DET-2026-00844",
            score=8.4, severity="high",
            technique_id="T1550.003", technique_name="Pass the Ticket",
            name="Pass the Ticket — Lateral Move",
            host="WS-FIN-022", tactic="Lateral Movement",
            status="resolved",
            time=datetime(2026, 2, 19, 13, 58, 0, tzinfo=timezone.utc),
            rule_name="win_pass_the_ticket", log_source="Elastic SIEM",
            occurrence_count=2, cvss_v3=7.9, confidence=85, tactic_id="TA0008",
            assigned_to="J. Smith", priority="P2 High",
        ),
        Detection(
            id="DET-2026-00843",
            score=8.1, severity="high",
            technique_id="T1078.002", technique_name="Valid Accounts",
            name="Valid Domain Admin Account Login",
            host="FS-CORP-05", tactic="Initial Access",
            status="active",
            time=datetime(2026, 2, 19, 13, 44, 0, tzinfo=timezone.utc),
            rule_name="win_admin_logon_unusual", log_source="Elastic SIEM",
            occurrence_count=1, cvss_v3=7.5, confidence=79, tactic_id="TA0001",
            assigned_to="K. Lee", priority="P2 High",
        ),
        Detection(
            id="DET-2026-00842",
            score=6.8, severity="medium",
            technique_id="T1059.001", technique_name="PowerShell",
            name="PowerShell Encoded Command Exec",
            host="WS-DEV-031", tactic="Execution",
            status="resolved",
            time=datetime(2026, 2, 19, 13, 30, 0, tzinfo=timezone.utc),
            rule_name="win_powershell_encoded", log_source="Elastic SIEM",
            occurrence_count=5, cvss_v3=6.1, confidence=72, tactic_id="TA0002",
            assigned_to="M. Park", priority="P3 Medium",
        ),
        Detection(
            id="DET-2026-00841",
            score=6.5, severity="medium",
            technique_id="T1021.001", technique_name="RDP",
            name="RDP Lateral Movement",
            host="WS-MGMT-04", tactic="Lateral Movement",
            status="investigating",
            time=datetime(2026, 2, 19, 13, 15, 0, tzinfo=timezone.utc),
            rule_name="win_rdp_lateral", log_source="Elastic SIEM",
            occurrence_count=3, cvss_v3=6.0, confidence=68, tactic_id="TA0008",
            assigned_to="J. Smith", priority="P3 Medium",
        ),
        Detection(
            id="DET-2026-00840",
            score=5.9, severity="medium",
            technique_id="T1218.011", technique_name="Rundll32",
            name="Rundll32 Proxy Execution",
            host="WS-DEV-018", tactic="Defense Evasion",
            status="resolved",
            time=datetime(2026, 2, 19, 12, 58, 0, tzinfo=timezone.utc),
            rule_name="win_rundll32_proxy", log_source="Elastic SIEM",
            occurrence_count=2, cvss_v3=5.6, confidence=65, tactic_id="TA0005",
            assigned_to="K. Lee", priority="P3 Medium",
        ),
        Detection(
            id="DET-2026-00839",
            score=5.6, severity="medium",
            technique_id="T1136.001", technique_name="Local Account",
            name="New Local Admin Account Created",
            host="SRV-JUMP-02", tactic="Persistence",
            status="active",
            time=datetime(2026, 2, 19, 12, 41, 0, tzinfo=timezone.utc),
            rule_name="win_new_local_admin", log_source="MS Sentinel",
            occurrence_count=1, cvss_v3=5.5, confidence=82, tactic_id="TA0003",
            assigned_to="M. Park", priority="P3 Medium",
        ),
        Detection(
            id="DET-2026-00838",
            score=5.2, severity="medium",
            technique_id="T1098.001", technique_name="Additional Cloud Credentials",
            name="Azure AD Credential Added",
            host="CLOUDAzure-04", tactic="Persistence",
            status="investigating",
            time=datetime(2026, 2, 19, 12, 20, 0, tzinfo=timezone.utc),
            rule_name="azure_cred_added", log_source="MS Sentinel",
            occurrence_count=1, cvss_v3=5.0, confidence=70, tactic_id="TA0003",
            assigned_to="J. Smith", priority="P3 Medium",
        ),
        Detection(
            id="DET-2026-00837",
            score=3.8, severity="low",
            technique_id="T1070.004", technique_name="File Deletion",
            name="File Deletion to Cover Tracks",
            host="WS-HR-011", tactic="Defense Evasion",
            status="resolved",
            time=datetime(2026, 2, 19, 11, 55, 0, tzinfo=timezone.utc),
            rule_name="win_file_deletion_cover", log_source="Elastic SIEM",
            occurrence_count=8, cvss_v3=3.3, confidence=55, tactic_id="TA0005",
            assigned_to="K. Lee", priority="P4 Low",
        ),
    ]
    session.add_all(detections)

    # ── Connectors ───────────────────────────────────────────────────────────
    connectors = [
        Connector(
            name="Wazuh Manager",
            connector_type="wazuh",
            config_json=json.dumps({"url": "https://wazuh.internal:55000", "username": "wazuh-wui"}),
            status="inactive",
            enabled=True,
        ),
        Connector(
            name="Zeek Network Monitor",
            connector_type="zeek",
            config_json=json.dumps({"log_dir": "/opt/zeek/logs/current"}),
            status="inactive",
            enabled=True,
        ),
        Connector(
            name="Suricata IDS",
            connector_type="suricata",
            config_json=json.dumps({"eve_file": "/var/log/suricata/eve.json"}),
            status="inactive",
            enabled=True,
        ),
    ]
    session.add_all(connectors)

    # ── Rules (Sigma) ─────────────────────────────────────────────────────────
    rules = [
        Rule(
            title="DCSync via DRSUAPI GetNCChanges",
            description="Detects DCSync attacks using DRSUAPI replication RPC call (event 4662).",
            rule_type="sigma",
            content=(
                "title: DCSync via DRSUAPI GetNCChanges\n"
                "status: stable\n"
                "level: critical\n"
                "logsource:\n"
                "    product: windows\n"
                "    service: security\n"
                "detection:\n"
                "    selection:\n"
                "        EventID: 4662\n"
                "        Properties|contains:\n"
                "            - '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'\n"
                "            - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'\n"
                "    filter:\n"
                "        SubjectUserName|endswith: '$'\n"
                "    condition: selection and not filter\n"
                "tags:\n"
                "    - attack.credential_access\n"
                "    - attack.t1003.006\n"
            ),
            status="stable",
            level="critical",
            enabled=True,
            logsource_product="windows",
            logsource_service="security",
            technique_ids=json.dumps(["T1003.006"]),
            tactic_ids=json.dumps(["TA0006"]),
            source="sigmaHQ",
            created_by="system",
        ),
        Rule(
            title="Kerberoasting SPN Enumeration",
            description="Detects Kerberoasting via suspicious TGS-REQ for service accounts (event 4769).",
            rule_type="sigma",
            content=(
                "title: Kerberoasting SPN Enumeration\n"
                "status: stable\n"
                "level: high\n"
                "logsource:\n"
                "    product: windows\n"
                "    service: security\n"
                "detection:\n"
                "    selection:\n"
                "        EventID: 4769\n"
                "        TicketOptions: '0x40810000'\n"
                "        TicketEncryptionType: '0x17'\n"
                "    filter:\n"
                "        ServiceName|endswith: '$'\n"
                "    condition: selection and not filter\n"
                "tags:\n"
                "    - attack.credential_access\n"
                "    - attack.t1558.003\n"
            ),
            status="stable",
            level="high",
            enabled=True,
            logsource_product="windows",
            logsource_service="security",
            technique_ids=json.dumps(["T1558.003"]),
            tactic_ids=json.dumps(["TA0006"]),
            source="sigmaHQ",
            created_by="system",
        ),
        Rule(
            title="PowerShell Encoded Command Execution",
            description="Detects PowerShell launched with -EncodedCommand or -enc flags to hide payloads.",
            rule_type="sigma",
            content=(
                "title: PowerShell Encoded Command Execution\n"
                "status: experimental\n"
                "level: medium\n"
                "logsource:\n"
                "    product: windows\n"
                "    category: process_creation\n"
                "detection:\n"
                "    selection:\n"
                "        Image|endswith: '\\\\powershell.exe'\n"
                "        CommandLine|contains:\n"
                "            - ' -EncodedCommand '\n"
                "            - ' -enc '\n"
                "            - ' -ec '\n"
                "    condition: selection\n"
                "tags:\n"
                "    - attack.execution\n"
                "    - attack.t1059.001\n"
            ),
            status="experimental",
            level="medium",
            enabled=True,
            logsource_product="windows",
            logsource_category="process_creation",
            technique_ids=json.dumps(["T1059.001"]),
            tactic_ids=json.dumps(["TA0002"]),
            source="sigmaHQ",
            created_by="system",
        ),
        Rule(
            title="New Local Administrator Account Created",
            description="Detects creation of a new local administrator account via net user commands.",
            rule_type="sigma",
            content=(
                "title: New Local Administrator Account Created\n"
                "status: stable\n"
                "level: medium\n"
                "logsource:\n"
                "    product: windows\n"
                "    service: security\n"
                "detection:\n"
                "    selection:\n"
                "        EventID:\n"
                "            - 4720\n"
                "            - 4732\n"
                "        TargetSid|endswith: '-544'\n"
                "    condition: selection\n"
                "tags:\n"
                "    - attack.persistence\n"
                "    - attack.t1136.001\n"
            ),
            status="stable",
            level="medium",
            enabled=True,
            logsource_product="windows",
            logsource_service="security",
            technique_ids=json.dumps(["T1136.001"]),
            tactic_ids=json.dumps(["TA0003"]),
            source="sigmaHQ",
            created_by="system",
        ),
    ]
    session.add_all(rules)

    # ── Incidents ─────────────────────────────────────────────────────────────
    incidents = [
        Incident(
            title="Active Directory Credential Theft Campaign",
            description=(
                "Coordinated credential theft campaign targeting Active Directory. "
                "DCSync attack combined with Kerberoasting indicates attacker with "
                "elevated privileges performing offline password cracking."
            ),
            severity="critical",
            status="investigating",
            priority=1,
            assigned_to="J. Smith",
            created_by="system",
            detection_ids=["DET-2026-00847", "DET-2026-00845"],
            technique_ids=["T1003.006", "T1558.003"],
            tactic_ids=["TA0006"],
            hosts=["DC-PROD-01", "SRV-AUTH-07"],
        ),
        Incident(
            title="Lateral Movement via Pass-the-Ticket and RDP",
            description=(
                "Attacker using stolen Kerberos tickets to move laterally across "
                "finance and management workstations via RDP after initial compromise."
            ),
            severity="high",
            status="new",
            priority=2,
            assigned_to="K. Lee",
            created_by="system",
            detection_ids=["DET-2026-00844", "DET-2026-00841"],
            technique_ids=["T1550.003", "T1021.001"],
            tactic_ids=["TA0008"],
            hosts=["WS-FIN-022", "WS-MGMT-04"],
        ),
        Incident(
            title="Persistence via New Local Admin Account",
            description=(
                "Threat actor established persistence by creating a new local "
                "administrator account on the jump server to maintain access."
            ),
            severity="medium",
            status="new",
            priority=3,
            assigned_to="M. Park",
            created_by="system",
            detection_ids=["DET-2026-00839"],
            technique_ids=["T1136.001"],
            tactic_ids=["TA0003"],
            hosts=["SRV-JUMP-02"],
        ),
    ]
    session.add_all(incidents)

    await session.commit()
    logger.info(
        "Database seeded with DEMO data: %d users, %d detections, %d connectors, %d rules, %d incidents",
        len(users), len(detections), len(connectors), len(rules), len(incidents),
    )
    _announce_initial_password(initial_password, generated=generated)
