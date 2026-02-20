"""
Mock data service — provides realistic in-memory data for all API endpoints.
Replace with real DB queries / OpenSearch calls in production.
"""
from datetime import datetime, timezone
from ..schemas.detection import Detection
from ..schemas.overview import (
    KpiMetrics, TimelinePoint, TacticBar, HeatCell, HeatRow, IntegrationStatus
)

# ── Detections ────────────────────────────────────────────────────────────────

DETECTIONS: list[Detection] = [
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
        description=(
            "DCSync attack detected. Account CORP\\svc-backup invoked DRSUAPI "
            "replication from DC-PROD-01. Consistent with credential dumping via "
            "DCSync (Mimikatz). Investigate service account immediately."
        ),
        cvss_v3=8.8, confidence=96, tactic_id="TA0006",
        related_technique_ids=["T1558.003", "T1550.003", "T1078.002"],
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
        related_technique_ids=["T1055.012", "T1055.002"],
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
        related_technique_ids=["T1003.006", "T1550.003"],
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
        related_technique_ids=["T1558.003", "T1078.002"],
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
        related_technique_ids=["T1550.003"],
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
        related_technique_ids=["T1059.003"],
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
        related_technique_ids=["T1078.002"],
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
        related_technique_ids=["T1059.001"],
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
        related_technique_ids=["T1098.001"],
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
        related_technique_ids=["T1136.001"],
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
        related_technique_ids=[],
        assigned_to="K. Lee", priority="P4 Low",
    ),
]

# ── Overview data ─────────────────────────────────────────────────────────────

KPI = KpiMetrics(
    total_detections=2847,
    total_detections_delta_pct=12.4,
    critical_alerts=47,
    critical_alerts_new_today=8,
    attack_coverage_pct=73.0,
    attack_covered=187,
    attack_total=256,
    attack_coverage_delta=6,
    mttd_minutes=4.2,
    mttd_delta_minutes=-0.8,
    integrations_active=7,
    integrations_total=8,
    sigma_rules_active=1204,
    sigma_rules_critical=312,
    sigma_rules_high=460,
    sigma_rules_deployed_this_week=18,
)

TIMELINE: list[TimelinePoint] = [
    TimelinePoint(date="Feb 13", critical=52, high=180, medium=210, total=442),
    TimelinePoint(date="Feb 14", critical=61, high=195, medium=220, total=476),
    TimelinePoint(date="Feb 15", critical=48, high=170, medium=205, total=423),
    TimelinePoint(date="Feb 16", critical=79, high=205, medium=235, total=519),
    TimelinePoint(date="Feb 17", critical=187, high=220, medium=215, total=622),
    TimelinePoint(date="Feb 18", critical=69, high=190, medium=218, total=477),
    TimelinePoint(date="Feb 19", critical=83, high=198, medium=206, total=487),
]

TACTICS: list[TacticBar] = [
    TacticBar(tactic="Execution",          count=634, trend_pct=18.0),
    TacticBar(tactic="Defense Evasion",    count=547, trend_pct=9.0),
    TacticBar(tactic="Credential Access",  count=461, trend_pct=5.0),
    TacticBar(tactic="Lateral Movement",   count=382, trend_pct=22.0),
    TacticBar(tactic="Persistence",        count=324, trend_pct=-3.0),
    TacticBar(tactic="Command & Control",  count=284, trend_pct=0.0),
]

TACTIC_LABELS = ["RECON", "RES", "INIT", "EXEC", "PERS", "PRIV", "DEF-E", "CRED", "DISC"]

HEATMAP: list[HeatRow] = [
    HeatRow(technique_id="T1059", row=0, cells=[
        HeatCell(tactic="RECON", covered=4, total=9),
        HeatCell(tactic="RES",   covered=3, total=6),
        HeatCell(tactic="INIT",  covered=9, total=9),
        HeatCell(tactic="EXEC",  covered=12, total=14),
        HeatCell(tactic="PERS",  covered=7, total=12),
        HeatCell(tactic="PRIV",  covered=6, total=11),
        HeatCell(tactic="DEF-E", covered=14, total=17),
        HeatCell(tactic="CRED",  covered=5, total=14),
        HeatCell(tactic="DISC",  covered=8, total=13),
    ]),
    HeatRow(technique_id="T1003", row=1, cells=[
        HeatCell(tactic="RECON", covered=6, total=9),
        HeatCell(tactic="RES",   covered=2, total=6),
        HeatCell(tactic="INIT",  covered=8, total=9),
        HeatCell(tactic="EXEC",  covered=13, total=14),
        HeatCell(tactic="PERS",  covered=5, total=12),
        HeatCell(tactic="PRIV",  covered=9, total=11),
        HeatCell(tactic="DEF-E", covered=10, total=17),
        HeatCell(tactic="CRED",  covered=6, total=14),
        HeatCell(tactic="DISC",  covered=9, total=13),
    ]),
    HeatRow(technique_id="T1021", row=2, cells=[
        HeatCell(tactic="RECON", covered=2, total=9),
        HeatCell(tactic="RES",   covered=1, total=6),
        HeatCell(tactic="INIT",  covered=7, total=9),
        HeatCell(tactic="EXEC",  covered=11, total=14),
        HeatCell(tactic="PERS",  covered=8, total=12),
        HeatCell(tactic="PRIV",  covered=4, total=11),
        HeatCell(tactic="DEF-E", covered=15, total=17),
        HeatCell(tactic="CRED",  covered=8, total=14),
        HeatCell(tactic="DISC",  covered=6, total=13),
    ]),
    HeatRow(technique_id="T1078", row=3, cells=[
        HeatCell(tactic="RECON", covered=1, total=9),
        HeatCell(tactic="RES",   covered=3, total=6),
        HeatCell(tactic="INIT",  covered=6, total=9),
        HeatCell(tactic="EXEC",  covered=9, total=14),
        HeatCell(tactic="PERS",  covered=4, total=12),
        HeatCell(tactic="PRIV",  covered=7, total=11),
        HeatCell(tactic="DEF-E", covered=12, total=17),
        HeatCell(tactic="CRED",  covered=3, total=14),
        HeatCell(tactic="DISC",  covered=7, total=13),
    ]),
]

INTEGRATIONS: list[IntegrationStatus] = [
    IntegrationStatus(id="elastic",      name="Elastic SIEM",  status="connected", metric="14,204 events/min"),
    IntegrationStatus(id="sentinel",     name="MS Sentinel",   status="connected", metric="8,901 events/min"),
    IntegrationStatus(id="splunk",       name="Splunk",        status="warning",   metric="Auth error", detail="Token expired"),
    IntegrationStatus(id="crowdstrike",  name="CrowdStrike",   status="connected", metric="EDR: 2,102 hosts"),
    IntegrationStatus(id="tenable",      name="Tenable.io",    status="connected", metric="VM: 4,780 assets"),
    IntegrationStatus(id="okta",         name="Okta",          status="connected", metric="IAM: 12,400 users"),
    IntegrationStatus(id="paloalto",     name="Palo Alto FW",  status="connected", metric="NGFW: 6 devices"),
    IntegrationStatus(id="wiz",          name="Wiz CSPM",      status="disabled",  metric="Not configured"),
]
