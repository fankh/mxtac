"""Report generation engine — produces structured, JSON-serializable report data.

Each template queries the DB via the repository layer and returns a plain dict.
Rendering to PDF/CSV is out of scope here and handled by the caller.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.detection import Detection
from ..models.incident import Incident
from ..repositories.detection_repo import DetectionRepo
from ..repositories.incident_repo import IncidentRepo
from ..repositories.rule_repo import RuleRepo
from .compliance_mapper import ComplianceMapper

# ---------------------------------------------------------------------------
# Static compliance framework mappings (tactic → control IDs)
# ---------------------------------------------------------------------------

_NIST_TACTIC_MAP: dict[str, list[str]] = {
    "Reconnaissance":       ["CA-2", "RA-3", "SI-4"],
    "Resource Development": ["SC-7", "SI-4"],
    "Initial Access":       ["AC-3", "SC-7", "SI-3"],
    "Execution":            ["CM-7", "SI-2", "SI-3"],
    "Persistence":          ["AC-2", "CM-6", "SI-7"],
    "Privilege Escalation": ["AC-6", "IA-2", "IA-8"],
    "Defense Evasion":      ["AU-2", "AU-9", "SI-4"],
    "Credential Access":    ["AC-2", "IA-5", "SC-28"],
    "Discovery":            ["AC-3", "AU-12", "CM-2"],
    "Lateral Movement":     ["AC-4", "SC-7", "SC-8"],
    "Collection":           ["AC-3", "MP-2", "SC-28"],
    "Command and Control":  ["SC-7", "SI-4", "SC-8"],
    "Exfiltration":         ["SC-7", "SC-28"],
    "Impact":               ["CP-9", "SI-7", "SA-10"],
}

_PCI_TACTIC_MAP: dict[str, list[str]] = {
    "Reconnaissance":       ["Req-11.4"],
    "Resource Development": ["Req-6.3"],
    "Initial Access":       ["Req-1.3", "Req-6.3"],
    "Execution":            ["Req-6.3", "Req-6.4"],
    "Persistence":          ["Req-8.2", "Req-10.2"],
    "Privilege Escalation": ["Req-7.1", "Req-8.3"],
    "Defense Evasion":      ["Req-10.5", "Req-10.7"],
    "Credential Access":    ["Req-8.4", "Req-8.6"],
    "Discovery":            ["Req-11.5"],
    "Lateral Movement":     ["Req-1.3", "Req-7.1"],
    "Collection":           ["Req-9.8", "Req-3.4"],
    "Command and Control":  ["Req-1.3", "Req-11.4"],
    "Exfiltration":         ["Req-4.2", "Req-9.8"],
    "Impact":               ["Req-6.5", "Req-12.10"],
}

# Max detections fetched per report (prevents unbounded memory use)
_DETECTION_PAGE_SIZE = 500
# Max incidents fetched per report
_INCIDENT_PAGE_SIZE = 200


class ReportEngine:
    """Generates structured report data for various report templates.

    Each ``generate`` call is read-only: it queries the database through the
    repository layer and returns a JSON-serializable dict.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def generate(
        self,
        template_type: str,
        params: dict[str, Any],
    ) -> dict[str, Any]:
        """Generate a report for the given template type.

        Required params for all templates:
            from_date (datetime) — start of the reporting period (UTC)
            to_date   (datetime) — end of the reporting period (UTC)

        Optional per-template params are documented on each template method.

        Returns a JSON-serializable dict. Raises ``ValueError`` for unknown
        template types or missing / invalid required params.
        """
        from_date, to_date = _parse_time_range(params)
        prev_from_date = from_date - (to_date - from_date)

        dispatch: dict[str, Any] = {
            "executive_summary":  self._executive_summary,
            "detection_report":   self._detection_report,
            "incident_report":    self._incident_report,
            "coverage_report":    self._coverage_report,
            "compliance_summary": self._compliance_summary,
        }

        handler = dispatch.get(template_type)
        if handler is None:
            valid = ", ".join(sorted(dispatch))
            raise ValueError(
                f"Unknown template type {template_type!r}. Valid: {valid}"
            )

        return await handler(
            from_date=from_date,
            to_date=to_date,
            prev_from_date=prev_from_date,
            params=params,
        )

    # ------------------------------------------------------------------
    # Template: executive_summary
    # ------------------------------------------------------------------

    async def _executive_summary(
        self,
        *,
        from_date: datetime,
        to_date: datetime,
        prev_from_date: datetime,
        params: dict[str, Any],
    ) -> dict[str, Any]:
        """High-level KPIs: top risks, incident counts, MTTR."""
        today_start = datetime.now(timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0
        )

        det_kpis, incident_metrics, coverage, tactics = await asyncio.gather(
            DetectionRepo.get_kpi_counts(
                self._session,
                from_date=from_date,
                to_date=to_date,
                prev_from_date=prev_from_date,
                today_start=today_start,
            ),
            IncidentRepo.get_metrics(
                self._session,
                from_date=from_date,
                to_date=to_date,
            ),
            DetectionRepo.get_coverage_summary(self._session),
            DetectionRepo.get_tactics(
                self._session,
                from_date=from_date,
                to_date=to_date,
                prev_from_date=prev_from_date,
            ),
        )

        total_current = det_kpis["total_current"]
        total_prev = det_kpis["total_prev"]
        detection_trend_pct = (
            round((total_current - total_prev) / total_prev * 100, 1)
            if total_prev > 0
            else 0.0
        )

        avg_ttr_seconds = incident_metrics.get("avg_ttr")
        mttr_hours = (
            round(avg_ttr_seconds / 3600, 1) if avg_ttr_seconds is not None else None
        )

        return {
            "template": "executive_summary",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "period": {
                "from": from_date.isoformat(),
                "to": to_date.isoformat(),
            },
            "kpis": {
                "total_detections": total_current,
                "critical_detections": det_kpis["critical"],
                "critical_today": det_kpis["critical_today"],
                "detection_trend_pct": detection_trend_pct,
                "total_incidents": sum(incident_metrics["status_counts"].values()),
                "open_incidents": incident_metrics["open_count"],
                "mttr_hours": mttr_hours,
                "coverage_pct": coverage["coverage_pct"] if coverage else None,
            },
            "top_risks": tactics[:5],
            "incident_severity_breakdown": incident_metrics["severity_counts"],
            "incident_status_breakdown": incident_metrics["status_counts"],
        }

    # ------------------------------------------------------------------
    # Template: detection_report
    # ------------------------------------------------------------------

    async def _detection_report(
        self,
        *,
        from_date: datetime,
        to_date: datetime,
        prev_from_date: datetime,
        params: dict[str, Any],
    ) -> dict[str, Any]:
        """All detections in time range, grouped by severity and tactic."""
        # Direct query with time-range filter (DetectionRepo.list lacks this)
        det_q = (
            select(Detection)
            .where(Detection.time >= from_date)
            .where(Detection.time <= to_date)
            .order_by(Detection.time.desc())
            .limit(_DETECTION_PAGE_SIZE)
        )
        total_q = (
            select(func.count())
            .select_from(Detection)
            .where(Detection.time >= from_date)
            .where(Detection.time <= to_date)
        )

        det_result, total_in_range, timeline, tactic_summary = await asyncio.gather(
            self._session.execute(det_q),
            self._session.scalar(total_q),
            DetectionRepo.get_timeline(
                self._session, from_date=from_date, to_date=to_date
            ),
            DetectionRepo.get_tactics(
                self._session,
                from_date=from_date,
                to_date=to_date,
                prev_from_date=prev_from_date,
            ),
        )

        detections = list(det_result.scalars().all())
        total_in_range = total_in_range or 0

        _sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        by_severity: dict[str, list[dict]] = {}
        by_tactic: dict[str, list[dict]] = {}

        for det in detections:
            d = _detection_to_dict(det)
            by_severity.setdefault(det.severity or "unknown", []).append(d)
            by_tactic.setdefault(det.tactic or "unknown", []).append(d)

        return {
            "template": "detection_report",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "period": {
                "from": from_date.isoformat(),
                "to": to_date.isoformat(),
            },
            "summary": {
                "total": total_in_range,
                "shown": len(detections),
                "truncated": total_in_range > _DETECTION_PAGE_SIZE,
            },
            "by_severity": {
                sev: {"count": len(items), "detections": items}
                for sev, items in sorted(
                    by_severity.items(),
                    key=lambda kv: _sev_order.get(kv[0], 4),
                )
            },
            "by_tactic": {
                tactic: {"count": len(items), "detections": items}
                for tactic, items in sorted(
                    by_tactic.items(), key=lambda kv: -len(kv[1])
                )
            },
            "tactic_summary": tactic_summary,
            "timeline": timeline,
        }

    # ------------------------------------------------------------------
    # Template: incident_report
    # ------------------------------------------------------------------

    async def _incident_report(
        self,
        *,
        from_date: datetime,
        to_date: datetime,
        prev_from_date: datetime,
        params: dict[str, Any],
    ) -> dict[str, Any]:
        """Incident details with timeline and linked detections."""
        inc_q = (
            select(Incident)
            .where(Incident.created_at >= from_date)
            .where(Incident.created_at <= to_date)
            .order_by(Incident.created_at.desc())
            .limit(_INCIDENT_PAGE_SIZE)
        )
        total_q = (
            select(func.count())
            .select_from(Incident)
            .where(Incident.created_at >= from_date)
            .where(Incident.created_at <= to_date)
        )

        inc_result, total_in_range, metrics = await asyncio.gather(
            self._session.execute(inc_q),
            self._session.scalar(total_q),
            IncidentRepo.get_metrics(
                self._session, from_date=from_date, to_date=to_date
            ),
        )

        incidents_raw = list(inc_result.scalars().all())
        total_in_range = total_in_range or 0

        avg_ttr_s = metrics.get("avg_ttr")
        avg_ttd_s = metrics.get("avg_ttd")
        mttr_hours = round(avg_ttr_s / 3600, 1) if avg_ttr_s is not None else None
        mttd_hours = round(avg_ttd_s / 3600, 1) if avg_ttd_s is not None else None

        incidents = [_incident_to_dict(inc) for inc in incidents_raw]

        return {
            "template": "incident_report",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "period": {
                "from": from_date.isoformat(),
                "to": to_date.isoformat(),
            },
            "summary": {
                "total": total_in_range,
                "shown": len(incidents),
                "truncated": total_in_range > _INCIDENT_PAGE_SIZE,
                "open": metrics["open_count"],
                "mttr_hours": mttr_hours,
                "mttd_hours": mttd_hours,
                "status_breakdown": metrics["status_counts"],
                "severity_breakdown": metrics["severity_counts"],
            },
            "incidents": incidents,
        }

    # ------------------------------------------------------------------
    # Template: coverage_report
    # ------------------------------------------------------------------

    async def _coverage_report(
        self,
        *,
        from_date: datetime,
        to_date: datetime,
        prev_from_date: datetime,
        params: dict[str, Any],
    ) -> dict[str, Any]:
        """ATT&CK coverage %, gaps, rules by technique."""
        coverage_gaps, coverage_by_ds, navigator_techniques, heatmap = (
            await asyncio.gather(
                RuleRepo.get_coverage_gaps(self._session),
                RuleRepo.get_coverage_by_datasource(self._session),
                RuleRepo.get_navigator_techniques(self._session),
                DetectionRepo.get_heatmap(self._session),
            )
        )

        return {
            "template": "coverage_report",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "period": {
                "from": from_date.isoformat(),
                "to": to_date.isoformat(),
            },
            "overall": {
                "coverage_pct": coverage_gaps["coverage_pct"],
                "covered_count": coverage_gaps["covered_count"],
                "total_count": coverage_gaps["total_count"],
                "gap_count": coverage_gaps["gap_count"],
            },
            "coverage_by_datasource": coverage_by_ds,
            "uncovered_techniques": coverage_gaps["uncovered_techniques"],
            "rules_by_technique": navigator_techniques,
            "heatmap": heatmap,
        }

    # ------------------------------------------------------------------
    # Template: compliance_summary
    # ------------------------------------------------------------------

    async def _compliance_summary(
        self,
        *,
        from_date: datetime,
        to_date: datetime,
        prev_from_date: datetime,
        params: dict[str, Any],
    ) -> dict[str, Any]:
        """Controls mapped to detections for NIST 800-53 and/or PCI-DSS.

        Optional param:
            framework (str) — "nist" | "pci_dss" | "both" (default: "both")

        Output includes both:
          - Detection-count based mapping (nist_800_53, pci_dss) — how many
            detections occurred per control, derived from tactic counts.
          - Technique-coverage matrix (technique_coverage) — which controls are
            covered by active Sigma rules, derived from ComplianceMapper.
        """
        framework = params.get("framework", "both")
        if framework not in ("nist", "pci_dss", "both"):
            raise ValueError(
                f"Invalid framework {framework!r}. Valid: nist, pci_dss, both"
            )

        # Build coroutines for technique-level coverage (ComplianceMapper)
        mapper = ComplianceMapper(self._session)
        if framework == "nist":
            mapper_coros = [mapper.get_compliance_status("nist")]
        elif framework == "pci_dss":
            mapper_coros = [mapper.get_compliance_status("pci-dss")]
        else:  # both
            mapper_coros = [
                mapper.get_compliance_status("nist"),
                mapper.get_compliance_status("pci-dss"),
            ]

        results = await asyncio.gather(
            DetectionRepo.get_tactics(
                self._session,
                from_date=from_date,
                to_date=to_date,
                prev_from_date=prev_from_date,
            ),
            DetectionRepo.get_coverage_summary(self._session),
            *mapper_coros,
        )

        tactic_counts_raw = results[0]
        coverage = results[1]
        mapper_results = results[2:]

        tactic_counts = {row["tactic"]: row["count"] for row in tactic_counts_raw}

        nist_controls = (
            _build_nist_mapping(tactic_counts)
            if framework in ("nist", "both")
            else None
        )
        pci_controls = (
            _build_pci_mapping(tactic_counts)
            if framework in ("pci_dss", "both")
            else None
        )

        # Technique-coverage matrix from ComplianceMapper
        if framework == "nist":
            technique_coverage = {"nist": mapper_results[0]}
        elif framework == "pci_dss":
            technique_coverage = {"pci_dss": mapper_results[0]}
        else:
            technique_coverage = {
                "nist": mapper_results[0],
                "pci_dss": mapper_results[1],
            }

        return {
            "template": "compliance_summary",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "period": {
                "from": from_date.isoformat(),
                "to": to_date.isoformat(),
            },
            "framework": framework,
            "coverage_context": coverage,
            "nist_800_53": nist_controls,
            "pci_dss": pci_controls,
            "technique_coverage": technique_coverage,
        }


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _parse_time_range(params: dict[str, Any]) -> tuple[datetime, datetime]:
    """Validate and return (from_date, to_date) from params as UTC datetimes."""
    from_date = params.get("from_date")
    to_date = params.get("to_date")

    if from_date is None or to_date is None:
        raise ValueError("from_date and to_date are required parameters")
    if not isinstance(from_date, datetime):
        raise ValueError("from_date must be a datetime object")
    if not isinstance(to_date, datetime):
        raise ValueError("to_date must be a datetime object")
    if from_date > to_date:
        raise ValueError("from_date must not be after to_date")

    if from_date.tzinfo is None:
        from_date = from_date.replace(tzinfo=timezone.utc)
    if to_date.tzinfo is None:
        to_date = to_date.replace(tzinfo=timezone.utc)

    return from_date, to_date


def _detection_to_dict(det: Detection) -> dict[str, Any]:
    return {
        "id": det.id,
        "name": det.name,
        "severity": det.severity,
        "tactic": det.tactic,
        "technique_id": det.technique_id,
        "technique_name": det.technique_name,
        "host": det.host,
        "user": det.user,
        "time": det.time.isoformat() if det.time else None,
        "status": det.status,
        "score": det.score,
        "rule_name": det.rule_name,
    }


def _incident_to_dict(inc: Incident) -> dict[str, Any]:
    return {
        "id": inc.id,
        "title": inc.title,
        "description": inc.description,
        "severity": inc.severity,
        "status": inc.status,
        "priority": inc.priority,
        "assigned_to": inc.assigned_to,
        "created_by": inc.created_by,
        "created_at": inc.created_at.isoformat() if inc.created_at else None,
        "closed_at": inc.closed_at.isoformat() if inc.closed_at else None,
        "ttd_seconds": inc.ttd_seconds,
        "ttr_seconds": inc.ttr_seconds,
        "detection_ids": inc.detection_ids or [],
        "technique_ids": inc.technique_ids or [],
        "tactic_ids": inc.tactic_ids or [],
        "hosts": inc.hosts or [],
        "timeline": _build_incident_timeline(inc),
    }


def _build_incident_timeline(inc: Incident) -> list[dict[str, Any]]:
    """Chronological timeline from lifecycle events and notes."""
    events: list[dict[str, Any]] = []

    if inc.created_at:
        events.append({
            "timestamp": inc.created_at.isoformat(),
            "event": "created",
            "detail": f"Incident created with severity={inc.severity}",
        })

    for note in (inc.notes or []):
        if isinstance(note, dict) and note.get("created_at"):
            events.append({
                "timestamp": note["created_at"],
                "event": "note",
                "author": note.get("author", "unknown"),
                "detail": note.get("content", ""),
            })

    if inc.closed_at:
        events.append({
            "timestamp": inc.closed_at.isoformat(),
            "event": "closed",
            "detail": f"Incident closed with status={inc.status}",
        })

    events.sort(key=lambda x: x["timestamp"])
    return events


def _build_nist_mapping(tactic_counts: dict[str, int]) -> list[dict[str, Any]]:
    """Map tactic detection counts to NIST 800-53 controls."""
    control_map: dict[str, dict[str, Any]] = {}

    for tactic, count in tactic_counts.items():
        for control_id in _NIST_TACTIC_MAP.get(tactic, []):
            if control_id not in control_map:
                control_map[control_id] = {
                    "control_id": control_id,
                    "detection_count": 0,
                    "tactics": [],
                }
            control_map[control_id]["detection_count"] += count
            if tactic not in control_map[control_id]["tactics"]:
                control_map[control_id]["tactics"].append(tactic)

    return sorted(control_map.values(), key=lambda x: -x["detection_count"])


def _build_pci_mapping(tactic_counts: dict[str, int]) -> list[dict[str, Any]]:
    """Map tactic detection counts to PCI-DSS requirements."""
    req_map: dict[str, dict[str, Any]] = {}

    for tactic, count in tactic_counts.items():
        for req_id in _PCI_TACTIC_MAP.get(tactic, []):
            if req_id not in req_map:
                req_map[req_id] = {
                    "requirement": req_id,
                    "detection_count": 0,
                    "tactics": [],
                }
            req_map[req_id]["detection_count"] += count
            if tactic not in req_map[req_id]["tactics"]:
                req_map[req_id]["tactics"].append(tactic)

    return sorted(req_map.values(), key=lambda x: -x["detection_count"])
