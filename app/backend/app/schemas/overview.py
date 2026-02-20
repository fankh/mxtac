from pydantic import BaseModel


class KpiMetrics(BaseModel):
    total_detections: int
    total_detections_delta_pct: float
    critical_alerts: int
    critical_alerts_new_today: int
    attack_coverage_pct: float
    attack_covered: int
    attack_total: int
    attack_coverage_delta: int
    mttd_minutes: float
    mttd_delta_minutes: float
    integrations_active: int
    integrations_total: int
    sigma_rules_active: int
    sigma_rules_critical: int
    sigma_rules_high: int
    sigma_rules_deployed_this_week: int
    # Incident SLA metrics (from real DB data)
    open_incidents_count: int = 0
    mttr_minutes: float | None = None


class TimelinePoint(BaseModel):
    date: str  # "Feb 13"
    critical: int
    high: int
    medium: int
    total: int


class TacticBar(BaseModel):
    tactic: str
    count: int
    trend_pct: float


class HeatCell(BaseModel):
    tactic: str
    covered: int
    total: int

    @property
    def opacity(self) -> float:
        if self.total == 0:
            return 0.0
        ratio = self.covered / self.total
        # scale 0→0.10, 1→0.85
        return round(0.10 + ratio * 0.75, 2)


class HeatRow(BaseModel):
    row: int
    cells: list[HeatCell]


class IntegrationStatus(BaseModel):
    id: str
    name: str
    status: str  # "connected" | "warning" | "disabled"
    metric: str
    detail: str | None = None
