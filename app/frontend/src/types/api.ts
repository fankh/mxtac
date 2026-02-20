// ── Shared ────────────────────────────────────────────────────────────────────

export interface Pagination {
  page: number
  page_size: number
  total: number
  total_pages: number
}

export interface PaginatedResponse<T> {
  items: T[]
  pagination: Pagination
}

// ── Overview ──────────────────────────────────────────────────────────────────

export interface KpiMetrics {
  total_detections: number
  total_detections_delta_pct: number
  critical_alerts: number
  critical_alerts_new_today: number
  attack_coverage_pct: number
  attack_covered: number
  attack_total: number
  attack_coverage_delta: number
  mttd_minutes: number
  mttd_delta_minutes: number
  integrations_active: number
  integrations_total: number
  sigma_rules_active: number
  sigma_rules_critical: number
  sigma_rules_high: number
  sigma_rules_deployed_this_week: number
}

export interface TimelinePoint {
  date: string
  critical: number
  high: number
  medium: number
  total: number
}

export interface TacticBar {
  tactic: string
  count: number
  trend_pct: number
}

export interface HeatCell {
  tactic: string
  covered: number
  total: number
  opacity: number
}

export interface HeatRow {
  technique_id: string
  row: number
  cells: HeatCell[]
}

export interface IntegrationStatus {
  id: string
  name: string
  status: 'connected' | 'warning' | 'disabled'
  metric: string
  detail?: string
}

// ── Detections ────────────────────────────────────────────────────────────────

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low'
export type DetectionStatus = 'active' | 'investigating' | 'resolved' | 'false_positive'

export interface Detection {
  id: string
  score: number
  severity: SeverityLevel
  technique_id: string
  technique_name: string
  name: string
  host: string
  tactic: string
  status: DetectionStatus
  time: string
  // Detail fields
  user?: string
  process?: string
  rule_name?: string
  log_source?: string
  event_id?: string
  occurrence_count?: number
  description?: string
  cvss_v3?: number
  confidence?: number
  tactic_id?: string
  related_technique_ids: string[]
  assigned_to?: string
  priority?: string
}

export interface DetectionUpdate {
  status?: DetectionStatus
  assigned_to?: string
  priority?: string
}
