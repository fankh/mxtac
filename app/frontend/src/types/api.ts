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

// ── Events ────────────────────────────────────────────────────────────────────

export interface EventFilter {
  field: string
  operator: 'eq' | 'ne' | 'contains' | 'gt' | 'lt' | 'gte' | 'lte'
  value: string | number | boolean
}

export interface EventItem {
  id: string
  event_uid?: string
  time: string
  class_name?: string
  class_uid?: number
  severity_id?: number
  src_ip?: string
  dst_ip?: string
  hostname?: string
  username?: string
  process_hash?: string
  source?: string
  summary?: string
  [key: string]: unknown
}

export interface SearchRequest {
  query?: string
  filters?: EventFilter[]
  time_from?: string
  time_to?: string
  size?: number
  from_?: number
}

export interface SearchResponse {
  total: number
  items: EventItem[]
  from_: number
  size: number
  backend: 'opensearch' | 'postgres'
}

export interface AggregationBucket {
  key: string
  count: number
}

export interface AggregationRequest {
  field?: string
  agg_type?: 'terms' | 'date_histogram'
  interval?: string
  size?: number
  time_from?: string
  time_to?: string
}

export interface AggregationResponse {
  agg_type?: string
  interval?: string
  field?: string
  buckets: AggregationBucket[]
  backend?: string
}

export interface EntityTimeline {
  entity_type: string
  entity_value: string
  total: number
  events: EventItem[]
}

// ── Assets ────────────────────────────────────────────────────────────────────

export type AssetType = 'server' | 'workstation' | 'network' | 'cloud' | 'container'
export type OsFamily  = 'linux' | 'windows' | 'macos' | 'other'

export interface Asset {
  id: number
  hostname: string
  ip_addresses: string[]
  os: string | null
  os_family: OsFamily | null
  asset_type: AssetType
  criticality: number          // 1 (low) – 5 (mission-critical)
  owner: string | null
  department: string | null
  location: string | null
  tags: string[]
  is_active: boolean
  last_seen_at: string | null
  agent_id: string | null
  detection_count: number
  incident_count: number
  created_at: string
  updated_at: string
}

export interface AssetCreate {
  hostname: string
  ip_addresses?: string[]
  os?: string | null
  os_family?: OsFamily | null
  asset_type: AssetType
  criticality?: number
  owner?: string | null
  department?: string | null
  location?: string | null
  tags?: string[]
  is_active?: boolean
  agent_id?: string | null
}

export interface AssetStats {
  total: number
  by_type: Record<string, number>
  by_criticality: Record<string, number>
  by_os_family: Record<string, number>
}

export interface BulkAssetResult {
  created: number
  skipped: number
}

// ── Saved Hunt Queries ────────────────────────────────────────────────────────

export interface SavedQueryFilter {
  field: string
  operator: string
  value: string | number | boolean
}

export interface SavedQuery {
  id: string
  name: string
  description: string | null
  query: string | null
  filters: SavedQueryFilter[]
  time_from: string
  time_to: string
  created_by: string
  created_at: string
  updated_at: string
}

export interface SavedQueryCreate {
  name: string
  description?: string
  query?: string
  filters?: SavedQueryFilter[]
  time_from?: string
  time_to?: string
}

export interface SavedQueryUpdate {
  name?: string
  description?: string
  query?: string
  filters?: SavedQueryFilter[]
  time_from?: string
  time_to?: string
}

// ── Incidents ─────────────────────────────────────────────────────────────────

export type IncidentStatus = 'new' | 'investigating' | 'contained' | 'resolved' | 'closed'
export type NoteType = 'comment' | 'status_change' | 'evidence'

export interface IncidentNote {
  id: string
  author: string
  content: string
  note_type: NoteType
  created_at: string
}

export interface Incident {
  id: number
  title: string
  description: string | null
  severity: SeverityLevel
  status: IncidentStatus
  priority: number
  assigned_to: string | null
  created_by: string
  detection_ids: string[]
  technique_ids: string[]
  tactic_ids: string[]
  hosts: string[]
  ttd_seconds: number | null
  ttr_seconds: number | null
  closed_at: string | null
  created_at: string
  updated_at: string
}

export interface IncidentDetail extends Incident {
  detections: Detection[]
  notes: IncidentNote[]
  duration_seconds: number
}

export interface IncidentCreate {
  title: string
  description?: string | null
  severity: SeverityLevel
  detection_ids?: string[]
  assigned_to?: string | null
}

export interface IncidentUpdate {
  title?: string | null
  description?: string | null
  severity?: SeverityLevel | null
  status?: IncidentStatus | null
  priority?: number | null
  assigned_to?: string | null
  detection_ids?: string[] | null
}

export interface IncidentMetrics {
  total_incidents: Record<string, number>
  mttr_seconds: number | null
  mttd_seconds: number | null
  open_incidents_count: number
  incidents_by_severity: Record<string, number>
  incidents_this_week: number
  incidents_this_month: number
  from_date: string
  to_date: string
}

// ── Coverage Trend ────────────────────────────────────────────────────────────

export interface CoverageTrendPoint {
  date: string          // ISO-8601 YYYY-MM-DD
  coverage_pct: number
  covered_count: number
  total_count: number
}

export interface CoverageTrend {
  points: CoverageTrendPoint[]
  days: number
}

// ── Threat Intel / IOCs ───────────────────────────────────────────────────────

export type IOCType = 'ip' | 'domain' | 'hash_md5' | 'hash_sha256' | 'url' | 'email'

export interface IOC {
  id: number
  ioc_type: IOCType
  value: string
  source: string
  confidence: number
  severity: SeverityLevel
  description: string | null
  tags: string[]
  first_seen: string
  last_seen: string
  expires_at: string | null
  is_active: boolean
  hit_count: number
  last_hit_at: string | null
  created_at: string
  updated_at: string
}

export interface IOCCreate {
  ioc_type: IOCType
  value: string
  source: string
  confidence?: number
  severity: SeverityLevel
  description?: string | null
  tags?: string[]
  first_seen: string
  last_seen: string
  expires_at?: string | null
  is_active?: boolean
}

export interface IOCUpdate {
  confidence?: number | null
  severity?: SeverityLevel | null
  description?: string | null
  tags?: string[] | null
  last_seen?: string | null
  expires_at?: string | null
  is_active?: boolean | null
}

export interface IOCStats {
  total: number
  by_type: Record<string, number>
  by_source: Record<string, number>
  active: number
  expired: number
  total_hits: number
}

export interface IOCBulkImportResult {
  created: number
  skipped: number
}

// ── Reports ───────────────────────────────────────────────────────────────────

export type ReportStatus = 'generating' | 'ready' | 'failed'
export type ReportFormat = 'json' | 'csv'
export type ReportTemplate =
  | 'executive_summary'
  | 'detection_report'
  | 'incident_report'
  | 'coverage_report'
  | 'compliance_summary'

export interface Report {
  id: string
  template_type: ReportTemplate
  status: ReportStatus
  format: ReportFormat
  created_by: string
  created_at: string
  updated_at: string
  /** Only present on detail endpoint (GET /reports/{id}), not the list */
  params_json?: {
    from_date: string
    to_date: string
    [key: string]: unknown
  }
  error?: string | null
}

export interface ReportGenerateRequest {
  template_type: ReportTemplate
  from_date: string   // ISO datetime string, e.g. "2025-01-01T00:00:00Z"
  to_date: string     // ISO datetime string
  format?: ReportFormat
  extra_params?: Record<string, unknown> | null
}

export interface ReportGenerateResponse {
  report_id: string
  status: 'generating'
}

export interface ReportSchedule {
  id: string
  name: string
  template_type: ReportTemplate
  format: ReportFormat
  cron_expression: string
  enabled: boolean
  last_run_at: string | null
  next_run_at: string | null
  created_by: string
  created_at: string
}

export interface ReportScheduleCreate {
  name: string
  template_type: ReportTemplate
  format: ReportFormat
  cron_expression: string
  enabled?: boolean
}

export interface ReportScheduleUpdate {
  name?: string
  enabled?: boolean
  cron_expression?: string
}

// ── Audit Logs ────────────────────────────────────────────────────────────────

export interface AuditLogEntry {
  id: string
  timestamp: string
  actor: string
  action: string
  resource_type: string
  resource_id: string | null
  details: Record<string, unknown> | null
  request_ip: string | null
  request_method: string | null
  request_path: string | null
  user_agent: string | null
}
