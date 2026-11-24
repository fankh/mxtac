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
  /** null until an incident has time-to-detect data */
  mttd_minutes: number | null
  mttd_delta_minutes: number | null
  integrations_active: number
  integrations_total: number
  sigma_rules_active: number
  sigma_rules_critical: number
  sigma_rules_high: number
  sigma_rules_deployed_this_week: number
  open_incidents_count: number
  /** null until an incident has been resolved */
  mttr_minutes: number | null
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
  // Detail fields (the backend sends null when a value is not set)
  user?: string | null
  process?: string | null
  rule_name?: string | null
  log_source?: string | null
  event_id?: string | null
  occurrence_count?: number | null
  description?: string | null
  cvss_v3?: number | null
  confidence?: number | null
  tactic_id?: string | null
  related_technique_ids?: string[]
  assigned_to?: string | null
  priority?: string | null
}

export type DetectionSortField = 'score' | 'time' | 'severity' | 'host' | 'tactic'

export interface DetectionUpdate {
  status?: DetectionStatus
  assigned_to?: string
  priority?: string
}

/** POST /detections/bulk: sets one status on 1-500 detections. */
export interface BulkDetectionRequest {
  ids: string[]
  status: DetectionStatus
}

export interface BulkDetectionResult {
  updated: number
  not_found: string[]
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

export type AggregationInterval =
  | '1m' | 'minute' | '1h' | 'hour' | '1d' | '24h' | 'day' | '1w' | 'week' | '1M' | 'month'

export interface AggregationRequest {
  field?: string
  agg_type?: 'terms' | 'date_histogram'
  interval?: AggregationInterval
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

export interface NoteCreate {
  content: string
  note_type?: NoteType
}

export type IncidentSortField = 'created_at' | 'severity' | 'status'

export interface IncidentMetrics {
  total_incidents: Record<IncidentStatus, number>
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

export interface CoverageSummary {
  coverage_pct: number
  covered_count: number
  total_count: number
}

export interface CoverageGaps {
  covered_count: number
  total_count: number
  gap_count: number
  coverage_pct: number
  /** Technique IDs that only disabled rules cover. */
  uncovered_techniques: string[]
}

export interface DataSourceCoverage {
  source: string
  covered_count: number
  total_count: number
  coverage_pct: number
  rule_count: number
}

export interface CoverageByDataSource {
  sources: DataSourceCoverage[]
  total_covered_count: number
  total_count: number
  total_coverage_pct: number
}

export interface CoverageTarget {
  target_pct: number
  enabled: boolean
  label: string | null
  current_pct: number
  is_below_threshold: boolean
}

export interface CoverageTargetUpdate {
  target_pct: number
  enabled?: boolean
  label?: string | null
}

export interface NavigatorTechnique {
  techniqueID: string
  /** Number of enabled rules that cover the technique. */
  score: number
  comment: string
  enabled: boolean
}

/** ATT&CK Navigator layer (v4.5). Only the fields the app reads are typed. */
export interface NavigatorLayer {
  name: string
  domain: string
  description: string
  versions: { attack: string; navigator: string; layer: string }
  techniques: NavigatorTechnique[]
  [key: string]: unknown
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

// ── Notification Channels ─────────────────────────────────────────────────────

export type NotificationChannelType = 'email' | 'slack' | 'webhook' | 'msteams'

export interface NotificationChannel {
  id: number
  name: string
  channel_type: NotificationChannelType
  config: Record<string, unknown>
  enabled: boolean
  min_severity: SeverityLevel
  created_at: string
  updated_at: string
}

export interface NotificationChannelCreate {
  name: string
  channel_type: NotificationChannelType
  config?: Record<string, unknown>
  enabled?: boolean
  min_severity?: SeverityLevel
}

export interface NotificationChannelUpdate {
  enabled?: boolean
  config?: Record<string, unknown>
  min_severity?: SeverityLevel
}

export interface NotificationChannelTestResult {
  channel_id: number
  sent: boolean
  message: string
}

// ── Sigma rules (/rules) ──────────────────────────────────────────────────────

export interface RuleLogsource {
  product?: string
  category?: string
  service?: string
}

export interface Rule {
  id: string
  title: string
  level: string
  status: string
  enabled: boolean
  technique_ids: string[]
  tactic_ids: string[]
  logsource: RuleLogsource
  hit_count: number
  fp_count: number
}

export interface RuleDetail extends Rule {
  content: string
  description: string
  source: string | null
  created_by: string | null
}

export interface RuleCreate {
  title: string
  content: string
  enabled?: boolean
}

export interface RuleUpdate {
  enabled?: boolean
  content?: string
}

export interface RuleListParams {
  enabled?: boolean
  level?: string
}

export interface RuleTestResult {
  matched: boolean
  errors: string[]
}

export interface RuleStatsSummary {
  total: number
  enabled: number
  by_level: Record<string, number>
}

export interface RuleImportResult {
  imported: number
  total_rules: number
}

export interface RuleReloadResult {
  reloaded: number
  total_rules: number
}

export interface RuleMarkFpResult {
  rule_id: string
  status: string
}

// ── Connectors (/connectors) ──────────────────────────────────────────────────

export type ConnectorType = 'wazuh' | 'zeek' | 'suricata' | 'syslog' | 'generic'

export type ConnectorConfig = Record<string, string | number | boolean | string[]>

export interface Connector {
  id: string
  name: string
  connector_type: ConnectorType
  /** inactive | connecting | active | error */
  status: string
  enabled: boolean
  events_total: number
  errors_total: number
  last_seen_at: string | null
  error_message: string | null
}

export interface ConnectorHealth extends Connector {
  healthy: boolean
}

export interface ConnectorCreate {
  name: string
  connector_type: ConnectorType
  config: ConnectorConfig
  enabled?: boolean
}

export interface ConnectorUpdate {
  enabled?: boolean
  /** Merged into the stored config; keys left out keep their current value. */
  config?: ConnectorConfig
}

export interface ConnectorTestResult {
  connector_id: string
  reachable: boolean
  message: string
}

// ── Users (/users, admin only) ────────────────────────────────────────────────

export type UserRole = 'viewer' | 'analyst' | 'hunter' | 'engineer' | 'admin'

export interface User {
  id: string
  email: string
  full_name: string | null
  role: UserRole
  is_active: boolean
  mfa_enabled: boolean
  must_change_password: boolean
}

export interface UserCreate {
  email: string
  full_name?: string | null
  role?: UserRole
  /** Temporary: the server always requires a new password at the first sign-in. */
  password: string
}

export interface UserUpdate {
  full_name?: string
  role?: UserRole
  is_active?: boolean
}

// ── Webhook ingest (POST /ingest) ─────────────────────────────────────────────

export interface IngestResult {
  accepted: number
  rejected: number
}
