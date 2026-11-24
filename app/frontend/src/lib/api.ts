import axios from 'axios'
import type {
  KpiMetrics, TimelinePoint, TacticBar, HeatRow, IntegrationStatus,
  Detection, PaginatedResponse, DetectionUpdate, BulkDetectionRequest, BulkDetectionResult,
  SeverityLevel, DetectionStatus, DetectionSortField, IncidentStatus, IncidentSortField, NoteType,
  SearchRequest, SearchResponse, AggregationRequest, AggregationResponse, EntityTimeline,
  SavedQuery, SavedQueryCreate, SavedQueryUpdate,
  Incident, IncidentDetail, IncidentCreate, IncidentUpdate, IncidentNote, IncidentMetrics,
  CoverageTrend, EventItem,
  CoverageSummary, CoverageGaps, CoverageByDataSource, CoverageTarget, CoverageTargetUpdate,
  NavigatorLayer,
  Rule, RuleDetail, RuleCreate, RuleUpdate, RuleListParams, RuleTestResult, RuleStatsSummary,
  RuleImportResult, RuleReloadResult, RuleMarkFpResult,
  Connector, ConnectorHealth, ConnectorCreate, ConnectorUpdate, ConnectorTestResult,
  User, UserCreate, UserUpdate,
  IngestResult,
} from '../types/api'

const http = axios.create({
  baseURL: '/api/v1',
  headers: { 'Content-Type': 'application/json' },
  paramsSerializer: {
    // Serialize arrays as repeated keys: severity=critical&severity=high
    // (FastAPI's list[...] = Query(None) expects this format, not bracket notation)
    serialize: (params: Record<string, unknown>) => {
      const parts: string[] = []
      for (const [key, value] of Object.entries(params)) {
        if (value === undefined || value === null) continue
        if (Array.isArray(value)) {
          for (const v of value) parts.push(`${encodeURIComponent(key)}=${encodeURIComponent(String(v))}`)
        } else {
          parts.push(`${encodeURIComponent(key)}=${encodeURIComponent(String(value))}`)
        }
      }
      return parts.join('&')
    },
  },
})

// Attach token if present
http.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

// Redirect to login on 401 (expired/missing token)
http.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401 && !error.config?.url?.includes('/auth/')) {
      localStorage.removeItem('access_token')
      localStorage.removeItem('mxtac-auth')
      sessionStorage.clear()
      if (typeof window !== 'undefined' && window.location.pathname !== '/login') {
        window.location.replace('/login')
      }
    }
    return Promise.reject(error)
  }
)

// ── Raw axios instance (for pages that need direct access) ────────────────────
export const apiClient = http

// ── Auth ──────────────────────────────────────────────────────────────────────

/**
 * Answer of every sign-in step (POST /auth/login, /auth/change-password, /auth/mfa/verify).
 * Exactly one of three shapes comes back:
 *  - session:         access_token, refresh_token, token_type, expires_in, email, role
 *  - MFA needed:      mfa_required: true, mfa_token
 *  - password change: password_change_required: true, password_change_token
 */
export interface AuthStepResponse {
  access_token?: string
  refresh_token?: string
  token_type?: string
  expires_in?: number
  email?: string
  role?: string
  mfa_required?: boolean
  mfa_token?: string
  password_change_required?: boolean
  password_change_token?: string
}

export const authApi = {
  login: (email: string, password: string): Promise<AuthStepResponse> =>
    http.post('/auth/login', { email, password }).then(r => r.data),
  mfaVerify: (mfa_token: string, code: string): Promise<AuthStepResponse> =>
    http.post('/auth/mfa/verify', { mfa_token, code }).then(r => r.data),
  /** Forced change at sign-in, authorised by the one-time token from POST /auth/login. */
  changePasswordWithToken: (password_change_token: string, new_password: string): Promise<AuthStepResponse> =>
    http.post('/auth/change-password', { password_change_token, new_password, confirm_password: new_password })
      .then(r => r.data),
  /** A signed-in user changes their own password. Answers 204 with no body. */
  changePassword: (current_password: string, new_password: string): Promise<void> =>
    http.post('/auth/password', { current_password, new_password }).then(() => undefined),
  logout: () => http.post('/auth/logout'),
  me: (): Promise<{ email: string; role: string; full_name: string | null; mfa_enabled: boolean }> =>
    http.get('/auth/me').then(r => r.data),
  mfaSetup: (): Promise<{ secret: string; qr_code_uri: string; backup_codes: string[] }> =>
    http.post('/auth/mfa/setup').then(r => r.data),
  mfaVerifySetup: (code: string): Promise<{ message: string }> =>
    http.post('/auth/mfa/verify-setup', { code }).then(r => r.data),
  mfaDisable: (user_id: string): Promise<{ message: string }> =>
    http.post('/auth/mfa/disable', { user_id }).then(r => r.data),
}

// ── Overview ──────────────────────────────────────────────────────────────────

export const overviewApi = {
  kpis: (range = '7d'): Promise<KpiMetrics> =>
    http.get('/overview/kpis', { params: { range } }).then(r => r.data),

  timeline: (range = '7d'): Promise<TimelinePoint[]> =>
    http.get('/overview/timeline', { params: { range } }).then(r => r.data),

  tactics: (range = '7d'): Promise<TacticBar[]> =>
    http.get('/overview/tactics', { params: { range } }).then(r => r.data),

  heatmap: (): Promise<HeatRow[]> =>
    http.get('/overview/coverage/heatmap').then(r => r.data),

  tacticLabels: (): Promise<string[]> =>
    http.get('/overview/coverage/tactic-labels').then(r => r.data),

  integrations: (): Promise<IntegrationStatus[]> =>
    http.get('/overview/integrations').then(r => r.data),

  recentDetections: (limit = 6): Promise<Detection[]> =>
    http.get('/overview/recent-detections', { params: { limit } }).then(r => r.data),
}

// ── Detections ────────────────────────────────────────────────────────────────

export interface DetectionListParams {
  page?: number
  page_size?: number
  severity?: SeverityLevel[]
  status?: DetectionStatus[]
  tactic?: string
  host?: string
  search?: string
  sort?: DetectionSortField
  order?: 'asc' | 'desc'
}

/** GET /detections/export takes the list filters and sort, without paging. */
export type DetectionExportParams = Omit<DetectionListParams, 'page' | 'page_size'>

export const detectionsApi = {
  list: (params: DetectionListParams = {}): Promise<PaginatedResponse<Detection>> =>
    http.get('/detections', { params }).then(r => r.data),

  get: (id: string): Promise<Detection> =>
    http.get(`/detections/${id}`).then(r => r.data),

  update: (id: string, body: DetectionUpdate): Promise<Detection> =>
    http.patch(`/detections/${id}`, body).then(r => r.data),

  bulk: (body: BulkDetectionRequest): Promise<BulkDetectionResult> =>
    http.post('/detections/bulk', body).then(r => r.data),

  /** CSV of the filtered detections (max 10,000 rows). */
  export: (params: DetectionExportParams = {}): Promise<Blob> =>
    http.get('/detections/export', { params, responseType: 'blob' }).then(r => r.data),

  delete: (id: string): Promise<void> =>
    http.delete(`/detections/${id}`).then(r => r.data),
}

// ── Events ────────────────────────────────────────────────────────────────────

export const eventsApi = {
  search: (body: SearchRequest = {}): Promise<SearchResponse> =>
    http.post('/events/search', body).then(r => r.data),

  aggregate: (body: AggregationRequest = {}): Promise<AggregationResponse> =>
    http.post('/events/aggregate', body).then(r => r.data),

  entity: (type: string, value: string, time_from = 'now-7d'): Promise<EntityTimeline> =>
    http.get(`/events/entity/${encodeURIComponent(type)}/${encodeURIComponent(value)}`, {
      params: { time_from },
    }).then(r => r.data),

  queryDsl: (body: SearchRequest): Promise<{ lucene: string }> =>
    http.post('/events/query-dsl', body).then(r => r.data),

  /** CSV of the matching events (the backend caps it at 10,000 rows). */
  exportCsv: (body: SearchRequest): Promise<Blob> =>
    http.post('/events/export', body, { responseType: 'blob' }).then(r => r.data),

  get: (id: string): Promise<EventItem> =>
    http.get(`/events/${id}`).then(r => r.data),
}

// ── Incidents ─────────────────────────────────────────────────────────────────

export interface IncidentListParams {
  page?: number
  page_size?: number
  severity?: SeverityLevel[]
  status?: IncidentStatus[]
  assigned_to?: string
  search?: string
  sort?: IncidentSortField
}

export const incidentsApi = {
  list: (params: IncidentListParams = {}): Promise<PaginatedResponse<Incident>> =>
    http.get('/incidents', { params }).then(r => r.data),

  get: (id: number): Promise<IncidentDetail> =>
    http.get(`/incidents/${id}`).then(r => r.data),

  create: (body: IncidentCreate): Promise<Incident> =>
    http.post('/incidents', body).then(r => r.data),

  update: (id: number, body: IncidentUpdate): Promise<Incident> =>
    http.patch(`/incidents/${id}`, body).then(r => r.data),

  delete: (id: number): Promise<void> =>
    http.delete(`/incidents/${id}`).then(r => r.data),

  addNote: (id: number, content: string, note_type: NoteType = 'comment'): Promise<IncidentNote> =>
    http.post(`/incidents/${id}/notes`, { content, note_type }).then(r => r.data),

  listNotes: (id: number): Promise<IncidentNote[]> =>
    http.get(`/incidents/${id}/notes`).then(r => r.data),

  metrics: (from_date?: string, to_date?: string): Promise<IncidentMetrics> =>
    http.get('/incidents/metrics', { params: { from_date, to_date } }).then(r => r.data),
}

// ── Saved Hunt Queries ────────────────────────────────────────────────────────

export const savedQueriesApi = {
  list: (): Promise<{ items: SavedQuery[]; total: number }> =>
    http.get('/hunt/queries').then(r => r.data),

  get: (id: string): Promise<SavedQuery> =>
    http.get(`/hunt/queries/${id}`).then(r => r.data),

  create: (body: SavedQueryCreate): Promise<SavedQuery> =>
    http.post('/hunt/queries', body).then(r => r.data),

  update: (id: string, body: SavedQueryUpdate): Promise<SavedQuery> =>
    http.put(`/hunt/queries/${id}`, body).then(r => r.data),

  delete: (id: string): Promise<void> =>
    http.delete(`/hunt/queries/${id}`).then(r => r.data),
}

// ── Coverage ──────────────────────────────────────────────────────────────────

export const coverageApi = {
  summary: (): Promise<CoverageSummary> =>
    http.get('/coverage').then(r => r.data),

  byDatasource: (): Promise<CoverageByDataSource> =>
    http.get('/coverage/by-datasource').then(r => r.data),

  gaps: (): Promise<CoverageGaps> =>
    http.get('/coverage/gaps').then(r => r.data),

  navigator: (): Promise<NavigatorLayer> =>
    http.get('/coverage/navigator').then(r => r.data),

  trend: (days = 30): Promise<CoverageTrend> =>
    http.get('/coverage/trend', { params: { days } }).then(r => r.data),

  target: (): Promise<CoverageTarget> =>
    http.get('/coverage/target').then(r => r.data),

  updateTarget: (body: CoverageTargetUpdate): Promise<CoverageTarget> =>
    http.put('/coverage/target', body).then(r => r.data),
}

// ── Sigma rules ───────────────────────────────────────────────────────────────

export const rulesApi = {
  list: (params: RuleListParams = {}): Promise<Rule[]> =>
    http.get('/rules', { params }).then(r => r.data),

  stats: (): Promise<RuleStatsSummary> =>
    http.get('/rules/stats/summary').then(r => r.data),

  get: (id: string): Promise<RuleDetail> =>
    http.get(`/rules/${encodeURIComponent(id)}`).then(r => r.data),

  create: (body: RuleCreate): Promise<Rule> =>
    http.post('/rules', body).then(r => r.data),

  update: (id: string, body: RuleUpdate): Promise<Rule> =>
    http.patch(`/rules/${encodeURIComponent(id)}`, body).then(r => r.data),

  delete: (id: string): Promise<void> =>
    http.delete(`/rules/${encodeURIComponent(id)}`).then(r => r.data),

  import: (yaml_content: string): Promise<RuleImportResult> =>
    http.post('/rules/import', { yaml_content }).then(r => r.data),

  reload: (): Promise<RuleReloadResult> =>
    http.post('/rules/reload').then(r => r.data),

  /** Validate unsaved YAML and evaluate it against a sample event. */
  testContent: (content: string, sample_event: Record<string, unknown>): Promise<RuleTestResult> =>
    http.post('/rules/test', { content, sample_event }).then(r => r.data),

  /** Evaluate a stored rule against a sample event. */
  test: (id: string, sample_event: Record<string, unknown>): Promise<RuleTestResult> =>
    http.post(`/rules/${encodeURIComponent(id)}/test`, { sample_event }).then(r => r.data),

  markFalsePositive: (id: string): Promise<RuleMarkFpResult> =>
    http.post(`/rules/${encodeURIComponent(id)}/mark_fp`).then(r => r.data),
}

// ── Connectors (data sources) ─────────────────────────────────────────────────

export const connectorsApi = {
  list: (): Promise<Connector[]> =>
    http.get('/connectors').then(r => r.data),

  get: (id: string): Promise<Connector> =>
    http.get(`/connectors/${id}`).then(r => r.data),

  create: (body: ConnectorCreate): Promise<Connector> =>
    http.post('/connectors', body).then(r => r.data),

  update: (id: string, body: ConnectorUpdate): Promise<Connector> =>
    http.patch(`/connectors/${id}`, body).then(r => r.data),

  delete: (id: string): Promise<void> =>
    http.delete(`/connectors/${id}`).then(r => r.data),

  health: (id: string): Promise<ConnectorHealth> =>
    http.get(`/connectors/${id}/health`).then(r => r.data),

  start: (id: string): Promise<Connector> =>
    http.post(`/connectors/${id}/start`).then(r => r.data),

  stop: (id: string): Promise<Connector> =>
    http.post(`/connectors/${id}/stop`).then(r => r.data),

  test: (id: string): Promise<ConnectorTestResult> =>
    http.post(`/connectors/${id}/test`).then(r => r.data),
}

// ── Users (admin only) ────────────────────────────────────────────────────────

export const usersApi = {
  list: (): Promise<User[]> =>
    http.get('/users').then(r => r.data),

  create: (body: UserCreate): Promise<User> =>
    http.post('/users', body).then(r => r.data),

  update: (id: string, body: UserUpdate): Promise<User> =>
    http.patch(`/users/${id}`, body).then(r => r.data),

  /** The backend soft-deletes: the account is kept with is_active=false. */
  delete: (id: string): Promise<void> =>
    http.delete(`/users/${id}`).then(r => r.data),
}

// ── Webhook ingest (generic sources) ──────────────────────────────────────────

export const ingestApi = {
  /**
   * Send events as a generic webhook source. Auth is the source name and its webhook token,
   * not the user session, so this uses plain axios: a 401 here means a wrong token and must
   * not sign the user out.
   */
  send: (
    source: string,
    token: string,
    events: Record<string, unknown> | Record<string, unknown>[],
  ): Promise<IngestResult> =>
    axios.post('/api/v1/ingest', events, {
      headers: { 'Content-Type': 'application/json', 'X-MxTac-Source': source, 'X-MxTac-Token': token },
    }).then(r => r.data),
}

// ── Error text ────────────────────────────────────────────────────────────────

/** Readable message from a failed request: FastAPI `detail` (text or validation list), else the fallback. */
export function apiErrorMessage(err: unknown, fallback: string): string {
  const detail = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
  if (typeof detail === 'string' && detail) return detail
  if (Array.isArray(detail)) {
    const parts = detail
      .map((d) => (typeof d === 'string' ? d : (d as { msg?: unknown })?.msg))
      .filter((m): m is string => typeof m === 'string' && m.length > 0)
    if (parts.length > 0) return parts.join('; ')
  }
  return fallback
}
