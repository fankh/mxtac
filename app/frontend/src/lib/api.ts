import axios, { type InternalAxiosRequestConfig } from 'axios'
import type {
  KpiMetrics, TimelinePoint, TacticBar, HeatRow, IntegrationStatus,
  Detection, PaginatedResponse, DetectionUpdate, BulkDetectionRequest, BulkDetectionResult,
  SeverityLevel, DetectionStatus, DetectionSortField, IncidentStatus, IncidentSortField, NoteType,
  SearchRequest, SearchResponse, AggregationRequest, AggregationResponse, EntityTimeline,
  SavedQuery, SavedQueryCreate, SavedQueryUpdate,
  Incident, IncidentDetail, IncidentCreate, IncidentUpdate, IncidentNote, IncidentMetrics,
  CoverageTrend, EventItem, AttackTechniques,
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

// ── Session: access token, silent refresh, sign-out ───────────────────────────
//
// The access token lives in localStorage and is sent as a Bearer header. The refresh token is an
// HttpOnly cookie that the browser sends only to POST /auth/refresh, so no script here can read it.
// When a request is answered with 401, the session is refreshed once and the request is repeated.
// Only when the refresh itself is refused does the user get signed out.

const ACCESS_TOKEN_KEY = 'access_token'
/** sessionStorage flag: the login page shows "Your session has ended" once. */
export const SESSION_ENDED_KEY = 'mxtac-session-ended'
/** sessionStorage: the page that was open when the session ended, reopened after sign-in. */
export const RETURN_TO_KEY = 'mxtac-return-to'
/** Name of the cross-tab lock that lets one tab at a time use the single-use refresh token. */
const REFRESH_LOCK = 'mxtac-auth-refresh'
/** Sign-in steps and the refresh itself: a 401 there is the answer, not an expired session. */
const NO_REFRESH_URLS = new Set(['/auth/login', '/auth/mfa/verify', '/auth/change-password', '/auth/refresh'])
/** A request is repeated at most this often: once with a refreshed token, once more if that token came from another tab. */
const MAX_AUTH_RETRIES = 2

interface RetriableConfig extends InternalAxiosRequestConfig {
  _authRetries?: number
}

/** Full page load. An object so that tests can replace it: jsdom does not navigate. */
export const pageNavigation = {
  replace: (path: string): void => window.location.replace(path),
}

export function getAccessToken(): string | null {
  return localStorage.getItem(ACCESS_TOKEN_KEY)
}

export function setAccessToken(token: string): void {
  localStorage.setItem(ACCESS_TOKEN_KEY, token)
}

/** Forget the local session without a notice (used by sign-out). */
export function clearSession(): void {
  localStorage.removeItem(ACCESS_TOKEN_KEY)
  localStorage.removeItem('mxtac-auth')
  sessionStorage.clear()
}

/**
 * The server no longer accepts the session: forget it and show the login page with a notice.
 * The open page is remembered so that the next sign-in returns to it.
 */
export function endSession(): void {
  clearSession()
  if (typeof window === 'undefined' || window.location.pathname === '/login') return
  sessionStorage.setItem(SESSION_ENDED_KEY, '1')
  sessionStorage.setItem(RETURN_TO_KEY, `${window.location.pathname}${window.location.search}`)
  pageNavigation.replace('/login')
}

function isUnauthorized(error: unknown): boolean {
  return (error as { response?: { status?: number } } | null)?.response?.status === 401
}

/** Run `task` while holding the cross-tab refresh lock (directly where the Web Locks API is missing). */
async function withRefreshLock(task: () => Promise<string>): Promise<string> {
  const locks = typeof navigator === 'undefined' ? undefined : (navigator.locks as LockManager | undefined)
  return locks ? await locks.request(REFRESH_LOCK, task) : task()
}

let refreshInFlight: Promise<string> | null = null

/**
 * Exchange the refresh cookie for a new access token and return it.
 *
 * Single-flight: calls made while a refresh is running share its result, so a burst of 401s costs
 * one POST /auth/refresh. The refresh token is single use, so tabs take turns through a lock; a tab
 * that waited finds the token another tab just stored and uses that one instead of refreshing again.
 * `staleToken` is the token the failed request was sent with.
 */
export function refreshAccessToken(staleToken: string | null = null): Promise<string> {
  if (!refreshInFlight) {
    refreshInFlight = withRefreshLock(async () => {
      const current = getAccessToken()
      if (current && staleToken && current !== staleToken) return current
      // Plain axios: this call must not pass through the interceptors below.
      const { data } = await axios.post<AuthStepResponse>('/api/v1/auth/refresh', null, { withCredentials: true })
      if (!data.access_token) throw new Error('The server did not return a session')
      setAccessToken(data.access_token)
      return data.access_token
    }).finally(() => {
      refreshInFlight = null
    })
  }
  return refreshInFlight
}

function bearerToken(config: InternalAxiosRequestConfig): string | null {
  const header = config.headers.Authorization
  return typeof header === 'string' && header.startsWith('Bearer ') ? header.slice('Bearer '.length) : null
}

// Attach token if present
http.interceptors.request.use((config) => {
  const token = getAccessToken()
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

// 401 (expired or revoked access token): refresh once, then repeat the request.
http.interceptors.response.use(
  (response) => response,
  async (error) => {
    const config = error.config as RetriableConfig | undefined
    if (!isUnauthorized(error) || !config || NO_REFRESH_URLS.has(config.url ?? '')) {
      return Promise.reject(error)
    }
    const retries = config._authRetries ?? 0
    if (retries >= MAX_AUTH_RETRIES) {
      endSession()
      return Promise.reject(error)
    }
    let token: string
    try {
      token = await refreshAccessToken(bearerToken(config))
    } catch (refreshError: unknown) {
      // Only a refusal ends the session. A network failure or a 5xx leaves it alone: the next
      // request tries again.
      if (isUnauthorized(refreshError)) endSession()
      return Promise.reject(error)
    }
    config._authRetries = retries + 1
    config.headers.Authorization = `Bearer ${token}`
    return http.request(config)
  }
)

// ── Auth ──────────────────────────────────────────────────────────────────────

/**
 * Answer of every sign-in step (POST /auth/login, /auth/change-password, /auth/mfa/verify).
 * Exactly one of three shapes comes back:
 *  - session:         access_token, token_type, expires_in, email, role
 *                     (the refresh token arrives as an HttpOnly cookie, not in the body)
 *  - MFA needed:      mfa_required: true, mfa_token
 *  - password change: password_change_required: true, password_change_token
 */
export interface AuthStepResponse {
  access_token?: string
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
  /**
   * A signed-in user changes their own password. The change ends every session of the account;
   * the answer is a new session for this browser, whose access token is stored here.
   */
  changePassword: (current_password: string, new_password: string): Promise<void> =>
    http.post<AuthStepResponse>('/auth/password', { current_password, new_password }).then((r) => {
      if (r.data.access_token) setAccessToken(r.data.access_token)
    }),
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

  update: (id: string, body: DetectionUpdate): Promise<Detection> =>
    http.patch(`/detections/${id}`, body).then(r => r.data),

  bulk: (body: BulkDetectionRequest): Promise<BulkDetectionResult> =>
    http.post('/detections/bulk', body).then(r => r.data),

  /** CSV of the filtered detections (max 10,000 rows). */
  export: (params: DetectionExportParams = {}): Promise<Blob> =>
    http.get('/detections/export', { params, responseType: 'blob' }).then(r => r.data),
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

  addNote: (id: number, content: string, note_type: NoteType = 'comment'): Promise<IncidentNote> =>
    http.post(`/incidents/${id}/notes`, { content, note_type }).then(r => r.data),

  metrics: (from_date?: string, to_date?: string): Promise<IncidentMetrics> =>
    http.get('/incidents/metrics', { params: { from_date, to_date } }).then(r => r.data),
}

// ── Saved Hunt Queries ────────────────────────────────────────────────────────

export const savedQueriesApi = {
  list: (): Promise<{ items: SavedQuery[]; total: number }> =>
    http.get('/hunt/queries').then(r => r.data),

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

// ── ATT&CK reference data ─────────────────────────────────────────────────────

export const attackApi = {
  /** Names of the ATT&CK Enterprise techniques and sub-techniques, by ID. */
  techniques: (): Promise<AttackTechniques> =>
    http.get('/attack/techniques').then(r => r.data),
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

/**
 * Readable message from a failed request: the FastAPI `detail` (text or validation list) when there is one.
 * Otherwise the given fallback; without a fallback, the error's own message or a generic line.
 */
export function apiErrorMessage(err: unknown, fallback?: string): string {
  const response = (err as { response?: { status?: number; data?: { detail?: unknown; retry_after?: unknown } } })?.response
  const detail = response?.data?.detail
  const retryAfter = response?.data?.retry_after
  if (response?.status === 429 && typeof retryAfter === 'number') {
    // The per-client rate limit of the API (core/rate_limit.py); its detail is only "Too Many Requests".
    const seconds = Math.max(1, Math.ceil(retryAfter))
    return `Too many requests. Try again in ${seconds} second${seconds === 1 ? '' : 's'}.`
  }
  if (typeof detail === 'string' && detail) return detail
  if (Array.isArray(detail)) {
    const parts = detail
      .map((d) => (typeof d === 'string' ? d : (d as { msg?: unknown })?.msg))
      .filter((m): m is string => typeof m === 'string' && m.length > 0)
    if (parts.length > 0) return parts.join('; ')
  }
  if (fallback !== undefined) return fallback
  if (err instanceof Error && err.message) return err.message
  return 'The request failed. Try again.'
}
