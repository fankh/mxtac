import axios from 'axios'
import type {
  KpiMetrics, TimelinePoint, TacticBar, HeatRow, IntegrationStatus,
  Detection, PaginatedResponse, DetectionUpdate, BulkDetectionRequest, BulkDetectionResult,
  SearchRequest, SearchResponse, AggregationRequest, AggregationResponse, EntityTimeline,
  SavedQuery, SavedQueryCreate, SavedQueryUpdate,
  Incident, IncidentDetail, IncidentCreate, IncidentUpdate, IncidentNote, IncidentMetrics,
  CoverageTrend, EventItem,
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

export const authApi = {
  login: (email: string, password: string) =>
    http.post('/auth/login', { email, password }).then(r => r.data),
  mfaVerify: (mfa_token: string, code: string) =>
    http.post('/auth/mfa/verify', { mfa_token, code }).then(r => r.data),
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
  severity?: string[]
  status?: string[]
  tactic?: string
  host?: string
  search?: string
  sort?: string
  order?: 'asc' | 'desc'
}

export const detectionsApi = {
  list: (params: DetectionListParams = {}): Promise<PaginatedResponse<Detection>> =>
    http.get('/detections', { params }).then(r => r.data),

  get: (id: string): Promise<Detection> =>
    http.get(`/detections/${id}`).then(r => r.data),

  update: (id: string, body: DetectionUpdate): Promise<Detection> =>
    http.patch(`/detections/${id}`, body).then(r => r.data),

  bulk: (body: BulkDetectionRequest): Promise<BulkDetectionResult> =>
    http.post('/detections/bulk', body).then(r => r.data),
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

  get: (id: string): Promise<EventItem> =>
    http.get(`/events/${id}`).then(r => r.data),
}

// ── Incidents ─────────────────────────────────────────────────────────────────

export interface IncidentListParams {
  page?: number
  page_size?: number
  severity?: string[]
  status?: string[]
  assigned_to?: string
  search?: string
  sort?: 'created_at' | 'severity' | 'status'
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

  addNote: (id: number, content: string, note_type = 'comment'): Promise<IncidentNote> =>
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
  trend: (days = 30): Promise<CoverageTrend> =>
    http.get('/coverage/trend', { params: { days } }).then(r => r.data),
}
