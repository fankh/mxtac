import axios from 'axios'
import type {
  KpiMetrics, TimelinePoint, TacticBar, HeatRow, IntegrationStatus,
  Detection, PaginatedResponse, DetectionUpdate,
  SearchRequest, SearchResponse, AggregationRequest, AggregationResponse, EntityTimeline,
  AuditLogEntry,
  Asset, AssetCreate, AssetStats, BulkAssetResult,
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

// ── Raw axios instance (for pages that need direct access) ────────────────────
export const apiClient = http

// ── Auth ──────────────────────────────────────────────────────────────────────

export const authApi = {
  login: (email: string, password: string) =>
    http.post('/auth/login', { email, password }).then(r => r.data),
  mfaVerify: (mfa_token: string, code: string) =>
    http.post('/auth/mfa/verify', { mfa_token, code }).then(r => r.data),
  logout: () => http.post('/auth/logout'),
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

  get: (id: string): Promise<import('../types/api').EventItem> =>
    http.get(`/events/${id}`).then(r => r.data),
}

// ── Audit Logs ────────────────────────────────────────────────────────────────

export interface AuditLogListParams {
  page?: number
  page_size?: number
  actor?: string
  action?: string
  resource_type?: string
  from_ts?: string
  to_ts?: string
}

export const auditLogsApi = {
  list: (params: AuditLogListParams = {}): Promise<PaginatedResponse<AuditLogEntry>> =>
    http.get('/audit-logs', { params }).then(r => r.data),

  get: (id: string): Promise<AuditLogEntry> =>
    http.get(`/audit-logs/${id}`).then(r => r.data),
}

// ── Assets ────────────────────────────────────────────────────────────────────

export interface AssetListParams {
  page?: number
  page_size?: number
  asset_type?: string
  criticality?: number
  is_active?: boolean
  search?: string
}

export const assetsApi = {
  list: (params: AssetListParams = {}): Promise<PaginatedResponse<Asset>> =>
    http.get('/assets', { params }).then(r => r.data),

  stats: (): Promise<AssetStats> =>
    http.get('/assets/stats').then(r => r.data),

  get: (id: number): Promise<Asset> =>
    http.get(`/assets/${id}`).then(r => r.data),

  create: (body: AssetCreate): Promise<Asset> =>
    http.post('/assets', body).then(r => r.data),

  update: (id: number, body: Partial<AssetCreate>): Promise<Asset> =>
    http.patch(`/assets/${id}`, body).then(r => r.data),

  bulkImport: (assets: AssetCreate[]): Promise<BulkAssetResult> =>
    http.post('/assets/bulk', assets).then(r => r.data),

  getDetections: (id: number, params: { page?: number; page_size?: number } = {}): Promise<PaginatedResponse<Record<string, unknown>>> =>
    http.get(`/assets/${id}/detections`, { params }).then(r => r.data),

  getIncidents: (id: number, params: { page?: number; page_size?: number } = {}): Promise<PaginatedResponse<Record<string, unknown>>> =>
    http.get(`/assets/${id}/incidents`, { params }).then(r => r.data),
}
