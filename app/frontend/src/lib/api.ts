import axios from 'axios'
import type {
  KpiMetrics, TimelinePoint, TacticBar, HeatRow, IntegrationStatus,
  Detection, PaginatedResponse, DetectionUpdate,
} from '../types/api'

const http = axios.create({
  baseURL: '/api/v1',
  headers: { 'Content-Type': 'application/json' },
})

// Attach token if present
http.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

// ── Auth ──────────────────────────────────────────────────────────────────────

export const authApi = {
  login: (email: string, password: string) =>
    http.post('/auth/login', { email, password }).then(r => r.data),
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
