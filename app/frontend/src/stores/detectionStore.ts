import { create } from 'zustand'
import type { Detection, SeverityLevel, DetectionStatus } from '../types/api'

type SortKey = 'score' | 'time' | 'severity' | 'host' | 'tactic'

interface DetectionFilters {
  severity?: SeverityLevel
  status?: DetectionStatus
  tactic?: string
  host?: string
  search?: string
  sortKey: SortKey
  sortOrder: 'asc' | 'desc'
  page: number
  pageSize: number
}

/** Maximum number of live alerts kept in memory. */
const MAX_LIVE_ALERTS = 200

interface DetectionState {
  filters: DetectionFilters
  selected: Detection | null

  /** Live alerts pushed via WebSocket (newest first). */
  liveAlerts: Detection[]

  setFilter: <K extends keyof DetectionFilters>(key: K, value: DetectionFilters[K]) => void
  resetFilters: () => void
  toggleSort: (key: SortKey) => void
  setSelected: (d: Detection | null) => void
  nextPage: () => void
  prevPage: () => void

  /** Prepend a live alert from the WebSocket stream. Caps at MAX_LIVE_ALERTS. */
  addLiveAlert: (alert: Detection) => void
}

const DEFAULT_FILTERS: DetectionFilters = {
  severity: undefined,
  status: undefined,
  tactic: undefined,
  host: undefined,
  search: undefined,
  sortKey: 'score',
  sortOrder: 'desc',
  page: 1,
  pageSize: 20,
}

export const useDetectionStore = create<DetectionState>()((set, get) => ({
  filters: { ...DEFAULT_FILTERS },
  selected: null,
  liveAlerts: [],

  setFilter: (key, value) =>
    set((s) => ({ filters: { ...s.filters, [key]: value, page: 1 } })),

  resetFilters: () => set({ filters: { ...DEFAULT_FILTERS } }),

  toggleSort: (key) =>
    set((s) => ({
      filters: {
        ...s.filters,
        sortKey: key,
        sortOrder: s.filters.sortKey === key && s.filters.sortOrder === 'desc' ? 'asc' : 'desc',
        page: 1,
      },
    })),

  setSelected: (d) => set({ selected: d }),

  nextPage: () =>
    set((s) => ({ filters: { ...s.filters, page: s.filters.page + 1 } })),

  prevPage: () =>
    set((s) => ({ filters: { ...s.filters, page: Math.max(1, s.filters.page - 1) } })),

  addLiveAlert: (alert) =>
    set((s) => ({
      liveAlerts: [alert, ...s.liveAlerts].slice(0, MAX_LIVE_ALERTS),
    })),
}))
