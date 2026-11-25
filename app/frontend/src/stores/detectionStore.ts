import { create } from 'zustand'
import type { Detection } from '../types/api'

/** Maximum number of live alerts kept in memory. */
const MAX_LIVE_ALERTS = 200

interface DetectionState {
  /** Live alerts pushed via WebSocket (newest first). */
  liveAlerts: Detection[]

  /** Prepend a live alert from the WebSocket stream. Caps at MAX_LIVE_ALERTS. */
  addLiveAlert: (alert: Detection) => void
}

export const useDetectionStore = create<DetectionState>()((set) => ({
  liveAlerts: [],

  addLiveAlert: (alert) =>
    set((s) => ({ liveAlerts: [alert, ...s.liveAlerts].slice(0, MAX_LIVE_ALERTS) })),
}))
