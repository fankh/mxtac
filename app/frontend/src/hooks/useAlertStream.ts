/**
 * useAlertStream -- WebSocket hook for real-time alert streaming.
 *
 * Connects to:  ws(s)://host/api/v1/ws/alerts?token=<jwt>
 *
 * On "alert" messages the hook pushes the detection into the zustand
 * detectionStore via `addLiveAlert`.
 *
 * Features:
 *  - Auto-reconnect after 5 seconds on close / error
 *  - Exposes connection state: "connected" | "reconnecting" | "disconnected"
 *  - Cleans up on unmount
 */

import { useEffect, useRef, useState, useCallback } from 'react'
import { useDetectionStore } from '../stores/detectionStore'
import type { Detection } from '../types/api'

export type ConnectionState = 'connected' | 'reconnecting' | 'disconnected'

const RECONNECT_DELAY_MS = 5_000

export function useAlertStream(): ConnectionState {
  const [state, setState] = useState<ConnectionState>('disconnected')
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const unmounted = useRef(false)

  const addLiveAlert = useDetectionStore((s) => s.addLiveAlert)

  const connect = useCallback(() => {
    // Don't attempt if component was unmounted
    if (unmounted.current) return

    const token = localStorage.getItem('access_token')
    if (!token) {
      setState('disconnected')
      return
    }

    // Build WebSocket URL from current page location
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const url = `${protocol}//${window.location.host}/api/v1/ws/alerts?token=${encodeURIComponent(token)}`

    const ws = new WebSocket(url)
    wsRef.current = ws

    ws.onopen = () => {
      if (!unmounted.current) {
        setState('connected')
      }
    }

    ws.onmessage = (event: MessageEvent) => {
      try {
        const msg = JSON.parse(event.data) as { type: string; data?: Detection }
        if (msg.type === 'alert' && msg.data) {
          addLiveAlert(msg.data)
        }
      } catch {
        // Ignore malformed messages
      }
    }

    ws.onclose = () => {
      if (unmounted.current) return
      setState('reconnecting')
      scheduleReconnect()
    }

    ws.onerror = () => {
      // onclose will fire after onerror; reconnection is handled there.
      // Close explicitly to ensure onclose triggers.
      ws.close()
    }
  }, [addLiveAlert])

  const scheduleReconnect = useCallback(() => {
    if (unmounted.current) return
    if (reconnectTimer.current) clearTimeout(reconnectTimer.current)
    reconnectTimer.current = setTimeout(() => {
      connect()
    }, RECONNECT_DELAY_MS)
  }, [connect])

  useEffect(() => {
    unmounted.current = false
    connect()

    return () => {
      unmounted.current = true
      if (reconnectTimer.current) {
        clearTimeout(reconnectTimer.current)
        reconnectTimer.current = null
      }
      if (wsRef.current) {
        wsRef.current.onclose = null   // prevent reconnect on intentional close
        wsRef.current.onerror = null
        wsRef.current.close()
        wsRef.current = null
      }
      setState('disconnected')
    }
  }, [connect])

  return state
}
