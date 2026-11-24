/**
 * useAlertStream -- WebSocket hook for real-time alert streaming.
 *
 * Connects to:  ws(s)://host/api/v1/ws/alerts?token=<access token>
 *
 * On "alert" messages the hook pushes the detection into the zustand
 * detectionStore via `addLiveAlert`.
 *
 * Features:
 *  - Reads the current access token from localStorage on every connect attempt
 *  - Auto-reconnect after 5 seconds on close / error
 *  - Stops reconnecting when the server refuses the token (see below)
 *  - Exposes connection state: "connected" | "reconnecting" | "disconnected"
 *  - Cleans up on unmount
 *
 * Refused token: the server closes with code 1008 (policy violation) when the
 * token is missing, invalid, expired or belongs to a deactivated account.  A
 * browser only sees that code when the close happens after the handshake.  The
 * server refuses before accepting, which a browser reports as an abnormal
 * close (1006), the same as a network failure.  So when a socket closes without
 * ever having opened, the hook also asks `GET /auth/me` whether the session is
 * still valid and stops when the answer is 401.
 */

import { useEffect, useRef, useState, useCallback } from 'react'
import { authApi } from '../lib/api'
import { useDetectionStore } from '../stores/detectionStore'
import type { Detection } from '../types/api'

export type ConnectionState = 'connected' | 'reconnecting' | 'disconnected'

const RECONNECT_DELAY_MS = 5_000
const WS_POLICY_VIOLATION = 1008

function isUnauthorized(error: unknown): boolean {
  return (error as { response?: { status?: number } } | null)?.response?.status === 401
}

export function useAlertStream(): ConnectionState {
  const [state, setState] = useState<ConnectionState>('disconnected')
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const unmounted = useRef(false)
  /** True once the server has refused the token; no further attempts are made. */
  const refused = useRef(false)

  const addLiveAlert = useDetectionStore((s) => s.addLiveAlert)

  const stopAfterRefusal = useCallback(() => {
    refused.current = true
    if (reconnectTimer.current) {
      clearTimeout(reconnectTimer.current)
      reconnectTimer.current = null
    }
    if (!unmounted.current) setState('disconnected')
  }, [])

  const connect = useCallback(() => {
    // Don't attempt if component was unmounted or the token was refused
    if (unmounted.current || refused.current) return

    // Read the token on every attempt so a new sign-in is picked up
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
    let opened = false

    ws.onopen = () => {
      opened = true
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

    ws.onclose = (event: CloseEvent) => {
      if (unmounted.current) return

      if (event.code === WS_POLICY_VIOLATION) {
        // The server refused the token. Retrying with it cannot succeed.
        stopAfterRefusal()
        return
      }

      setState('reconnecting')
      scheduleReconnect()

      if (!opened) {
        // Refused handshake or network failure: the close code does not say
        // which. A 401 from the API means the token is no longer accepted.
        authApi.me().catch((error: unknown) => {
          if (isUnauthorized(error)) stopAfterRefusal()
        })
      }
    }

    ws.onerror = () => {
      // onclose will fire after onerror; reconnection is handled there.
      // Close explicitly to ensure onclose triggers.
      ws.close()
    }
  }, [addLiveAlert, stopAfterRefusal])

  const scheduleReconnect = useCallback(() => {
    if (unmounted.current || refused.current) return
    if (reconnectTimer.current) clearTimeout(reconnectTimer.current)
    reconnectTimer.current = setTimeout(() => {
      connect()
    }, RECONNECT_DELAY_MS)
  }, [connect])

  useEffect(() => {
    unmounted.current = false
    refused.current = false
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
