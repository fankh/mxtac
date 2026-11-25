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
 *  - Reconnects at once with the new token after a silent session refresh
 *  - Stops reconnecting when the session is over (see below)
 *  - Exposes connection state: "connected" | "reconnecting" | "disconnected"
 *  - Cleans up on unmount
 *
 * Refused token: the server closes with code 1008 (policy violation) when the
 * token is missing, invalid, expired or belongs to a deactivated account.  A
 * browser only sees that code when the close happens after the handshake.  The
 * server refuses before accepting, which a browser reports as an abnormal
 * close (1006), the same as a network failure.  So when a socket is refused, or
 * closes without ever having opened, the hook asks `GET /auth/me`.  That call
 * goes through the API client, which exchanges an expired access token for a
 * new one (silent refresh):
 *  - the access token changed: reconnect immediately with the new one
 *  - 401: the session could not be refreshed and is over; stop
 *  - same token and close code 1008: the account may not read the stream; stop
 */

import { useEffect, useRef, useState, useCallback } from 'react'
import { authApi, getAccessToken } from '../lib/api'
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
  /** True once the session is over or the account is refused; no further attempts are made. */
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
    const token = getAccessToken()
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

      const policyViolation = event.code === WS_POLICY_VIOLATION
      setState('reconnecting')
      // After a policy violation, retrying with the same token cannot succeed.
      if (!policyViolation) scheduleReconnect()
      if (opened && !policyViolation) return

      // Refused token, refused handshake or network failure: the close code
      // does not always say which. GET /auth/me refreshes an expired session.
      authApi.me().then(
        () => {
          if (unmounted.current || refused.current || wsRef.current !== ws) return
          if (getAccessToken() !== token) reconnectNow()
          else if (policyViolation) stopAfterRefusal()
        },
        (error: unknown) => {
          if (isUnauthorized(error)) stopAfterRefusal()
          else if (policyViolation) scheduleReconnect()
        },
      )
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

  /** Connect without waiting for the reconnect delay (a new access token is available). */
  const reconnectNow = useCallback(() => {
    if (reconnectTimer.current) {
      clearTimeout(reconnectTimer.current)
      reconnectTimer.current = null
    }
    connect()
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
