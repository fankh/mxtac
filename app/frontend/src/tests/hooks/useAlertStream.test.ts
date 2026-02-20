/**
 * Tests for useAlertStream
 *
 * Covers:
 *  - Initial state
 *  - No-token guard (stays disconnected)
 *  - WebSocket URL construction
 *  - State transition: disconnected → connected
 *  - Message handling: alert, non-alert, malformed JSON
 *  - Reconnect on close (state + timing)
 *  - Reconnect on error (via onerror → close chain)
 *  - Cleanup on unmount (no spurious reconnect)
 */

import { renderHook, act } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { useAlertStream } from '../../hooks/useAlertStream'
import { useDetectionStore } from '../../stores/detectionStore'
import type { Detection } from '../../types/api'

// ── Minimal Detection fixture ──────────────────────────────────────────────────

const MOCK_DETECTION: Detection = {
  id: 'det-001',
  score: 9.2,
  severity: 'critical',
  technique_id: 'T1003.001',
  technique_name: 'LSASS Memory Dump',
  name: 'Suspicious LSASS Memory Access',
  host: 'WIN-DC01',
  tactic: 'Credential Access',
  status: 'active',
  time: '2026-02-19T08:30:00Z',
  related_technique_ids: [],
}

// ── Mock WebSocket ─────────────────────────────────────────────────────────────

class MockWebSocket {
  static instances: MockWebSocket[] = []

  url: string
  onopen: ((event: Event) => void) | null = null
  onmessage: ((event: MessageEvent) => void) | null = null
  onclose: ((event: CloseEvent) => void) | null = null
  onerror: ((event: Event) => void) | null = null
  readyState = 0 // CONNECTING

  constructor(url: string) {
    this.url = url
    MockWebSocket.instances.push(this)
  }

  /** Simulate server closing / network drop */
  close() {
    this.readyState = 3 // CLOSED
    if (this.onclose) this.onclose(new CloseEvent('close'))
  }

  // ── Helpers for simulating server-side events ──────────────────────────────

  simulateOpen() {
    this.readyState = 1 // OPEN
    if (this.onopen) this.onopen(new Event('open'))
  }

  simulateMessage(data: unknown) {
    if (this.onmessage) {
      this.onmessage(new MessageEvent('message', { data: JSON.stringify(data) }))
    }
  }

  simulateRawMessage(raw: string) {
    if (this.onmessage) {
      this.onmessage(new MessageEvent('message', { data: raw }))
    }
  }

  simulateClose() {
    this.readyState = 3
    if (this.onclose) this.onclose(new CloseEvent('close'))
  }

  simulateError() {
    if (this.onerror) this.onerror(new Event('error'))
  }
}

// ── Test helpers ───────────────────────────────────────────────────────────────

const TOKEN = 'test-jwt-token-abc123'

function latestWs(): MockWebSocket {
  const instances = MockWebSocket.instances
  expect(instances.length).toBeGreaterThan(0)
  return instances[instances.length - 1]
}

// ── Suite ──────────────────────────────────────────────────────────────────────

describe('useAlertStream', () => {
  beforeEach(() => {
    MockWebSocket.instances = []
    vi.stubGlobal('WebSocket', MockWebSocket)
    vi.useFakeTimers()
    localStorage.setItem('access_token', TOKEN)
    // Reset live alerts between tests
    useDetectionStore.setState({ liveAlerts: [] })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    vi.useRealTimers()
    localStorage.removeItem('access_token')
  })

  // ── Initial state ────────────────────────────────────────────────────────────

  describe('initial state', () => {
    it('returns "disconnected" before the WS connection opens', () => {
      const { result } = renderHook(() => useAlertStream())
      // WS has been created but onopen hasn't fired yet
      expect(result.current).toBe('disconnected')
    })

    it('creates exactly one WebSocket on mount', () => {
      renderHook(() => useAlertStream())
      expect(MockWebSocket.instances).toHaveLength(1)
    })
  })

  // ── No-token guard ───────────────────────────────────────────────────────────

  describe('no access token', () => {
    it('does not create a WebSocket when no token is in localStorage', () => {
      localStorage.removeItem('access_token')
      renderHook(() => useAlertStream())
      expect(MockWebSocket.instances).toHaveLength(0)
    })

    it('stays "disconnected" when no token is present', () => {
      localStorage.removeItem('access_token')
      const { result } = renderHook(() => useAlertStream())
      expect(result.current).toBe('disconnected')
    })
  })

  // ── URL construction ─────────────────────────────────────────────────────────

  describe('WebSocket URL', () => {
    it('uses ws:// for http pages', () => {
      // jsdom default is http:
      renderHook(() => useAlertStream())
      expect(latestWs().url).toMatch(/^ws:\/\//)
    })

    it('includes the API path /api/v1/ws/alerts', () => {
      renderHook(() => useAlertStream())
      expect(latestWs().url).toContain('/api/v1/ws/alerts')
    })

    it('appends the token as a query parameter', () => {
      renderHook(() => useAlertStream())
      expect(latestWs().url).toContain(`token=${encodeURIComponent(TOKEN)}`)
    })

    it('URL-encodes special characters in the token', () => {
      const specialToken = 'tok/en+with=specials'
      localStorage.setItem('access_token', specialToken)
      renderHook(() => useAlertStream())
      expect(latestWs().url).toContain(`token=${encodeURIComponent(specialToken)}`)
    })
  })

  // ── State transitions ────────────────────────────────────────────────────────

  describe('state transitions', () => {
    it('becomes "connected" when the WebSocket opens', () => {
      const { result } = renderHook(() => useAlertStream())
      act(() => latestWs().simulateOpen())
      expect(result.current).toBe('connected')
    })

    it('becomes "reconnecting" when the WebSocket closes', () => {
      const { result } = renderHook(() => useAlertStream())
      act(() => latestWs().simulateOpen())
      act(() => latestWs().simulateClose())
      expect(result.current).toBe('reconnecting')
    })
  })

  // ── Message handling ─────────────────────────────────────────────────────────

  describe('message handling', () => {
    it('calls addLiveAlert when an alert message is received', () => {
      renderHook(() => useAlertStream())
      act(() => latestWs().simulateOpen())

      act(() => {
        latestWs().simulateMessage({ type: 'alert', data: MOCK_DETECTION })
      })

      const { liveAlerts } = useDetectionStore.getState()
      expect(liveAlerts).toHaveLength(1)
      expect(liveAlerts[0]).toEqual(MOCK_DETECTION)
    })

    it('prepends new alerts so the latest is first', () => {
      const second: Detection = { ...MOCK_DETECTION, id: 'det-002' }

      renderHook(() => useAlertStream())
      act(() => latestWs().simulateOpen())

      act(() => latestWs().simulateMessage({ type: 'alert', data: MOCK_DETECTION }))
      act(() => latestWs().simulateMessage({ type: 'alert', data: second }))

      const { liveAlerts } = useDetectionStore.getState()
      expect(liveAlerts[0].id).toBe('det-002')
      expect(liveAlerts[1].id).toBe('det-001')
    })

    it('ignores messages whose type is not "alert"', () => {
      renderHook(() => useAlertStream())
      act(() => latestWs().simulateOpen())

      act(() => {
        latestWs().simulateMessage({ type: 'heartbeat' })
        latestWs().simulateMessage({ type: 'status', data: MOCK_DETECTION })
      })

      expect(useDetectionStore.getState().liveAlerts).toHaveLength(0)
    })

    it('ignores alert messages that have no data field', () => {
      renderHook(() => useAlertStream())
      act(() => latestWs().simulateOpen())

      act(() => {
        latestWs().simulateMessage({ type: 'alert' })
      })

      expect(useDetectionStore.getState().liveAlerts).toHaveLength(0)
    })

    it('silently ignores malformed (non-JSON) messages', () => {
      renderHook(() => useAlertStream())
      act(() => latestWs().simulateOpen())

      // Should not throw
      act(() => {
        latestWs().simulateRawMessage('this is not json {{{}')
      })

      expect(useDetectionStore.getState().liveAlerts).toHaveLength(0)
    })

    it('silently ignores an empty string message', () => {
      renderHook(() => useAlertStream())
      act(() => latestWs().simulateOpen())

      act(() => {
        latestWs().simulateRawMessage('')
      })

      expect(useDetectionStore.getState().liveAlerts).toHaveLength(0)
    })
  })

  // ── Reconnect on close ───────────────────────────────────────────────────────

  describe('reconnect on close', () => {
    it('does not reconnect immediately after close', () => {
      renderHook(() => useAlertStream())
      act(() => latestWs().simulateOpen())
      act(() => latestWs().simulateClose())

      // Still only 1 WebSocket
      expect(MockWebSocket.instances).toHaveLength(1)
    })

    it('creates a new WebSocket after the reconnect delay (5 s)', () => {
      renderHook(() => useAlertStream())
      act(() => latestWs().simulateOpen())
      act(() => latestWs().simulateClose())

      act(() => {
        vi.advanceTimersByTime(5_000)
      })

      expect(MockWebSocket.instances).toHaveLength(2)
    })

    it('does not reconnect before the 5 s delay elapses', () => {
      renderHook(() => useAlertStream())
      act(() => latestWs().simulateOpen())
      act(() => latestWs().simulateClose())

      act(() => {
        vi.advanceTimersByTime(4_999)
      })

      expect(MockWebSocket.instances).toHaveLength(1)
    })

    it('becomes "connected" again after successful reconnect', () => {
      const { result } = renderHook(() => useAlertStream())
      act(() => latestWs().simulateOpen())
      act(() => latestWs().simulateClose())

      act(() => {
        vi.advanceTimersByTime(5_000)
      })

      // Second WS opened
      act(() => latestWs().simulateOpen())
      expect(result.current).toBe('connected')
    })

    it('reconnect state is "reconnecting" during the 5 s window', () => {
      const { result } = renderHook(() => useAlertStream())
      act(() => latestWs().simulateOpen())
      act(() => latestWs().simulateClose())

      act(() => vi.advanceTimersByTime(2_500))
      expect(result.current).toBe('reconnecting')
    })
  })

  // ── Reconnect on error ───────────────────────────────────────────────────────

  describe('reconnect on error', () => {
    it('transitions to "reconnecting" when an error fires', () => {
      const { result } = renderHook(() => useAlertStream())
      act(() => latestWs().simulateOpen())

      act(() => {
        // onerror → hook calls ws.close() → onclose fires (if not cleared)
        // MockWebSocket.simulateError triggers onerror
        // The hook's onerror handler calls ws.close() which calls onclose
        latestWs().simulateError()
      })

      expect(result.current).toBe('reconnecting')
    })

    it('creates a new WebSocket after error + 5 s delay', () => {
      renderHook(() => useAlertStream())
      act(() => latestWs().simulateOpen())
      act(() => latestWs().simulateError())

      act(() => {
        vi.advanceTimersByTime(5_000)
      })

      expect(MockWebSocket.instances).toHaveLength(2)
    })
  })

  // ── Cleanup on unmount ───────────────────────────────────────────────────────

  describe('cleanup on unmount', () => {
    it('closes the WebSocket when the hook unmounts', () => {
      const { unmount } = renderHook(() => useAlertStream())
      act(() => latestWs().simulateOpen())

      const ws = latestWs()
      act(() => unmount())

      expect(ws.readyState).toBe(3) // CLOSED
    })

    it('does not create a new WebSocket after unmount even when the timer fires', () => {
      const { unmount } = renderHook(() => useAlertStream())
      act(() => latestWs().simulateOpen())
      act(() => latestWs().simulateClose())

      // Unmount before the reconnect timer fires
      act(() => unmount())

      // Advancing past the delay should NOT trigger a new connection
      act(() => {
        vi.advanceTimersByTime(10_000)
      })

      expect(MockWebSocket.instances).toHaveLength(1)
    })

    it('clears a pending reconnect timer on unmount', () => {
      const { unmount } = renderHook(() => useAlertStream())
      act(() => latestWs().simulateOpen())
      act(() => latestWs().simulateClose())

      // Unmount while 'reconnecting'
      act(() => unmount())

      // Spy: clearTimeout should prevent the callback from running
      const clearSpy = vi.spyOn(globalThis, 'clearTimeout')
      // No new connection after a full delay
      act(() => vi.advanceTimersByTime(5_000))
      // Whether clearTimeout was called is implementation detail;
      // the important assertion is that no extra WS was created.
      expect(MockWebSocket.instances).toHaveLength(1)
      clearSpy.mockRestore()
    })

    it('removes onclose and onerror handlers before closing to prevent reconnect', () => {
      const { unmount } = renderHook(() => useAlertStream())
      act(() => latestWs().simulateOpen())

      const ws = latestWs()
      act(() => unmount())

      // After cleanup the handlers are nullified so close() won't trigger reconnect
      expect(ws.onclose).toBeNull()
      expect(ws.onerror).toBeNull()
    })

    it('does not reconnect when token is removed and mount fires connect', () => {
      // Token present initially, removed before timer fires
      const { unmount } = renderHook(() => useAlertStream())
      act(() => latestWs().simulateOpen())
      act(() => latestWs().simulateClose())

      localStorage.removeItem('access_token')
      act(() => unmount())

      act(() => vi.advanceTimersByTime(5_000))
      // No additional WebSocket instances
      expect(MockWebSocket.instances).toHaveLength(1)
    })
  })
})
