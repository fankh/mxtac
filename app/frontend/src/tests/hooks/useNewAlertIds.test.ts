import { renderHook, act } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { useNewAlertIds } from '../../hooks/useNewAlertIds'
import { useDetectionStore } from '../../stores/detectionStore'
import type { Detection } from '../../types/api'

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

const makeDetection = (overrides: Partial<Detection> = {}): Detection => ({
  id: 'det-1',
  score: 85,
  severity: 'high',
  technique_id: 'T1059',
  technique_name: 'Command and Scripting Interpreter',
  name: 'Suspicious PowerShell',
  host: 'workstation-01',
  tactic: 'Execution',
  status: 'active',
  time: '2024-01-15T10:00:00Z',
  related_technique_ids: [],
  ...overrides,
})

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

describe('useNewAlertIds', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    useDetectionStore.setState({ liveAlerts: [] })
  })

  afterEach(() => {
    vi.useRealTimers()
    useDetectionStore.setState({ liveAlerts: [] })
  })

  // =========================================================================
  // Initial state
  // =========================================================================
  describe('initial state', () => {
    it('returns an empty set on mount', () => {
      const { result } = renderHook(() => useNewAlertIds())
      expect(result.current.size).toBe(0)
    })

    it('returns an empty set when liveAlerts is empty', () => {
      useDetectionStore.setState({ liveAlerts: [] })
      const { result } = renderHook(() => useNewAlertIds())
      expect(result.current.size).toBe(0)
    })
  })

  // =========================================================================
  // Single alert
  // =========================================================================
  describe('single alert', () => {
    it('includes the alert ID immediately after addLiveAlert', () => {
      const { result } = renderHook(() => useNewAlertIds())

      act(() => {
        useDetectionStore.getState().addLiveAlert(makeDetection({ id: 'alert-a' }))
      })

      expect(result.current.has('alert-a')).toBe(true)
    })

    it('size is 1 after one alert', () => {
      const { result } = renderHook(() => useNewAlertIds())

      act(() => {
        useDetectionStore.getState().addLiveAlert(makeDetection({ id: 'alert-a' }))
      })

      expect(result.current.size).toBe(1)
    })

    it('removes the alert ID after 31 s', () => {
      const { result } = renderHook(() => useNewAlertIds())

      act(() => {
        useDetectionStore.getState().addLiveAlert(makeDetection({ id: 'alert-a' }))
      })

      expect(result.current.has('alert-a')).toBe(true)

      act(() => {
        vi.advanceTimersByTime(31_000)
      })

      expect(result.current.has('alert-a')).toBe(false)
    })

    it('still has the ID at 30 s (not yet removed)', () => {
      const { result } = renderHook(() => useNewAlertIds())

      act(() => {
        useDetectionStore.getState().addLiveAlert(makeDetection({ id: 'alert-a' }))
      })

      act(() => {
        vi.advanceTimersByTime(30_000)
      })

      expect(result.current.has('alert-a')).toBe(true)
    })

    it('set is empty after 31 s', () => {
      const { result } = renderHook(() => useNewAlertIds())

      act(() => {
        useDetectionStore.getState().addLiveAlert(makeDetection({ id: 'alert-a' }))
      })

      act(() => {
        vi.advanceTimersByTime(31_000)
      })

      expect(result.current.size).toBe(0)
    })
  })

  // =========================================================================
  // Multiple alerts
  // =========================================================================
  describe('multiple alerts', () => {
    it('includes all IDs when multiple alerts arrive', () => {
      const { result } = renderHook(() => useNewAlertIds())

      act(() => {
        useDetectionStore.getState().addLiveAlert(makeDetection({ id: 'a1' }))
        useDetectionStore.getState().addLiveAlert(makeDetection({ id: 'a2' }))
        useDetectionStore.getState().addLiveAlert(makeDetection({ id: 'a3' }))
      })

      expect(result.current.has('a1')).toBe(true)
      expect(result.current.has('a2')).toBe(true)
      expect(result.current.has('a3')).toBe(true)
    })

    it('size equals the number of unique alerts added', () => {
      const { result } = renderHook(() => useNewAlertIds())

      act(() => {
        useDetectionStore.getState().addLiveAlert(makeDetection({ id: 'a1' }))
        useDetectionStore.getState().addLiveAlert(makeDetection({ id: 'a2' }))
      })

      expect(result.current.size).toBe(2)
    })

    it('removes all IDs after 31 s', () => {
      const { result } = renderHook(() => useNewAlertIds())

      act(() => {
        useDetectionStore.getState().addLiveAlert(makeDetection({ id: 'a1' }))
        useDetectionStore.getState().addLiveAlert(makeDetection({ id: 'a2' }))
      })

      act(() => {
        vi.advanceTimersByTime(31_000)
      })

      expect(result.current.size).toBe(0)
    })

    it('does not double-track the same alert ID', () => {
      const { result } = renderHook(() => useNewAlertIds())
      const alert = makeDetection({ id: 'dup-id' })

      act(() => {
        useDetectionStore.getState().addLiveAlert(alert)
      })

      // Manually trigger a re-render by "adding" the same state (no actual change)
      act(() => {
        // Simulate re-render without adding a new alert — set is unchanged
        useDetectionStore.setState((s) => ({ liveAlerts: [...s.liveAlerts] }))
      })

      expect(result.current.size).toBe(1)
    })
  })

  // =========================================================================
  // Staggered alerts
  // =========================================================================
  describe('staggered alerts', () => {
    it('only early IDs expire when timer fires at 31 s from first alert', () => {
      const { result } = renderHook(() => useNewAlertIds())

      act(() => {
        useDetectionStore.getState().addLiveAlert(makeDetection({ id: 'early' }))
      })

      // Advance 20 s — add a second alert mid-way
      act(() => {
        vi.advanceTimersByTime(20_000)
        useDetectionStore.getState().addLiveAlert(makeDetection({ id: 'later' }))
      })

      // Advance another 11 s — total: 31 s from 'early', only 11 s from 'later'
      act(() => {
        vi.advanceTimersByTime(11_000)
      })

      expect(result.current.has('early')).toBe(false)
      expect(result.current.has('later')).toBe(true)
    })

    it('later ID also expires after its own 31 s', () => {
      const { result } = renderHook(() => useNewAlertIds())

      act(() => {
        useDetectionStore.getState().addLiveAlert(makeDetection({ id: 'early' }))
      })

      act(() => {
        vi.advanceTimersByTime(20_000)
        useDetectionStore.getState().addLiveAlert(makeDetection({ id: 'later' }))
      })

      // Advance 31 s from 'later': total 20 + 31 = 51 s elapsed
      act(() => {
        vi.advanceTimersByTime(31_000)
      })

      expect(result.current.has('later')).toBe(false)
    })
  })

  // =========================================================================
  // Cleanup on unmount
  // =========================================================================
  describe('cleanup on unmount', () => {
    it('does not throw or update state after unmount', () => {
      const { result, unmount } = renderHook(() => useNewAlertIds())

      act(() => {
        useDetectionStore.getState().addLiveAlert(makeDetection({ id: 'will-expire' }))
      })

      unmount()

      // Advance time past expiry — no errors or state updates expected
      expect(() => {
        act(() => {
          vi.advanceTimersByTime(31_000)
        })
      }).not.toThrow()
    })
  })
})
