import { describe, it, expect, beforeEach } from 'vitest'
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

describe('detectionStore', () => {
  beforeEach(() => {
    useDetectionStore.setState({ liveAlerts: [] })
  })

  it('liveAlerts is empty by default', () => {
    expect(useDetectionStore.getInitialState().liveAlerts).toEqual([])
  })

  describe('addLiveAlert', () => {
    it('adds a single alert to the empty list', () => {
      useDetectionStore.getState().addLiveAlert(makeDetection({ id: 'a1' }))
      expect(useDetectionStore.getState().liveAlerts).toHaveLength(1)
    })

    it('stores the alert at index 0 (newest first)', () => {
      const alert = makeDetection({ id: 'newest' })
      useDetectionStore.getState().addLiveAlert(alert)
      expect(useDetectionStore.getState().liveAlerts[0].id).toBe('newest')
    })

    it('prepends new alerts so the most recent is always at index 0', () => {
      useDetectionStore.getState().addLiveAlert(makeDetection({ id: 'first' }))
      useDetectionStore.getState().addLiveAlert(makeDetection({ id: 'second' }))
      useDetectionStore.getState().addLiveAlert(makeDetection({ id: 'third' }))

      const alerts = useDetectionStore.getState().liveAlerts
      expect(alerts[0].id).toBe('third')
      expect(alerts[1].id).toBe('second')
      expect(alerts[2].id).toBe('first')
    })

    it('accumulates alerts up to the MAX_LIVE_ALERTS limit (200)', () => {
      for (let i = 0; i < 200; i++) {
        useDetectionStore.getState().addLiveAlert(makeDetection({ id: `alert-${i}` }))
      }
      expect(useDetectionStore.getState().liveAlerts).toHaveLength(200)
    })

    it('does not exceed MAX_LIVE_ALERTS (200) when an extra alert is added', () => {
      for (let i = 0; i < 201; i++) {
        useDetectionStore.getState().addLiveAlert(makeDetection({ id: `alert-${i}` }))
      }
      expect(useDetectionStore.getState().liveAlerts).toHaveLength(200)
    })

    it('drops the oldest alert when MAX_LIVE_ALERTS is reached', () => {
      // Fill to capacity; alert-0 is added first and ends up at the tail
      for (let i = 0; i < 200; i++) {
        useDetectionStore.getState().addLiveAlert(makeDetection({ id: `alert-${i}` }))
      }
      // alert-199 is at [0], alert-0 is at [199]
      expect(useDetectionStore.getState().liveAlerts[199].id).toBe('alert-0')

      // Adding alert-200 should evict alert-0
      useDetectionStore.getState().addLiveAlert(makeDetection({ id: 'alert-200' }))
      const alerts = useDetectionStore.getState().liveAlerts
      expect(alerts).toHaveLength(200)
      expect(alerts[0].id).toBe('alert-200')
      expect(alerts.find((a) => a.id === 'alert-0')).toBeUndefined()
    })
  })
})
