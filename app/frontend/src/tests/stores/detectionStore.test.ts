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

const DEFAULT_FILTERS = {
  severity: undefined,
  status: undefined,
  tactic: undefined,
  host: undefined,
  search: undefined,
  sortKey: 'score',
  sortOrder: 'desc',
  page: 1,
  pageSize: 20,
} as const

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

describe('detectionStore', () => {
  beforeEach(() => {
    useDetectionStore.setState({
      filters: { ...DEFAULT_FILTERS },
      selected: null,
      liveAlerts: [],
      unreadCount: 0,
    })
  })

  // =========================================================================
  // Default state
  // =========================================================================
  describe('default state', () => {
    it('sortKey defaults to "score"', () => {
      expect(useDetectionStore.getState().filters.sortKey).toBe('score')
    })

    it('sortOrder defaults to "desc"', () => {
      expect(useDetectionStore.getState().filters.sortOrder).toBe('desc')
    })

    it('page defaults to 1', () => {
      expect(useDetectionStore.getState().filters.page).toBe(1)
    })

    it('pageSize defaults to 20', () => {
      expect(useDetectionStore.getState().filters.pageSize).toBe(20)
    })

    it('severity filter is undefined by default', () => {
      expect(useDetectionStore.getState().filters.severity).toBeUndefined()
    })

    it('status filter is undefined by default', () => {
      expect(useDetectionStore.getState().filters.status).toBeUndefined()
    })

    it('tactic filter is undefined by default', () => {
      expect(useDetectionStore.getState().filters.tactic).toBeUndefined()
    })

    it('host filter is undefined by default', () => {
      expect(useDetectionStore.getState().filters.host).toBeUndefined()
    })

    it('search filter is undefined by default', () => {
      expect(useDetectionStore.getState().filters.search).toBeUndefined()
    })

    it('selected is null by default', () => {
      expect(useDetectionStore.getState().selected).toBeNull()
    })

    it('liveAlerts is empty by default', () => {
      expect(useDetectionStore.getState().liveAlerts).toEqual([])
    })
  })

  // =========================================================================
  // setFilter
  // =========================================================================
  describe('setFilter', () => {
    it('updates the severity filter', () => {
      useDetectionStore.getState().setFilter('severity', ['critical'])
      expect(useDetectionStore.getState().filters.severity).toEqual(['critical'])
    })

    it('accepts multiple severity values', () => {
      useDetectionStore.getState().setFilter('severity', ['critical', 'high'])
      expect(useDetectionStore.getState().filters.severity).toEqual(['critical', 'high'])
    })

    it('updates the status filter', () => {
      useDetectionStore.getState().setFilter('status', 'investigating')
      expect(useDetectionStore.getState().filters.status).toBe('investigating')
    })

    it('updates the tactic filter', () => {
      useDetectionStore.getState().setFilter('tactic', 'Execution')
      expect(useDetectionStore.getState().filters.tactic).toBe('Execution')
    })

    it('updates the host filter', () => {
      useDetectionStore.getState().setFilter('host', 'server-42')
      expect(useDetectionStore.getState().filters.host).toBe('server-42')
    })

    it('updates the search filter', () => {
      useDetectionStore.getState().setFilter('search', 'powershell')
      expect(useDetectionStore.getState().filters.search).toBe('powershell')
    })

    it('updates pageSize', () => {
      useDetectionStore.getState().setFilter('pageSize', 50)
      expect(useDetectionStore.getState().filters.pageSize).toBe(50)
    })

    it('resets page to 1 when setting any filter', () => {
      useDetectionStore.setState({ filters: { ...DEFAULT_FILTERS, page: 5 } })
      useDetectionStore.getState().setFilter('tactic', 'Defense Evasion')
      expect(useDetectionStore.getState().filters.page).toBe(1)
    })

    it('resets page to 1 even when already on page 1', () => {
      useDetectionStore.getState().setFilter('host', 'dc-01')
      expect(useDetectionStore.getState().filters.page).toBe(1)
    })

    it('clears a filter by setting it to undefined', () => {
      useDetectionStore.getState().setFilter('tactic', 'Execution')
      useDetectionStore.getState().setFilter('tactic', undefined)
      expect(useDetectionStore.getState().filters.tactic).toBeUndefined()
    })

    it('preserves unrelated filter fields when updating one', () => {
      useDetectionStore.getState().setFilter('status', 'active')
      useDetectionStore.getState().setFilter('tactic', 'Lateral Movement')

      const { filters } = useDetectionStore.getState()
      expect(filters.status).toBe('active')
      expect(filters.tactic).toBe('Lateral Movement')
      expect(filters.sortKey).toBe('score')
      expect(filters.sortOrder).toBe('desc')
      expect(filters.pageSize).toBe(20)
    })
  })

  // =========================================================================
  // resetFilters
  // =========================================================================
  describe('resetFilters', () => {
    it('clears severity filter', () => {
      useDetectionStore.getState().setFilter('severity', ['critical'])
      useDetectionStore.getState().resetFilters()
      expect(useDetectionStore.getState().filters.severity).toBeUndefined()
    })

    it('clears status filter', () => {
      useDetectionStore.getState().setFilter('status', 'resolved')
      useDetectionStore.getState().resetFilters()
      expect(useDetectionStore.getState().filters.status).toBeUndefined()
    })

    it('clears tactic filter', () => {
      useDetectionStore.getState().setFilter('tactic', 'Exfiltration')
      useDetectionStore.getState().resetFilters()
      expect(useDetectionStore.getState().filters.tactic).toBeUndefined()
    })

    it('clears host filter', () => {
      useDetectionStore.getState().setFilter('host', 'dc-01')
      useDetectionStore.getState().resetFilters()
      expect(useDetectionStore.getState().filters.host).toBeUndefined()
    })

    it('clears search filter', () => {
      useDetectionStore.getState().setFilter('search', 'mimikatz')
      useDetectionStore.getState().resetFilters()
      expect(useDetectionStore.getState().filters.search).toBeUndefined()
    })

    it('restores default sortKey', () => {
      useDetectionStore.getState().toggleSort('time')
      useDetectionStore.getState().resetFilters()
      expect(useDetectionStore.getState().filters.sortKey).toBe('score')
    })

    it('restores default sortOrder', () => {
      useDetectionStore.getState().toggleSort('score') // flips to 'asc'
      useDetectionStore.getState().resetFilters()
      expect(useDetectionStore.getState().filters.sortOrder).toBe('desc')
    })

    it('restores page to 1', () => {
      useDetectionStore.setState({ filters: { ...DEFAULT_FILTERS, page: 7 } })
      useDetectionStore.getState().resetFilters()
      expect(useDetectionStore.getState().filters.page).toBe(1)
    })

    it('restores default pageSize', () => {
      useDetectionStore.getState().setFilter('pageSize', 100)
      useDetectionStore.getState().resetFilters()
      expect(useDetectionStore.getState().filters.pageSize).toBe(20)
    })

    it('does not clear the selected detection', () => {
      const det = makeDetection()
      useDetectionStore.getState().setSelected(det)
      useDetectionStore.getState().resetFilters()
      expect(useDetectionStore.getState().selected).toEqual(det)
    })

    it('does not clear liveAlerts', () => {
      useDetectionStore.getState().addLiveAlert(makeDetection())
      useDetectionStore.getState().resetFilters()
      expect(useDetectionStore.getState().liveAlerts).toHaveLength(1)
    })
  })

  // =========================================================================
  // toggleSort
  // =========================================================================
  describe('toggleSort', () => {
    it('flips sortOrder from desc to asc when toggling the active key', () => {
      // Default is sortKey='score', sortOrder='desc'
      useDetectionStore.getState().toggleSort('score')
      expect(useDetectionStore.getState().filters.sortOrder).toBe('asc')
    })

    it('flips sortOrder from asc to desc when toggling the active key again', () => {
      useDetectionStore.getState().toggleSort('score') // desc → asc
      useDetectionStore.getState().toggleSort('score') // asc → desc
      expect(useDetectionStore.getState().filters.sortOrder).toBe('desc')
    })

    it('sets sortOrder to desc when switching to a new key', () => {
      // Currently on 'score' desc; switch to 'time'
      useDetectionStore.getState().toggleSort('time')
      const { filters } = useDetectionStore.getState()
      expect(filters.sortKey).toBe('time')
      expect(filters.sortOrder).toBe('desc')
    })

    it('sets sortOrder to desc when switching keys while order was asc', () => {
      useDetectionStore.getState().toggleSort('score') // score asc
      useDetectionStore.getState().toggleSort('severity') // new key → desc
      const { filters } = useDetectionStore.getState()
      expect(filters.sortKey).toBe('severity')
      expect(filters.sortOrder).toBe('desc')
    })

    it('resets page to 1 when toggling sort', () => {
      useDetectionStore.setState({ filters: { ...DEFAULT_FILTERS, page: 4 } })
      useDetectionStore.getState().toggleSort('score')
      expect(useDetectionStore.getState().filters.page).toBe(1)
    })

    it('works with sort key "time"', () => {
      useDetectionStore.getState().toggleSort('time')
      expect(useDetectionStore.getState().filters.sortKey).toBe('time')
    })

    it('works with sort key "severity"', () => {
      useDetectionStore.getState().toggleSort('severity')
      expect(useDetectionStore.getState().filters.sortKey).toBe('severity')
    })

    it('works with sort key "host"', () => {
      useDetectionStore.getState().toggleSort('host')
      expect(useDetectionStore.getState().filters.sortKey).toBe('host')
    })

    it('works with sort key "tactic"', () => {
      useDetectionStore.getState().toggleSort('tactic')
      expect(useDetectionStore.getState().filters.sortKey).toBe('tactic')
    })

    it('preserves unrelated filter fields when toggling sort', () => {
      useDetectionStore.getState().setFilter('status', 'active')
      useDetectionStore.getState().toggleSort('host')
      expect(useDetectionStore.getState().filters.status).toBe('active')
    })
  })

  // =========================================================================
  // setSelected
  // =========================================================================
  describe('setSelected', () => {
    it('stores the provided detection', () => {
      const det = makeDetection({ id: 'det-abc', name: 'Credential Dumping' })
      useDetectionStore.getState().setSelected(det)
      expect(useDetectionStore.getState().selected).toEqual(det)
    })

    it('replaces a previously selected detection', () => {
      const first = makeDetection({ id: 'first' })
      const second = makeDetection({ id: 'second', name: 'New Detection' })
      useDetectionStore.getState().setSelected(first)
      useDetectionStore.getState().setSelected(second)
      expect(useDetectionStore.getState().selected?.id).toBe('second')
    })

    it('clears the selection when called with null', () => {
      useDetectionStore.getState().setSelected(makeDetection())
      useDetectionStore.getState().setSelected(null)
      expect(useDetectionStore.getState().selected).toBeNull()
    })

    it('does not affect filters when a detection is selected', () => {
      useDetectionStore.getState().setFilter('status', 'active')
      useDetectionStore.getState().setSelected(makeDetection())
      expect(useDetectionStore.getState().filters.status).toBe('active')
    })
  })

  // =========================================================================
  // nextPage
  // =========================================================================
  describe('nextPage', () => {
    it('increments page from 1 to 2', () => {
      useDetectionStore.getState().nextPage()
      expect(useDetectionStore.getState().filters.page).toBe(2)
    })

    it('increments page on each successive call', () => {
      useDetectionStore.getState().nextPage()
      useDetectionStore.getState().nextPage()
      useDetectionStore.getState().nextPage()
      expect(useDetectionStore.getState().filters.page).toBe(4)
    })

    it('preserves all other filter fields when paginating forward', () => {
      useDetectionStore.getState().setFilter('tactic', 'Collection')
      // setFilter resets page to 1; now move forward
      useDetectionStore.getState().nextPage()
      const { filters } = useDetectionStore.getState()
      expect(filters.tactic).toBe('Collection')
      expect(filters.page).toBe(2)
    })
  })

  // =========================================================================
  // prevPage
  // =========================================================================
  describe('prevPage', () => {
    it('decrements page from 2 to 1', () => {
      useDetectionStore.setState({ filters: { ...DEFAULT_FILTERS, page: 2 } })
      useDetectionStore.getState().prevPage()
      expect(useDetectionStore.getState().filters.page).toBe(1)
    })

    it('decrements page from 5 to 4', () => {
      useDetectionStore.setState({ filters: { ...DEFAULT_FILTERS, page: 5 } })
      useDetectionStore.getState().prevPage()
      expect(useDetectionStore.getState().filters.page).toBe(4)
    })

    it('does not go below page 1', () => {
      // page is already 1 (default)
      useDetectionStore.getState().prevPage()
      expect(useDetectionStore.getState().filters.page).toBe(1)
    })

    it('stays at 1 on repeated prevPage calls from page 1', () => {
      useDetectionStore.getState().prevPage()
      useDetectionStore.getState().prevPage()
      useDetectionStore.getState().prevPage()
      expect(useDetectionStore.getState().filters.page).toBe(1)
    })

    it('preserves all other filter fields when paginating backward', () => {
      useDetectionStore.setState({
        filters: { ...DEFAULT_FILTERS, page: 3, host: 'dc-01' },
      })
      useDetectionStore.getState().prevPage()
      const { filters } = useDetectionStore.getState()
      expect(filters.host).toBe('dc-01')
      expect(filters.page).toBe(2)
    })
  })

  // =========================================================================
  // addLiveAlert
  // =========================================================================
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

    it('does not affect filters when a live alert is added', () => {
      useDetectionStore.getState().setFilter('status', 'active')
      useDetectionStore.getState().addLiveAlert(makeDetection())
      expect(useDetectionStore.getState().filters.status).toBe('active')
    })

    it('does not affect selected when a live alert is added', () => {
      const det = makeDetection({ id: 'selected-det' })
      useDetectionStore.getState().setSelected(det)
      useDetectionStore.getState().addLiveAlert(makeDetection({ id: 'live-1' }))
      expect(useDetectionStore.getState().selected?.id).toBe('selected-det')
    })
  })

  // =========================================================================
  // unreadCount
  // =========================================================================
  describe('unreadCount', () => {
    it('defaults to 0', () => {
      expect(useDetectionStore.getState().unreadCount).toBe(0)
    })

    it('increments by 1 when addLiveAlert is called', () => {
      useDetectionStore.getState().addLiveAlert(makeDetection({ id: 'a1' }))
      expect(useDetectionStore.getState().unreadCount).toBe(1)
    })

    it('increments on each successive addLiveAlert call', () => {
      useDetectionStore.getState().addLiveAlert(makeDetection({ id: 'a1' }))
      useDetectionStore.getState().addLiveAlert(makeDetection({ id: 'a2' }))
      useDetectionStore.getState().addLiveAlert(makeDetection({ id: 'a3' }))
      expect(useDetectionStore.getState().unreadCount).toBe(3)
    })

    it('does not affect liveAlerts count tracking', () => {
      useDetectionStore.getState().addLiveAlert(makeDetection({ id: 'a1' }))
      useDetectionStore.getState().addLiveAlert(makeDetection({ id: 'a2' }))
      expect(useDetectionStore.getState().liveAlerts).toHaveLength(2)
      expect(useDetectionStore.getState().unreadCount).toBe(2)
    })
  })

  // =========================================================================
  // clearUnread
  // =========================================================================
  describe('clearUnread', () => {
    it('resets unreadCount to 0', () => {
      useDetectionStore.getState().addLiveAlert(makeDetection({ id: 'a1' }))
      useDetectionStore.getState().addLiveAlert(makeDetection({ id: 'a2' }))
      useDetectionStore.getState().clearUnread()
      expect(useDetectionStore.getState().unreadCount).toBe(0)
    })

    it('is a no-op when unreadCount is already 0', () => {
      useDetectionStore.getState().clearUnread()
      expect(useDetectionStore.getState().unreadCount).toBe(0)
    })

    it('does not affect liveAlerts', () => {
      useDetectionStore.getState().addLiveAlert(makeDetection({ id: 'a1' }))
      useDetectionStore.getState().clearUnread()
      expect(useDetectionStore.getState().liveAlerts).toHaveLength(1)
    })

    it('does not affect filters', () => {
      useDetectionStore.getState().setFilter('status', 'active')
      useDetectionStore.getState().addLiveAlert(makeDetection())
      useDetectionStore.getState().clearUnread()
      expect(useDetectionStore.getState().filters.status).toBe('active')
    })

    it('unreadCount can be incremented again after being cleared', () => {
      useDetectionStore.getState().addLiveAlert(makeDetection({ id: 'a1' }))
      useDetectionStore.getState().clearUnread()
      useDetectionStore.getState().addLiveAlert(makeDetection({ id: 'a2' }))
      expect(useDetectionStore.getState().unreadCount).toBe(1)
    })
  })
})
