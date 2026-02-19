import { describe, it, expect, beforeEach } from 'vitest'
import { useDetectionStore } from '../../stores/detectionStore'

describe('detectionStore', () => {
  beforeEach(() => {
    useDetectionStore.setState({
      filters: {
        severity: undefined,
        status: undefined,
        tactic: undefined,
        host: undefined,
        search: undefined,
        sortKey: 'score',
        sortOrder: 'desc',
        page: 1,
        pageSize: 20,
      },
      selected: null,
    })
  })

  it('starts with default filters', () => {
    const { filters } = useDetectionStore.getState()
    expect(filters.sortKey).toBe('score')
    expect(filters.sortOrder).toBe('desc')
    expect(filters.page).toBe(1)
  })

  it('setFilter updates the filter and resets page', () => {
    useDetectionStore.getState().setFilter('severity', 'critical')
    const { filters } = useDetectionStore.getState()
    expect(filters.severity).toBe('critical')
    expect(filters.page).toBe(1)
  })

  it('toggleSort switches order when same key', () => {
    useDetectionStore.getState().toggleSort('score')
    expect(useDetectionStore.getState().filters.sortOrder).toBe('asc')
    useDetectionStore.getState().toggleSort('score')
    expect(useDetectionStore.getState().filters.sortOrder).toBe('desc')
  })

  it('toggleSort changes key when different key', () => {
    useDetectionStore.getState().toggleSort('time')
    const { filters } = useDetectionStore.getState()
    expect(filters.sortKey).toBe('time')
    expect(filters.sortOrder).toBe('desc')
  })

  it('resetFilters restores defaults', () => {
    useDetectionStore.getState().setFilter('severity', 'critical')
    useDetectionStore.getState().resetFilters()
    const { filters } = useDetectionStore.getState()
    expect(filters.severity).toBeUndefined()
    expect(filters.sortKey).toBe('score')
  })
})
