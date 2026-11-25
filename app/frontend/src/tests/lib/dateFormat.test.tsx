import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { HuntResults } from '../../components/features/hunt/HuntResults'
import { formatDateTime as formatEventTime } from '../../components/features/hunt/huntUtils'
import { formatDuration } from '../../components/features/incidents/incidentUtils'
import { formatLastSeen } from '../../components/features/sources/connectorTypes'
import { formatDateTime, formatDateTimeSeconds } from '../../lib/format'

const ISO = '2026-11-24T14:34:48Z'

describe('dates read the same on every page', () => {
  it('shows the year, and the seconds only where asked', () => {
    expect(formatDateTime(ISO)).toMatch(/2026/)
    expect(formatDateTime(ISO)).not.toMatch(/:48/)
    expect(formatDateTimeSeconds(ISO)).toMatch(/2026/)
    expect(formatDateTimeSeconds(ISO)).toMatch(/:34:48/)
  })

  it('uses a dash for a missing or unreadable value', () => {
    expect(formatDateTimeSeconds(null)).toBe('—')
    expect(formatDateTimeSeconds('not a date')).toBe('—')
  })

  it('formats an event time on the Hunt page like the shared format with seconds', () => {
    expect(formatEventTime(ISO)).toBe(formatDateTimeSeconds(ISO))
  })

  it('formats the last-seen time of a source like the shared format', () => {
    expect(formatLastSeen(ISO)).toBe(formatDateTime(ISO))
    expect(formatLastSeen(null)).toBe('Never')
  })
})

describe('durations read the same on Overview and Incidents', () => {
  it.each([
    [45, '45 s'],
    [300, '5 min'],
    [7200, '2.0 h'],
    [129600, '1.5 d'],
  ])('formats %d seconds as %s', (seconds, text) => {
    expect(formatDuration(seconds)).toBe(text)
  })

  it('uses a dash without a value', () => {
    expect(formatDuration(null)).toBe('—')
  })
})

describe('HuntResults when the search fails', () => {
  const props = { data: undefined, loading: false, error: true, onRetry: () => {}, page: 0, onPageChange: () => {}, onSelect: () => {}, lucene: undefined }

  it('shows the reason the server gave, for example the rate limit', () => {
    render(<HuntResults {...props} errorMessage="Too many requests. Try again in 12 seconds." />)
    expect(screen.getByText('The search failed: Too many requests. Try again in 12 seconds.')).toBeInTheDocument()
    expect(screen.queryByText(/Check the query syntax/)).not.toBeInTheDocument()
  })

  it('falls back to the general hint without a reason', () => {
    render(<HuntResults {...props} />)
    expect(screen.getByText('The search failed. Check the query syntax and try again.')).toBeInTheDocument()
  })
})
