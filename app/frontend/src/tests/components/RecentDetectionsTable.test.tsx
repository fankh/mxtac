import { render, screen, within } from '@testing-library/react'
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { RecentDetectionsTable } from '../../components/features/overview/RecentDetectionsTable'
import type { Detection } from '../../types/api'

const detections: Detection[] = [
  {
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
  },
  {
    id: 'det-002',
    score: 7.5,
    severity: 'high',
    technique_id: 'T1059.001',
    technique_name: 'PowerShell',
    name: 'Encoded PowerShell Command',
    host: 'WS-FIN-07',
    tactic: 'Execution',
    status: 'resolved',
    time: '2026-02-19T05:30:00Z',
  },
]

function renderTable(data: Detection[] = detections) {
  return render(
    <MemoryRouter>
      <RecentDetectionsTable data={data} />
    </MemoryRouter>,
  )
}

describe('RecentDetectionsTable', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-02-19T10:30:00Z'))
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('shows the heading and a link to all detections', () => {
    renderTable()
    expect(screen.getByRole('heading', { name: 'Recent critical and high detections' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'View all' })).toHaveAttribute('href', '/detections')
  })

  it('shows the column headers', () => {
    renderTable()
    expect(screen.getAllByRole('columnheader').map((h) => h.textContent)).toEqual([
      'Score', 'Detection', 'Technique', 'Host', 'Status', 'Time',
    ])
  })

  it('shows one row per detection with its details', () => {
    renderTable()
    const rows = screen.getAllByRole('row').slice(1)
    expect(rows).toHaveLength(2)

    const first = within(rows[0])
    expect(first.getByLabelText('Score 9.2, Critical')).toHaveClass('sev-critical')
    expect(first.getByText('Suspicious LSASS Memory Access')).toBeInTheDocument()
    expect(first.getByText('Credential Access')).toBeInTheDocument()
    expect(first.getByText('T1003.001')).toBeInTheDocument()
    expect(first.getByText('LSASS Memory Dump')).toBeInTheDocument()
    expect(first.getByText('WIN-DC01')).toBeInTheDocument()
    expect(first.getByText('Active')).toHaveClass('sev-critical')
    expect(first.getByText('2 hours ago')).toBeInTheDocument()

    const second = within(rows[1])
    expect(second.getByLabelText('Score 7.5, High')).toHaveClass('sev-high')
    expect(second.getByText('Resolved')).toHaveClass('status-green')
    expect(second.getByText('5 hours ago')).toBeInTheDocument()
  })

  it('leaves the time blank when the timestamp is not a valid date', () => {
    renderTable([{ ...detections[0], time: 'not-a-date' }])
    expect(screen.getByText('WIN-DC01')).toBeInTheDocument()
    expect(screen.queryByText(/ago$/)).not.toBeInTheDocument()
  })

  it('shows an empty state and no table when there are no detections', () => {
    renderTable([])
    expect(screen.getByText('No critical or high detections')).toBeInTheDocument()
    expect(screen.getByText('New alerts appear here as they arrive.')).toBeInTheDocument()
    expect(screen.queryByRole('table')).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'View all' })).toBeInTheDocument()
  })
})
