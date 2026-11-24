import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { StatusPill } from '../../components/shared/StatusPill'
import type { DetectionStatus } from '../../types/api'

const STATUSES: [DetectionStatus, string, string][] = [
  ['active', 'Active', 'sev-critical'],
  ['investigating', 'Investigating', 'sev-high'],
  ['resolved', 'Resolved', 'status-green'],
  ['false_positive', 'False Positive', 'sev-info'],
]

describe('StatusPill', () => {
  it.each(STATUSES)('%s shows the label "%s" with class %s', (status, label, cls) => {
    render(<StatusPill status={status} />)
    expect(screen.getByText(label)).toHaveClass(cls)
  })

  it('shows the raw value for an unknown status', () => {
    render(<StatusPill status={'escalated' as DetectionStatus} />)
    expect(screen.getByText('escalated')).toHaveClass('sev-info')
  })

  it('keeps a caller-supplied class next to the status class', () => {
    render(<StatusPill status="resolved" className="extra" />)
    expect(screen.getByText('Resolved')).toHaveClass('status-green', 'extra')
  })
})
