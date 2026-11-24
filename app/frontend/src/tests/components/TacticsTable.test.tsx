import { render, screen, within } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { TacticsTable } from '../../components/features/overview/TacticsTable'
import type { TacticBar } from '../../types/api'

const data: TacticBar[] = [
  { tactic: 'Execution', count: 1200, trend_pct: 18 },
  { tactic: 'Persistence', count: 600, trend_pct: -4 },
  { tactic: 'Discovery', count: 0, trend_pct: 0 },
]

describe('TacticsTable', () => {
  it('shows the heading and the selected range', () => {
    render(<TacticsTable data={data} rangeLabel="last 30 days" />)
    expect(screen.getByRole('heading', { name: 'Top ATT&CK tactics' })).toBeInTheDocument()
    expect(screen.getByText('Detections by tactic, last 30 days')).toBeInTheDocument()
  })

  it('lists one row per tactic, in the order given', () => {
    render(<TacticsTable data={data} rangeLabel="last 7 days" />)
    const items = screen.getAllByRole('listitem')
    expect(items).toHaveLength(3)
    expect(within(items[0]).getByText('Execution')).toBeInTheDocument()
    expect(within(items[1]).getByText('Persistence')).toBeInTheDocument()
    expect(within(items[2]).getByText('Discovery')).toBeInTheDocument()
  })

  it('shows the count with thousands separators and a signed trend', () => {
    render(<TacticsTable data={data} rangeLabel="last 7 days" />)
    const [execution, persistence, discovery] = screen.getAllByRole('listitem')
    expect(execution).toHaveTextContent('1,200')
    expect(execution).toHaveTextContent('+18%')
    expect(persistence).toHaveTextContent('600')
    expect(persistence).toHaveTextContent('-4%')
    expect(discovery).toHaveTextContent('Discovery0')
  })

  it('shows no trend when there is nothing to compare with', () => {
    // The API sends 0 when the previous period had no detections of the tactic.
    render(<TacticsTable data={[{ tactic: 'Execution', count: 5, trend_pct: 0 }]} rangeLabel="last 7 days" />)
    const row = screen.getByRole('listitem')
    expect(row).toHaveTextContent('Execution5')
    expect(row).not.toHaveTextContent('%')
  })

  it('shows an empty state when there are no tactics', () => {
    render(<TacticsTable data={[]} rangeLabel="last 7 days" />)
    expect(screen.getByText('No tactics observed yet')).toBeInTheDocument()
    expect(screen.queryByRole('list')).not.toBeInTheDocument()
  })
})
