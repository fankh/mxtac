import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { AttackHeatmap } from '../../components/features/overview/AttackHeatmap'
import type { HeatRow } from '../../types/api'

const tacticLabels = ['Recon', 'Exec', 'Persist']

const rows: HeatRow[] = [
  {
    technique_id: 'T1059',
    row: 0,
    cells: [
      { tactic: 'Recon', covered: 0, total: 9, opacity: 0 },
      { tactic: 'Exec', covered: 7, total: 14, opacity: 0.5 },
      { tactic: 'Persist', covered: 1, total: 20, opacity: 0.05 },
    ],
  },
  {
    technique_id: 'T1003',
    row: 1,
    cells: [
      { tactic: 'Recon', covered: 9, total: 9, opacity: 1 },
      { tactic: 'Exec', covered: 0, total: 14, opacity: 0 },
      { tactic: 'Persist', covered: 0, total: 20, opacity: 0 },
    ],
  },
]

function renderHeatmap(r: HeatRow[] = rows, labels: string[] = tacticLabels) {
  return render(
    <MemoryRouter>
      <AttackHeatmap rows={r} tacticLabels={labels} />
    </MemoryRouter>,
  )
}

describe('AttackHeatmap', () => {
  it('shows the heading and a link to the coverage page', () => {
    renderHeatmap()
    expect(screen.getByRole('heading', { name: 'ATT&CK coverage heatmap' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Open coverage' })).toHaveAttribute('href', '/coverage')
  })

  it('shows a column label per tactic and a row label per technique', () => {
    renderHeatmap()
    for (const label of [...tacticLabels, 'T1059', 'T1003']) {
      expect(screen.getByText(label)).toBeInTheDocument()
    }
  })

  it('renders one cell per technique and tactic', () => {
    renderHeatmap()
    expect(screen.getAllByTestId('heat-cell')).toHaveLength(6)
  })

  it('describes each cell as covered of total', () => {
    renderHeatmap()
    expect(screen.getByTitle('T1059 · Exec: 7 of 14')).toBeInTheDocument()
    expect(screen.getByTitle('T1003 · Recon: 9 of 9')).toBeInTheDocument()
  })

  it('tints covered cells by opacity and leaves uncovered cells untinted', () => {
    renderHeatmap()
    expect(screen.getByTitle('T1059 · Recon: 0 of 9').style.backgroundColor).toBe('')
    expect(screen.getByTitle('T1059 · Exec: 7 of 14').style.backgroundColor).toContain('0.5')
    // A faint value is raised to a visible minimum
    expect(screen.getByTitle('T1059 · Persist: 1 of 20').style.backgroundColor).toContain('0.3')
  })

  it('shows the legend', () => {
    renderHeatmap()
    expect(screen.getByText('None')).toBeInTheDocument()
    expect(screen.getByText('Full')).toBeInTheDocument()
  })

  it('renders the frame without cells when there is no data', () => {
    renderHeatmap([], [])
    expect(screen.getByRole('heading', { name: 'ATT&CK coverage heatmap' })).toBeInTheDocument()
    expect(screen.queryAllByTestId('heat-cell')).toHaveLength(0)
  })
})
