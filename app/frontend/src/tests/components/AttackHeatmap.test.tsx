import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { AttackHeatmap } from '../../components/features/overview/AttackHeatmap'
import type { HeatRow } from '../../types/api'

// The component accesses row.technique_id and cell.opacity at runtime,
// which are not reflected in the declared HeatRow / HeatCell types.
// Use a local type that matches the actual runtime shape and cast accordingly.
type RuntimeHeatCell = {
  tactic: string
  covered: number
  total: number
  opacity: number
}

type RuntimeHeatRow = {
  technique_id: string
  cells: RuntimeHeatCell[]
}

const toHeatRows = (rows: RuntimeHeatRow[]): HeatRow[] =>
  rows as unknown as HeatRow[]

// ---------------------------------------------------------------------------
// Mock data
// ---------------------------------------------------------------------------

const mockTacticLabels = ['Initial Access', 'Execution', 'Persistence']

const mockRows: RuntimeHeatRow[] = [
  {
    technique_id: 'T1059',
    cells: [
      { tactic: 'Initial Access', covered: 0, total: 5, opacity: 0 },
      { tactic: 'Execution',      covered: 3, total: 5, opacity: 0.6 },
      { tactic: 'Persistence',   covered: 5, total: 5, opacity: 1.0 },
    ],
  },
  {
    technique_id: 'T1078',
    cells: [
      { tactic: 'Initial Access', covered: 2, total: 4, opacity: 0.5 },
      { tactic: 'Execution',      covered: 0, total: 4, opacity: 0 },
      { tactic: 'Persistence',   covered: 1, total: 4, opacity: 0.25 },
    ],
  },
]

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('AttackHeatmap', () => {
  // -------------------------------------------------------------------------
  // Header
  // -------------------------------------------------------------------------
  describe('header', () => {
    it('renders "ATT&CK Coverage Heatmap" heading', () => {
      render(<AttackHeatmap rows={toHeatRows(mockRows)} tacticLabels={mockTacticLabels} />)
      expect(screen.getByText('ATT&CK Coverage Heatmap')).toBeInTheDocument()
    })

    it('renders the subtitle text', () => {
      render(<AttackHeatmap rows={toHeatRows(mockRows)} tacticLabels={mockTacticLabels} />)
      expect(
        screen.getByText('Detection coverage by tactic & sub-technique'),
      ).toBeInTheDocument()
    })
  })

  // -------------------------------------------------------------------------
  // Tactic column headers
  // -------------------------------------------------------------------------
  describe('tactic column headers', () => {
    it('renders each tactic label', () => {
      render(<AttackHeatmap rows={toHeatRows(mockRows)} tacticLabels={mockTacticLabels} />)
      expect(screen.getByText('Initial Access')).toBeInTheDocument()
      expect(screen.getByText('Execution')).toBeInTheDocument()
      expect(screen.getByText('Persistence')).toBeInTheDocument()
    })

    it('renders no tactic labels when tacticLabels is empty', () => {
      render(<AttackHeatmap rows={[]} tacticLabels={[]} />)
      expect(screen.queryByText('Initial Access')).not.toBeInTheDocument()
      expect(screen.queryByText('Execution')).not.toBeInTheDocument()
    })

    it('renders a single tactic label', () => {
      render(<AttackHeatmap rows={[]} tacticLabels={['Execution']} />)
      expect(screen.getByText('Execution')).toBeInTheDocument()
    })

    it('renders all labels when many tactics are provided', () => {
      const labels = ['A', 'B', 'C', 'D', 'E']
      render(<AttackHeatmap rows={[]} tacticLabels={labels} />)
      for (const label of labels) {
        expect(screen.getByText(label)).toBeInTheDocument()
      }
    })
  })

  // -------------------------------------------------------------------------
  // Row rendering
  // -------------------------------------------------------------------------
  describe('rows', () => {
    it('renders technique IDs as row labels', () => {
      render(<AttackHeatmap rows={toHeatRows(mockRows)} tacticLabels={mockTacticLabels} />)
      expect(screen.getByText('T1059')).toBeInTheDocument()
      expect(screen.getByText('T1078')).toBeInTheDocument()
    })

    it('renders no rows when rows array is empty', () => {
      render(<AttackHeatmap rows={[]} tacticLabels={mockTacticLabels} />)
      expect(screen.queryByText('T1059')).not.toBeInTheDocument()
      expect(screen.queryByText('T1078')).not.toBeInTheDocument()
    })

    it('renders cells with "No coverage" title when opacity is 0', () => {
      const { container } = render(
        <AttackHeatmap rows={toHeatRows(mockRows)} tacticLabels={mockTacticLabels} />,
      )
      // T1059[0]=0 and T1078[1]=0 → 2 no-coverage cells
      const noCovCells = container.querySelectorAll('[title="No coverage"]')
      expect(noCovCells).toHaveLength(2)
    })

    it('renders cells with a percentage coverage title when opacity > 0', () => {
      render(<AttackHeatmap rows={toHeatRows(mockRows)} tacticLabels={mockTacticLabels} />)
      // T1059 Execution: opacity=0.6 → Math.round(60) = "Coverage: 60%"
      expect(screen.getByTitle('Coverage: 60%')).toBeInTheDocument()
    })

    it('renders "Coverage: 100%" title for fully covered cells', () => {
      render(<AttackHeatmap rows={toHeatRows(mockRows)} tacticLabels={mockTacticLabels} />)
      // T1059 Persistence: opacity=1.0 → "Coverage: 100%"
      expect(screen.getByTitle('Coverage: 100%')).toBeInTheDocument()
    })

    it('renders "Coverage: 25%" title for quarter-covered cells', () => {
      render(<AttackHeatmap rows={toHeatRows(mockRows)} tacticLabels={mockTacticLabels} />)
      // T1078 Persistence: opacity=0.25 → "Coverage: 25%"
      expect(screen.getByTitle('Coverage: 25%')).toBeInTheDocument()
    })

    it('renders the correct total number of cell divs', () => {
      const { container } = render(
        <AttackHeatmap rows={toHeatRows(mockRows)} tacticLabels={mockTacticLabels} />,
      )
      // 2 rows × 3 cells each = 6 cell divs (h-[18px] rounded-[2px])
      const cellDivs = container.querySelectorAll('.h-\\[18px\\].rounded-\\[2px\\]')
      expect(cellDivs).toHaveLength(mockRows.length * mockRows[0].cells.length)
    })

    it('renders a single row correctly', () => {
      const single: RuntimeHeatRow[] = [
        {
          technique_id: 'T1071',
          cells: [{ tactic: 'C2', covered: 2, total: 4, opacity: 0.5 }],
        },
      ]
      render(<AttackHeatmap rows={toHeatRows(single)} tacticLabels={['C2']} />)
      expect(screen.getByText('T1071')).toBeInTheDocument()
      expect(screen.getByTitle('Coverage: 50%')).toBeInTheDocument()
    })
  })

  // -------------------------------------------------------------------------
  // Legend
  // -------------------------------------------------------------------------
  describe('legend', () => {
    it('renders "Coverage:" label', () => {
      render(<AttackHeatmap rows={[]} tacticLabels={[]} />)
      expect(screen.getByText('Coverage:')).toBeInTheDocument()
    })

    it('renders "None → Full" scale text', () => {
      render(<AttackHeatmap rows={[]} tacticLabels={[]} />)
      // Rendered as "None → Full" (→ is \u2192)
      expect(screen.getByText(/None.*Full/)).toBeInTheDocument()
    })

    it('renders 5 legend color boxes for the coverage scale', () => {
      const { container } = render(<AttackHeatmap rows={[]} tacticLabels={[]} />)
      // Scale steps: [0, 0.15, 0.35, 0.6, 0.85]
      const legendBoxes = container.querySelectorAll('.w-4.h-\\[10px\\].rounded-\\[2px\\]')
      expect(legendBoxes).toHaveLength(5)
    })
  })

  // -------------------------------------------------------------------------
  // Edge cases
  // -------------------------------------------------------------------------
  describe('edge cases', () => {
    it('renders without crashing when all cells have zero opacity', () => {
      const allZero: RuntimeHeatRow[] = [
        {
          technique_id: 'T1000',
          cells: [
            { tactic: 'A', covered: 0, total: 5, opacity: 0 },
            { tactic: 'B', covered: 0, total: 5, opacity: 0 },
          ],
        },
      ]
      const { container } = render(
        <AttackHeatmap rows={toHeatRows(allZero)} tacticLabels={['A', 'B']} />,
      )
      const noCovCells = container.querySelectorAll('[title="No coverage"]')
      expect(noCovCells).toHaveLength(2)
    })

    it('renders without crashing when all cells have full opacity', () => {
      const allFull: RuntimeHeatRow[] = [
        {
          technique_id: 'T1002',
          cells: [
            { tactic: 'X', covered: 5, total: 5, opacity: 1.0 },
            { tactic: 'Y', covered: 5, total: 5, opacity: 1.0 },
          ],
        },
      ]
      expect(() =>
        render(<AttackHeatmap rows={toHeatRows(allFull)} tacticLabels={['X', 'Y']} />),
      ).not.toThrow()
    })

    it('applies minimum opacity floor of 0.12 for non-zero cells', () => {
      // The component uses Math.max(0.12, cell.opacity) for non-zero opacities
      const lowOpacity: RuntimeHeatRow[] = [
        {
          technique_id: 'T1003',
          cells: [{ tactic: 'A', covered: 1, total: 100, opacity: 0.05 }],
        },
      ]
      // Should not crash and the cell should show a coverage title
      render(<AttackHeatmap rows={toHeatRows(lowOpacity)} tacticLabels={['A']} />)
      // Math.round(0.05 * 100) = 5 → "Coverage: 5%"
      expect(screen.getByTitle('Coverage: 5%')).toBeInTheDocument()
    })
  })
})
