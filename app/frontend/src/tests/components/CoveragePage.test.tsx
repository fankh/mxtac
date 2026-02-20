// vi.mock is hoisted before imports — declare all module mocks first.

vi.mock('../../lib/api', () => ({
  overviewApi: {
    heatmap:      vi.fn(),
    tacticLabels: vi.fn(),
  },
}))

vi.mock('../../components/layout/TopBar', () => ({
  TopBar: ({ crumb }: { crumb: string }) => (
    <header data-testid="topbar">{crumb}</header>
  ),
}))

vi.mock('../../components/features/overview/AttackHeatmap', () => ({
  AttackHeatmap: ({ rows, tacticLabels }: { rows: unknown[]; tacticLabels: string[] }) => (
    <div data-testid="attack-heatmap" data-rows={rows.length} data-labels={tacticLabels.join(',')} />
  ),
}))

import { render, screen, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { CoveragePage, buildGapTable } from '../../components/features/coverage/CoveragePage'
import { overviewApi } from '../../lib/api'
import type { HeatRow } from '../../types/api'

// ---------------------------------------------------------------------------
// Typed reference to the mocked API
// ---------------------------------------------------------------------------

const mockApi = overviewApi as {
  heatmap:      ReturnType<typeof vi.fn>
  tacticLabels: ReturnType<typeof vi.fn>
}

// ---------------------------------------------------------------------------
// Mock data fixtures
// ---------------------------------------------------------------------------

/** 2-row heatmap with 3 tactics, known coverage percentages. */
const mockHeatmapData: HeatRow[] = [
  {
    row: 0,
    cells: [
      { tactic: 'RECON', covered: 1, total: 9 },   // 11%
      { tactic: 'EXEC',  covered: 9, total: 9 },   // 100%
      { tactic: 'CRED',  covered: 3, total: 6 },   // 50%
    ],
  },
  {
    row: 1,
    cells: [
      { tactic: 'RECON', covered: 2, total: 9 },   // row1 contribution
      { tactic: 'EXEC',  covered: 8, total: 9 },   // row1 contribution
      { tactic: 'CRED',  covered: 2, total: 6 },   // row1 contribution
    ],
  },
]
// Aggregated totals:
//  RECON: covered=3, total=18 → pct=17%
//  EXEC:  covered=17, total=18 → pct=94%
//  CRED:  covered=5, total=12 → pct=42%
// Sorted ascending: RECON(17%) → CRED(42%) → EXEC(94%)

const mockTacticLabels = ['RECON', 'EXEC', 'CRED']

// ---------------------------------------------------------------------------
// Render helper
// ---------------------------------------------------------------------------

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <CoveragePage />
    </QueryClientProvider>,
  )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('CoveragePage', () => {
  beforeEach(() => {
    // Default: both queries return a pending promise (loading state).
    const pending = new Promise<never>(() => {})
    mockApi.heatmap.mockReturnValue(pending)
    mockApi.tacticLabels.mockReturnValue(pending)
  })

  // -------------------------------------------------------------------------
  // Loading state
  // -------------------------------------------------------------------------
  describe('loading state', () => {
    it('shows a loading indicator while queries are pending', () => {
      renderPage()
      expect(screen.getByText('Loading…')).toBeInTheDocument()
    })

    it('does not show the error message while loading', () => {
      renderPage()
      expect(screen.queryByText(/Failed to load coverage data/)).not.toBeInTheDocument()
    })

    it('does not render the heatmap while loading', () => {
      renderPage()
      expect(screen.queryByTestId('attack-heatmap')).not.toBeInTheDocument()
    })

    it('does not render the gap table heading while loading', () => {
      renderPage()
      expect(screen.queryByText('Coverage Gaps')).not.toBeInTheDocument()
    })

    it('stays in loading state when only heatmap has resolved', () => {
      mockApi.heatmap.mockResolvedValue(mockHeatmapData)
      // tacticLabels still pending — keeps overall loading=true
      mockApi.tacticLabels.mockReturnValue(new Promise<never>(() => {}))
      renderPage()
      expect(screen.getByText('Loading…')).toBeInTheDocument()
    })

    it('stays in loading state when only tacticLabels has resolved', () => {
      mockApi.heatmap.mockReturnValue(new Promise<never>(() => {}))
      mockApi.tacticLabels.mockResolvedValue(mockTacticLabels)
      renderPage()
      expect(screen.getByText('Loading…')).toBeInTheDocument()
    })
  })

  // -------------------------------------------------------------------------
  // Error state
  // -------------------------------------------------------------------------
  describe('error state', () => {
    it('shows the error message when the heatmap query fails', async () => {
      mockApi.heatmap.mockRejectedValue(new Error('Network error'))
      mockApi.tacticLabels.mockResolvedValue(mockTacticLabels)
      renderPage()
      await waitFor(() => {
        expect(
          screen.getByText('Failed to load coverage data. Is the backend running?'),
        ).toBeInTheDocument()
      })
    })

    it('shows the error message when the tacticLabels query fails', async () => {
      mockApi.heatmap.mockResolvedValue(mockHeatmapData)
      mockApi.tacticLabels.mockRejectedValue(new Error('Server error'))
      renderPage()
      await waitFor(() => {
        expect(
          screen.getByText('Failed to load coverage data. Is the backend running?'),
        ).toBeInTheDocument()
      })
    })

    it('does not show the loading indicator in error state', async () => {
      mockApi.heatmap.mockRejectedValue(new Error('fail'))
      mockApi.tacticLabels.mockResolvedValue(mockTacticLabels)
      renderPage()
      await waitFor(() => {
        expect(screen.queryByText('Loading…')).not.toBeInTheDocument()
      })
    })

    it('does not render the heatmap in error state', async () => {
      mockApi.heatmap.mockRejectedValue(new Error('fail'))
      mockApi.tacticLabels.mockResolvedValue(mockTacticLabels)
      renderPage()
      await waitFor(() => {
        expect(screen.queryByTestId('attack-heatmap')).not.toBeInTheDocument()
      })
    })

    it('does not render the gap table in error state', async () => {
      mockApi.heatmap.mockRejectedValue(new Error('fail'))
      mockApi.tacticLabels.mockResolvedValue(mockTacticLabels)
      renderPage()
      await waitFor(() => {
        expect(screen.queryByText('Coverage Gaps')).not.toBeInTheDocument()
      })
    })
  })

  // -------------------------------------------------------------------------
  // Success state
  // -------------------------------------------------------------------------
  describe('success state', () => {
    beforeEach(() => {
      mockApi.heatmap.mockResolvedValue(mockHeatmapData)
      mockApi.tacticLabels.mockResolvedValue(mockTacticLabels)
    })

    it('renders the TopBar with the "ATT&CK Coverage" crumb', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.getByTestId('topbar')).toBeInTheDocument()
      })
    })

    it('renders the AttackHeatmap component', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.getByTestId('attack-heatmap')).toBeInTheDocument()
      })
    })

    it('does not show the loading indicator in success state', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.queryByText('Loading…')).not.toBeInTheDocument()
      })
    })

    it('does not show the error message in success state', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.queryByText(/Failed to load coverage data/)).not.toBeInTheDocument()
      })
    })

    it('renders the "Coverage Gaps" heading', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('Coverage Gaps')).toBeInTheDocument()
      })
    })

    it('renders the gap table subtitle', async () => {
      renderPage()
      await waitFor(() => {
        expect(
          screen.getByText('Tactics sorted by coverage (lowest first)'),
        ).toBeInTheDocument()
      })
    })

    it('renders column headers: Tactic, Covered, Total, Coverage %', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('Tactic')).toBeInTheDocument()
        expect(screen.getByText('Covered')).toBeInTheDocument()
        expect(screen.getByText('Total')).toBeInTheDocument()
        expect(screen.getByText('Coverage %')).toBeInTheDocument()
      })
    })

    it('renders a row for each tactic in the gap table', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('RECON')).toBeInTheDocument()
        expect(screen.getByText('EXEC')).toBeInTheDocument()
        expect(screen.getByText('CRED')).toBeInTheDocument()
      })
    })

    it('renders percentage labels for each tactic row', async () => {
      renderPage()
      // RECON: 3/18 = 17%, CRED: 5/12 = 42%, EXEC: 17/18 = 94%
      await waitFor(() => {
        expect(screen.getByText('17%')).toBeInTheDocument()
        expect(screen.getByText('42%')).toBeInTheDocument()
        expect(screen.getByText('94%')).toBeInTheDocument()
      })
    })

    it('passes heatmap data to AttackHeatmap', async () => {
      renderPage()
      await waitFor(() => {
        const heatmap = screen.getByTestId('attack-heatmap')
        expect(heatmap).toHaveAttribute('data-rows', String(mockHeatmapData.length))
      })
    })

    it('passes tactic labels to AttackHeatmap', async () => {
      renderPage()
      await waitFor(() => {
        const heatmap = screen.getByTestId('attack-heatmap')
        expect(heatmap).toHaveAttribute('data-labels', mockTacticLabels.join(','))
      })
    })
  })

  // -------------------------------------------------------------------------
  // Gap table — empty data
  // -------------------------------------------------------------------------
  describe('empty data', () => {
    it('shows "No data" message when heatmap returns empty array', async () => {
      mockApi.heatmap.mockResolvedValue([])
      mockApi.tacticLabels.mockResolvedValue([])
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('No data')).toBeInTheDocument()
      })
    })

    it('still renders the gap table heading with empty data', async () => {
      mockApi.heatmap.mockResolvedValue([])
      mockApi.tacticLabels.mockResolvedValue([])
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('Coverage Gaps')).toBeInTheDocument()
      })
    })

    it('still renders the heatmap with empty rows', async () => {
      mockApi.heatmap.mockResolvedValue([])
      mockApi.tacticLabels.mockResolvedValue([])
      renderPage()
      await waitFor(() => {
        expect(screen.getByTestId('attack-heatmap')).toBeInTheDocument()
      })
    })
  })
})

// ---------------------------------------------------------------------------
// Unit tests for buildGapTable helper
// ---------------------------------------------------------------------------

describe('buildGapTable', () => {
  it('returns an empty array for empty input', () => {
    expect(buildGapTable([])).toEqual([])
  })

  it('aggregates covered and total across all rows for the same tactic', () => {
    const rows: HeatRow[] = [
      { row: 0, cells: [{ tactic: 'EXEC', covered: 5, total: 9 }] },
      { row: 1, cells: [{ tactic: 'EXEC', covered: 3, total: 9 }] },
    ]
    const result = buildGapTable(rows)
    expect(result).toHaveLength(1)
    expect(result[0]).toMatchObject({ tactic: 'EXEC', covered: 8, total: 18 })
  })

  it('calculates percentage as Math.round(covered/total * 100)', () => {
    const rows: HeatRow[] = [
      { row: 0, cells: [{ tactic: 'RECON', covered: 1, total: 3 }] },
    ]
    // 1/3 = 0.333... → 33%
    const result = buildGapTable(rows)
    expect(result[0].pct).toBe(33)
  })

  it('returns pct=0 when total is 0', () => {
    const rows: HeatRow[] = [
      { row: 0, cells: [{ tactic: 'INIT', covered: 0, total: 0 }] },
    ]
    const result = buildGapTable(rows)
    expect(result[0].pct).toBe(0)
  })

  it('sorts results ascending by coverage percentage (lowest gaps first)', () => {
    const rows: HeatRow[] = [
      {
        row: 0,
        cells: [
          { tactic: 'HIGH_COV', covered: 9, total: 9 },   // 100%
          { tactic: 'LOW_COV',  covered: 1, total: 9 },   // 11%
          { tactic: 'MID_COV',  covered: 5, total: 9 },   // 56%
        ],
      },
    ]
    const result = buildGapTable(rows)
    expect(result.map((r) => r.tactic)).toEqual(['LOW_COV', 'MID_COV', 'HIGH_COV'])
  })

  it('handles multiple rows with different tactics correctly', () => {
    const result = buildGapTable(mockHeatmapData)
    // RECON: 3/18≈17%, CRED: 5/12≈42%, EXEC: 17/18≈94%
    expect(result).toHaveLength(3)
    expect(result[0].tactic).toBe('RECON')
    expect(result[0].covered).toBe(3)
    expect(result[0].total).toBe(18)
    expect(result[1].tactic).toBe('CRED')
    expect(result[2].tactic).toBe('EXEC')
  })

  it('returns pct=100 for fully covered tactics', () => {
    const rows: HeatRow[] = [
      { row: 0, cells: [{ tactic: 'FULL', covered: 10, total: 10 }] },
    ]
    const result = buildGapTable(rows)
    expect(result[0].pct).toBe(100)
  })

  it('handles a single row with a single tactic', () => {
    const rows: HeatRow[] = [
      { row: 0, cells: [{ tactic: 'ONLY', covered: 3, total: 4 }] },
    ]
    const result = buildGapTable(rows)
    expect(result).toHaveLength(1)
    expect(result[0]).toMatchObject({ tactic: 'ONLY', covered: 3, total: 4, pct: 75 })
  })

  it('preserves all tactics present in cell data', () => {
    const rows: HeatRow[] = [
      {
        row: 0,
        cells: [
          { tactic: 'A', covered: 1, total: 2 },
          { tactic: 'B', covered: 2, total: 2 },
          { tactic: 'C', covered: 0, total: 2 },
        ],
      },
    ]
    const result = buildGapTable(rows)
    const tactics = result.map((r) => r.tactic).sort()
    expect(tactics).toEqual(['A', 'B', 'C'])
  })
})
