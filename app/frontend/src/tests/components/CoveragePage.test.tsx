// vi.mock is hoisted before imports — declare all module mocks first.

vi.mock('../../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof ApiModule>()),
  overviewApi: {
    heatmap: vi.fn(),
    tacticLabels: vi.fn(),
  },
  coverageApi: {
    summary: vi.fn(),
    byDatasource: vi.fn(),
    gaps: vi.fn(),
    navigator: vi.fn(),
    trend: vi.fn(),
    target: vi.fn(),
    updateTarget: vi.fn(),
  },
}))

vi.mock('../../components/layout/TopBar', () => ({
  TopBar: ({ crumb, actions }: { crumb: string; actions?: ReactNode }) => (
    <header data-testid="topbar">
      <h1>{crumb}</h1>
      {actions}
    </header>
  ),
}))

import type { ReactNode } from 'react'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, it, expect, vi, beforeAll, beforeEach, afterEach } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { CoveragePage } from '../../components/features/coverage/CoveragePage'
import {
  attackUrl, formatPct, groupTechniques, heatOpacity,
} from '../../components/features/coverage/coverageUtils'
import type * as ApiModule from '../../lib/api'
import { coverageApi, overviewApi } from '../../lib/api'
import { useAuthStore } from '../../stores/authStore'
import { useUIStore } from '../../stores/uiStore'
import type {
  CoverageByDataSource, CoverageGaps, CoverageSummary, CoverageTarget, CoverageTrend, HeatRow,
  NavigatorLayer, NavigatorTechnique,
} from '../../types/api'

const mockCoverage = vi.mocked(coverageApi)
const mockOverview = vi.mocked(overviewApi)

// ---------------------------------------------------------------------------
// Fixtures (shapes follow app/backend/app/api/v1/endpoints/coverage.py)
// ---------------------------------------------------------------------------

const SUMMARY: CoverageSummary = { coverage_pct: 40, covered_count: 42, total_count: 105 }

const GAPS: CoverageGaps = {
  covered_count: 42,
  total_count: 105,
  gap_count: 63,
  coverage_pct: 40,
  uncovered_techniques: ['T1566.001', 'T1021.002'],
}

const TARGET: CoverageTarget = {
  target_pct: 80,
  enabled: true,
  label: 'Q1 goal',
  current_pct: 40,
  is_below_threshold: true,
}

const BY_SOURCE: CoverageByDataSource = {
  sources: [
    { source: 'wazuh', covered_count: 30, total_count: 105, coverage_pct: 28.6, rule_count: 55 },
    { source: 'zeek', covered_count: 10, total_count: 105, coverage_pct: 9.5, rule_count: 1 },
    { source: 'suricata', covered_count: 0, total_count: 105, coverage_pct: 0, rule_count: 0 },
  ],
  total_covered_count: 38,
  total_count: 105,
  total_coverage_pct: 36.2,
}

const TREND: CoverageTrend = {
  days: 30,
  points: [
    { date: '2026-02-17', coverage_pct: 38.1, covered_count: 40, total_count: 105 },
    { date: '2026-02-18', coverage_pct: 39, covered_count: 41, total_count: 105 },
    { date: '2026-02-19', coverage_pct: 40, covered_count: 42, total_count: 105 },
  ],
}

function technique(techniqueID: string, score: number): NavigatorTechnique {
  return { techniqueID, score, comment: `${score} rules covering this technique`, enabled: true }
}

const LAYER: NavigatorLayer = {
  name: 'MxTac Coverage',
  domain: 'enterprise-attack',
  description: 'ATT&CK coverage exported from MxTac',
  versions: { attack: '14', navigator: '4.9', layer: '4.5' },
  techniques: [technique('T1003.001', 4), technique('T1059.001', 2), technique('T1059.003', 1)],
}

const HEATMAP: HeatRow[] = [
  {
    technique_id: 'T1059',
    row: 0,
    cells: [
      { tactic: 'EXEC', covered: 12, total: 14, opacity: 0.74 },
      { tactic: 'CRED', covered: 0, total: 17, opacity: 0.1 },
    ],
  },
  {
    technique_id: 'T1003',
    row: 1,
    cells: [
      { tactic: 'EXEC', covered: 1, total: 14, opacity: 0.15 },
      { tactic: 'CRED', covered: 8, total: 17, opacity: 0.45 },
    ],
  },
]

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return render(
    <MemoryRouter>
      <QueryClientProvider client={queryClient}>
        <CoveragePage />
      </QueryClientProvider>
    </MemoryRouter>,
  )
}

async function renderLoaded() {
  const user = userEvent.setup()
  renderPage()
  await screen.findByTestId('coverage-pct')
  await screen.findByTestId('covered-techniques')
  return user
}

beforeAll(() => {
  // Recharts' ResponsiveContainer needs ResizeObserver, which jsdom lacks.
  vi.stubGlobal(
    'ResizeObserver',
    vi.fn().mockImplementation(() => ({ observe: vi.fn(), unobserve: vi.fn(), disconnect: vi.fn() })),
  )
})

beforeEach(() => {
  vi.clearAllMocks()
  useAuthStore.setState({ user: { email: 'analyst@mxtac.local', role: 'analyst' } })
  useUIStore.setState({ notifications: [] })

  mockCoverage.summary.mockResolvedValue(SUMMARY)
  mockCoverage.gaps.mockResolvedValue(GAPS)
  mockCoverage.target.mockResolvedValue(TARGET)
  mockCoverage.byDatasource.mockResolvedValue(BY_SOURCE)
  mockCoverage.trend.mockResolvedValue(TREND)
  mockCoverage.navigator.mockResolvedValue(LAYER)
  mockOverview.heatmap.mockResolvedValue(HEATMAP)
  mockOverview.tacticLabels.mockResolvedValue(['EXEC', 'CRED'])
})

afterEach(() => {
  useAuthStore.setState({ user: null })
})

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('CoveragePage', () => {
  describe('loading and errors', () => {
    it('renders the page title while requests are pending', () => {
      const pending = new Promise<never>(() => {})
      mockCoverage.summary.mockReturnValue(pending)
      mockCoverage.gaps.mockReturnValue(pending)
      mockCoverage.target.mockReturnValue(pending)
      renderPage()
      expect(screen.getByRole('heading', { name: 'ATT&CK coverage' })).toBeInTheDocument()
      expect(screen.queryByTestId('coverage-pct')).not.toBeInTheDocument()
    })

    it('shows an error card and retries the failed request', async () => {
      mockCoverage.summary.mockRejectedValueOnce(new Error('boom'))
      const user = userEvent.setup()
      renderPage()
      const message = await screen.findByText('Could not load some coverage numbers.')
      const card = message.closest('[role="alert"]') as HTMLElement
      await user.click(within(card).getByRole('button', { name: 'Retry' }))
      expect(await screen.findByTestId('coverage-pct')).toHaveTextContent('40%')
      expect(mockCoverage.summary).toHaveBeenCalledTimes(2)
      expect(screen.queryByText('Could not load some coverage numbers.')).not.toBeInTheDocument()
    })

    it('shows a retry in the data source card when that request fails', async () => {
      mockCoverage.byDatasource.mockRejectedValue(new Error('boom'))
      renderPage()
      expect(await screen.findByText('Could not load coverage by data source.')).toBeInTheDocument()
    })
  })

  describe('headline numbers', () => {
    it('shows the coverage percentage and technique counts from GET /coverage', async () => {
      await renderLoaded()
      expect(screen.getByTestId('coverage-pct')).toHaveTextContent('40%')
      expect(screen.getByText('42 of 105 techniques have an enabled rule')).toBeInTheDocument()
      expect(screen.getByRole('progressbar', { name: 'Technique coverage' })).toHaveAttribute('aria-valuenow', '40')
    })

    it('shows the target, its label and how far coverage is from it', async () => {
      await renderLoaded()
      expect(screen.getByTestId('target-pct')).toHaveTextContent('80%')
      expect(screen.getByText('Below target')).toBeInTheDocument()
      expect(screen.getByText('Q1 goal · 40 points below target')).toBeInTheDocument()
    })

    it('shows "On target" when coverage meets an enabled target', async () => {
      mockCoverage.target.mockResolvedValue({ ...TARGET, target_pct: 30, is_below_threshold: false })
      await renderLoaded()
      expect(screen.getByText('On target')).toBeInTheDocument()
      expect(screen.getByText('Q1 goal · 10 points above target')).toBeInTheDocument()
    })

    it('shows "Not flagged" when the target is disabled', async () => {
      mockCoverage.target.mockResolvedValue({ ...TARGET, enabled: false, is_below_threshold: false })
      await renderLoaded()
      expect(screen.getByText('Not flagged')).toBeInTheDocument()
    })

    it('shows the gap counts from GET /coverage/gaps', async () => {
      await renderLoaded()
      expect(screen.getByTestId('gap-count')).toHaveTextContent('63')
      expect(screen.getByTestId('disabled-gap-count')).toHaveTextContent('2')
    })
  })

  describe('trend', () => {
    it('requests 30 days of snapshots and renders the chart container', async () => {
      await renderLoaded()
      expect(mockCoverage.trend).toHaveBeenCalledWith(30)
      expect(await screen.findByTestId('coverage-trend-chart')).toHaveAttribute('data-points', '3')
    })

    it('shows an empty state when there are no snapshots', async () => {
      mockCoverage.trend.mockResolvedValue({ days: 30, points: [] })
      await renderLoaded()
      expect(await screen.findByText('No snapshots yet')).toBeInTheDocument()
    })
  })

  describe('by data source', () => {
    it('lists each source with its technique and rule counts', async () => {
      await renderLoaded()
      const wazuh = await screen.findByTestId('source-wazuh')
      expect(within(wazuh).getByText('Wazuh')).toBeInTheDocument()
      expect(within(wazuh).getByText('30 of 105 · 28.6%')).toBeInTheDocument()
      expect(within(wazuh).getByText('55 enabled rules')).toBeInTheDocument()
      expect(within(screen.getByTestId('source-zeek')).getByText('1 enabled rule')).toBeInTheDocument()
      expect(within(screen.getByTestId('source-suricata')).getByText('0 of 105 · 0%')).toBeInTheDocument()
    })
  })

  describe('matrix', () => {
    it('renders a row per technique family and a column per tactic', async () => {
      await renderLoaded()
      const matrix = await screen.findByTestId('coverage-matrix')
      expect(within(matrix).getByRole('columnheader', { name: 'EXEC' })).toBeInTheDocument()
      expect(within(matrix).getByRole('columnheader', { name: 'CRED' })).toBeInTheDocument()
      expect(within(matrix).getByRole('rowheader', { name: 'T1059' })).toBeInTheDocument()
      expect(within(matrix).getByRole('rowheader', { name: 'T1003' })).toBeInTheDocument()
      expect(within(matrix).getByText('12/14')).toBeInTheDocument()
      expect(within(matrix).getByTitle('T1003 · CRED: 8 of 17 techniques')).toBeInTheDocument()
    })

    it('falls back to the tactics in the rows when the label request fails', async () => {
      mockOverview.tacticLabels.mockRejectedValue(new Error('boom'))
      await renderLoaded()
      const matrix = await screen.findByTestId('coverage-matrix')
      expect(within(matrix).getByRole('columnheader', { name: 'EXEC' })).toBeInTheDocument()
    })
  })

  describe('techniques', () => {
    it('groups covered techniques under their parent with the rule count', async () => {
      await renderLoaded()
      const list = screen.getByTestId('covered-techniques')
      expect(within(list).getByText('T1059')).toBeInTheDocument()
      expect(within(list).getByText('T1003')).toBeInTheDocument()
      const chip = within(list).getByTitle('T1059.001: 2 enabled rules')
      expect(chip).toHaveAttribute('href', 'https://attack.mitre.org/techniques/T1059/001/')
      expect(within(list).getByTitle('T1059.003: 1 enabled rule')).toBeInTheDocument()
      expect(screen.getByRole('tab', { name: 'Covered (3)' })).toBeInTheDocument()
    })

    it('filters covered techniques by ID and clears the search with Escape', async () => {
      const user = await renderLoaded()
      const input = screen.getByLabelText('Find a technique ID')
      await user.type(input, 't1003')
      expect(screen.queryByTitle('T1059.001: 2 enabled rules')).not.toBeInTheDocument()
      expect(screen.getByTitle('T1003.001: 4 enabled rules')).toBeInTheDocument()

      await user.keyboard('{Escape}')
      expect(input).toHaveValue('')
      expect(screen.getByTitle('T1059.001: 2 enabled rules')).toBeInTheDocument()
    })

    it('shows the techniques that only disabled rules cover on the Gaps tab', async () => {
      const user = await renderLoaded()
      await user.click(screen.getByRole('tab', { name: 'Gaps (2)' }))
      const list = screen.getByTestId('gap-techniques')
      expect(within(list).getAllByRole('link').map((a) => a.textContent)).toEqual(['T1021.002', 'T1566.001'])
      expect(screen.getByText(/63 of 105 in-scope techniques have no enabled rule/)).toBeInTheDocument()
      expect(screen.getByRole('link', { name: 'Open rules' })).toHaveAttribute('href', '/rules')
    })

    it('shows an empty state when no technique is covered', async () => {
      mockCoverage.navigator.mockResolvedValue({ ...LAYER, techniques: [] })
      renderPage()
      expect(await screen.findByText('No technique is covered yet')).toBeInTheDocument()
    })
  })

  describe('target editing', () => {
    it('hides the edit button for a role without detections:write', async () => {
      useAuthStore.setState({ user: { email: 'viewer@mxtac.local', role: 'viewer' } })
      await renderLoaded()
      expect(screen.queryByRole('button', { name: 'Edit target' })).not.toBeInTheDocument()
    })

    it('saves a new target with PUT /coverage/target and shows it', async () => {
      mockCoverage.updateTarget.mockResolvedValue({ ...TARGET, target_pct: 35, is_below_threshold: false })
      const user = await renderLoaded()
      await user.click(screen.getByRole('button', { name: 'Edit target' }))
      const dialog = await screen.findByRole('dialog')
      const pct = within(dialog).getByLabelText('Target (%)')
      expect(pct).toHaveValue(80)
      await user.clear(pct)
      await user.type(pct, '35')
      await user.click(within(dialog).getByRole('button', { name: 'Save target' }))

      await waitFor(() =>
        expect(mockCoverage.updateTarget).toHaveBeenCalledWith({ target_pct: 35, enabled: true, label: 'Q1 goal' }),
      )
      await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
      expect(screen.getByTestId('target-pct')).toHaveTextContent('35%')
      expect(screen.getByText('On target')).toBeInTheDocument()
    })

    it('does not submit a target outside 0 to 100', async () => {
      const user = await renderLoaded()
      await user.click(screen.getByRole('button', { name: 'Edit target' }))
      const dialog = await screen.findByRole('dialog')
      const pct = within(dialog).getByLabelText('Target (%)')
      await user.clear(pct)
      await user.type(pct, '140')
      expect(within(dialog).getByText('Enter a number from 0 to 100.')).toBeInTheDocument()
      expect(within(dialog).getByRole('button', { name: 'Save target' })).toBeDisabled()
    })

    it('reports a failed save as an error notification and keeps the dialog open', async () => {
      mockCoverage.updateTarget.mockRejectedValue({ response: { data: { detail: 'Forbidden' } } })
      const user = await renderLoaded()
      await user.click(screen.getByRole('button', { name: 'Edit target' }))
      const dialog = await screen.findByRole('dialog')
      await user.click(within(dialog).getByRole('button', { name: 'Save target' }))
      await waitFor(() =>
        expect(useUIStore.getState().notifications).toEqual([
          expect.objectContaining({ type: 'error', title: 'Could not save the coverage target', message: 'Forbidden' }),
        ]),
      )
      expect(screen.getByRole('dialog')).toBeInTheDocument()
    })
  })

  describe('Navigator layer download', () => {
    it('fetches the layer and saves it as a JSON file', async () => {
      const createObjectURL = vi.fn((_: Blob) => 'blob:mock')
      const revokeObjectURL = vi.fn()
      vi.stubGlobal('URL', Object.assign(URL, { createObjectURL, revokeObjectURL }))
      const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})

      const user = await renderLoaded()
      const callsBefore = mockCoverage.navigator.mock.calls.length
      await user.click(screen.getByRole('button', { name: 'Download Navigator layer' }))
      await waitFor(() => expect(createObjectURL).toHaveBeenCalledTimes(1))
      expect(mockCoverage.navigator.mock.calls.length).toBe(callsBefore + 1)
      const blob = createObjectURL.mock.calls[0][0]
      expect(blob.type).toBe('application/json')
      expect(click).toHaveBeenCalled()
      click.mockRestore()
    })

    it('reports a failed download as an error notification', async () => {
      const user = await renderLoaded()
      mockCoverage.navigator.mockRejectedValue(new Error('Network Error'))
      await user.click(screen.getByRole('button', { name: 'Download Navigator layer' }))
      await waitFor(() =>
        expect(useUIStore.getState().notifications).toEqual([
          expect.objectContaining({ type: 'error', title: 'Could not download the Navigator layer' }),
        ]),
      )
    })
  })
})

// ---------------------------------------------------------------------------
// coverageUtils
// ---------------------------------------------------------------------------

describe('groupTechniques', () => {
  it('returns an empty array for no techniques', () => {
    expect(groupTechniques([])).toEqual([])
  })

  it('groups sub-techniques under the parent ID and sorts groups and members', () => {
    const groups = groupTechniques([
      technique('T1059.003', 1), technique('T1003', 2), technique('T1059.001', 5),
    ])
    expect(groups.map((g) => g.parent)).toEqual(['T1003', 'T1059'])
    expect(groups[1].techniques.map((t) => t.techniqueID)).toEqual(['T1059.001', 'T1059.003'])
    expect(groups[1].ruleCount).toBe(6)
  })

  it('does not mutate its input', () => {
    const input = [technique('T1059.003', 1), technique('T1059.001', 5)]
    groupTechniques(input)
    expect(input.map((t) => t.techniqueID)).toEqual(['T1059.003', 'T1059.001'])
  })
})

describe('coverage helpers', () => {
  it('builds MITRE ATT&CK links for techniques and sub-techniques', () => {
    expect(attackUrl('T1059')).toBe('https://attack.mitre.org/techniques/T1059/')
    expect(attackUrl('t1059.001')).toBe('https://attack.mitre.org/techniques/T1059/001/')
  })

  it('formats whole and fractional percentages', () => {
    expect(formatPct(40)).toBe('40%')
    expect(formatPct(28.57)).toBe('28.6%')
  })

  it('scales heat opacity from 0.15 to 1 and returns 0 for no value', () => {
    expect(heatOpacity(0, 10)).toBe(0)
    expect(heatOpacity(5, 0)).toBe(0)
    expect(heatOpacity(10, 10)).toBe(1)
    expect(heatOpacity(20, 10)).toBe(1)
    expect(heatOpacity(1, 100)).toBeCloseTo(0.16, 2)
  })
})
