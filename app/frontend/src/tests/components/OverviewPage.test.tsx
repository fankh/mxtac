// vi.mock is hoisted before imports
vi.mock('../../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../lib/api')>()),
  overviewApi: {
    kpis: vi.fn(),
    timeline: vi.fn(),
    tactics: vi.fn(),
    heatmap: vi.fn(),
    tacticLabels: vi.fn(),
    integrations: vi.fn(),
    recentDetections: vi.fn(),
  },
}))

vi.mock('../../hooks/useAlertStream', () => ({ useAlertStream: () => 'connected' }))

// Recharts does not lay out in jsdom (ResponsiveContainer has zero size)
vi.mock('recharts', async (importOriginal) => ({
  ...(await importOriginal<typeof import('recharts')>()),
  ResponsiveContainer: () => <div data-testid="chart" />,
}))

import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, it, expect, vi, beforeAll, beforeEach } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { OverviewPage } from '../../components/features/overview/OverviewPage'
import { overviewApi } from '../../lib/api'
import type { Detection, HeatRow, IntegrationStatus, KpiMetrics, TacticBar, TimelinePoint } from '../../types/api'

const api = vi.mocked(overviewApi)

const kpi: KpiMetrics = {
  total_detections: 4821,
  total_detections_delta_pct: 12,
  critical_alerts: 23,
  critical_alerts_new_today: 5,
  attack_coverage_pct: 25,
  attack_covered: 185,
  attack_total: 740,
  attack_coverage_delta: 4,
  mttd_minutes: 8,
  mttd_delta_minutes: -2,
  integrations_active: 6,
  integrations_total: 8,
  sigma_rules_active: 1247,
  sigma_rules_critical: 89,
  sigma_rules_high: 312,
  sigma_rules_deployed_this_week: 14,
  open_incidents_count: 3,
  mttr_minutes: 210,
}

const timeline: TimelinePoint[] = [{ date: 'Mon', critical: 5, high: 12, medium: 20, total: 40 }]
const tactics: TacticBar[] = [{ tactic: 'Execution', count: 1200, trend_pct: 18 }]
const heatmap: HeatRow[] = [
  { technique_id: 'T1059', row: 0, cells: [{ tactic: 'Exec', covered: 7, total: 14, opacity: 0.5 }] },
]
const sources: IntegrationStatus[] = [{ id: 'wazuh', name: 'Wazuh', status: 'connected', metric: '1,204 events/min' }]
const recent: Detection[] = [
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
]

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <OverviewPage />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('OverviewPage', () => {
  beforeAll(() => {
    // Radix Select relies on pointer capture and scrollIntoView, which jsdom lacks
    Element.prototype.hasPointerCapture = () => false
    Element.prototype.setPointerCapture = () => {}
    Element.prototype.releasePointerCapture = () => {}
    Element.prototype.scrollIntoView = () => {}
  })

  beforeEach(() => {
    vi.clearAllMocks()
    api.kpis.mockResolvedValue(kpi)
    api.timeline.mockResolvedValue(timeline)
    api.tactics.mockResolvedValue(tactics)
    api.heatmap.mockResolvedValue(heatmap)
    api.tacticLabels.mockResolvedValue(['Exec'])
    api.integrations.mockResolvedValue(sources)
    api.recentDetections.mockResolvedValue(recent)
  })

  it('shows the page header with the time range set to the last 7 days', async () => {
    renderPage()
    expect(screen.getByRole('heading', { level: 1, name: 'Overview' })).toBeInTheDocument()
    expect(screen.getByText('Detections, coverage and source health')).toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: 'Time range' })).toHaveTextContent('Last 7 days')
    await screen.findByText('4,821')
  })

  it('shows a loading placeholder and no sections while the KPIs load', () => {
    api.kpis.mockReturnValue(new Promise(() => {}))
    renderPage()
    expect(screen.getByLabelText('Loading')).toBeInTheDocument()
    expect(screen.queryByText('Critical alerts')).not.toBeInTheDocument()
    expect(screen.queryByText('Data sources')).not.toBeInTheDocument()
  })

  it('shows every section with its data once loaded', async () => {
    renderPage()

    expect(await screen.findByText('4,821')).toBeInTheDocument()
    expect(screen.queryByLabelText('Loading')).not.toBeInTheDocument()

    expect(screen.getByRole('heading', { name: 'Detections over time' })).toBeInTheDocument()
    expect(screen.getByText('Per day, by severity, last 7 days')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Top ATT&CK tactics' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Recent critical and high detections' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Data sources' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'ATT&CK coverage heatmap' })).toBeInTheDocument()

    expect(await screen.findByTestId('chart')).toBeInTheDocument()
    expect(await screen.findByText('Execution')).toBeInTheDocument()
    expect(await screen.findByText('Suspicious LSASS Memory Access')).toBeInTheDocument()
    expect(await screen.findByText('Wazuh')).toBeInTheDocument()
    expect(await screen.findByTitle('T1059 · Exec: 7 of 14')).toBeInTheDocument()
  })

  it('requests the default range, and the eight most recent detections', async () => {
    renderPage()
    await screen.findByText('4,821')
    expect(api.kpis).toHaveBeenCalledWith('7d')
    expect(api.timeline).toHaveBeenCalledWith('7d')
    expect(api.tactics).toHaveBeenCalledWith('7d')
    expect(api.recentDetections).toHaveBeenCalledWith(8)
  })

  it('shows empty states when the sections have no data', async () => {
    api.timeline.mockResolvedValue([])
    api.tactics.mockResolvedValue([])
    api.integrations.mockResolvedValue([])
    api.recentDetections.mockResolvedValue([])
    api.heatmap.mockResolvedValue([])
    renderPage()

    expect(await screen.findByText('No detections in this period')).toBeInTheDocument()
    expect(screen.getByText('No tactics observed yet')).toBeInTheDocument()
    expect(screen.getByText('No critical or high detections')).toBeInTheDocument()
    expect(screen.getByText('No data sources connected')).toBeInTheDocument()
  })

  it('shows a dash when there is no time-to-detect data yet', async () => {
    api.kpis.mockResolvedValue({ ...kpi, mttd_minutes: null, mttr_minutes: null })
    renderPage()
    expect(await screen.findByText('No incident data yet')).toBeInTheDocument()
    expect(screen.getByText('–')).toBeInTheDocument()
    expect(screen.getByText('Mean time to resolve: –')).toBeInTheDocument()
  })

  it('still shows the KPIs when a secondary request fails', async () => {
    api.timeline.mockRejectedValue(new Error('boom'))
    api.integrations.mockRejectedValue(new Error('boom'))
    renderPage()
    expect(await screen.findByText('4,821')).toBeInTheDocument()
    expect(await screen.findByText('No data sources connected')).toBeInTheDocument()
  })

  it('shows an error with a retry button when the KPIs fail, and recovers on retry', async () => {
    api.kpis.mockRejectedValueOnce(new Error('Network error'))
    const user = userEvent.setup()
    renderPage()

    expect(await screen.findByText(/Could not load the overview/)).toBeInTheDocument()
    expect(screen.queryByText('Critical alerts')).not.toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Retry' }))

    expect(await screen.findByText('4,821')).toBeInTheDocument()
    expect(screen.queryByText(/Could not load the overview/)).not.toBeInTheDocument()
  })

  it('reloads the range-dependent data when another time range is chosen', async () => {
    const user = userEvent.setup()
    renderPage()
    await screen.findByText('4,821')

    await user.click(screen.getByRole('combobox', { name: 'Time range' }))
    await user.click(await screen.findByRole('option', { name: 'Last 30 days' }))

    await waitFor(() => expect(api.kpis).toHaveBeenCalledWith('30d'))
    expect(api.timeline).toHaveBeenCalledWith('30d')
    expect(api.tactics).toHaveBeenCalledWith('30d')
    expect(await screen.findByText('Per day, by severity, last 30 days')).toBeInTheDocument()
    expect(screen.getByText('Detections by tactic, last 30 days')).toBeInTheDocument()
    // Range-independent data is not requested again
    expect(api.heatmap).toHaveBeenCalledTimes(1)
    expect(api.recentDetections).toHaveBeenCalledTimes(1)
  })
})
