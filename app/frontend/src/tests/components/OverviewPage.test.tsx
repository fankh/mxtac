// vi.mock is hoisted before imports — declare all module mocks first.

vi.mock('../../lib/api', () => ({
  overviewApi: {
    kpis:             vi.fn(),
    timeline:         vi.fn(),
    tactics:          vi.fn(),
    heatmap:          vi.fn(),
    tacticLabels:     vi.fn(),
    integrations:     vi.fn(),
    recentDetections: vi.fn(),
  },
}))

vi.mock('../../components/layout/TopBar', () => ({
  TopBar: ({ crumb }: { crumb: string }) => (
    <header data-testid="topbar">{crumb}</header>
  ),
}))

vi.mock('../../components/features/overview/KpiCards', () => ({
  KpiCards: () => <div data-testid="kpi-cards" />,
}))

vi.mock('../../components/features/overview/DetectionTimeline', () => ({
  DetectionTimeline: () => <div data-testid="detection-timeline" />,
}))

vi.mock('../../components/features/overview/TacticsTable', () => ({
  TacticsTable: () => <div data-testid="tactics-table" />,
}))

vi.mock('../../components/features/overview/AttackHeatmap', () => ({
  AttackHeatmap: () => <div data-testid="attack-heatmap" />,
}))

vi.mock('../../components/features/overview/IntegrationStatusRow', () => ({
  IntegrationStatusRow: () => <div data-testid="integration-status-row" />,
}))

vi.mock('../../components/features/overview/RecentDetectionsTable', () => ({
  RecentDetectionsTable: () => <div data-testid="recent-detections-table" />,
}))

import { render, screen, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { OverviewPage } from '../../components/features/overview/OverviewPage'
import { overviewApi } from '../../lib/api'

// ---------------------------------------------------------------------------
// Typed reference to the mocked API
// ---------------------------------------------------------------------------

const mockApi = overviewApi as {
  kpis:             ReturnType<typeof vi.fn>
  timeline:         ReturnType<typeof vi.fn>
  tactics:          ReturnType<typeof vi.fn>
  heatmap:          ReturnType<typeof vi.fn>
  tacticLabels:     ReturnType<typeof vi.fn>
  integrations:     ReturnType<typeof vi.fn>
  recentDetections: ReturnType<typeof vi.fn>
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <OverviewPage />
    </QueryClientProvider>,
  )
}

/** A resolved KpiMetrics object with all required fields. */
const mockKpi = {
  total_detections:               4821,
  total_detections_delta_pct:     12,
  critical_alerts:                23,
  critical_alerts_new_today:      5,
  attack_coverage_pct:            25,
  attack_covered:                 187,
  attack_total:                   740,
  attack_coverage_delta:          4,
  mttd_minutes:                   8,
  mttd_delta_minutes:             -2,
  integrations_active:            6,
  integrations_total:             8,
  sigma_rules_active:             1247,
  sigma_rules_critical:           89,
  sigma_rules_high:               312,
  sigma_rules_deployed_this_week: 14,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('OverviewPage', () => {
  beforeEach(() => {
    // Default: all queries return a pending promise (loading state).
    const pending = new Promise<never>(() => {})
    mockApi.kpis.mockReturnValue(pending)
    mockApi.timeline.mockReturnValue(pending)
    mockApi.tactics.mockReturnValue(pending)
    mockApi.heatmap.mockReturnValue(pending)
    mockApi.tacticLabels.mockReturnValue(pending)
    mockApi.integrations.mockReturnValue(pending)
    mockApi.recentDetections.mockReturnValue(pending)
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
      expect(screen.queryByText(/Failed to load data/)).not.toBeInTheDocument()
    })

    it('does not render KPI cards while loading', () => {
      renderPage()
      expect(screen.queryByTestId('kpi-cards')).not.toBeInTheDocument()
    })

    it('does not render any sub-component while loading', () => {
      renderPage()
      const testIds = [
        'kpi-cards',
        'detection-timeline',
        'tactics-table',
        'attack-heatmap',
        'recent-detections-table',
        'integration-status-row',
      ]
      for (const id of testIds) {
        expect(screen.queryByTestId(id)).not.toBeInTheDocument()
      }
    })
  })

  // -------------------------------------------------------------------------
  // Error state
  // -------------------------------------------------------------------------
  describe('error state', () => {
    beforeEach(() => {
      // Resolve all secondary queries; kpis will be overridden per-test.
      mockApi.timeline.mockResolvedValue([])
      mockApi.tactics.mockResolvedValue([])
      mockApi.heatmap.mockResolvedValue([])
      mockApi.tacticLabels.mockResolvedValue([])
      mockApi.integrations.mockResolvedValue([])
      mockApi.recentDetections.mockResolvedValue([])
    })

    it('shows the error message when the kpis query fails', async () => {
      mockApi.kpis.mockRejectedValue(new Error('Network error'))
      renderPage()
      await waitFor(() => {
        expect(
          screen.getByText('Failed to load data. Is the backend running?'),
        ).toBeInTheDocument()
      })
    })

    it('does not show the loading indicator in error state', async () => {
      mockApi.kpis.mockRejectedValue(new Error('Server error'))
      renderPage()
      await waitFor(() => {
        expect(screen.queryByText('Loading…')).not.toBeInTheDocument()
      })
    })

    it('does not render KPI cards in error state', async () => {
      mockApi.kpis.mockRejectedValue(new Error('fail'))
      renderPage()
      await waitFor(() => {
        expect(screen.queryByTestId('kpi-cards')).not.toBeInTheDocument()
      })
    })

    it('shows error when any non-kpis query fails', async () => {
      mockApi.kpis.mockResolvedValue(mockKpi)
      mockApi.timeline.mockRejectedValue(new Error('timeline error'))
      renderPage()
      await waitFor(() => {
        expect(
          screen.getByText('Failed to load data. Is the backend running?'),
        ).toBeInTheDocument()
      })
    })
  })

  // -------------------------------------------------------------------------
  // Success state
  // -------------------------------------------------------------------------
  describe('success state', () => {
    beforeEach(() => {
      mockApi.kpis.mockResolvedValue(mockKpi)
      mockApi.timeline.mockResolvedValue([])
      mockApi.tactics.mockResolvedValue([])
      mockApi.heatmap.mockResolvedValue([])
      mockApi.tacticLabels.mockResolvedValue([])
      mockApi.integrations.mockResolvedValue([])
      mockApi.recentDetections.mockResolvedValue([])
    })

    it('renders KPI cards when all queries succeed', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.getByTestId('kpi-cards')).toBeInTheDocument()
      })
    })

    it('renders the detection timeline when all queries succeed', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.getByTestId('detection-timeline')).toBeInTheDocument()
      })
    })

    it('renders the tactics table when all queries succeed', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.getByTestId('tactics-table')).toBeInTheDocument()
      })
    })

    it('renders the attack heatmap when all queries succeed', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.getByTestId('attack-heatmap')).toBeInTheDocument()
      })
    })

    it('renders the recent detections table when all queries succeed', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.getByTestId('recent-detections-table')).toBeInTheDocument()
      })
    })

    it('renders the integration status row when all queries succeed', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.getByTestId('integration-status-row')).toBeInTheDocument()
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
        expect(screen.queryByText(/Failed to load data/)).not.toBeInTheDocument()
      })
    })

    it('renders the TopBar with the "Overview" crumb', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.getByTestId('topbar')).toHaveTextContent('Overview')
      })
    })

    it('renders all 6 sub-components together', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.getByTestId('kpi-cards')).toBeInTheDocument()
        expect(screen.getByTestId('detection-timeline')).toBeInTheDocument()
        expect(screen.getByTestId('tactics-table')).toBeInTheDocument()
        expect(screen.getByTestId('attack-heatmap')).toBeInTheDocument()
        expect(screen.getByTestId('recent-detections-table')).toBeInTheDocument()
        expect(screen.getByTestId('integration-status-row')).toBeInTheDocument()
      })
    })
  })

  // -------------------------------------------------------------------------
  // Partial loading — stays in loading state until ALL queries complete
  // -------------------------------------------------------------------------
  describe('partial loading', () => {
    it('stays in loading state when only kpis has resolved', () => {
      mockApi.kpis.mockResolvedValue(mockKpi)
      // timeline still pending — keeps overall loading=true
      mockApi.timeline.mockReturnValue(new Promise<never>(() => {}))
      mockApi.tactics.mockResolvedValue([])
      mockApi.heatmap.mockResolvedValue([])
      mockApi.tacticLabels.mockResolvedValue([])
      mockApi.integrations.mockResolvedValue([])
      mockApi.recentDetections.mockResolvedValue([])

      renderPage()
      // Dashboard content must not appear while any query is still loading
      expect(screen.queryByTestId('kpi-cards')).not.toBeInTheDocument()
    })

    it('shows loading indicator when the heatmap query is still pending', () => {
      mockApi.kpis.mockResolvedValue(mockKpi)
      mockApi.timeline.mockResolvedValue([])
      mockApi.tactics.mockResolvedValue([])
      mockApi.heatmap.mockReturnValue(new Promise<never>(() => {}))
      mockApi.tacticLabels.mockResolvedValue([])
      mockApi.integrations.mockResolvedValue([])
      mockApi.recentDetections.mockResolvedValue([])

      renderPage()
      expect(screen.getByText('Loading…')).toBeInTheDocument()
    })
  })
})
