// vi.mock is hoisted before imports — declare all module mocks first.

vi.mock('../../lib/api', () => ({
  incidentsApi: {
    list:    vi.fn(),
    metrics: vi.fn(),
    create:  vi.fn(),
  },
}))

vi.mock('../../components/layout/TopBar', () => ({
  TopBar: ({ crumb }: { crumb: string }) => (
    <header data-testid="topbar">{crumb}</header>
  ),
}))

vi.mock('../../components/features/incidents/IncidentPanel', () => ({
  IncidentPanel: ({
    incident,
    onClose,
  }: {
    incident: { id: number; title: string } | null
    onClose: () => void
  }) =>
    incident ? (
      <div data-testid="incident-panel" data-incident-id={String(incident.id)}>
        <button onClick={onClose} data-testid="panel-close">Close</button>
      </div>
    ) : null,
}))

import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { IncidentsPage } from '../../components/features/incidents/IncidentsPage'
import { incidentsApi } from '../../lib/api'

// ---------------------------------------------------------------------------
// Typed reference to the mocked API
// ---------------------------------------------------------------------------

const mockApi = incidentsApi as {
  list:    ReturnType<typeof vi.fn>
  metrics: ReturnType<typeof vi.fn>
  create:  ReturnType<typeof vi.fn>
}

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

const makeIncident = (overrides: Record<string, unknown> = {}) => ({
  id: 1,
  title: 'Lateral Movement via Pass-the-Hash',
  description: null,
  severity: 'high' as const,
  status: 'new' as const,
  priority: 2,
  assigned_to: null,
  created_by: 'analyst@mxtac.local',
  detection_ids: [],
  technique_ids: ['T1550.002'],
  tactic_ids: ['lateral_movement'],
  hosts: ['WIN-DC01'],
  ttd_seconds: null,
  ttr_seconds: null,
  closed_at: null,
  created_at: '2026-02-19T08:30:00Z',
  updated_at: '2026-02-19T08:30:00Z',
  ...overrides,
})

const makeResponse = (
  items = [makeIncident()],
  paginationOverrides: Record<string, unknown> = {},
) => ({
  items,
  pagination: {
    page: 1,
    page_size: 20,
    total: items.length,
    total_pages: 1,
    ...paginationOverrides,
  },
})

const makeMetrics = (overrides: Record<string, unknown> = {}) => ({
  total_incidents: { new: 5, investigating: 3, contained: 2, resolved: 10, closed: 8 },
  mttr_seconds: 7200,
  mttd_seconds: 1800,
  open_incidents_count: 10,
  incidents_by_severity: { critical: 3, high: 5, medium: 7, low: 13 },
  incidents_this_week: 8,
  incidents_this_month: 28,
  from_date: '2026-01-22T00:00:00Z',
  to_date: '2026-02-21T00:00:00Z',
  ...overrides,
})

// ---------------------------------------------------------------------------
// Render helper
// ---------------------------------------------------------------------------

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
        staleTime: Infinity,
      },
    },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <IncidentsPage />
    </QueryClientProvider>,
  )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('IncidentsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    // Default: list pending forever → loading state
    mockApi.list.mockReturnValue(new Promise<never>(() => {}))
    // Metrics pending by default (no stats cards until specific tests)
    mockApi.metrics.mockReturnValue(new Promise<never>(() => {}))
  })

  // =========================================================================
  // Loading state
  // =========================================================================
  describe('loading state', () => {
    it('shows "Loading…" while the query is pending', () => {
      renderPage()
      expect(screen.getByText('Loading…')).toBeInTheDocument()
    })

    it('does not show the error message while loading', () => {
      renderPage()
      expect(screen.queryByText(/Failed to load/)).not.toBeInTheDocument()
    })

    it('does not show incident rows while loading', () => {
      renderPage()
      expect(
        screen.queryByText('Lateral Movement via Pass-the-Hash'),
      ).not.toBeInTheDocument()
    })

    it('does not show the empty-state message while loading', () => {
      renderPage()
      expect(
        screen.queryByText('No incidents match the current filters.'),
      ).not.toBeInTheDocument()
    })

    it('does not show the incident panel while loading', () => {
      renderPage()
      expect(screen.queryByTestId('incident-panel')).not.toBeInTheDocument()
    })

    it('does not show the summary row while loading', () => {
      renderPage()
      expect(screen.queryByText(/incidents/)).not.toBeInTheDocument()
    })
  })

  // =========================================================================
  // Error state
  // =========================================================================
  describe('error state', () => {
    it('shows the error message when the query fails', async () => {
      mockApi.list.mockRejectedValue(new Error('Network error'))
      renderPage()
      await waitFor(() => {
        expect(
          screen.getByText('Failed to load. Is the backend running?'),
        ).toBeInTheDocument()
      })
    })

    it('does not show "Loading…" in error state', async () => {
      mockApi.list.mockRejectedValue(new Error('fail'))
      renderPage()
      await waitFor(() => {
        expect(screen.queryByText('Loading…')).not.toBeInTheDocument()
      })
    })

    it('does not show incident rows in error state', async () => {
      mockApi.list.mockRejectedValue(new Error('fail'))
      renderPage()
      await waitFor(() => {
        expect(
          screen.queryByText('Lateral Movement via Pass-the-Hash'),
        ).not.toBeInTheDocument()
      })
    })

    it('does not show the empty-state message in error state', async () => {
      mockApi.list.mockRejectedValue(new Error('fail'))
      renderPage()
      await waitFor(() => {
        expect(
          screen.queryByText('No incidents match the current filters.'),
        ).not.toBeInTheDocument()
      })
    })
  })

  // =========================================================================
  // Success state — table rendering
  // =========================================================================
  describe('success state', () => {
    beforeEach(() => {
      mockApi.list.mockResolvedValue(makeResponse())
    })

    it('renders the incident title', async () => {
      renderPage()
      await waitFor(() => {
        expect(
          screen.getByText('Lateral Movement via Pass-the-Hash'),
        ).toBeInTheDocument()
      })
    })

    it('renders the incident ID as INC-{id}', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('INC-1')).toBeInTheDocument()
      })
    })

    it('renders the tactic as secondary text under the title', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('lateral_movement')).toBeInTheDocument()
      })
    })

    it('renders the host', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('WIN-DC01')).toBeInTheDocument()
      })
    })

    it('renders "Unassigned" when assigned_to is null', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('Unassigned')).toBeInTheDocument()
      })
    })

    it('renders the assigned_to value when set', async () => {
      mockApi.list.mockResolvedValue(
        makeResponse([makeIncident({ assigned_to: 'analyst@mxtac.local' })]),
      )
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('analyst@mxtac.local')).toBeInTheDocument()
      })
    })

    it('renders multiple incident rows', async () => {
      mockApi.list.mockResolvedValue(
        makeResponse([
          makeIncident({ id: 1, title: 'Incident Alpha' }),
          makeIncident({ id: 2, title: 'Incident Beta' }),
        ]),
      )
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('Incident Alpha')).toBeInTheDocument()
        expect(screen.getByText('Incident Beta')).toBeInTheDocument()
      })
    })

    it('does not show "Loading…" in success state', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.queryByText('Loading…')).not.toBeInTheDocument()
      })
    })

    it('does not show the error message in success state', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.queryByText(/Failed to load/)).not.toBeInTheDocument()
      })
    })

    it('does not show the empty-state message when there are incidents', async () => {
      renderPage()
      await waitFor(() => {
        expect(
          screen.queryByText('No incidents match the current filters.'),
        ).not.toBeInTheDocument()
      })
    })
  })

  // =========================================================================
  // Empty state
  // =========================================================================
  describe('empty state', () => {
    it('shows the empty-state message when the list is empty', async () => {
      mockApi.list.mockResolvedValue(makeResponse([]))
      renderPage()
      await waitFor(() => {
        expect(
          screen.getByText('No incidents match the current filters.'),
        ).toBeInTheDocument()
      })
    })

    it('does not show the empty-state message when incidents are present', async () => {
      mockApi.list.mockResolvedValue(makeResponse([makeIncident()]))
      renderPage()
      await waitFor(() => {
        expect(
          screen.queryByText('No incidents match the current filters.'),
        ).not.toBeInTheDocument()
      })
    })
  })

  // =========================================================================
  // Summary row
  // =========================================================================
  describe('summary row', () => {
    it('shows the total incident count', async () => {
      mockApi.list.mockResolvedValue(
        makeResponse(
          Array.from({ length: 3 }, (_, i) => makeIncident({ id: i + 1 })),
          { total: 42 },
        ),
      )
      renderPage()
      await waitFor(() => {
        expect(screen.getByText(/42 incidents/)).toBeInTheDocument()
      })
    })

    it('does not show the summary row while loading', () => {
      renderPage()
      expect(screen.queryByText(/incidents/)).not.toBeInTheDocument()
    })

    it('appends active severity filters to the summary', async () => {
      mockApi.list.mockResolvedValue(makeResponse([], { total: 0 }))
      renderPage()
      const criticalChip = await screen.findByRole('button', { name: 'Critical' })
      fireEvent.click(criticalChip)
      await waitFor(() => {
        expect(screen.getByText(/· critical/)).toBeInTheDocument()
      })
    })

    it('appends active status filters to the summary', async () => {
      mockApi.list.mockResolvedValue(makeResponse([], { total: 0 }))
      renderPage()
      const newChip = await screen.findByRole('button', { name: 'New' })
      fireEvent.click(newChip)
      await waitFor(() => {
        expect(screen.getByText(/· new/)).toBeInTheDocument()
      })
    })
  })

  // =========================================================================
  // Filter bar — static rendering
  // =========================================================================
  describe('filter bar', () => {
    beforeEach(() => {
      mockApi.list.mockResolvedValue(makeResponse())
    })

    it('renders the Critical severity chip', async () => {
      renderPage()
      expect(await screen.findByRole('button', { name: 'Critical' })).toBeInTheDocument()
    })

    it('renders the High severity chip', async () => {
      renderPage()
      expect(await screen.findByRole('button', { name: 'High' })).toBeInTheDocument()
    })

    it('renders the Medium severity chip', async () => {
      renderPage()
      expect(await screen.findByRole('button', { name: 'Medium' })).toBeInTheDocument()
    })

    it('renders the Low severity chip', async () => {
      renderPage()
      expect(await screen.findByRole('button', { name: 'Low' })).toBeInTheDocument()
    })

    it('renders the New status chip', async () => {
      renderPage()
      expect(await screen.findByRole('button', { name: 'New' })).toBeInTheDocument()
    })

    it('renders the Investigating status chip', async () => {
      renderPage()
      expect(await screen.findByRole('button', { name: 'Investigating' })).toBeInTheDocument()
    })

    it('renders the Contained status chip', async () => {
      renderPage()
      expect(await screen.findByRole('button', { name: 'Contained' })).toBeInTheDocument()
    })

    it('renders the Resolved status chip', async () => {
      renderPage()
      expect(await screen.findByRole('button', { name: 'Resolved' })).toBeInTheDocument()
    })

    it('renders the Closed status chip', async () => {
      renderPage()
      expect(await screen.findByRole('button', { name: 'Closed' })).toBeInTheDocument()
    })

    it('renders the search input', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.getByPlaceholderText('Search incidents…')).toBeInTheDocument()
      })
    })

    it('renders the "+ New Incident" button', async () => {
      renderPage()
      expect(await screen.findByRole('button', { name: /New Incident/ })).toBeInTheDocument()
    })
  })

  // =========================================================================
  // Table column headers
  // =========================================================================
  describe('table column headers', () => {
    beforeEach(() => {
      mockApi.list.mockResolvedValue(makeResponse())
    })

    it('renders the ID column header', async () => {
      renderPage()
      await waitFor(() => expect(screen.getByText('ID')).toBeInTheDocument())
    })

    it('renders the Title column header', async () => {
      renderPage()
      await waitFor(() => expect(screen.getByText('Title')).toBeInTheDocument())
    })

    it('renders the Severity column header', async () => {
      renderPage()
      await waitFor(() => expect(screen.getByText('Severity')).toBeInTheDocument())
    })

    it('renders the Status column header', async () => {
      renderPage()
      await waitFor(() => expect(screen.getByText('Status')).toBeInTheDocument())
    })

    it('renders the Assigned To column header', async () => {
      renderPage()
      await waitFor(() => expect(screen.getByText('Assigned To')).toBeInTheDocument())
    })

    it('renders the Hosts column header', async () => {
      renderPage()
      await waitFor(() => expect(screen.getByText('Hosts')).toBeInTheDocument())
    })

    it('renders the Created column header', async () => {
      renderPage()
      await waitFor(() => expect(screen.getByText('Created')).toBeInTheDocument())
    })
  })

  // =========================================================================
  // Severity filter — interaction
  // =========================================================================
  describe('severity filter', () => {
    beforeEach(() => {
      mockApi.list.mockResolvedValue(makeResponse())
    })

    it('activates a severity chip when clicked (adds bg-blue class)', async () => {
      renderPage()
      const chip = await screen.findByRole('button', { name: 'Critical' })
      fireEvent.click(chip)
      expect(chip).toHaveClass('bg-blue')
    })

    it('deactivates an active severity chip when clicked again', async () => {
      renderPage()
      const chip = await screen.findByRole('button', { name: 'Critical' })
      fireEvent.click(chip) // activate
      fireEvent.click(chip) // deactivate
      expect(chip).not.toHaveClass('bg-blue')
    })

    it('allows multiple severity chips to be active simultaneously', async () => {
      renderPage()
      const critical = await screen.findByRole('button', { name: 'Critical' })
      const high = screen.getByRole('button', { name: 'High' })
      fireEvent.click(critical)
      fireEvent.click(high)
      expect(critical).toHaveClass('bg-blue')
      expect(high).toHaveClass('bg-blue')
    })

    it('deactivating one severity chip keeps others active', async () => {
      renderPage()
      const critical = await screen.findByRole('button', { name: 'Critical' })
      const high = screen.getByRole('button', { name: 'High' })
      fireEvent.click(critical)
      fireEvent.click(high)
      fireEvent.click(critical) // deactivate critical only
      expect(critical).not.toHaveClass('bg-blue')
      expect(high).toHaveClass('bg-blue')
    })

    it('triggers a new API call when a severity chip is clicked', async () => {
      renderPage()
      await waitFor(() => expect(mockApi.list).toHaveBeenCalledTimes(1))
      const chip = await screen.findByRole('button', { name: 'High' })
      fireEvent.click(chip)
      await waitFor(() => expect(mockApi.list).toHaveBeenCalledTimes(2))
    })

    it('passes the selected severity to the API call', async () => {
      renderPage()
      await waitFor(() => expect(mockApi.list).toHaveBeenCalledTimes(1))
      const chip = await screen.findByRole('button', { name: 'Critical' })
      fireEvent.click(chip)
      await waitFor(() => {
        const lastCall = mockApi.list.mock.calls.at(-1)![0]
        expect(lastCall.severity).toContain('critical')
      })
    })

    it('passes undefined severity when no chip is selected', async () => {
      renderPage()
      await waitFor(() => {
        const firstCall = mockApi.list.mock.calls[0][0]
        expect(firstCall.severity).toBeUndefined()
      })
    })

    it('resets to page 1 when a severity chip is clicked', async () => {
      mockApi.list
        .mockResolvedValueOnce(makeResponse([makeIncident()], { total: 50, total_pages: 3, page: 1 }))
        .mockResolvedValue(makeResponse([makeIncident()], { total: 50, total_pages: 3, page: 2 }))
      renderPage()
      const nextBtn = await screen.findByText(/Next →/)
      fireEvent.click(nextBtn)
      await waitFor(() => expect(mockApi.list).toHaveBeenCalledTimes(2))
      const chip = screen.getByRole('button', { name: 'Critical' })
      fireEvent.click(chip)
      await waitFor(() => {
        const lastCall = mockApi.list.mock.calls.at(-1)![0]
        expect(lastCall.page).toBe(1)
      })
    })
  })

  // =========================================================================
  // Status filter — interaction (multi-select)
  // =========================================================================
  describe('status filter', () => {
    beforeEach(() => {
      mockApi.list.mockResolvedValue(makeResponse())
    })

    it('activates a status chip when clicked', async () => {
      renderPage()
      const chip = await screen.findByRole('button', { name: 'New' })
      fireEvent.click(chip)
      expect(chip).toHaveClass('bg-blue')
    })

    it('deactivates the status chip when clicked again (toggle off)', async () => {
      renderPage()
      const chip = await screen.findByRole('button', { name: 'New' })
      fireEvent.click(chip) // activate
      fireEvent.click(chip) // deactivate
      expect(chip).not.toHaveClass('bg-blue')
    })

    it('allows multiple status chips to be active simultaneously', async () => {
      renderPage()
      const newChip = await screen.findByRole('button', { name: 'New' })
      const resolved = screen.getByRole('button', { name: 'Resolved' })
      fireEvent.click(newChip)
      fireEvent.click(resolved)
      expect(newChip).toHaveClass('bg-blue')
      expect(resolved).toHaveClass('bg-blue')
    })

    it('deactivating one status chip keeps others active', async () => {
      renderPage()
      const newChip = await screen.findByRole('button', { name: 'New' })
      const resolved = screen.getByRole('button', { name: 'Resolved' })
      fireEvent.click(newChip)
      fireEvent.click(resolved)
      fireEvent.click(newChip) // deactivate New only
      expect(newChip).not.toHaveClass('bg-blue')
      expect(resolved).toHaveClass('bg-blue')
    })

    it('passes the selected status array to the API call', async () => {
      renderPage()
      await waitFor(() => expect(mockApi.list).toHaveBeenCalledTimes(1))
      const chip = await screen.findByRole('button', { name: 'Investigating' })
      fireEvent.click(chip)
      await waitFor(() => {
        const lastCall = mockApi.list.mock.calls.at(-1)![0]
        expect(lastCall.status).toContain('investigating')
      })
    })

    it('passes undefined status when no status chip is selected', async () => {
      renderPage()
      await waitFor(() => {
        const firstCall = mockApi.list.mock.calls[0][0]
        expect(firstCall.status).toBeUndefined()
      })
    })

    it('resets to page 1 when a status chip is clicked', async () => {
      mockApi.list
        .mockResolvedValueOnce(makeResponse([makeIncident()], { total: 50, total_pages: 3, page: 1 }))
        .mockResolvedValue(makeResponse([makeIncident()], { total: 50, total_pages: 3, page: 2 }))
      renderPage()
      const nextBtn = await screen.findByText(/Next →/)
      fireEvent.click(nextBtn)
      await waitFor(() => expect(mockApi.list).toHaveBeenCalledTimes(2))
      const statusChip = screen.getByRole('button', { name: 'New' })
      fireEvent.click(statusChip)
      await waitFor(() => {
        const lastCall = mockApi.list.mock.calls.at(-1)![0]
        expect(lastCall.page).toBe(1)
      })
    })
  })

  // =========================================================================
  // Search input — interaction
  // =========================================================================
  describe('search input', () => {
    beforeEach(() => {
      mockApi.list.mockResolvedValue(makeResponse())
    })

    it('updates the input value as the user types', async () => {
      renderPage()
      const input = await screen.findByPlaceholderText('Search incidents…')
      fireEvent.change(input, { target: { value: 'pass-the-hash' } })
      expect(input).toHaveValue('pass-the-hash')
    })

    it('triggers a new API call after the search value changes', async () => {
      renderPage()
      await waitFor(() => expect(mockApi.list).toHaveBeenCalledTimes(1))
      const input = await screen.findByPlaceholderText('Search incidents…')
      fireEvent.change(input, { target: { value: 'lateral' } })
      await waitFor(() => expect(mockApi.list).toHaveBeenCalledTimes(2))
    })

    it('passes the search term to the API call', async () => {
      renderPage()
      await waitFor(() => expect(mockApi.list).toHaveBeenCalledTimes(1))
      const input = await screen.findByPlaceholderText('Search incidents…')
      fireEvent.change(input, { target: { value: 'ransomware' } })
      await waitFor(() => {
        const lastCall = mockApi.list.mock.calls.at(-1)![0]
        expect(lastCall.search).toBe('ransomware')
      })
    })

    it('passes undefined search when the input is empty', async () => {
      renderPage()
      await waitFor(() => {
        const firstCall = mockApi.list.mock.calls[0][0]
        expect(firstCall.search).toBeUndefined()
      })
    })

    it('resets to page 1 when the search value changes', async () => {
      mockApi.list
        .mockResolvedValueOnce(makeResponse([makeIncident()], { total: 50, total_pages: 3, page: 1 }))
        .mockResolvedValue(makeResponse([makeIncident()], { total: 50, total_pages: 3, page: 2 }))
      renderPage()
      const nextBtn = await screen.findByText(/Next →/)
      fireEvent.click(nextBtn)
      await waitFor(() => expect(mockApi.list).toHaveBeenCalledTimes(2))
      const input = screen.getByPlaceholderText('Search incidents…')
      fireEvent.change(input, { target: { value: 'pivot' } })
      await waitFor(() => {
        const lastCall = mockApi.list.mock.calls.at(-1)![0]
        expect(lastCall.page).toBe(1)
      })
    })
  })

  // =========================================================================
  // Pagination
  // =========================================================================
  describe('pagination', () => {
    it('does not show pagination controls when total_pages is 1', async () => {
      mockApi.list.mockResolvedValue(makeResponse([makeIncident()], { total: 5, total_pages: 1 }))
      renderPage()
      await waitFor(() => {
        expect(screen.queryByText(/← Prev/)).not.toBeInTheDocument()
        expect(screen.queryByText(/Next →/)).not.toBeInTheDocument()
      })
    })

    it('shows pagination controls when total_pages > 1', async () => {
      mockApi.list.mockResolvedValue(makeResponse([makeIncident()], { total: 50, total_pages: 3, page: 1 }))
      renderPage()
      await waitFor(() => {
        expect(screen.getByText(/← Prev/)).toBeInTheDocument()
        expect(screen.getByText(/Next →/)).toBeInTheDocument()
      })
    })

    it('shows the current page and total pages', async () => {
      mockApi.list.mockResolvedValue(makeResponse([makeIncident()], { total: 50, total_pages: 3, page: 1 }))
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('Page 1 of 3')).toBeInTheDocument()
      })
    })

    it('Prev button is disabled on page 1', async () => {
      mockApi.list.mockResolvedValue(makeResponse([makeIncident()], { total: 50, total_pages: 3, page: 1 }))
      renderPage()
      const prevBtn = await screen.findByText(/← Prev/)
      expect(prevBtn.closest('button')).toBeDisabled()
    })

    it('Next button is not disabled on page 1 of 3', async () => {
      mockApi.list.mockResolvedValue(makeResponse([makeIncident()], { total: 50, total_pages: 3, page: 1 }))
      renderPage()
      const nextBtn = await screen.findByText(/Next →/)
      expect(nextBtn.closest('button')).not.toBeDisabled()
    })

    it('clicking Next requests page 2', async () => {
      mockApi.list.mockResolvedValue(makeResponse([makeIncident()], { total: 50, total_pages: 3, page: 1 }))
      renderPage()
      await waitFor(() => expect(mockApi.list).toHaveBeenCalledTimes(1))
      fireEvent.click(await screen.findByText(/Next →/))
      await waitFor(() => {
        const lastCall = mockApi.list.mock.calls.at(-1)![0]
        expect(lastCall.page).toBe(2)
      })
    })

    it('clicking Next twice requests page 3', async () => {
      mockApi.list
        .mockResolvedValueOnce(makeResponse([makeIncident()], { total: 60, total_pages: 3, page: 1 }))
        .mockResolvedValueOnce(makeResponse([makeIncident()], { total: 60, total_pages: 3, page: 2 }))
        .mockResolvedValue(makeResponse([makeIncident()], { total: 60, total_pages: 3, page: 3 }))
      renderPage()
      fireEvent.click(await screen.findByText(/Next →/)) // page 1 → 2
      fireEvent.click(await screen.findByText(/Next →/)) // page 2 → 3
      await waitFor(() => {
        expect(
          mockApi.list.mock.calls.some((c: unknown[]) => (c[0] as Record<string, unknown>).page === 3),
        ).toBe(true)
      })
    })

    it('clicking Prev requests the previous page', async () => {
      mockApi.list
        .mockResolvedValueOnce(makeResponse([makeIncident()], { total: 50, total_pages: 3, page: 1 }))
        .mockResolvedValueOnce(makeResponse([makeIncident()], { total: 50, total_pages: 3, page: 2 }))
        .mockResolvedValue(makeResponse([makeIncident()], { total: 50, total_pages: 3, page: 1 }))
      renderPage()
      fireEvent.click(await screen.findByText(/Next →/))  // page 1 → 2
      fireEvent.click(await screen.findByText(/← Prev/))  // page 2 → 1
      await waitFor(() => {
        expect(
          mockApi.list.mock.calls.some((c: unknown[]) => (c[0] as Record<string, unknown>).page === 1),
        ).toBe(true)
      })
    })

    it('Next button is disabled on the last page', async () => {
      mockApi.list
        .mockResolvedValueOnce(makeResponse([makeIncident()], { total: 40, total_pages: 2, page: 1 }))
        .mockResolvedValue(makeResponse([makeIncident()], { total: 40, total_pages: 2, page: 2 }))
      renderPage()
      fireEvent.click(await screen.findByText(/Next →/)) // advance to page 2
      await waitFor(() => expect(mockApi.list).toHaveBeenCalledTimes(2))
      await waitFor(() => {
        const nextBtn = screen.getByText(/Next →/)
        expect(nextBtn.closest('button')).toBeDisabled()
      })
    })

    it('Prev button is enabled after navigating to page 2', async () => {
      mockApi.list
        .mockResolvedValueOnce(makeResponse([makeIncident()], { total: 40, total_pages: 2, page: 1 }))
        .mockResolvedValue(makeResponse([makeIncident()], { total: 40, total_pages: 2, page: 2 }))
      renderPage()
      fireEvent.click(await screen.findByText(/Next →/))
      await waitFor(() => expect(mockApi.list).toHaveBeenCalledTimes(2))
      await waitFor(() => {
        const prevBtn = screen.getByText(/← Prev/)
        expect(prevBtn.closest('button')).not.toBeDisabled()
      })
    })
  })

  // =========================================================================
  // TopBar
  // =========================================================================
  describe('TopBar', () => {
    it('renders the TopBar with the "Incidents" crumb', () => {
      renderPage()
      expect(screen.getByTestId('topbar')).toHaveTextContent('Incidents')
    })
  })

  // =========================================================================
  // Initial API call parameters
  // =========================================================================
  describe('initial API call parameters', () => {
    beforeEach(() => {
      mockApi.list.mockResolvedValue(makeResponse())
    })

    it('calls incidentsApi.list once on mount', async () => {
      renderPage()
      await waitFor(() => expect(mockApi.list).toHaveBeenCalledTimes(1))
    })

    it('defaults to page=1', async () => {
      renderPage()
      await waitFor(() => {
        expect(mockApi.list.mock.calls[0][0].page).toBe(1)
      })
    })

    it('defaults to page_size=20', async () => {
      renderPage()
      await waitFor(() => {
        expect(mockApi.list.mock.calls[0][0].page_size).toBe(20)
      })
    })

    it('defaults to sort=created_at', async () => {
      renderPage()
      await waitFor(() => {
        expect(mockApi.list.mock.calls[0][0].sort).toBe('created_at')
      })
    })

    it('does not pass a severity filter by default', async () => {
      renderPage()
      await waitFor(() => {
        expect(mockApi.list.mock.calls[0][0].severity).toBeUndefined()
      })
    })

    it('does not pass a status filter by default', async () => {
      renderPage()
      await waitFor(() => {
        expect(mockApi.list.mock.calls[0][0].status).toBeUndefined()
      })
    })

    it('does not pass a search term by default', async () => {
      renderPage()
      await waitFor(() => {
        expect(mockApi.list.mock.calls[0][0].search).toBeUndefined()
      })
    })
  })

  // =========================================================================
  // Row selection / IncidentPanel
  // =========================================================================
  describe('row selection', () => {
    beforeEach(() => {
      mockApi.list.mockResolvedValue(
        makeResponse([makeIncident({ id: 1, title: 'Lateral Movement via Pass-the-Hash' })]),
      )
    })

    it('incident panel is not shown initially', () => {
      renderPage()
      expect(screen.queryByTestId('incident-panel')).not.toBeInTheDocument()
    })

    it('clicking a row opens the incident panel', async () => {
      renderPage()
      fireEvent.click(await screen.findByText('Lateral Movement via Pass-the-Hash'))
      expect(screen.getByTestId('incident-panel')).toBeInTheDocument()
    })

    it('the panel receives the correct incident id', async () => {
      renderPage()
      fireEvent.click(await screen.findByText('Lateral Movement via Pass-the-Hash'))
      expect(screen.getByTestId('incident-panel')).toHaveAttribute('data-incident-id', '1')
    })

    it('clicking a selected row closes the panel', async () => {
      renderPage()
      const row = await screen.findByText('Lateral Movement via Pass-the-Hash')
      fireEvent.click(row) // open
      expect(screen.getByTestId('incident-panel')).toBeInTheDocument()
      fireEvent.click(row) // close (deselect same row)
      expect(screen.queryByTestId('incident-panel')).not.toBeInTheDocument()
    })

    it('clicking the panel close button closes the panel', async () => {
      renderPage()
      fireEvent.click(await screen.findByText('Lateral Movement via Pass-the-Hash'))
      expect(screen.getByTestId('incident-panel')).toBeInTheDocument()
      fireEvent.click(screen.getByTestId('panel-close'))
      expect(screen.queryByTestId('incident-panel')).not.toBeInTheDocument()
    })

    it('clicking a different row replaces the selected incident in the panel', async () => {
      mockApi.list.mockResolvedValue(
        makeResponse([
          makeIncident({ id: 1, title: 'Incident Alpha' }),
          makeIncident({ id: 2, title: 'Incident Beta' }),
        ]),
      )
      renderPage()
      fireEvent.click(await screen.findByText('Incident Alpha'))
      expect(screen.getByTestId('incident-panel')).toHaveAttribute('data-incident-id', '1')
      fireEvent.click(screen.getByText('Incident Beta'))
      expect(screen.getByTestId('incident-panel')).toHaveAttribute('data-incident-id', '2')
    })
  })

  // =========================================================================
  // Create Incident modal
  // =========================================================================
  describe('create incident modal', () => {
    beforeEach(() => {
      mockApi.list.mockResolvedValue(makeResponse())
    })

    it('modal is not shown initially', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.queryByText('Create Incident')).not.toBeInTheDocument()
      })
    })

    it('clicking "+ New Incident" opens the create modal', async () => {
      renderPage()
      const btn = await screen.findByRole('button', { name: /New Incident/ })
      fireEvent.click(btn)
      expect(screen.getByRole('heading', { name: 'Create Incident' })).toBeInTheDocument()
    })

    it('the modal contains the Title field', async () => {
      renderPage()
      const btn = await screen.findByRole('button', { name: /New Incident/ })
      fireEvent.click(btn)
      expect(
        screen.getByPlaceholderText('e.g. Lateral Movement via Pass-the-Hash'),
      ).toBeInTheDocument()
    })

    it('the modal contains the Severity select', async () => {
      renderPage()
      const btn = await screen.findByRole('button', { name: /New Incident/ })
      fireEvent.click(btn)
      expect(screen.getByRole('combobox')).toBeInTheDocument()
    })

    it('clicking Cancel closes the modal', async () => {
      renderPage()
      const btn = await screen.findByRole('button', { name: /New Incident/ })
      fireEvent.click(btn)
      expect(screen.getByRole('heading', { name: 'Create Incident' })).toBeInTheDocument()
      fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
      await waitFor(() => {
        expect(screen.queryByRole('heading', { name: 'Create Incident' })).not.toBeInTheDocument()
      })
    })
  })

  // =========================================================================
  // Stats cards (metrics query)
  // =========================================================================
  describe('stats cards', () => {
    it('does not show stats cards while metrics are loading', () => {
      mockApi.list.mockResolvedValue(makeResponse())
      // metrics is pending (default)
      renderPage()
      expect(screen.queryByText('Total Incidents')).not.toBeInTheDocument()
    })

    it('shows stats cards when metrics resolve', async () => {
      mockApi.list.mockResolvedValue(makeResponse())
      mockApi.metrics.mockResolvedValue(makeMetrics())
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('Total Incidents')).toBeInTheDocument()
      })
    })

    it('shows the open incidents count in the Open card', async () => {
      mockApi.list.mockResolvedValue(makeResponse())
      mockApi.metrics.mockResolvedValue(makeMetrics({ open_incidents_count: 10 }))
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('Open')).toBeInTheDocument()
      })
    })

    it('shows the Avg MTTR card', async () => {
      mockApi.list.mockResolvedValue(makeResponse())
      mockApi.metrics.mockResolvedValue(makeMetrics())
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('Avg MTTR')).toBeInTheDocument()
      })
    })

    it('shows the Critical / High card', async () => {
      mockApi.list.mockResolvedValue(makeResponse())
      mockApi.metrics.mockResolvedValue(makeMetrics())
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('Critical / High')).toBeInTheDocument()
      })
    })
  })
})
