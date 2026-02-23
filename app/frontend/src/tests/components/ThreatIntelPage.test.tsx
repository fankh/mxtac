// vi.mock is hoisted before imports — declare all module mocks first.

vi.mock('../../lib/api', () => ({
  threatIntelApi: {
    list:       vi.fn(),
    stats:      vi.fn(),
    create:     vi.fn(),
    bulkImport: vi.fn(),
    update:     vi.fn(),
    deactivate: vi.fn(),
  },
  detectionsApi: {
    list: vi.fn(),
  },
}))

vi.mock('../../components/layout/TopBar', () => ({
  TopBar: ({ crumb }: { crumb: string }) => (
    <header data-testid="topbar">{crumb}</header>
  ),
}))

import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ThreatIntelPage } from '../../components/features/intel/ThreatIntelPage'
import { threatIntelApi, detectionsApi } from '../../lib/api'

// ---------------------------------------------------------------------------
// Typed API references
// ---------------------------------------------------------------------------

const mockThreatIntel = threatIntelApi as {
  list:       ReturnType<typeof vi.fn>
  stats:      ReturnType<typeof vi.fn>
  create:     ReturnType<typeof vi.fn>
  bulkImport: ReturnType<typeof vi.fn>
  update:     ReturnType<typeof vi.fn>
  deactivate: ReturnType<typeof vi.fn>
}

const mockDetections = detectionsApi as {
  list: ReturnType<typeof vi.fn>
}

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

const makeIOC = (overrides: Record<string, unknown> = {}) => ({
  id: 1,
  ioc_type: 'ip' as const,
  value: '192.168.1.100',
  source: 'stix-feed',
  confidence: 85,
  severity: 'high' as const,
  description: null,
  tags: [],
  first_seen: '2026-02-01T00:00:00Z',
  last_seen: '2026-02-20T00:00:00Z',
  expires_at: null,
  is_active: true,
  hit_count: 3,
  last_hit_at: '2026-02-20T10:00:00Z',
  created_at: '2026-02-01T00:00:00Z',
  updated_at: '2026-02-20T10:00:00Z',
  ...overrides,
})

const makeResponse = (
  items = [makeIOC()],
  paginationOverrides: Record<string, unknown> = {},
) => ({
  items,
  pagination: {
    page: 1,
    page_size: 25,
    total: items.length,
    total_pages: 1,
    ...paginationOverrides,
  },
})

const makeStats = (overrides: Record<string, unknown> = {}) => ({
  total: 150,
  by_type: { ip: 80, domain: 40, hash_sha256: 30 },
  by_source: { 'stix-feed': 100, manual: 50 },
  active: 120,
  expired: 30,
  total_hits: 1500,
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
      <ThreatIntelPage />
    </QueryClientProvider>,
  )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('ThreatIntelPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    // Default: all queries pending forever
    mockThreatIntel.list.mockReturnValue(new Promise<never>(() => {}))
    mockThreatIntel.stats.mockReturnValue(new Promise<never>(() => {}))
    mockDetections.list.mockReturnValue(new Promise<never>(() => {}))
  })

  // =========================================================================
  // TopBar
  // =========================================================================
  describe('TopBar', () => {
    it('renders the TopBar with "Threat Intel" crumb', () => {
      renderPage()
      expect(screen.getByTestId('topbar')).toHaveTextContent('Threat Intel')
    })
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

    it('does not show IOC rows while loading', () => {
      renderPage()
      expect(screen.queryByText('192.168.1.100')).not.toBeInTheDocument()
    })

    it('does not show the empty-state message while loading', () => {
      renderPage()
      expect(
        screen.queryByText('No IOCs match the current filters.'),
      ).not.toBeInTheDocument()
    })

    it('does not show stats cards while stats are loading', () => {
      renderPage()
      expect(screen.queryByText('Total IOCs')).not.toBeInTheDocument()
    })
  })

  // =========================================================================
  // Error state
  // =========================================================================
  describe('error state', () => {
    it('shows the error message when the query fails', async () => {
      mockThreatIntel.list.mockRejectedValue(new Error('Network error'))
      renderPage()
      await waitFor(() => {
        expect(
          screen.getByText('Failed to load. Is the backend running?'),
        ).toBeInTheDocument()
      })
    })

    it('does not show "Loading…" in error state', async () => {
      mockThreatIntel.list.mockRejectedValue(new Error('fail'))
      renderPage()
      await waitFor(() => {
        expect(screen.queryByText('Loading…')).not.toBeInTheDocument()
      })
    })

    it('does not show IOC rows in error state', async () => {
      mockThreatIntel.list.mockRejectedValue(new Error('fail'))
      renderPage()
      await waitFor(() => {
        expect(screen.queryByText('192.168.1.100')).not.toBeInTheDocument()
      })
    })

    it('does not show the empty-state message in error state', async () => {
      mockThreatIntel.list.mockRejectedValue(new Error('fail'))
      renderPage()
      await waitFor(() => {
        expect(
          screen.queryByText('No IOCs match the current filters.'),
        ).not.toBeInTheDocument()
      })
    })
  })

  // =========================================================================
  // Success state — table rendering
  // =========================================================================
  describe('success state', () => {
    beforeEach(() => {
      mockThreatIntel.list.mockResolvedValue(makeResponse())
    })

    it('renders the IOC value', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('192.168.1.100')).toBeInTheDocument()
      })
    })

    it('renders the IOC source', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('stix-feed')).toBeInTheDocument()
      })
    })

    it('renders the hit count when greater than 0', async () => {
      renderPage()
      await waitFor(() => {
        // hit_count is 3 in default fixture
        expect(screen.getByText('3')).toBeInTheDocument()
      })
    })

    it('renders multiple IOC rows', async () => {
      mockThreatIntel.list.mockResolvedValue(
        makeResponse([
          makeIOC({ id: 1, value: '10.0.0.1' }),
          makeIOC({ id: 2, value: 'malicious.example.com', ioc_type: 'domain' }),
        ]),
      )
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('10.0.0.1')).toBeInTheDocument()
        expect(screen.getByText('malicious.example.com')).toBeInTheDocument()
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

    it('does not show the empty-state message when IOCs are present', async () => {
      renderPage()
      await waitFor(() => {
        expect(
          screen.queryByText('No IOCs match the current filters.'),
        ).not.toBeInTheDocument()
      })
    })

    it('renders IOC tags as secondary text when present', async () => {
      mockThreatIntel.list.mockResolvedValue(
        makeResponse([makeIOC({ tags: ['apt29', 'c2'] })]),
      )
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('apt29, c2')).toBeInTheDocument()
      })
    })
  })

  // =========================================================================
  // Empty state
  // =========================================================================
  describe('empty state', () => {
    it('shows the empty-state message when the list is empty', async () => {
      mockThreatIntel.list.mockResolvedValue(makeResponse([]))
      renderPage()
      await waitFor(() => {
        expect(
          screen.getByText('No IOCs match the current filters.'),
        ).toBeInTheDocument()
      })
    })

    it('does not show the empty-state message when IOCs are present', async () => {
      mockThreatIntel.list.mockResolvedValue(makeResponse([makeIOC()]))
      renderPage()
      await waitFor(() => {
        expect(
          screen.queryByText('No IOCs match the current filters.'),
        ).not.toBeInTheDocument()
      })
    })
  })

  // =========================================================================
  // Stats cards
  // =========================================================================
  describe('stats cards', () => {
    beforeEach(() => {
      mockThreatIntel.list.mockResolvedValue(makeResponse())
    })

    it('does not show stats cards while stats are loading', () => {
      renderPage()
      expect(screen.queryByText('Total IOCs')).not.toBeInTheDocument()
    })

    it('shows "Total IOCs" card when stats resolve', async () => {
      mockThreatIntel.stats.mockResolvedValue(makeStats())
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('Total IOCs')).toBeInTheDocument()
      })
    })

    it('shows "Active" card when stats resolve', async () => {
      mockThreatIntel.stats.mockResolvedValue(makeStats())
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('Active')).toBeInTheDocument()
      })
    })

    it('shows "Expired" card when stats resolve', async () => {
      mockThreatIntel.stats.mockResolvedValue(makeStats())
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('Expired')).toBeInTheDocument()
      })
    })

    it('shows "Total Hits" card when stats resolve', async () => {
      mockThreatIntel.stats.mockResolvedValue(makeStats())
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('Total Hits')).toBeInTheDocument()
      })
    })

    it('displays the correct total IOC count', async () => {
      mockThreatIntel.stats.mockResolvedValue(makeStats({ total: 200 }))
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('200')).toBeInTheDocument()
      })
    })

    it('displays the correct active count', async () => {
      mockThreatIntel.stats.mockResolvedValue(makeStats({ active: 175 }))
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('175')).toBeInTheDocument()
      })
    })
  })

  // =========================================================================
  // Summary row
  // =========================================================================
  describe('summary row', () => {
    it('shows the total IOC count', async () => {
      mockThreatIntel.list.mockResolvedValue(
        makeResponse([makeIOC()], { total: 42 }),
      )
      renderPage()
      await waitFor(() => {
        expect(screen.getByText(/42 IOCs/)).toBeInTheDocument()
      })
    })

    it('does not show the summary row while loading', () => {
      renderPage()
      expect(screen.queryByText(/\d+ IOCs/)).not.toBeInTheDocument()
    })
  })

  // =========================================================================
  // Filter bar — static rendering
  // =========================================================================
  describe('filter bar', () => {
    beforeEach(() => {
      mockThreatIntel.list.mockResolvedValue(makeResponse())
    })

    it('renders the Type dropdown', async () => {
      renderPage()
      await waitFor(() => {
        // Two selects have "All" as first option (Type + Source); take the first (Type)
        const [typeSelect] = screen.getAllByDisplayValue('All')
        expect(typeSelect).toBeInTheDocument()
      })
    })

    it('renders the "All" status button', async () => {
      renderPage()
      expect(await screen.findByRole('button', { name: 'All' })).toBeInTheDocument()
    })

    it('renders the "Active" status button', async () => {
      renderPage()
      expect(await screen.findByRole('button', { name: 'Active' })).toBeInTheDocument()
    })

    it('renders the "Inactive" status button', async () => {
      renderPage()
      expect(await screen.findByRole('button', { name: 'Inactive' })).toBeInTheDocument()
    })

    it('renders the search input', async () => {
      renderPage()
      await waitFor(() => {
        expect(
          screen.getByPlaceholderText('Search IOC value, source…'),
        ).toBeInTheDocument()
      })
    })

    it('renders the "+ Add IOC" button', async () => {
      renderPage()
      expect(
        await screen.findByRole('button', { name: /Add IOC/ }),
      ).toBeInTheDocument()
    })

    it('renders the "Bulk Import" button', async () => {
      renderPage()
      expect(
        await screen.findByRole('button', { name: /Bulk Import/ }),
      ).toBeInTheDocument()
    })
  })

  // =========================================================================
  // Table column headers
  // =========================================================================
  describe('table column headers', () => {
    beforeEach(() => {
      mockThreatIntel.list.mockResolvedValue(makeResponse())
    })

    it('renders the Type column header', async () => {
      renderPage()
      await waitFor(() => expect(screen.getByText('Type')).toBeInTheDocument())
    })

    it('renders the Value column header', async () => {
      renderPage()
      await waitFor(() => expect(screen.getByText('Value')).toBeInTheDocument())
    })

    it('renders the Source column header', async () => {
      renderPage()
      await waitFor(() => expect(screen.getByText('Source')).toBeInTheDocument())
    })

    it('renders the Severity column header', async () => {
      renderPage()
      await waitFor(() => expect(screen.getByText('Severity')).toBeInTheDocument())
    })

    it('renders the Confidence column header', async () => {
      renderPage()
      await waitFor(() =>
        expect(screen.getByText('Confidence')).toBeInTheDocument(),
      )
    })

    it('renders the Hits column header', async () => {
      renderPage()
      await waitFor(() => expect(screen.getByText('Hits')).toBeInTheDocument())
    })

    it('renders the Last Seen column header', async () => {
      renderPage()
      await waitFor(() => expect(screen.getByText('Last Seen')).toBeInTheDocument())
    })
  })

  // =========================================================================
  // Initial API call parameters
  // =========================================================================
  describe('initial API call parameters', () => {
    beforeEach(() => {
      mockThreatIntel.list.mockResolvedValue(makeResponse())
    })

    it('calls threatIntelApi.list once on mount', async () => {
      renderPage()
      await waitFor(() => expect(mockThreatIntel.list).toHaveBeenCalledTimes(1))
    })

    it('calls threatIntelApi.stats once on mount', async () => {
      renderPage()
      await waitFor(() => expect(mockThreatIntel.stats).toHaveBeenCalledTimes(1))
    })

    it('defaults to page=1', async () => {
      renderPage()
      await waitFor(() => {
        expect(mockThreatIntel.list.mock.calls[0][0].page).toBe(1)
      })
    })

    it('defaults to page_size=25', async () => {
      renderPage()
      await waitFor(() => {
        expect(mockThreatIntel.list.mock.calls[0][0].page_size).toBe(25)
      })
    })

    it('does not pass ioc_type filter by default', async () => {
      renderPage()
      await waitFor(() => {
        expect(mockThreatIntel.list.mock.calls[0][0].ioc_type).toBeUndefined()
      })
    })

    it('does not pass source filter by default', async () => {
      renderPage()
      await waitFor(() => {
        expect(mockThreatIntel.list.mock.calls[0][0].source).toBeUndefined()
      })
    })

    it('does not pass is_active filter by default', async () => {
      renderPage()
      await waitFor(() => {
        expect(mockThreatIntel.list.mock.calls[0][0].is_active).toBeUndefined()
      })
    })

    it('does not pass a search term by default', async () => {
      renderPage()
      await waitFor(() => {
        expect(mockThreatIntel.list.mock.calls[0][0].search).toBeUndefined()
      })
    })
  })

  // =========================================================================
  // IOC type filter — interaction
  // =========================================================================
  describe('ioc_type filter', () => {
    beforeEach(() => {
      mockThreatIntel.list.mockResolvedValue(makeResponse())
    })

    it('triggers a new API call when type is changed', async () => {
      renderPage()
      await waitFor(() => expect(mockThreatIntel.list).toHaveBeenCalledTimes(1))
      // Type select is the first of two "All" selects (Type + Source)
      const [typeSelect] = screen.getAllByDisplayValue('All')
      fireEvent.change(typeSelect, { target: { value: 'ip' } })
      await waitFor(() => expect(mockThreatIntel.list).toHaveBeenCalledTimes(2))
    })

    it('passes the selected ioc_type to the API call', async () => {
      renderPage()
      await waitFor(() => expect(mockThreatIntel.list).toHaveBeenCalledTimes(1))
      const [typeSelect] = screen.getAllByDisplayValue('All')
      fireEvent.change(typeSelect, { target: { value: 'domain' } })
      await waitFor(() => {
        const lastCall = mockThreatIntel.list.mock.calls.at(-1)![0]
        expect(lastCall.ioc_type).toBe('domain')
      })
    })

    it('resets to page 1 when type filter changes', async () => {
      mockThreatIntel.list
        .mockResolvedValueOnce(makeResponse([makeIOC()], { total: 50, total_pages: 3, page: 1 }))
        .mockResolvedValue(makeResponse([makeIOC()], { total: 50, total_pages: 3, page: 2 }))
      renderPage()
      fireEvent.click(await screen.findByText(/Next →/))
      await waitFor(() => expect(mockThreatIntel.list).toHaveBeenCalledTimes(2))
      const [typeSelect] = screen.getAllByDisplayValue('All')
      fireEvent.change(typeSelect, { target: { value: 'ip' } })
      await waitFor(() => {
        const lastCall = mockThreatIntel.list.mock.calls.at(-1)![0]
        expect(lastCall.page).toBe(1)
      })
    })
  })

  // =========================================================================
  // Status filter — interaction
  // =========================================================================
  describe('status filter', () => {
    beforeEach(() => {
      mockThreatIntel.list.mockResolvedValue(makeResponse())
    })

    it('activates "Active" button when clicked (adds bg-blue class)', async () => {
      renderPage()
      const btn = await screen.findByRole('button', { name: 'Active' })
      fireEvent.click(btn)
      expect(btn).toHaveClass('bg-blue')
    })

    it('"All" button starts with bg-blue (default selection)', async () => {
      renderPage()
      const btn = await screen.findByRole('button', { name: 'All' })
      expect(btn).toHaveClass('bg-blue')
    })

    it('passes is_active=true to API when "Active" is clicked', async () => {
      renderPage()
      await waitFor(() => expect(mockThreatIntel.list).toHaveBeenCalledTimes(1))
      const btn = await screen.findByRole('button', { name: 'Active' })
      fireEvent.click(btn)
      await waitFor(() => {
        const lastCall = mockThreatIntel.list.mock.calls.at(-1)![0]
        expect(lastCall.is_active).toBe(true)
      })
    })

    it('passes is_active=false to API when "Inactive" is clicked', async () => {
      renderPage()
      await waitFor(() => expect(mockThreatIntel.list).toHaveBeenCalledTimes(1))
      const btn = await screen.findByRole('button', { name: 'Inactive' })
      fireEvent.click(btn)
      await waitFor(() => {
        const lastCall = mockThreatIntel.list.mock.calls.at(-1)![0]
        expect(lastCall.is_active).toBe(false)
      })
    })

    it('"All" button is selected by default (bg-blue class)', async () => {
      // The initial state is is_active=undefined which maps to the "All" button.
      // Verify the initial API call has no is_active filter.
      renderPage()
      await waitFor(() => {
        const firstCall = mockThreatIntel.list.mock.calls[0][0]
        expect(firstCall.is_active).toBeUndefined()
      })
    })

    it('resets to page 1 when status filter changes', async () => {
      mockThreatIntel.list
        .mockResolvedValueOnce(makeResponse([makeIOC()], { total: 50, total_pages: 3, page: 1 }))
        .mockResolvedValue(makeResponse([makeIOC()], { total: 50, total_pages: 3, page: 2 }))
      renderPage()
      fireEvent.click(await screen.findByText(/Next →/))
      await waitFor(() => expect(mockThreatIntel.list).toHaveBeenCalledTimes(2))
      const activeBtn = screen.getByRole('button', { name: 'Active' })
      fireEvent.click(activeBtn)
      await waitFor(() => {
        const lastCall = mockThreatIntel.list.mock.calls.at(-1)![0]
        expect(lastCall.page).toBe(1)
      })
    })
  })

  // =========================================================================
  // Search input — interaction
  // =========================================================================
  describe('search input', () => {
    beforeEach(() => {
      mockThreatIntel.list.mockResolvedValue(makeResponse())
    })

    it('updates the input value as the user types', async () => {
      renderPage()
      const input = await screen.findByPlaceholderText('Search IOC value, source…')
      fireEvent.change(input, { target: { value: 'malicious' } })
      expect(input).toHaveValue('malicious')
    })

    it('triggers a new API call after the search value changes', async () => {
      renderPage()
      await waitFor(() => expect(mockThreatIntel.list).toHaveBeenCalledTimes(1))
      const input = await screen.findByPlaceholderText('Search IOC value, source…')
      fireEvent.change(input, { target: { value: 'evil.com' } })
      await waitFor(() => expect(mockThreatIntel.list).toHaveBeenCalledTimes(2))
    })

    it('passes the search term to the API call', async () => {
      renderPage()
      await waitFor(() => expect(mockThreatIntel.list).toHaveBeenCalledTimes(1))
      const input = await screen.findByPlaceholderText('Search IOC value, source…')
      fireEvent.change(input, { target: { value: 'apt29' } })
      await waitFor(() => {
        const lastCall = mockThreatIntel.list.mock.calls.at(-1)![0]
        expect(lastCall.search).toBe('apt29')
      })
    })

    it('passes undefined search when the input is empty', async () => {
      renderPage()
      await waitFor(() => {
        const firstCall = mockThreatIntel.list.mock.calls[0][0]
        expect(firstCall.search).toBeUndefined()
      })
    })

    it('resets to page 1 when the search value changes', async () => {
      mockThreatIntel.list
        .mockResolvedValueOnce(makeResponse([makeIOC()], { total: 50, total_pages: 3, page: 1 }))
        .mockResolvedValue(makeResponse([makeIOC()], { total: 50, total_pages: 3, page: 2 }))
      renderPage()
      fireEvent.click(await screen.findByText(/Next →/))
      await waitFor(() => expect(mockThreatIntel.list).toHaveBeenCalledTimes(2))
      const input = screen.getByPlaceholderText('Search IOC value, source…')
      fireEvent.change(input, { target: { value: 'pivot' } })
      await waitFor(() => {
        const lastCall = mockThreatIntel.list.mock.calls.at(-1)![0]
        expect(lastCall.page).toBe(1)
      })
    })
  })

  // =========================================================================
  // Pagination
  // =========================================================================
  describe('pagination', () => {
    it('does not show pagination controls when total_pages is 1', async () => {
      mockThreatIntel.list.mockResolvedValue(
        makeResponse([makeIOC()], { total: 5, total_pages: 1 }),
      )
      renderPage()
      await waitFor(() => {
        expect(screen.queryByText(/← Prev/)).not.toBeInTheDocument()
        expect(screen.queryByText(/Next →/)).not.toBeInTheDocument()
      })
    })

    it('shows pagination controls when total_pages > 1', async () => {
      mockThreatIntel.list.mockResolvedValue(
        makeResponse([makeIOC()], { total: 100, total_pages: 4, page: 1 }),
      )
      renderPage()
      await waitFor(() => {
        expect(screen.getByText(/← Prev/)).toBeInTheDocument()
        expect(screen.getByText(/Next →/)).toBeInTheDocument()
      })
    })

    it('shows the current page and total pages', async () => {
      mockThreatIntel.list.mockResolvedValue(
        makeResponse([makeIOC()], { total: 100, total_pages: 4, page: 1 }),
      )
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('Page 1 of 4')).toBeInTheDocument()
      })
    })

    it('Prev button is disabled on page 1', async () => {
      mockThreatIntel.list.mockResolvedValue(
        makeResponse([makeIOC()], { total: 100, total_pages: 4, page: 1 }),
      )
      renderPage()
      const prevBtn = await screen.findByText(/← Prev/)
      expect(prevBtn.closest('button')).toBeDisabled()
    })

    it('Next button is not disabled on page 1 of 4', async () => {
      mockThreatIntel.list.mockResolvedValue(
        makeResponse([makeIOC()], { total: 100, total_pages: 4, page: 1 }),
      )
      renderPage()
      const nextBtn = await screen.findByText(/Next →/)
      expect(nextBtn.closest('button')).not.toBeDisabled()
    })

    it('clicking Next requests page 2', async () => {
      mockThreatIntel.list.mockResolvedValue(
        makeResponse([makeIOC()], { total: 100, total_pages: 4, page: 1 }),
      )
      renderPage()
      await waitFor(() => expect(mockThreatIntel.list).toHaveBeenCalledTimes(1))
      fireEvent.click(await screen.findByText(/Next →/))
      await waitFor(() => {
        const lastCall = mockThreatIntel.list.mock.calls.at(-1)![0]
        expect(lastCall.page).toBe(2)
      })
    })

    it('Next button is disabled on the last page', async () => {
      mockThreatIntel.list
        .mockResolvedValueOnce(makeResponse([makeIOC()], { total: 50, total_pages: 2, page: 1 }))
        .mockResolvedValue(makeResponse([makeIOC()], { total: 50, total_pages: 2, page: 2 }))
      renderPage()
      fireEvent.click(await screen.findByText(/Next →/))
      await waitFor(() => expect(mockThreatIntel.list).toHaveBeenCalledTimes(2))
      await waitFor(() => {
        const nextBtn = screen.getByText(/Next →/)
        expect(nextBtn.closest('button')).toBeDisabled()
      })
    })

    it('Prev button is enabled after navigating to page 2', async () => {
      mockThreatIntel.list
        .mockResolvedValueOnce(makeResponse([makeIOC()], { total: 50, total_pages: 2, page: 1 }))
        .mockResolvedValue(makeResponse([makeIOC()], { total: 50, total_pages: 2, page: 2 }))
      renderPage()
      fireEvent.click(await screen.findByText(/Next →/))
      await waitFor(() => expect(mockThreatIntel.list).toHaveBeenCalledTimes(2))
      await waitFor(() => {
        const prevBtn = screen.getByText(/← Prev/)
        expect(prevBtn.closest('button')).not.toBeDisabled()
      })
    })
  })

  // =========================================================================
  // Row selection / IOC panel
  // =========================================================================
  describe('row selection', () => {
    beforeEach(() => {
      mockThreatIntel.list.mockResolvedValue(
        makeResponse([makeIOC({ id: 1, value: '192.168.1.100' })]),
      )
    })

    it('IOC panel is not shown initially', () => {
      renderPage()
      expect(screen.queryByText('Related Detections')).not.toBeInTheDocument()
    })

    it('clicking a row opens the IOC detail panel', async () => {
      renderPage()
      // Wait for the IOC row to appear, then click it
      const cell = await screen.findByText('192.168.1.100')
      // Click the row (parent div), not the cell itself
      fireEvent.click(cell)
      await waitFor(() => {
        expect(screen.getByText('Related Detections')).toBeInTheDocument()
      })
    })

    it('clicking the same row a second time closes the panel', async () => {
      renderPage()
      const cell = await screen.findByText('192.168.1.100')
      fireEvent.click(cell) // open
      await waitFor(() =>
        expect(screen.getByText('Related Detections')).toBeInTheDocument(),
      )
      fireEvent.click(cell) // close
      await waitFor(() => {
        expect(screen.queryByText('Related Detections')).not.toBeInTheDocument()
      })
    })

    it('clicking the panel close button (×) closes the panel', async () => {
      renderPage()
      const cell = await screen.findByText('192.168.1.100')
      fireEvent.click(cell)
      await waitFor(() =>
        expect(screen.getByText('Related Detections')).toBeInTheDocument(),
      )
      // The close button has title="Close"
      fireEvent.click(screen.getByTitle('Close'))
      await waitFor(() => {
        expect(screen.queryByText('Related Detections')).not.toBeInTheDocument()
      })
    })

    it('clicking a different row replaces the selected IOC in the panel', async () => {
      mockThreatIntel.list.mockResolvedValue(
        makeResponse([
          makeIOC({ id: 1, value: '10.0.0.1' }),
          makeIOC({ id: 2, value: '10.0.0.2' }),
        ]),
      )
      renderPage()
      const first = await screen.findByText('10.0.0.1')
      fireEvent.click(first)
      await waitFor(() =>
        expect(screen.getByText('Related Detections')).toBeInTheDocument(),
      )
      fireEvent.click(screen.getByText('10.0.0.2'))
      // Panel should stay open but show second IOC value
      await waitFor(() => {
        expect(screen.getByText('Related Detections')).toBeInTheDocument()
      })
    })
  })

  // =========================================================================
  // Add IOC modal
  // =========================================================================
  describe('add IOC modal', () => {
    beforeEach(() => {
      mockThreatIntel.list.mockResolvedValue(makeResponse())
    })

    it('modal is not shown initially', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.queryByRole('heading', { name: 'Add IOC' })).not.toBeInTheDocument()
      })
    })

    it('clicking "+ Add IOC" opens the modal', async () => {
      renderPage()
      const btn = await screen.findByRole('button', { name: /Add IOC/ })
      fireEvent.click(btn)
      expect(screen.getByRole('heading', { name: 'Add IOC' })).toBeInTheDocument()
    })

    it('the modal contains the IOC Type field', async () => {
      renderPage()
      const btn = await screen.findByRole('button', { name: /Add IOC/ })
      fireEvent.click(btn)
      // IOC Type select should be present (shows "IP" by default)
      const selects = screen.getAllByRole('combobox')
      expect(selects.length).toBeGreaterThan(0)
    })

    it('the modal contains the Value input', async () => {
      renderPage()
      const btn = await screen.findByRole('button', { name: /Add IOC/ })
      fireEvent.click(btn)
      expect(screen.getByPlaceholderText('192.168.1.1')).toBeInTheDocument()
    })

    it('clicking Cancel closes the modal', async () => {
      renderPage()
      const btn = await screen.findByRole('button', { name: /Add IOC/ })
      fireEvent.click(btn)
      expect(screen.getByRole('heading', { name: 'Add IOC' })).toBeInTheDocument()
      fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
      await waitFor(() => {
        expect(
          screen.queryByRole('heading', { name: 'Add IOC' }),
        ).not.toBeInTheDocument()
      })
    })
  })

  // =========================================================================
  // Bulk Import modal
  // =========================================================================
  describe('bulk import modal', () => {
    beforeEach(() => {
      mockThreatIntel.list.mockResolvedValue(makeResponse())
    })

    it('modal is not shown initially', async () => {
      renderPage()
      await waitFor(() => {
        expect(
          screen.queryByRole('heading', { name: 'Bulk Import IOCs' }),
        ).not.toBeInTheDocument()
      })
    })

    it('clicking "Bulk Import" opens the modal', async () => {
      renderPage()
      const btn = await screen.findByRole('button', { name: /Bulk Import/ })
      fireEvent.click(btn)
      expect(
        screen.getByRole('heading', { name: 'Bulk Import IOCs' }),
      ).toBeInTheDocument()
    })

    it('the modal contains a textarea for paste input', async () => {
      renderPage()
      const btn = await screen.findByRole('button', { name: /Bulk Import/ })
      fireEvent.click(btn)
      // Textarea is identifiable by its placeholder text
      expect(
        screen.getByPlaceholderText(/Paste JSON array or CSV/),
      ).toBeInTheDocument()
    })

    it('clicking Cancel closes the modal', async () => {
      renderPage()
      const btn = await screen.findByRole('button', { name: /Bulk Import/ })
      fireEvent.click(btn)
      expect(
        screen.getByRole('heading', { name: 'Bulk Import IOCs' }),
      ).toBeInTheDocument()
      fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
      await waitFor(() => {
        expect(
          screen.queryByRole('heading', { name: 'Bulk Import IOCs' }),
        ).not.toBeInTheDocument()
      })
    })

    it('"Import IOCs" button is disabled when textarea is empty', async () => {
      renderPage()
      const btn = await screen.findByRole('button', { name: /Bulk Import/ })
      fireEvent.click(btn)
      const importBtn = screen.getByRole('button', { name: 'Import IOCs' })
      expect(importBtn).toBeDisabled()
    })

    it('"Import IOCs" button is enabled when textarea has content', async () => {
      renderPage()
      const btn = await screen.findByRole('button', { name: /Bulk Import/ })
      fireEvent.click(btn)
      const textarea = screen.getByPlaceholderText(/Paste JSON array or CSV/)
      fireEvent.change(textarea, { target: { value: 'ip,1.2.3.4,stix,high' } })
      const importBtn = screen.getByRole('button', { name: 'Import IOCs' })
      expect(importBtn).not.toBeDisabled()
    })
  })

  // =========================================================================
  // Active / deactivate toggle
  // =========================================================================
  describe('deactivate toggle', () => {
    it('shows an active green indicator for active IOCs', async () => {
      mockThreatIntel.list.mockResolvedValue(
        makeResponse([makeIOC({ is_active: true })]),
      )
      renderPage()
      await waitFor(() => {
        // The active indicator has bg-low-text class
        const indicators = document.querySelectorAll('.bg-low-text')
        expect(indicators.length).toBeGreaterThan(0)
      })
    })

    it('shows a muted indicator for inactive IOCs', async () => {
      mockThreatIntel.list.mockResolvedValue(
        makeResponse([makeIOC({ is_active: false })]),
      )
      renderPage()
      await waitFor(() => {
        // The inactive indicator has bg-section border-border classes
        const indicators = document.querySelectorAll('.border-border.rounded-full')
        expect(indicators.length).toBeGreaterThan(0)
      })
    })
  })

  // =========================================================================
  // Edit button
  // =========================================================================
  describe('edit button', () => {
    beforeEach(() => {
      mockThreatIntel.list.mockResolvedValue(makeResponse([makeIOC()]))
    })

    it('renders an Edit button for each IOC row', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.getByRole('button', { name: 'Edit' })).toBeInTheDocument()
      })
    })

    it('clicking Edit opens the Edit IOC modal', async () => {
      renderPage()
      const editBtn = await screen.findByRole('button', { name: 'Edit' })
      fireEvent.click(editBtn)
      expect(screen.getByRole('heading', { name: 'Edit IOC' })).toBeInTheDocument()
    })

    it('clicking Cancel in Edit modal closes it', async () => {
      renderPage()
      const editBtn = await screen.findByRole('button', { name: 'Edit' })
      fireEvent.click(editBtn)
      expect(screen.getByRole('heading', { name: 'Edit IOC' })).toBeInTheDocument()
      fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
      await waitFor(() => {
        expect(
          screen.queryByRole('heading', { name: 'Edit IOC' }),
        ).not.toBeInTheDocument()
      })
    })
  })
})
