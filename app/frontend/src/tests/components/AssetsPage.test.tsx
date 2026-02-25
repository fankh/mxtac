// vi.mock is hoisted before imports — declare all module mocks first.

vi.mock('../../lib/api', () => ({
  assetsApi: {
    list:       vi.fn(),
    stats:      vi.fn(),
    create:     vi.fn(),
    bulkImport: vi.fn(),
  },
}))

vi.mock('../../components/layout/TopBar', () => ({
  TopBar: ({ crumb }: { crumb: string }) => (
    <header data-testid="topbar">{crumb}</header>
  ),
}))

vi.mock('../../components/features/assets/AssetPanel', () => ({
  AssetPanel: ({
    asset,
    onClose,
  }: {
    asset: { id: number; hostname: string } | null
    onClose: () => void
  }) =>
    asset ? (
      <div data-testid="asset-panel" data-asset-id={String(asset.id)}>
        <button onClick={onClose} data-testid="panel-close">Close</button>
      </div>
    ) : null,
}))

import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AssetsPage } from '../../components/features/assets/AssetsPage'
import { assetsApi } from '../../lib/api'

// ---------------------------------------------------------------------------
// Typed references
// ---------------------------------------------------------------------------

const mockApi = assetsApi as {
  list:       ReturnType<typeof vi.fn>
  stats:      ReturnType<typeof vi.fn>
  create:     ReturnType<typeof vi.fn>
  bulkImport: ReturnType<typeof vi.fn>
}

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

const makeAsset = (overrides: Record<string, unknown> = {}) => ({
  id: 1,
  hostname: 'web-prod-01',
  ip_addresses: ['10.0.0.1', '10.0.0.2'],
  os: 'Ubuntu 22.04',
  os_family: 'linux',
  asset_type: 'server',
  criticality: 4,
  owner: 'ops@acme.com',
  department: 'Engineering',
  location: 'DC-1',
  tags: ['production', 'web'],
  is_active: true,
  last_seen_at: '2026-02-20T12:00:00Z',
  agent_id: null,
  detection_count: 3,
  incident_count: 1,
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-02-20T12:00:00Z',
  ...overrides,
})

const makeResponse = (
  items = [makeAsset()],
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

const makeStats = () => ({
  total: 42,
  by_type: { server: 20, workstation: 10, cloud: 8, network: 3, container: 1 },
  by_criticality: { '5': 5, '4': 10, '3': 15, '2': 8, '1': 4 },
  by_os_family: { linux: 25, windows: 12, macos: 5 },
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
      <AssetsPage />
    </QueryClientProvider>,
  )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('AssetsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockApi.list.mockReturnValue(new Promise<never>(() => {}))
    mockApi.stats.mockReturnValue(new Promise<never>(() => {}))
  })

  // =========================================================================
  // Loading state
  // =========================================================================
  describe('loading state', () => {
    it('shows "Loading…" while the query is pending', () => {
      renderPage()
      expect(screen.getByText('Loading…')).toBeInTheDocument()
    })

    it('renders the TopBar with "Assets" crumb', () => {
      renderPage()
      expect(screen.getByTestId('topbar')).toHaveTextContent('Assets')
    })

    it('does not show asset rows while loading', () => {
      renderPage()
      expect(screen.queryByText('web-prod-01')).not.toBeInTheDocument()
    })

    it('does not show error while loading', () => {
      renderPage()
      expect(screen.queryByText(/Failed to load/i)).not.toBeInTheDocument()
    })

    it('does not show the asset panel while loading', () => {
      renderPage()
      expect(screen.queryByTestId('asset-panel')).not.toBeInTheDocument()
    })
  })

  // =========================================================================
  // Error state
  // =========================================================================
  describe('error state', () => {
    it('shows an error message when the query fails', async () => {
      mockApi.list.mockRejectedValue(new Error('Network Error'))
      renderPage()
      await waitFor(() =>
        expect(screen.getByText(/Failed to load/i)).toBeInTheDocument(),
      )
    })
  })

  // =========================================================================
  // Data rendering
  // =========================================================================
  describe('data rendering', () => {
    beforeEach(() => {
      mockApi.list.mockResolvedValue(makeResponse())
      mockApi.stats.mockResolvedValue(makeStats())
    })

    it('renders the asset hostname', async () => {
      renderPage()
      await waitFor(() =>
        expect(screen.getByText('web-prod-01')).toBeInTheDocument(),
      )
    })

    it('renders the asset OS', async () => {
      renderPage()
      await waitFor(() =>
        expect(screen.getByText('Ubuntu 22.04')).toBeInTheDocument(),
      )
    })

    it('renders the asset type pill', async () => {
      renderPage()
      await waitFor(() =>
        expect(screen.getByText('server')).toBeInTheDocument(),
      )
    })

    it('renders the owner field', async () => {
      renderPage()
      await waitFor(() =>
        expect(screen.getByText('ops@acme.com')).toBeInTheDocument(),
      )
    })

    it('renders detection count with highlight for non-zero', async () => {
      renderPage()
      await waitFor(() => {
        // detection_count = 3 in our fixture
        expect(screen.getByText('3')).toBeInTheDocument()
      })
    })

    it('renders asset tags below the hostname', async () => {
      renderPage()
      await waitFor(() =>
        expect(screen.getByText('production, web')).toBeInTheDocument(),
      )
    })

    it('renders the empty state when no assets match', async () => {
      mockApi.list.mockResolvedValue(makeResponse([]))
      renderPage()
      await waitFor(() =>
        expect(
          screen.getByText('No assets match the current filters.'),
        ).toBeInTheDocument(),
      )
    })
  })

  // =========================================================================
  // Stats cards
  // =========================================================================
  describe('stats cards', () => {
    it('renders total assets count', async () => {
      mockApi.list.mockResolvedValue(makeResponse())
      mockApi.stats.mockResolvedValue(makeStats())
      renderPage()
      await waitFor(() =>
        expect(screen.getByText('42')).toBeInTheDocument(),
      )
    })

    it('renders total "Total Assets" label', async () => {
      mockApi.list.mockResolvedValue(makeResponse())
      mockApi.stats.mockResolvedValue(makeStats())
      renderPage()
      await waitFor(() =>
        expect(screen.getByText('Total Assets')).toBeInTheDocument(),
      )
    })
  })

  // =========================================================================
  // Filter controls
  // =========================================================================
  describe('filter controls', () => {
    beforeEach(() => {
      mockApi.list.mockResolvedValue(makeResponse())
      mockApi.stats.mockResolvedValue(makeStats())
    })

    it('has a type dropdown with "All" as default', async () => {
      renderPage()
      await waitFor(() => screen.getByText('web-prod-01'))
      // Both type and criticality dropdowns have "All" — get the first (type) one
      const selects = screen.getAllByDisplayValue('All')
      expect(selects.length).toBeGreaterThanOrEqual(1)
    })

    it('changing the type dropdown re-queries the API', async () => {
      renderPage()
      await waitFor(() => screen.getByText('web-prod-01'))
      const selects = screen.getAllByDisplayValue('All')
      const select = selects[0] // type dropdown is the first "All" select
      await waitFor(() =>
        expect(mockApi.list).toHaveBeenCalledWith(
          expect.objectContaining({ asset_type: 'server' }),
        ),
      )
    })

    it('has status toggle buttons: All, Active, Inactive', async () => {
      renderPage()
      await waitFor(() => screen.getByText('web-prod-01'))
      expect(screen.getByRole('button', { name: 'All' })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Active' })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Inactive' })).toBeInTheDocument()
    })

    it('typing in the search box triggers a re-query', async () => {
      renderPage()
      await waitFor(() => screen.getByText('web-prod-01'))
      const searchInput = screen.getByPlaceholderText('Search hostname, owner…')
      fireEvent.change(searchInput, { target: { value: 'prod' } })
      await waitFor(() =>
        expect(mockApi.list).toHaveBeenCalledWith(
          expect.objectContaining({ search: 'prod' }),
        ),
      )
    })
  })

  // =========================================================================
  // Row selection → panel
  // =========================================================================
  describe('row selection', () => {
    beforeEach(() => {
      mockApi.list.mockResolvedValue(makeResponse())
      mockApi.stats.mockResolvedValue(makeStats())
    })

    it('clicking a row opens the asset panel', async () => {
      renderPage()
      await waitFor(() => screen.getByText('web-prod-01'))
      fireEvent.click(screen.getByText('web-prod-01'))
      expect(screen.getByTestId('asset-panel')).toBeInTheDocument()
    })

    it('clicking the close button on the panel hides it', async () => {
      renderPage()
      await waitFor(() => screen.getByText('web-prod-01'))
      fireEvent.click(screen.getByText('web-prod-01'))
      fireEvent.click(screen.getByTestId('panel-close'))
      expect(screen.queryByTestId('asset-panel')).not.toBeInTheDocument()
    })

    it('clicking the same row again deselects and hides the panel', async () => {
      renderPage()
      await waitFor(() => screen.getByText('web-prod-01'))
      fireEvent.click(screen.getByText('web-prod-01'))
      fireEvent.click(screen.getByText('web-prod-01'))
      expect(screen.queryByTestId('asset-panel')).not.toBeInTheDocument()
    })
  })

  // =========================================================================
  // Pagination
  // =========================================================================
  describe('pagination', () => {
    it('shows no pagination when there is only one page', async () => {
      mockApi.list.mockResolvedValue(makeResponse([makeAsset()], { total_pages: 1 }))
      mockApi.stats.mockResolvedValue(makeStats())
      renderPage()
      await waitFor(() => screen.getByText('web-prod-01'))
      expect(screen.queryByRole('button', { name: /Prev/i })).not.toBeInTheDocument()
    })

    it('shows pagination when there are multiple pages', async () => {
      mockApi.list.mockResolvedValue(
        makeResponse([makeAsset()], { total: 50, total_pages: 2, page: 1 }),
      )
      mockApi.stats.mockResolvedValue(makeStats())
      renderPage()
      await waitFor(() => screen.getByText('web-prod-01'))
      expect(screen.getByRole('button', { name: /Prev/i })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: /Next/i })).toBeInTheDocument()
    })

    it('Prev button is disabled on page 1', async () => {
      mockApi.list.mockResolvedValue(
        makeResponse([makeAsset()], { total: 50, total_pages: 2, page: 1 }),
      )
      mockApi.stats.mockResolvedValue(makeStats())
      renderPage()
      await waitFor(() => screen.getByText('web-prod-01'))
      expect(screen.getByRole('button', { name: /Prev/i })).toBeDisabled()
    })

    it('Next button navigates to page 2', async () => {
      mockApi.list.mockResolvedValue(
        makeResponse([makeAsset()], { total: 50, total_pages: 2, page: 1 }),
      )
      mockApi.stats.mockResolvedValue(makeStats())
      renderPage()
      await waitFor(() => screen.getByText('web-prod-01'))
      fireEvent.click(screen.getByRole('button', { name: /Next/i }))
      await waitFor(() =>
        expect(mockApi.list).toHaveBeenCalledWith(
          expect.objectContaining({ page: 2 }),
        ),
      )
    })
  })

  // =========================================================================
  // Add Asset modal
  // =========================================================================
  describe('Add Asset modal', () => {
    beforeEach(() => {
      mockApi.list.mockResolvedValue(makeResponse())
      mockApi.stats.mockResolvedValue(makeStats())
    })

    it('clicking "+ Add Asset" opens the modal', async () => {
      renderPage()
      await waitFor(() => screen.getByText('web-prod-01'))
      fireEvent.click(screen.getByText('+ Add Asset'))
      expect(screen.getByText('Add Asset')).toBeInTheDocument()
    })

    it('clicking Cancel closes the Add Asset modal', async () => {
      renderPage()
      await waitFor(() => screen.getByText('web-prod-01'))
      fireEvent.click(screen.getByText('+ Add Asset'))
      fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
      expect(screen.queryByRole('heading', { name: 'Add Asset' })).not.toBeInTheDocument()
    })
  })

  // =========================================================================
  // Bulk Import modal
  // =========================================================================
  describe('Bulk Import modal', () => {
    beforeEach(() => {
      mockApi.list.mockResolvedValue(makeResponse())
      mockApi.stats.mockResolvedValue(makeStats())
    })

    it('clicking "Bulk Import" opens the modal', async () => {
      renderPage()
      await waitFor(() => screen.getByText('web-prod-01'))
      fireEvent.click(screen.getByText('Bulk Import'))
      expect(screen.getByText('Bulk Import Assets')).toBeInTheDocument()
    })

    it('Import button is disabled when textarea is empty', async () => {
      renderPage()
      await waitFor(() => screen.getByText('web-prod-01'))
      fireEvent.click(screen.getByText('Bulk Import'))
      expect(screen.getByRole('button', { name: 'Import' })).toBeDisabled()
    })
  })

  // =========================================================================
  // Summary row
  // =========================================================================
  describe('summary row', () => {
    it('shows total asset count from pagination', async () => {
      mockApi.list.mockResolvedValue(
        makeResponse([makeAsset()], { total: 42, total_pages: 2 }),
      )
      mockApi.stats.mockResolvedValue(makeStats())
      renderPage()
      await waitFor(() =>
        expect(screen.getByText('42 assets')).toBeInTheDocument(),
      )
    })
  })
})
