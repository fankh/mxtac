// vi.mock is hoisted before imports — declare all module mocks first.

vi.mock('../../lib/api', () => ({
  apiClient: {
    get:   vi.fn(),
    patch: vi.fn(),
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
import { ConnectorsPage } from '../../components/features/connectors/ConnectorsPage'
import { apiClient } from '../../lib/api'

// ---------------------------------------------------------------------------
// Typed references to the mocked API
// ---------------------------------------------------------------------------

const mockGet   = apiClient.get   as ReturnType<typeof vi.fn>
const mockPatch = apiClient.patch as ReturnType<typeof vi.fn>

// ---------------------------------------------------------------------------
// Fixture helpers
//
// Use a name distinct from the type label to avoid duplicate-text errors.
// TYPE_LABELS['wazuh'] = 'Wazuh SIEM', so name = 'prod-wazuh' keeps them separate.
// ---------------------------------------------------------------------------

const makeConnector = (overrides: Record<string, unknown> = {}) => ({
  id:             'conn-001',
  name:           'prod-wazuh',
  connector_type: 'wazuh',
  status:         'active',
  enabled:        true,
  events_total:   12345,
  errors_total:   0,
  last_seen_at:   '2026-02-19T08:00:00Z',
  error_message:  null,
  ...overrides,
})

// ---------------------------------------------------------------------------
// Render helper
// ---------------------------------------------------------------------------

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        retry:     false,
        staleTime: Infinity,
      },
    },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <ConnectorsPage />
    </QueryClientProvider>,
  )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('ConnectorsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    // Default: pending forever → loading state
    mockGet.mockReturnValue(new Promise<never>(() => {}))
    mockPatch.mockReturnValue(new Promise<never>(() => {}))
  })

  // =========================================================================
  // TopBar
  // =========================================================================
  describe('TopBar', () => {
    it('renders the TopBar with the "Integrations" crumb', () => {
      renderPage()
      expect(screen.getByTestId('topbar')).toHaveTextContent('Integrations')
    })
  })

  // =========================================================================
  // Static header
  // =========================================================================
  describe('page header', () => {
    beforeEach(() => {
      mockGet.mockResolvedValue({ data: [] })
    })

    it('renders the "Data Source Connectors" heading', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('Data Source Connectors')).toBeInTheDocument()
      })
    })

    it('renders the subheading text', async () => {
      renderPage()
      await waitFor(() => {
        expect(
          screen.getByText('Configure connections to your security tools'),
        ).toBeInTheDocument()
      })
    })

    it('renders the "+ Add Connector" button', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.getByRole('button', { name: '+ Add Connector' })).toBeInTheDocument()
      })
    })
  })

  // =========================================================================
  // Loading state
  // =========================================================================
  describe('loading state', () => {
    it('shows "Loading connectors…" while the query is pending', () => {
      renderPage()
      expect(screen.getByText('Loading connectors…')).toBeInTheDocument()
    })

    it('does not show connector cards while loading', () => {
      renderPage()
      expect(screen.queryByText('prod-wazuh')).not.toBeInTheDocument()
    })
  })

  // =========================================================================
  // Success state — connector card rendering
  // =========================================================================
  describe('success state', () => {
    beforeEach(() => {
      mockGet.mockResolvedValue({ data: [makeConnector()] })
    })

    it('renders the connector name', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('prod-wazuh')).toBeInTheDocument()
      })
    })

    it('renders the human-readable connector type label', async () => {
      renderPage()
      await waitFor(() => {
        // TYPE_LABELS['wazuh'] = 'Wazuh SIEM' is the type description shown below the name
        expect(screen.getByText('Wazuh SIEM')).toBeInTheDocument()
      })
    })

    it('renders event count', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('12,345 events')).toBeInTheDocument()
      })
    })

    it('does not show error count when errors_total is 0', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.queryByText(/errors/)).not.toBeInTheDocument()
      })
    })

    it('shows error count when errors_total > 0', async () => {
      mockGet.mockResolvedValue({ data: [makeConnector({ errors_total: 3 })] })
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('3 errors')).toBeInTheDocument()
      })
    })

    it('renders "Enabled" status button for enabled connectors', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.getByRole('button', { name: 'Enabled' })).toBeInTheDocument()
      })
    })

    it('renders "Disabled" status button for disabled connectors', async () => {
      mockGet.mockResolvedValue({ data: [makeConnector({ enabled: false })] })
      renderPage()
      await waitFor(() => {
        expect(screen.getByRole('button', { name: 'Disabled' })).toBeInTheDocument()
      })
    })

    it('renders multiple connector cards', async () => {
      mockGet.mockResolvedValue({
        data: [
          makeConnector({ id: 'c1', name: 'alpha-wazuh',    connector_type: 'wazuh' }),
          makeConnector({ id: 'c2', name: 'beta-zeek',      connector_type: 'zeek' }),
          makeConnector({ id: 'c3', name: 'gamma-suricata', connector_type: 'suricata' }),
        ],
      })
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('alpha-wazuh')).toBeInTheDocument()
        expect(screen.getByText('beta-zeek')).toBeInTheDocument()
        expect(screen.getByText('gamma-suricata')).toBeInTheDocument()
      })
    })

    it('does not show "Loading connectors…" in success state', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.queryByText('Loading connectors…')).not.toBeInTheDocument()
      })
    })

    it('shows error_message when present', async () => {
      mockGet.mockResolvedValue({
        data: [makeConnector({ error_message: 'Connection refused' })],
      })
      renderPage()
      await waitFor(() => {
        expect(screen.getByText(/Connection refused/)).toBeInTheDocument()
      })
    })
  })

  // =========================================================================
  // Empty state
  // =========================================================================
  describe('empty state', () => {
    it('shows the "Add connector" placeholder card when no connectors are loaded', async () => {
      mockGet.mockResolvedValue({ data: [] })
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('Add connector')).toBeInTheDocument()
      })
    })
  })

  // =========================================================================
  // Enable / disable toggle
  // =========================================================================
  describe('enable / disable toggle', () => {
    beforeEach(() => {
      mockPatch.mockResolvedValue({ data: {} })
    })

    it('calls apiClient.patch with enabled=false when "Enabled" button is clicked', async () => {
      mockGet.mockResolvedValue({ data: [makeConnector({ id: 'conn-001', enabled: true })] })
      renderPage()
      const btn = await screen.findByRole('button', { name: 'Enabled' })
      fireEvent.click(btn)
      await waitFor(() => {
        expect(mockPatch).toHaveBeenCalledWith('/connectors/conn-001', { enabled: false })
      })
    })

    it('calls apiClient.patch with enabled=true when "Disabled" button is clicked', async () => {
      mockGet.mockResolvedValue({ data: [makeConnector({ id: 'conn-002', enabled: false })] })
      renderPage()
      const btn = await screen.findByRole('button', { name: 'Disabled' })
      fireEvent.click(btn)
      await waitFor(() => {
        expect(mockPatch).toHaveBeenCalledWith('/connectors/conn-002', { enabled: true })
      })
    })

    it('invalidates the connectors query after a successful toggle (triggers refetch)', async () => {
      mockGet
        .mockResolvedValueOnce({ data: [makeConnector({ enabled: true })] })
        .mockResolvedValue({ data: [makeConnector({ enabled: false })] })
      renderPage()
      await waitFor(() => expect(mockGet).toHaveBeenCalledTimes(1))
      const btn = await screen.findByRole('button', { name: 'Enabled' })
      fireEvent.click(btn)
      await waitFor(() => expect(mockGet).toHaveBeenCalledTimes(2))
    })

    it('toggle button click does not open the detail panel', async () => {
      mockGet.mockResolvedValue({ data: [makeConnector({ name: 'prod-wazuh' })] })
      renderPage()
      await screen.findByText('prod-wazuh')
      const btn = screen.getByRole('button', { name: 'Enabled' })
      fireEvent.click(btn)
      // The detail panel heading would include "— Configuration"; it should NOT appear
      expect(screen.queryByText(/— Configuration/)).not.toBeInTheDocument()
    })
  })

  // =========================================================================
  // Card selection and detail panel
  // =========================================================================
  describe('card selection / detail panel', () => {
    beforeEach(() => {
      mockGet.mockResolvedValue({ data: [makeConnector({ name: 'prod-wazuh' })] })
    })

    it('does not show the detail panel initially', async () => {
      renderPage()
      await waitFor(() => expect(screen.getByText('prod-wazuh')).toBeInTheDocument())
      expect(screen.queryByText('prod-wazuh — Configuration')).not.toBeInTheDocument()
    })

    it('clicking a card reveals the detail panel', async () => {
      renderPage()
      fireEvent.click(await screen.findByText('prod-wazuh'))
      await waitFor(() => {
        expect(screen.getByText('prod-wazuh — Configuration')).toBeInTheDocument()
      })
    })

    it('clicking the same card again closes the detail panel', async () => {
      renderPage()
      const card = await screen.findByText('prod-wazuh')
      fireEvent.click(card) // open
      await waitFor(() => expect(screen.getByText('prod-wazuh — Configuration')).toBeInTheDocument())
      fireEvent.click(card) // close
      expect(screen.queryByText('prod-wazuh — Configuration')).not.toBeInTheDocument()
    })

    it('detail panel shows the connector type label', async () => {
      renderPage()
      // Click the card name element specifically (not the type label)
      const names = await screen.findAllByText('prod-wazuh')
      fireEvent.click(names[0])
      await waitFor(() => {
        expect(screen.getByText('prod-wazuh — Configuration')).toBeInTheDocument()
        // TYPE_LABELS['wazuh'] = 'Wazuh SIEM' appears in card type area + detail panel Type field
        // Use getAllByText since it now appears in both the card grid and the detail panel
        expect(screen.getAllByText('Wazuh SIEM').length).toBeGreaterThanOrEqual(1)
      })
    })

    it('detail panel shows the "Test Connection" button', async () => {
      renderPage()
      const names = await screen.findAllByText('prod-wazuh')
      fireEvent.click(names[0])
      await waitFor(() => {
        expect(screen.getByRole('button', { name: 'Test Connection' })).toBeInTheDocument()
      })
    })
  })

  // =========================================================================
  // API call — correct endpoint
  // =========================================================================
  describe('API call', () => {
    it('calls apiClient.get with "/connectors" on mount', async () => {
      mockGet.mockResolvedValue({ data: [] })
      renderPage()
      await waitFor(() => expect(mockGet).toHaveBeenCalledWith('/connectors'))
    })

    it('only calls apiClient.get once on initial mount', async () => {
      mockGet.mockResolvedValue({ data: [] })
      renderPage()
      await waitFor(() => expect(mockGet).toHaveBeenCalledTimes(1))
    })
  })
})
