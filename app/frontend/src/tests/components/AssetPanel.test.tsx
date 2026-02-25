// vi.mock is hoisted before imports — declare all module mocks first.

vi.mock('../../lib/api', () => ({
  assetsApi: {
    getDetections: vi.fn(),
    getIncidents:  vi.fn(),
  },
}))

import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AssetPanel } from '../../components/features/assets/AssetPanel'
import { assetsApi } from '../../lib/api'

// ---------------------------------------------------------------------------
// Typed references
// ---------------------------------------------------------------------------

const mockApi = assetsApi as {
  getDetections: ReturnType<typeof vi.fn>
  getIncidents:  ReturnType<typeof vi.fn>
}

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

const makeAsset = (overrides: Record<string, unknown> = {}) => ({
  id: 42,
  hostname: 'db-prod-01',
  ip_addresses: ['10.0.1.10'],
  os: 'RHEL 9',
  os_family: 'linux',
  asset_type: 'server',
  criticality: 5,
  owner: 'dba@acme.com',
  department: 'Engineering',
  location: 'DC-1',
  tags: ['production', 'database'],
  is_active: true,
  last_seen_at: '2026-02-21T08:00:00Z',
  agent_id: 'agent-abc-123',
  detection_count: 7,
  incident_count: 2,
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-02-21T08:00:00Z',
  ...overrides,
})

const makeDetectionPage = (overrides: Record<string, unknown> = {}) => ({
  items: [
    {
      name: 'Suspicious Process',
      severity: 'high',
      technique_id: 'T1059',
      tactic: 'Execution',
      time: '2026-02-20T10:00:00Z',
      ...overrides,
    },
  ],
  pagination: { page: 1, page_size: 10, total: 1, total_pages: 1 },
})

const makeIncidentPage = () => ({
  items: [
    {
      title: 'Ransomware Attempt',
      severity: 'critical',
      status: 'investigating',
      assigned_to: 'alice@acme.com',
      created_at: '2026-02-19T07:00:00Z',
    },
  ],
  pagination: { page: 1, page_size: 10, total: 1, total_pages: 1 },
})

// ---------------------------------------------------------------------------
// Render helper
// ---------------------------------------------------------------------------

function renderPanel(asset: ReturnType<typeof makeAsset> | null, onClose = vi.fn()) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: Infinity } },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <AssetPanel asset={asset as never} onClose={onClose} />
    </QueryClientProvider>,
  )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('AssetPanel', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockApi.getDetections.mockReturnValue(new Promise<never>(() => {}))
    mockApi.getIncidents.mockReturnValue(new Promise<never>(() => {}))
  })

  // =========================================================================
  // Hidden when asset is null
  // =========================================================================
  describe('when asset is null', () => {
    it('renders nothing', () => {
      const { container } = renderPanel(null)
      expect(container).toBeEmptyDOMElement()
    })
  })

  // =========================================================================
  // Header / meta
  // =========================================================================
  describe('header section', () => {
    it('shows the asset hostname in the header', () => {
      renderPanel(makeAsset())
      expect(screen.getByRole('heading', { level: 2, name: 'db-prod-01' })).toBeInTheDocument()
    })

    it('shows asset type and OS family in subtitle', () => {
      renderPanel(makeAsset())
      expect(screen.getByText(/server · linux/i)).toBeInTheDocument()
    })

    it('shows "(inactive)" badge for inactive assets', () => {
      renderPanel(makeAsset({ is_active: false }))
      expect(screen.getByText('(inactive)')).toBeInTheDocument()
    })

    it('does not show "(inactive)" badge for active assets', () => {
      renderPanel(makeAsset({ is_active: true }))
      expect(screen.queryByText('(inactive)')).not.toBeInTheDocument()
    })

    it('shows tags in the badge row', () => {
      renderPanel(makeAsset())
      expect(screen.getByText('production')).toBeInTheDocument()
      expect(screen.getByText('database')).toBeInTheDocument()
    })

    it('calls onClose when the × button is clicked', () => {
      const onClose = vi.fn()
      renderPanel(makeAsset(), onClose)
      fireEvent.click(screen.getByTitle('Close'))
      expect(onClose).toHaveBeenCalledOnce()
    })
  })

  // =========================================================================
  // Tabs
  // =========================================================================
  describe('tab bar', () => {
    it('renders all three tabs', () => {
      renderPanel(makeAsset())
      expect(screen.getByRole('button', { name: 'Details' })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: /Detections/i })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: /Incidents/i })).toBeInTheDocument()
    })

    it('shows the detection count in the Detections tab label', () => {
      renderPanel(makeAsset({ detection_count: 7 }))
      expect(screen.getByRole('button', { name: 'Detections (7)' })).toBeInTheDocument()
    })

    it('shows the incident count in the Incidents tab label', () => {
      renderPanel(makeAsset({ incident_count: 2 }))
      expect(screen.getByRole('button', { name: 'Incidents (2)' })).toBeInTheDocument()
    })
  })

  // =========================================================================
  // Details tab (default)
  // =========================================================================
  describe('Details tab', () => {
    it('shows all key detail rows', () => {
      renderPanel(makeAsset())
      expect(screen.getByText('Hostname')).toBeInTheDocument()
      expect(screen.getByText('db-prod-01')).toBeInTheDocument()
      expect(screen.getByText('IP Addresses')).toBeInTheDocument()
      expect(screen.getByText('10.0.1.10')).toBeInTheDocument()
      expect(screen.getByText('OS')).toBeInTheDocument()
      expect(screen.getByText('RHEL 9')).toBeInTheDocument()
      expect(screen.getByText('Owner')).toBeInTheDocument()
      expect(screen.getByText('dba@acme.com')).toBeInTheDocument()
      expect(screen.getByText('Department')).toBeInTheDocument()
      expect(screen.getByText('Engineering')).toBeInTheDocument()
      expect(screen.getByText('Location')).toBeInTheDocument()
      expect(screen.getByText('DC-1')).toBeInTheDocument()
    })

    it('shows Agent ID when present', () => {
      renderPanel(makeAsset())
      expect(screen.getByText('agent-abc-123')).toBeInTheDocument()
    })

    it('shows Active status for active assets', () => {
      renderPanel(makeAsset({ is_active: true }))
      expect(screen.getByText('Active')).toBeInTheDocument()
    })

    it('shows Inactive status for inactive assets', () => {
      renderPanel(makeAsset({ is_active: false }))
      expect(screen.getByText('Inactive')).toBeInTheDocument()
    })
  })

  // =========================================================================
  // Detections tab
  // =========================================================================
  describe('Detections tab', () => {
    it('does not fetch detections until the tab is selected', () => {
      renderPanel(makeAsset())
      expect(mockApi.getDetections).not.toHaveBeenCalled()
    })

    it('fetches detections when the Detections tab is clicked', async () => {
      mockApi.getDetections.mockResolvedValue(makeDetectionPage())
      renderPanel(makeAsset())
      fireEvent.click(screen.getByRole('button', { name: /Detections/i }))
      await waitFor(() =>
        expect(mockApi.getDetections).toHaveBeenCalledWith(42, expect.any(Object)),
      )
    })

    it('shows detection name after loading', async () => {
      mockApi.getDetections.mockResolvedValue(makeDetectionPage())
      renderPanel(makeAsset())
      fireEvent.click(screen.getByRole('button', { name: /Detections/i }))
      await waitFor(() =>
        expect(screen.getByText('Suspicious Process')).toBeInTheDocument(),
      )
    })

    it('shows empty state when no detections', async () => {
      mockApi.getDetections.mockResolvedValue({
        items: [],
        pagination: { page: 1, page_size: 10, total: 0, total_pages: 1 },
      })
      renderPanel(makeAsset({ detection_count: 0 }))
      fireEvent.click(screen.getByRole('button', { name: /Detections/i }))
      await waitFor(() =>
        expect(screen.getByText('No detections for this asset.')).toBeInTheDocument(),
      )
    })

    it('shows error message when detection fetch fails', async () => {
      mockApi.getDetections.mockRejectedValue(new Error('Network Error'))
      renderPanel(makeAsset())
      fireEvent.click(screen.getByRole('button', { name: /Detections/i }))
      await waitFor(() =>
        expect(screen.getByText('Failed to load detections.')).toBeInTheDocument(),
      )
    })
  })

  // =========================================================================
  // Incidents tab
  // =========================================================================
  describe('Incidents tab', () => {
    it('does not fetch incidents until the tab is selected', () => {
      renderPanel(makeAsset())
      expect(mockApi.getIncidents).not.toHaveBeenCalled()
    })

    it('fetches incidents when the Incidents tab is clicked', async () => {
      mockApi.getIncidents.mockResolvedValue(makeIncidentPage())
      renderPanel(makeAsset())
      fireEvent.click(screen.getByRole('button', { name: /Incidents/i }))
      await waitFor(() =>
        expect(mockApi.getIncidents).toHaveBeenCalledWith(42, expect.any(Object)),
      )
    })

    it('shows incident title after loading', async () => {
      mockApi.getIncidents.mockResolvedValue(makeIncidentPage())
      renderPanel(makeAsset())
      fireEvent.click(screen.getByRole('button', { name: /Incidents/i }))
      await waitFor(() =>
        expect(screen.getByText('Ransomware Attempt')).toBeInTheDocument(),
      )
    })

    it('shows empty state when no incidents', async () => {
      mockApi.getIncidents.mockResolvedValue({
        items: [],
        pagination: { page: 1, page_size: 10, total: 0, total_pages: 1 },
      })
      renderPanel(makeAsset({ incident_count: 0 }))
      fireEvent.click(screen.getByRole('button', { name: /Incidents/i }))
      await waitFor(() =>
        expect(screen.getByText('No incidents for this asset.')).toBeInTheDocument(),
      )
    })

    it('shows error message when incidents fetch fails', async () => {
      mockApi.getIncidents.mockRejectedValue(new Error('Network Error'))
      renderPanel(makeAsset())
      fireEvent.click(screen.getByRole('button', { name: /Incidents/i }))
      await waitFor(() =>
        expect(screen.getByText('Failed to load incidents.')).toBeInTheDocument(),
      )
    })
  })
})
