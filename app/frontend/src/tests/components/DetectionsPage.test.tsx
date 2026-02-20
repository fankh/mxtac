// vi.mock is hoisted before imports — declare all module mocks first.

vi.mock('../../lib/api', () => ({
  detectionsApi: {
    list:   vi.fn(),
    get:    vi.fn(),
    update: vi.fn(),
  },
}))

vi.mock('../../components/layout/TopBar', () => ({
  TopBar: ({ crumb }: { crumb: string }) => (
    <header data-testid="topbar">{crumb}</header>
  ),
}))

vi.mock('../../components/features/detections/DetectionPanel', () => ({
  DetectionPanel: ({
    detection,
    onClose,
  }: {
    detection: { id: string; name: string } | null
    onClose: () => void
  }) =>
    detection ? (
      <div data-testid="detection-panel" data-detection-id={detection.id}>
        <button onClick={onClose} data-testid="panel-close">Close</button>
      </div>
    ) : null,
}))

import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { DetectionsPage } from '../../components/features/detections/DetectionsPage'
import { detectionsApi } from '../../lib/api'

// ---------------------------------------------------------------------------
// Typed reference to the mocked API
// ---------------------------------------------------------------------------

const mockApi = detectionsApi as { list: ReturnType<typeof vi.fn> }

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

const makeDetection = (overrides: Record<string, unknown> = {}) => ({
  id: 'det-001',
  score: 9.2,
  severity: 'critical' as const,
  technique_id: 'T1003.001',
  technique_name: 'LSASS Memory Dump',
  tactic: 'Credential Access',
  name: 'Suspicious LSASS Memory Access',
  host: 'WIN-DC01',
  status: 'active' as const,
  time: '2026-02-19T08:30:00Z',
  rule_name: 'proc_access_win_lsass_dump_tools_dll',
  related_technique_ids: [],
  ...overrides,
})

const makeResponse = (
  items = [makeDetection()],
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

// ---------------------------------------------------------------------------
// Render helper
// ---------------------------------------------------------------------------

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <DetectionsPage />
    </QueryClientProvider>,
  )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('DetectionsPage', () => {
  beforeEach(() => {
    // Default: pending forever → loading state
    mockApi.list.mockReturnValue(new Promise<never>(() => {}))
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

    it('does not show detection rows while loading', () => {
      renderPage()
      expect(screen.queryByText('Suspicious LSASS Memory Access')).not.toBeInTheDocument()
    })

    it('does not show the empty-state message while loading', () => {
      renderPage()
      expect(
        screen.queryByText('No detections match the current filters.'),
      ).not.toBeInTheDocument()
    })

    it('does not show the detection panel while loading', () => {
      renderPage()
      expect(screen.queryByTestId('detection-panel')).not.toBeInTheDocument()
    })

    it('does not show the summary row while loading', () => {
      renderPage()
      // Summary shows "{n} detections" — must not appear before data arrives
      expect(screen.queryByText(/detections/)).not.toBeInTheDocument()
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

    it('does not show detection rows in error state', async () => {
      mockApi.list.mockRejectedValue(new Error('fail'))
      renderPage()
      await waitFor(() => {
        expect(screen.queryByText('Suspicious LSASS Memory Access')).not.toBeInTheDocument()
      })
    })

    it('does not show the empty-state message in error state', async () => {
      mockApi.list.mockRejectedValue(new Error('fail'))
      renderPage()
      await waitFor(() => {
        expect(
          screen.queryByText('No detections match the current filters.'),
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

    it('renders the detection name', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('Suspicious LSASS Memory Access')).toBeInTheDocument()
      })
    })

    it('renders the technique ID', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('T1003.001')).toBeInTheDocument()
      })
    })

    it('renders the technique name', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('LSASS Memory Dump')).toBeInTheDocument()
      })
    })

    it('renders the host name', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('WIN-DC01')).toBeInTheDocument()
      })
    })

    it('renders the tactic', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('Credential Access')).toBeInTheDocument()
      })
    })

    it('renders the rule_name as a row sub-label', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('proc_access_win_lsass_dump_tools_dll')).toBeInTheDocument()
      })
    })

    it('renders multiple detection rows', async () => {
      mockApi.list.mockResolvedValue(
        makeResponse([
          makeDetection({ id: '1', name: 'Detection Alpha', host: 'host-a' }),
          makeDetection({ id: '2', name: 'Detection Beta',  host: 'host-b' }),
        ]),
      )
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('Detection Alpha')).toBeInTheDocument()
        expect(screen.getByText('Detection Beta')).toBeInTheDocument()
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

    it('does not show the empty-state message when there are detections', async () => {
      renderPage()
      await waitFor(() => {
        expect(
          screen.queryByText('No detections match the current filters.'),
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
          screen.getByText('No detections match the current filters.'),
        ).toBeInTheDocument()
      })
    })

    it('does not show the empty-state message when detections are present', async () => {
      mockApi.list.mockResolvedValue(makeResponse([makeDetection()]))
      renderPage()
      await waitFor(() => {
        expect(
          screen.queryByText('No detections match the current filters.'),
        ).not.toBeInTheDocument()
      })
    })
  })

  // =========================================================================
  // Summary row
  // =========================================================================
  describe('summary row', () => {
    it('shows the total detection count', async () => {
      mockApi.list.mockResolvedValue(
        makeResponse(
          Array.from({ length: 5 }, (_, i) => makeDetection({ id: `det-${i}` })),
          { total: 42 },
        ),
      )
      renderPage()
      await waitFor(() => {
        expect(screen.getByText(/42 detections/)).toBeInTheDocument()
      })
    })

    it('does not show the summary row while loading', () => {
      renderPage()
      // The summary renders "{n} detections" — no text matching /\d+ detections/ yet
      expect(screen.queryByText(/detections/)).not.toBeInTheDocument()
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

    it('appends the active status filter to the summary', async () => {
      mockApi.list.mockResolvedValue(makeResponse([], { total: 0 }))
      renderPage()
      const activeChip = await screen.findByRole('button', { name: 'Active' })
      fireEvent.click(activeChip)
      await waitFor(() => {
        expect(screen.getByText(/· active/)).toBeInTheDocument()
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

    it('renders the Active status chip', async () => {
      renderPage()
      expect(await screen.findByRole('button', { name: 'Active' })).toBeInTheDocument()
    })

    it('renders the Investigating status chip', async () => {
      renderPage()
      expect(await screen.findByRole('button', { name: 'Investigating' })).toBeInTheDocument()
    })

    it('renders the Resolved status chip', async () => {
      renderPage()
      expect(await screen.findByRole('button', { name: 'Resolved' })).toBeInTheDocument()
    })

    it('renders the FP (false_positive) status chip', async () => {
      renderPage()
      expect(await screen.findByRole('button', { name: 'FP' })).toBeInTheDocument()
    })

    it('renders the search input', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.getByPlaceholderText('Search detections…')).toBeInTheDocument()
      })
    })
  })

  // =========================================================================
  // Table column headers
  // =========================================================================
  describe('table column headers', () => {
    beforeEach(() => {
      mockApi.list.mockResolvedValue(makeResponse())
    })

    it('renders the Score column header', async () => {
      renderPage()
      await waitFor(() => expect(screen.getByText('Score')).toBeInTheDocument())
    })

    it('renders the Detection column header', async () => {
      renderPage()
      await waitFor(() => expect(screen.getByText('Detection')).toBeInTheDocument())
    })

    it('renders the Technique column header', async () => {
      renderPage()
      await waitFor(() => expect(screen.getByText('Technique')).toBeInTheDocument())
    })

    it('renders the Status column header (non-sortable)', async () => {
      renderPage()
      // Status column header is a plain <span>, not a <button>
      await waitFor(() => expect(screen.getByText('Status')).toBeInTheDocument())
    })

    it('renders a clickable Host sort button', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.getByRole('button', { name: /Host/i })).toBeInTheDocument()
      })
    })

    it('renders a clickable Tactic sort button', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.getByRole('button', { name: /Tactic/i })).toBeInTheDocument()
      })
    })

    it('renders a clickable Time sort button', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.getByRole('button', { name: /Time/i })).toBeInTheDocument()
      })
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
      // Manually advance to page 2 via another mock sequence
      mockApi.list
        .mockResolvedValueOnce(makeResponse([makeDetection()], { total: 50, total_pages: 3, page: 1 }))
        .mockResolvedValue(makeResponse([makeDetection()], { total: 50, total_pages: 3, page: 2 }))
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
  // Status filter — interaction
  // =========================================================================
  describe('status filter', () => {
    beforeEach(() => {
      mockApi.list.mockResolvedValue(makeResponse())
    })

    it('activates a status chip when clicked', async () => {
      renderPage()
      const chip = await screen.findByRole('button', { name: 'Active' })
      fireEvent.click(chip)
      expect(chip).toHaveClass('bg-blue')
    })

    it('deactivates the status chip when clicked again (toggle off)', async () => {
      renderPage()
      const chip = await screen.findByRole('button', { name: 'Active' })
      fireEvent.click(chip) // activate
      fireEvent.click(chip) // deactivate
      expect(chip).not.toHaveClass('bg-blue')
    })

    it('only one status chip is active at a time', async () => {
      renderPage()
      const active = await screen.findByRole('button', { name: 'Active' })
      const resolved = screen.getByRole('button', { name: 'Resolved' })
      fireEvent.click(active)
      fireEvent.click(resolved)
      expect(active).not.toHaveClass('bg-blue')
      expect(resolved).toHaveClass('bg-blue')
    })

    it('passes the selected status to the API call', async () => {
      renderPage()
      await waitFor(() => expect(mockApi.list).toHaveBeenCalledTimes(1))
      const chip = await screen.findByRole('button', { name: 'Resolved' })
      fireEvent.click(chip)
      await waitFor(() => {
        const lastCall = mockApi.list.mock.calls.at(-1)![0]
        expect(lastCall.status).toBe('resolved')
      })
    })

    it('passes undefined status when no status chip is selected', async () => {
      renderPage()
      await waitFor(() => {
        const firstCall = mockApi.list.mock.calls[0][0]
        expect(firstCall.status).toBeUndefined()
      })
    })

    it('passes false_positive status when FP chip is clicked', async () => {
      renderPage()
      await waitFor(() => expect(mockApi.list).toHaveBeenCalledTimes(1))
      const fpChip = await screen.findByRole('button', { name: 'FP' })
      fireEvent.click(fpChip)
      await waitFor(() => {
        const lastCall = mockApi.list.mock.calls.at(-1)![0]
        expect(lastCall.status).toBe('false_positive')
      })
    })

    it('resets to page 1 when status chip is clicked', async () => {
      mockApi.list
        .mockResolvedValueOnce(makeResponse([makeDetection()], { total: 50, total_pages: 3, page: 1 }))
        .mockResolvedValue(makeResponse([makeDetection()], { total: 50, total_pages: 3, page: 2 }))
      renderPage()
      const nextBtn = await screen.findByText(/Next →/)
      fireEvent.click(nextBtn)
      await waitFor(() => expect(mockApi.list).toHaveBeenCalledTimes(2))
      const statusChip = screen.getByRole('button', { name: 'Active' })
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
      const input = await screen.findByPlaceholderText('Search detections…')
      fireEvent.change(input, { target: { value: 'mimikatz' } })
      expect(input).toHaveValue('mimikatz')
    })

    it('triggers a new API call after the search value changes', async () => {
      renderPage()
      await waitFor(() => expect(mockApi.list).toHaveBeenCalledTimes(1))
      const input = await screen.findByPlaceholderText('Search detections…')
      fireEvent.change(input, { target: { value: 'ps' } })
      await waitFor(() => expect(mockApi.list).toHaveBeenCalledTimes(2))
    })

    it('passes the search term to the API call', async () => {
      renderPage()
      await waitFor(() => expect(mockApi.list).toHaveBeenCalledTimes(1))
      const input = await screen.findByPlaceholderText('Search detections…')
      fireEvent.change(input, { target: { value: 'mimikatz' } })
      await waitFor(() => {
        const lastCall = mockApi.list.mock.calls.at(-1)![0]
        expect(lastCall.search).toBe('mimikatz')
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
        .mockResolvedValueOnce(makeResponse([makeDetection()], { total: 50, total_pages: 3, page: 1 }))
        .mockResolvedValue(makeResponse([makeDetection()], { total: 50, total_pages: 3, page: 2 }))
      renderPage()
      const nextBtn = await screen.findByText(/Next →/)
      fireEvent.click(nextBtn)
      await waitFor(() => expect(mockApi.list).toHaveBeenCalledTimes(2))
      const input = screen.getByPlaceholderText('Search detections…')
      fireEvent.change(input, { target: { value: 'kerberos' } })
      await waitFor(() => {
        const lastCall = mockApi.list.mock.calls.at(-1)![0]
        expect(lastCall.page).toBe(1)
      })
    })
  })

  // =========================================================================
  // Sort headers — interaction
  // =========================================================================
  describe('sort headers', () => {
    beforeEach(() => {
      mockApi.list.mockResolvedValue(makeResponse())
    })

    it('clicking Time header queries with sort=time', async () => {
      renderPage()
      await waitFor(() => expect(mockApi.list).toHaveBeenCalledTimes(1))
      fireEvent.click(await screen.findByRole('button', { name: /Time/ }))
      await waitFor(() => {
        const lastCall = mockApi.list.mock.calls.at(-1)![0]
        expect(lastCall.sort).toBe('time')
      })
    })

    it('clicking Host header queries with sort=host', async () => {
      renderPage()
      await waitFor(() => expect(mockApi.list).toHaveBeenCalledTimes(1))
      fireEvent.click(await screen.findByRole('button', { name: /Host/ }))
      await waitFor(() => {
        const lastCall = mockApi.list.mock.calls.at(-1)![0]
        expect(lastCall.sort).toBe('host')
      })
    })

    it('clicking Tactic header queries with sort=tactic', async () => {
      renderPage()
      await waitFor(() => expect(mockApi.list).toHaveBeenCalledTimes(1))
      fireEvent.click(await screen.findByRole('button', { name: /Tactic/ }))
      await waitFor(() => {
        const lastCall = mockApi.list.mock.calls.at(-1)![0]
        expect(lastCall.sort).toBe('tactic')
      })
    })

    it('switching to a new sort key starts with order=desc', async () => {
      renderPage()
      await waitFor(() => expect(mockApi.list).toHaveBeenCalledTimes(1))
      fireEvent.click(await screen.findByRole('button', { name: /Host/ }))
      await waitFor(() => {
        const lastCall = mockApi.list.mock.calls.at(-1)![0]
        expect(lastCall.sort).toBe('host')
        expect(lastCall.order).toBe('desc')
      })
    })

    it('clicking the active sort header toggles from desc to asc', async () => {
      renderPage()
      await waitFor(() => expect(mockApi.list).toHaveBeenCalledTimes(1))
      const timeBtn = await screen.findByRole('button', { name: /Time/ })
      fireEvent.click(timeBtn) // time desc
      await waitFor(() => expect(mockApi.list).toHaveBeenCalledTimes(2))
      fireEvent.click(timeBtn) // time asc
      await waitFor(() => {
        const lastCall = mockApi.list.mock.calls.at(-1)![0]
        expect(lastCall.order).toBe('asc')
      })
    })

    it('clicking the active sort header again toggles back to desc', async () => {
      renderPage()
      await waitFor(() => expect(mockApi.list).toHaveBeenCalledTimes(1))
      const timeBtn = await screen.findByRole('button', { name: /Time/ })
      fireEvent.click(timeBtn) // desc
      await waitFor(() => expect(mockApi.list).toHaveBeenCalledTimes(2))
      fireEvent.click(timeBtn) // asc
      await waitFor(() => expect(mockApi.list).toHaveBeenCalledTimes(3))
      fireEvent.click(timeBtn) // desc again
      await waitFor(() => {
        const lastCall = mockApi.list.mock.calls.at(-1)![0]
        expect(lastCall.order).toBe('desc')
      })
    })

    it('shows the descending arrow indicator on the active sort column', async () => {
      renderPage()
      const timeBtn = await screen.findByRole('button', { name: /Time/ })
      fireEvent.click(timeBtn) // activate time desc
      await waitFor(() => expect(screen.getByText('↓')).toBeInTheDocument())
    })

    it('shows the ascending arrow indicator after toggling the active column', async () => {
      renderPage()
      const timeBtn = await screen.findByRole('button', { name: /Time/ })
      fireEvent.click(timeBtn) // time desc
      await waitFor(() => expect(screen.getByText('↓')).toBeInTheDocument())
      fireEvent.click(timeBtn) // time asc
      await waitFor(() => expect(screen.getByText('↑')).toBeInTheDocument())
    })

    it('sort change resets page to 1', async () => {
      mockApi.list
        .mockResolvedValueOnce(makeResponse([makeDetection()], { total: 50, total_pages: 3, page: 1 }))
        .mockResolvedValue(makeResponse([makeDetection()], { total: 50, total_pages: 3, page: 2 }))
      renderPage()
      const nextBtn = await screen.findByText(/Next →/)
      fireEvent.click(nextBtn)
      await waitFor(() => expect(mockApi.list).toHaveBeenCalledTimes(2))
      fireEvent.click(screen.getByRole('button', { name: /Time/ }))
      await waitFor(() => {
        const lastCall = mockApi.list.mock.calls.at(-1)![0]
        expect(lastCall.page).toBe(1)
      })
    })
  })

  // =========================================================================
  // Row selection / DetectionPanel
  // =========================================================================
  describe('row selection', () => {
    beforeEach(() => {
      mockApi.list.mockResolvedValue(
        makeResponse([makeDetection({ id: 'det-001', name: 'Suspicious LSASS Memory Access' })]),
      )
    })

    it('detection panel is not shown initially', () => {
      renderPage()
      expect(screen.queryByTestId('detection-panel')).not.toBeInTheDocument()
    })

    it('clicking a row opens the detection panel', async () => {
      renderPage()
      fireEvent.click(await screen.findByText('Suspicious LSASS Memory Access'))
      expect(screen.getByTestId('detection-panel')).toBeInTheDocument()
    })

    it('the panel receives the correct detection id', async () => {
      renderPage()
      fireEvent.click(await screen.findByText('Suspicious LSASS Memory Access'))
      expect(screen.getByTestId('detection-panel')).toHaveAttribute('data-detection-id', 'det-001')
    })

    it('clicking a selected row closes the panel', async () => {
      renderPage()
      const row = await screen.findByText('Suspicious LSASS Memory Access')
      fireEvent.click(row) // open
      expect(screen.getByTestId('detection-panel')).toBeInTheDocument()
      fireEvent.click(row) // close (deselect same row)
      expect(screen.queryByTestId('detection-panel')).not.toBeInTheDocument()
    })

    it('clicking the panel close button closes the panel', async () => {
      renderPage()
      fireEvent.click(await screen.findByText('Suspicious LSASS Memory Access'))
      expect(screen.getByTestId('detection-panel')).toBeInTheDocument()
      fireEvent.click(screen.getByTestId('panel-close'))
      expect(screen.queryByTestId('detection-panel')).not.toBeInTheDocument()
    })

    it('clicking a different row replaces the selected detection in the panel', async () => {
      mockApi.list.mockResolvedValue(
        makeResponse([
          makeDetection({ id: 'det-001', name: 'Detection Alpha' }),
          makeDetection({ id: 'det-002', name: 'Detection Beta' }),
        ]),
      )
      renderPage()
      fireEvent.click(await screen.findByText('Detection Alpha'))
      expect(screen.getByTestId('detection-panel')).toHaveAttribute('data-detection-id', 'det-001')
      fireEvent.click(screen.getByText('Detection Beta'))
      expect(screen.getByTestId('detection-panel')).toHaveAttribute('data-detection-id', 'det-002')
    })
  })

  // =========================================================================
  // Pagination
  // =========================================================================
  describe('pagination', () => {
    it('does not show pagination controls when total_pages is 1', async () => {
      mockApi.list.mockResolvedValue(makeResponse([makeDetection()], { total: 5, total_pages: 1 }))
      renderPage()
      await waitFor(() => {
        expect(screen.queryByText(/← Prev/)).not.toBeInTheDocument()
        expect(screen.queryByText(/Next →/)).not.toBeInTheDocument()
      })
    })

    it('shows pagination controls when total_pages > 1', async () => {
      mockApi.list.mockResolvedValue(makeResponse([makeDetection()], { total: 50, total_pages: 3, page: 1 }))
      renderPage()
      await waitFor(() => {
        expect(screen.getByText(/← Prev/)).toBeInTheDocument()
        expect(screen.getByText(/Next →/)).toBeInTheDocument()
      })
    })

    it('shows the current page and total pages', async () => {
      mockApi.list.mockResolvedValue(makeResponse([makeDetection()], { total: 50, total_pages: 3, page: 1 }))
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('Page 1 of 3')).toBeInTheDocument()
      })
    })

    it('Prev button is disabled on page 1', async () => {
      mockApi.list.mockResolvedValue(makeResponse([makeDetection()], { total: 50, total_pages: 3, page: 1 }))
      renderPage()
      const prevBtn = await screen.findByText(/← Prev/)
      expect(prevBtn.closest('button')).toBeDisabled()
    })

    it('Next button is not disabled on page 1 of 3', async () => {
      mockApi.list.mockResolvedValue(makeResponse([makeDetection()], { total: 50, total_pages: 3, page: 1 }))
      renderPage()
      const nextBtn = await screen.findByText(/Next →/)
      expect(nextBtn.closest('button')).not.toBeDisabled()
    })

    it('clicking Next requests page 2', async () => {
      mockApi.list.mockResolvedValue(makeResponse([makeDetection()], { total: 50, total_pages: 3, page: 1 }))
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
        .mockResolvedValueOnce(makeResponse([makeDetection()], { total: 60, total_pages: 3, page: 1 }))
        .mockResolvedValue(makeResponse([makeDetection()], { total: 60, total_pages: 3, page: 2 }))
      renderPage()
      await waitFor(() => expect(mockApi.list).toHaveBeenCalledTimes(1))
      fireEvent.click(await screen.findByText(/Next →/))
      await waitFor(() => expect(mockApi.list).toHaveBeenCalledTimes(2))
      fireEvent.click(screen.getByText(/Next →/))
      await waitFor(() => {
        const lastCall = mockApi.list.mock.calls.at(-1)![0]
        expect(lastCall.page).toBe(3)
      })
    })

    it('clicking Prev requests the previous page', async () => {
      mockApi.list
        .mockResolvedValueOnce(makeResponse([makeDetection()], { total: 50, total_pages: 3, page: 1 }))
        .mockResolvedValue(makeResponse([makeDetection()], { total: 50, total_pages: 3, page: 2 }))
      renderPage()
      fireEvent.click(await screen.findByText(/Next →/)) // go to page 2
      await waitFor(() => expect(mockApi.list).toHaveBeenCalledTimes(2))
      fireEvent.click(screen.getByText(/← Prev/)) // back to page 1
      await waitFor(() => {
        const lastCall = mockApi.list.mock.calls.at(-1)![0]
        expect(lastCall.page).toBe(1)
      })
    })

    it('Next button is disabled on the last page', async () => {
      mockApi.list
        .mockResolvedValueOnce(makeResponse([makeDetection()], { total: 40, total_pages: 2, page: 1 }))
        .mockResolvedValue(makeResponse([makeDetection()], { total: 40, total_pages: 2, page: 2 }))
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
        .mockResolvedValueOnce(makeResponse([makeDetection()], { total: 40, total_pages: 2, page: 1 }))
        .mockResolvedValue(makeResponse([makeDetection()], { total: 40, total_pages: 2, page: 2 }))
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
    it('renders the TopBar with the "Detections" crumb', () => {
      renderPage()
      expect(screen.getByTestId('topbar')).toHaveTextContent('Detections')
    })
  })

  // =========================================================================
  // Initial API call parameters
  // =========================================================================
  describe('initial API call parameters', () => {
    beforeEach(() => {
      mockApi.list.mockResolvedValue(makeResponse())
    })

    it('calls detectionsApi.list once on mount', async () => {
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

    it('defaults to sort=score', async () => {
      renderPage()
      await waitFor(() => {
        expect(mockApi.list.mock.calls[0][0].sort).toBe('score')
      })
    })

    it('defaults to order=desc', async () => {
      renderPage()
      await waitFor(() => {
        expect(mockApi.list.mock.calls[0][0].order).toBe('desc')
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
})
