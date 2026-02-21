// vi.mock is hoisted before imports — declare all module mocks first.

vi.mock('../../lib/api', () => ({
  reportsApi: {
    list:           vi.fn(),
    generate:       vi.fn(),
    download:       vi.fn(),
    delete:         vi.fn(),
    listSchedules:  vi.fn(),
    createSchedule: vi.fn(),
    updateSchedule: vi.fn(),
    deleteSchedule: vi.fn(),
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
import { ReportsPage } from '../../components/features/reports/ReportsPage'
import { reportsApi } from '../../lib/api'

// ---------------------------------------------------------------------------
// Typed reference to the mocked API
// ---------------------------------------------------------------------------

const mockApi = reportsApi as {
  list:           ReturnType<typeof vi.fn>
  generate:       ReturnType<typeof vi.fn>
  download:       ReturnType<typeof vi.fn>
  delete:         ReturnType<typeof vi.fn>
  listSchedules:  ReturnType<typeof vi.fn>
  createSchedule: ReturnType<typeof vi.fn>
  updateSchedule: ReturnType<typeof vi.fn>
  deleteSchedule: ReturnType<typeof vi.fn>
}

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

const makeReport = (overrides: Record<string, unknown> = {}) => ({
  id:            'abc123de-0000-0000-0000-000000000001',
  template_type: 'executive_summary' as const,
  status:        'ready' as const,
  format:        'json' as const,
  created_by:    'analyst@mxtac.local',
  created_at:    '2026-02-15T10:00:00Z',
  updated_at:    '2026-02-15T10:05:00Z',
  ...overrides,
})

const makeReportResponse = (
  items = [makeReport()],
  paginationOverrides: Record<string, unknown> = {},
) => ({
  items,
  pagination: {
    page:        1,
    page_size:   20,
    total:       items.length,
    total_pages: 1,
    ...paginationOverrides,
  },
})

const makeSchedule = (overrides: Record<string, unknown> = {}) => ({
  id:              'sched-0001',
  name:            'Weekly executive summary',
  template_type:   'executive_summary' as const,
  format:          'json' as const,
  cron_expression: '0 0 * * 1',
  enabled:         true,
  last_run_at:     null,
  next_run_at:     null,
  created_by:      'analyst@mxtac.local',
  created_at:      '2026-02-01T00:00:00Z',
  ...overrides,
})

const makeScheduleResponse = (items = [makeSchedule()]) => ({
  items,
  pagination: { page: 1, page_size: 20, total: items.length, total_pages: 1 },
})

// ---------------------------------------------------------------------------
// Render helper
// ---------------------------------------------------------------------------

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false, staleTime: Infinity },
    },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <ReportsPage />
    </QueryClientProvider>,
  )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('ReportsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    // Default: list is pending (loading state)
    mockApi.list.mockReturnValue(new Promise<never>(() => {}))
    mockApi.listSchedules.mockReturnValue(new Promise<never>(() => {}))
  })

  // =========================================================================
  // TopBar
  // =========================================================================
  describe('TopBar', () => {
    it('renders the TopBar with "Reports" crumb', () => {
      renderPage()
      expect(screen.getByTestId('topbar')).toHaveTextContent('Reports')
    })
  })

  // =========================================================================
  // Tab bar
  // =========================================================================
  describe('tab bar', () => {
    it('renders "Generated Reports" tab button', () => {
      renderPage()
      expect(screen.getByRole('button', { name: 'Generated Reports' })).toBeInTheDocument()
    })

    it('renders "Scheduled Reports" tab button', () => {
      renderPage()
      expect(screen.getByRole('button', { name: 'Scheduled Reports' })).toBeInTheDocument()
    })

    it('defaults to the Generated Reports tab (shows loading for list)', () => {
      renderPage()
      expect(screen.getByText('Loading…')).toBeInTheDocument()
    })

    it('switches to Scheduled Reports tab when clicked', async () => {
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Scheduled Reports' }))
      // Should show loading for schedules
      await waitFor(() => {
        expect(screen.getByText('Loading…')).toBeInTheDocument()
      })
    })
  })

  // =========================================================================
  // Generated Reports — loading state
  // =========================================================================
  describe('Generated Reports: loading state', () => {
    it('shows "Loading…" while query is pending', () => {
      renderPage()
      expect(screen.getByText('Loading…')).toBeInTheDocument()
    })
  })

  // =========================================================================
  // Generated Reports — error state
  // =========================================================================
  describe('Generated Reports: error state', () => {
    it('shows error message when list fails', async () => {
      mockApi.list.mockRejectedValue(new Error('Network error'))
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('Failed to load reports.')).toBeInTheDocument()
      })
    })
  })

  // =========================================================================
  // Generated Reports — empty state
  // =========================================================================
  describe('Generated Reports: empty state', () => {
    it('shows empty state message when no reports exist', async () => {
      mockApi.list.mockResolvedValue(makeReportResponse([]))
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('No reports generated yet')).toBeInTheDocument()
      })
    })

    it('shows helper text in empty state', async () => {
      mockApi.list.mockResolvedValue(makeReportResponse([]))
      renderPage()
      await waitFor(() => {
        expect(screen.getByText(/Click "Generate Report"/)).toBeInTheDocument()
      })
    })
  })

  // =========================================================================
  // Generated Reports — success state
  // =========================================================================
  describe('Generated Reports: success state', () => {
    beforeEach(() => {
      mockApi.list.mockResolvedValue(makeReportResponse())
    })

    it('renders the report template name', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('Executive Summary')).toBeInTheDocument()
      })
    })

    it('renders the created_by value under the template name', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('analyst@mxtac.local')).toBeInTheDocument()
      })
    })

    it('renders the format (css uppercase applied visually)', async () => {
      renderPage()
      await waitFor(() => {
        // The span has class "uppercase" — jsdom does not apply CSS transforms,
        // so we match the raw text content "json".
        expect(screen.getByText('json')).toBeInTheDocument()
      })
    })

    it('renders a "ready" status badge', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.getByText(/ready/)).toBeInTheDocument()
      })
    })

    it('renders a "generating" status badge for in-progress reports', async () => {
      mockApi.list.mockResolvedValue(
        makeReportResponse([makeReport({ status: 'generating' })]),
      )
      renderPage()
      await waitFor(() => {
        expect(screen.getByText(/generating/)).toBeInTheDocument()
      })
    })

    it('renders a "failed" status badge for failed reports', async () => {
      mockApi.list.mockResolvedValue(
        makeReportResponse([makeReport({ status: 'failed' })]),
      )
      renderPage()
      await waitFor(() => {
        expect(screen.getByText(/failed/)).toBeInTheDocument()
      })
    })

    it('renders the Download button for ready reports', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.getByRole('button', { name: 'Download report' })).not.toBeDisabled()
      })
    })

    it('Download button is disabled for generating reports', async () => {
      mockApi.list.mockResolvedValue(
        makeReportResponse([makeReport({ status: 'generating' })]),
      )
      renderPage()
      await waitFor(() => {
        expect(screen.getByRole('button', { name: 'Download report' })).toBeDisabled()
      })
    })

    it('renders the Delete button', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.getByRole('button', { name: 'Delete report' })).toBeInTheDocument()
      })
    })

    it('does not show empty state when reports are present', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.queryByText('No reports generated yet')).not.toBeInTheDocument()
      })
    })

    it('does not show error message on success', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.queryByText('Failed to load reports.')).not.toBeInTheDocument()
      })
    })

    it('does not show "Loading…" after data resolves', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.queryByText('Loading…')).not.toBeInTheDocument()
      })
    })
  })

  // =========================================================================
  // Generated Reports — table headers
  // =========================================================================
  describe('Generated Reports: table column headers', () => {
    beforeEach(() => {
      mockApi.list.mockResolvedValue(makeReportResponse())
    })

    it('renders the Template column header', async () => {
      renderPage()
      await waitFor(() => expect(screen.getByText('Template')).toBeInTheDocument())
    })

    it('renders the Created column header', async () => {
      renderPage()
      await waitFor(() => expect(screen.getByText('Created')).toBeInTheDocument())
    })

    it('renders the Status column header', async () => {
      renderPage()
      await waitFor(() => expect(screen.getByText('Status')).toBeInTheDocument())
    })

    it('renders the Format column header', async () => {
      renderPage()
      await waitFor(() => expect(screen.getByText('Format')).toBeInTheDocument())
    })

    it('renders the Actions column header', async () => {
      renderPage()
      await waitFor(() => expect(screen.getByText('Actions')).toBeInTheDocument())
    })
  })

  // =========================================================================
  // Generate Report modal
  // =========================================================================
  describe('Generate Report modal', () => {
    beforeEach(() => {
      mockApi.list.mockResolvedValue(makeReportResponse([]))
    })

    it('modal is not shown initially', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.queryByTestId('generate-modal')).not.toBeInTheDocument()
      })
    })

    it('clicking "+ Generate Report" opens the modal', async () => {
      renderPage()
      const btn = await screen.findByRole('button', { name: /Generate Report/ })
      fireEvent.click(btn)
      expect(screen.getByTestId('generate-modal')).toBeInTheDocument()
    })

    it('modal shows "Generate Report" heading', async () => {
      renderPage()
      fireEvent.click(await screen.findByRole('button', { name: /Generate Report/ }))
      expect(screen.getByText('Generate Report')).toBeInTheDocument()
    })

    it('modal contains the Template selector', async () => {
      renderPage()
      fireEvent.click(await screen.findByRole('button', { name: /Generate Report/ }))
      expect(screen.getByRole('combobox')).toBeInTheDocument()
    })

    it('modal contains From date input', async () => {
      renderPage()
      fireEvent.click(await screen.findByRole('button', { name: /Generate Report/ }))
      const inputs = screen.getAllByDisplayValue(/\d{4}-\d{2}-\d{2}/)
      expect(inputs.length).toBeGreaterThanOrEqual(2)
    })

    it('modal contains JSON and CSV format buttons', async () => {
      renderPage()
      fireEvent.click(await screen.findByRole('button', { name: /Generate Report/ }))
      expect(screen.getByRole('button', { name: 'JSON' })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'CSV' })).toBeInTheDocument()
    })

    it('clicking Cancel closes the modal', async () => {
      renderPage()
      fireEvent.click(await screen.findByRole('button', { name: /Generate Report/ }))
      expect(screen.getByTestId('generate-modal')).toBeInTheDocument()
      fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
      await waitFor(() => {
        expect(screen.queryByTestId('generate-modal')).not.toBeInTheDocument()
      })
    })

    it('clicking Generate calls reportsApi.generate', async () => {
      mockApi.generate.mockResolvedValue({ report_id: 'new-id', status: 'generating' })
      renderPage()
      fireEvent.click(await screen.findByRole('button', { name: /Generate Report/ }))
      fireEvent.click(screen.getByRole('button', { name: 'Generate' }))
      await waitFor(() => {
        expect(mockApi.generate).toHaveBeenCalledTimes(1)
      })
    })

    it('Generate call includes the selected template', async () => {
      mockApi.generate.mockResolvedValue({ report_id: 'new-id', status: 'generating' })
      renderPage()
      fireEvent.click(await screen.findByRole('button', { name: /Generate Report/ }))
      fireEvent.click(screen.getByRole('button', { name: 'Generate' }))
      await waitFor(() => {
        const arg = mockApi.generate.mock.calls[0][0]
        expect(arg.template_type).toBe('executive_summary')
      })
    })

    it('Generate call includes the selected format', async () => {
      mockApi.generate.mockResolvedValue({ report_id: 'new-id', status: 'generating' })
      renderPage()
      fireEvent.click(await screen.findByRole('button', { name: /Generate Report/ }))
      // Switch to CSV
      fireEvent.click(screen.getByRole('button', { name: 'CSV' }))
      fireEvent.click(screen.getByRole('button', { name: 'Generate' }))
      await waitFor(() => {
        const arg = mockApi.generate.mock.calls[0][0]
        expect(arg.format).toBe('csv')
      })
    })

    it('shows error message when generate fails', async () => {
      mockApi.generate.mockRejectedValue(new Error('Server error'))
      renderPage()
      fireEvent.click(await screen.findByRole('button', { name: /Generate Report/ }))
      fireEvent.click(screen.getByRole('button', { name: 'Generate' }))
      await waitFor(() => {
        expect(screen.getByRole('alert')).toHaveTextContent('Server error')
      })
    })
  })

  // =========================================================================
  // Pagination
  // =========================================================================
  describe('Generated Reports: pagination', () => {
    it('does not show pagination when total_pages is 1', async () => {
      mockApi.list.mockResolvedValue(makeReportResponse([makeReport()], { total: 5, total_pages: 1 }))
      renderPage()
      await waitFor(() => {
        expect(screen.queryByText(/Prev/)).not.toBeInTheDocument()
        expect(screen.queryByText(/Next/)).not.toBeInTheDocument()
      })
    })

    it('shows pagination when total_pages > 1', async () => {
      mockApi.list.mockResolvedValue(
        makeReportResponse([makeReport()], { total: 50, total_pages: 3 }),
      )
      renderPage()
      await waitFor(() => {
        expect(screen.getByText(/Prev/)).toBeInTheDocument()
        expect(screen.getByText(/Next/)).toBeInTheDocument()
      })
    })

    it('shows page indicator', async () => {
      mockApi.list.mockResolvedValue(
        makeReportResponse([makeReport()], { total: 50, total_pages: 3 }),
      )
      renderPage()
      await waitFor(() => {
        expect(screen.getByText(/Page 1 of 3/)).toBeInTheDocument()
      })
    })
  })

  // =========================================================================
  // Scheduled Reports tab
  // =========================================================================
  describe('Scheduled Reports tab', () => {
    beforeEach(() => {
      // Switch to scheduled tab
    })

    it('shows loading state for schedules while query is pending', async () => {
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Scheduled Reports' }))
      await waitFor(() => {
        expect(screen.getByText('Loading…')).toBeInTheDocument()
      })
    })

    it('shows empty state when no schedules exist', async () => {
      mockApi.listSchedules.mockResolvedValue(makeScheduleResponse([]))
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Scheduled Reports' }))
      await waitFor(() => {
        expect(screen.getByText('No scheduled reports')).toBeInTheDocument()
      })
    })

    it('renders schedule name', async () => {
      mockApi.listSchedules.mockResolvedValue(makeScheduleResponse())
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Scheduled Reports' }))
      await waitFor(() => {
        expect(screen.getByText('Weekly executive summary')).toBeInTheDocument()
      })
    })

    it('renders schedule template label', async () => {
      mockApi.listSchedules.mockResolvedValue(makeScheduleResponse())
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Scheduled Reports' }))
      await waitFor(() => {
        expect(screen.getByText('Executive Summary')).toBeInTheDocument()
      })
    })

    it('renders human-readable cron schedule', async () => {
      mockApi.listSchedules.mockResolvedValue(makeScheduleResponse())
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Scheduled Reports' }))
      await waitFor(() => {
        // '0 0 * * 1' → 'Weekly (Monday)'
        expect(screen.getByText('Weekly (Monday)')).toBeInTheDocument()
      })
    })

    it('renders cron expression in monospace', async () => {
      mockApi.listSchedules.mockResolvedValue(makeScheduleResponse())
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Scheduled Reports' }))
      await waitFor(() => {
        expect(screen.getByText('0 0 * * 1')).toBeInTheDocument()
      })
    })

    it('renders the enabled toggle as a switch', async () => {
      mockApi.listSchedules.mockResolvedValue(makeScheduleResponse())
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Scheduled Reports' }))
      await waitFor(() => {
        const toggle = screen.getByRole('switch')
        expect(toggle).toHaveAttribute('aria-checked', 'true')
      })
    })

    it('renders disabled toggle for disabled schedule', async () => {
      mockApi.listSchedules.mockResolvedValue(
        makeScheduleResponse([makeSchedule({ enabled: false })]),
      )
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Scheduled Reports' }))
      await waitFor(() => {
        const toggle = screen.getByRole('switch')
        expect(toggle).toHaveAttribute('aria-checked', 'false')
      })
    })

    it('clicking the toggle calls updateSchedule with toggled enabled value', async () => {
      mockApi.listSchedules.mockResolvedValue(makeScheduleResponse())
      mockApi.updateSchedule.mockResolvedValue(makeSchedule({ enabled: false }))
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Scheduled Reports' }))
      const toggle = await screen.findByRole('switch')
      fireEvent.click(toggle)
      await waitFor(() => {
        expect(mockApi.updateSchedule).toHaveBeenCalledWith('sched-0001', { enabled: false })
      })
    })

    it('renders "—" when last_run_at is null', async () => {
      mockApi.listSchedules.mockResolvedValue(
        makeScheduleResponse([makeSchedule({ last_run_at: null })]),
      )
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Scheduled Reports' }))
      await waitFor(() => {
        // two "—" expected: last_run_at and next_run_at
        const dashes = screen.getAllByText('—')
        expect(dashes.length).toBeGreaterThanOrEqual(1)
      })
    })

    it('renders the delete button for each schedule', async () => {
      mockApi.listSchedules.mockResolvedValue(makeScheduleResponse())
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Scheduled Reports' }))
      await waitFor(() => {
        expect(screen.getByRole('button', { name: 'Delete schedule' })).toBeInTheDocument()
      })
    })

    it('shows scheduled tab column headers', async () => {
      mockApi.listSchedules.mockResolvedValue(makeScheduleResponse())
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Scheduled Reports' }))
      await waitFor(() => {
        expect(screen.getByText('Name')).toBeInTheDocument()
        expect(screen.getByText('Schedule')).toBeInTheDocument()
        expect(screen.getByText('Last Run')).toBeInTheDocument()
        expect(screen.getByText('Next Run')).toBeInTheDocument()
      })
    })
  })

  // =========================================================================
  // Create Schedule modal
  // =========================================================================
  describe('Create Schedule modal', () => {
    beforeEach(() => {
      mockApi.listSchedules.mockResolvedValue(makeScheduleResponse([]))
    })

    it('modal is not shown initially', async () => {
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Scheduled Reports' }))
      await waitFor(() => {
        expect(screen.queryByTestId('schedule-modal')).not.toBeInTheDocument()
      })
    })

    it('clicking "+ Create Schedule" opens the modal', async () => {
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Scheduled Reports' }))
      const btn = await screen.findByRole('button', { name: /Create Schedule/ })
      fireEvent.click(btn)
      expect(screen.getByTestId('schedule-modal')).toBeInTheDocument()
    })

    it('modal shows "Create Schedule" heading', async () => {
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Scheduled Reports' }))
      fireEvent.click(await screen.findByRole('button', { name: /Create Schedule/ }))
      expect(screen.getByRole('heading', { name: 'Create Schedule' })).toBeInTheDocument()
    })

    it('modal contains a name input', async () => {
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Scheduled Reports' }))
      fireEvent.click(await screen.findByRole('button', { name: /Create Schedule/ }))
      expect(screen.getByPlaceholderText(/e.g. Weekly executive summary/)).toBeInTheDocument()
    })

    it('modal contains the cron preset selector', async () => {
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Scheduled Reports' }))
      fireEvent.click(await screen.findByRole('button', { name: /Create Schedule/ }))
      // There are two selects in the modal: template and preset
      const combos = screen.getAllByRole('combobox')
      expect(combos.length).toBeGreaterThanOrEqual(2)
    })

    it('clicking Cancel closes the modal', async () => {
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Scheduled Reports' }))
      fireEvent.click(await screen.findByRole('button', { name: /Create Schedule/ }))
      expect(screen.getByTestId('schedule-modal')).toBeInTheDocument()
      fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
      await waitFor(() => {
        expect(screen.queryByTestId('schedule-modal')).not.toBeInTheDocument()
      })
    })

    it('"Create Schedule" submit button is disabled when name is empty', async () => {
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Scheduled Reports' }))
      fireEvent.click(await screen.findByRole('button', { name: /Create Schedule/ }))
      // The submit button inside the modal
      const submitBtn = screen.getByRole('button', { name: 'Create Schedule' })
      expect(submitBtn).toBeDisabled()
    })

    it('"Create Schedule" submit button is enabled after name is entered', async () => {
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Scheduled Reports' }))
      fireEvent.click(await screen.findByRole('button', { name: /Create Schedule/ }))
      const nameInput = screen.getByPlaceholderText(/e.g. Weekly executive summary/)
      fireEvent.change(nameInput, { target: { value: 'My schedule' } })
      const submitBtn = screen.getByRole('button', { name: 'Create Schedule' })
      expect(submitBtn).not.toBeDisabled()
    })

    it('clicking Create Schedule calls reportsApi.createSchedule', async () => {
      mockApi.createSchedule.mockResolvedValue(makeSchedule())
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Scheduled Reports' }))
      fireEvent.click(await screen.findByRole('button', { name: /Create Schedule/ }))
      const nameInput = screen.getByPlaceholderText(/e.g. Weekly executive summary/)
      fireEvent.change(nameInput, { target: { value: 'My schedule' } })
      fireEvent.click(screen.getByRole('button', { name: 'Create Schedule' }))
      await waitFor(() => {
        expect(mockApi.createSchedule).toHaveBeenCalledTimes(1)
      })
    })

    it('createSchedule is called with the entered name', async () => {
      mockApi.createSchedule.mockResolvedValue(makeSchedule())
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Scheduled Reports' }))
      fireEvent.click(await screen.findByRole('button', { name: /Create Schedule/ }))
      const nameInput = screen.getByPlaceholderText(/e.g. Weekly executive summary/)
      fireEvent.change(nameInput, { target: { value: 'Daily coverage report' } })
      fireEvent.click(screen.getByRole('button', { name: 'Create Schedule' }))
      await waitFor(() => {
        const arg = mockApi.createSchedule.mock.calls[0][0]
        expect(arg.name).toBe('Daily coverage report')
      })
    })
  })
})
