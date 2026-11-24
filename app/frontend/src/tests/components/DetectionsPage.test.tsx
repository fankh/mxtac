// vi.mock is hoisted before imports — declare all module mocks first.

vi.mock('../../lib/api', () => ({
  authApi: {},
  detectionsApi: {
    list: vi.fn(),
    bulk: vi.fn(),
    export: vi.fn(),
    update: vi.fn(),
  },
  incidentsApi: {
    create: vi.fn(),
  },
}))

// The real TopBar opens the alert WebSocket; the page frame only needs its slots.
vi.mock('../../components/layout/TopBar', () => ({
  TopBar: ({ crumb, actions }: { crumb: string; actions?: ReactNode }) => (
    <header>
      <h1>{crumb}</h1>
      {actions}
    </header>
  ),
}))

vi.mock('../../components/features/detections/DetectionPanel', () => ({
  DetectionPanel: ({ detection, onClose }: { detection: Detection | null; onClose: () => void }) =>
    detection ? (
      <div data-testid="detection-panel">
        <span>Panel: {detection.name}</span>
        <button onClick={onClose}>Close panel</button>
      </div>
    ) : null,
}))

import type { ReactNode } from 'react'
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { DetectionsPage } from '../../components/features/detections/DetectionsPage'
import { detectionsApi, incidentsApi } from '../../lib/api'
import { useAuthStore } from '../../stores/authStore'
import { useDetectionStore } from '../../stores/detectionStore'
import { useUIStore } from '../../stores/uiStore'
import type { Detection, Incident, PaginatedResponse } from '../../types/api'
import { chooseOption, installRadixSelectPolyfills } from '../mocks/radixSelect'

installRadixSelectPolyfills()

const listMock = vi.mocked(detectionsApi.list)
const bulkMock = vi.mocked(detectionsApi.bulk)
const exportMock = vi.mocked(detectionsApi.export)
const createIncidentMock = vi.mocked(incidentsApi.create)

function makeDetection(overrides: Partial<Detection> = {}): Detection {
  return {
    id: 'det-001',
    score: 9.2,
    severity: 'critical',
    technique_id: 'T1003.001',
    technique_name: 'LSASS Memory',
    name: 'Suspicious LSASS access',
    host: 'WIN-DC01',
    tactic: 'Credential Access',
    status: 'active',
    time: '2026-02-19T08:30:00Z',
    rule_name: 'proc_access_win_lsass',
    related_technique_ids: [],
    ...overrides,
  }
}

const DETECTIONS: Detection[] = [
  makeDetection(),
  makeDetection({
    id: 'det-002',
    name: 'Encoded PowerShell command',
    severity: 'high',
    score: 7.4,
    host: 'WS-114',
    tactic: 'Execution',
    technique_id: 'T1059.001',
    technique_name: 'PowerShell',
    status: 'investigating',
  }),
  makeDetection({
    id: 'det-003',
    name: 'New local admin account',
    severity: 'medium',
    score: 5.1,
    host: 'SRV-FILE02',
    tactic: 'Persistence',
    technique_id: 'T1136.001',
    technique_name: 'Local Account',
    status: 'resolved',
  }),
]

function pageOf(items: Detection[], pagination: Partial<PaginatedResponse<Detection>['pagination']> = {}) {
  return {
    items,
    pagination: { page: 1, page_size: 25, total: items.length, total_pages: 1, ...pagination },
  }
}

function makeIncident(overrides: Partial<Incident> = {}): Incident {
  return {
    id: 42,
    title: 'Credential theft',
    description: null,
    severity: 'critical',
    status: 'new',
    priority: 3,
    assigned_to: null,
    created_by: 'analyst@mxtac.local',
    detection_ids: ['det-001', 'det-002'],
    technique_ids: [],
    tactic_ids: [],
    hosts: [],
    ttd_seconds: null,
    ttr_seconds: null,
    closed_at: null,
    created_at: '2026-02-19T09:00:00Z',
    updated_at: '2026-02-19T09:00:00Z',
    ...overrides,
  }
}

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <DetectionsPage />
    </QueryClientProvider>,
  )
}

async function renderLoaded() {
  const view = renderPage()
  await screen.findByText('Suspicious LSASS access')
  return view
}

function lastListParams() {
  const calls = listMock.mock.calls
  return calls[calls.length - 1][0]
}

function notifications() {
  return useUIStore.getState().notifications
}

beforeEach(() => {
  vi.clearAllMocks()
  listMock.mockResolvedValue(pageOf(DETECTIONS))
  useAuthStore.setState({ user: { email: 'analyst@mxtac.local', role: 'analyst' } })
  useDetectionStore.setState({ liveAlerts: [], unreadCount: 0 })
  useUIStore.setState({ notifications: [] })
})

describe('DetectionsPage', () => {
  describe('list', () => {
    it('shows the page title and one row per detection', async () => {
      await renderLoaded()
      expect(screen.getByRole('heading', { name: 'Detections' })).toBeInTheDocument()
      expect(screen.getByText('Encoded PowerShell command')).toBeInTheDocument()
      expect(screen.getByText('New local admin account')).toBeInTheDocument()
      expect(screen.getByText('WIN-DC01')).toBeInTheDocument()
      expect(screen.getByText('T1059.001')).toBeInTheDocument()
    })

    it('requests the first page sorted by newest, with no filters', async () => {
      await renderLoaded()
      expect(lastListParams()).toEqual({
        severity: undefined,
        status: undefined,
        tactic: undefined,
        host: undefined,
        search: undefined,
        sort: 'time',
        order: 'desc',
        page: 1,
        page_size: 25,
      })
    })

    it('shows a loading placeholder until the first response', () => {
      listMock.mockReturnValue(new Promise(() => {}))
      renderPage()
      expect(screen.getByLabelText('Loading detections')).toBeInTheDocument()
    })

    it('shows an error card and retries on request', async () => {
      listMock.mockRejectedValueOnce(new Error('Network down'))
      renderPage()
      const alert = await screen.findByRole('alert')
      expect(within(alert).getByText('Could not load detections')).toBeInTheDocument()
      expect(within(alert).getByText('Network down')).toBeInTheDocument()

      fireEvent.click(within(alert).getByRole('button', { name: /retry/i }))
      expect(await screen.findByText('Suspicious LSASS access')).toBeInTheDocument()
    })

    it('shows an empty state when there are no detections', async () => {
      listMock.mockResolvedValue(pageOf([]))
      renderPage()
      expect(await screen.findByText('No detections yet')).toBeInTheDocument()
    })

    it('offers to clear the filters when they match nothing', async () => {
      listMock.mockResolvedValue(pageOf([]))
      renderPage()
      await screen.findByText('No detections yet')
      fireEvent.click(screen.getByRole('button', { name: 'Critical' }))
      expect(await screen.findByText('No detections match the filters')).toBeInTheDocument()

      fireEvent.click(screen.getByRole('button', { name: 'Clear filters' }))
      await waitFor(() => expect(lastListParams()?.severity).toBeUndefined())
      expect(screen.getByRole('button', { name: 'Critical' })).toHaveAttribute('aria-pressed', 'false')
    })
  })

  describe('filters', () => {
    it('sends the chosen severities as a list', async () => {
      await renderLoaded()
      fireEvent.click(screen.getByRole('button', { name: 'Critical' }))
      fireEvent.click(screen.getByRole('button', { name: 'High' }))
      await waitFor(() => expect(lastListParams()?.severity).toEqual(['critical', 'high']))

      fireEvent.click(screen.getByRole('button', { name: 'Critical' }))
      await waitFor(() => expect(lastListParams()?.severity).toEqual(['high']))
    })

    it('sends the chosen statuses as a list', async () => {
      await renderLoaded()
      const statusGroup = screen.getByRole('group', { name: 'Status' })
      fireEvent.click(within(statusGroup).getByRole('button', { name: 'Active' }))
      await waitFor(() => expect(lastListParams()?.status).toEqual(['active']))

      fireEvent.click(within(statusGroup).getByRole('button', { name: 'False positive' }))
      await waitFor(() => expect(lastListParams()?.status).toEqual(['active', 'false_positive']))
    })

    it('sends the search text, and clears it with the clear button', async () => {
      await renderLoaded()
      const input = screen.getByRole('textbox', { name: 'Search detections' })
      fireEvent.change(input, { target: { value: '  lsass ' } })
      await waitFor(() => expect(lastListParams()?.search).toBe('lsass'))

      fireEvent.click(screen.getByRole('button', { name: 'Clear search detections' }))
      expect(input).toHaveValue('')
      await waitFor(() => expect(lastListParams()?.search).toBeUndefined())
    })

    it('clears the search on Escape', async () => {
      await renderLoaded()
      const input = screen.getByRole('textbox', { name: 'Search detections' })
      fireEvent.change(input, { target: { value: 'mimikatz' } })
      fireEvent.keyDown(input, { key: 'Escape' })
      expect(input).toHaveValue('')
    })

    it('sends the tactic and host filters', async () => {
      await renderLoaded()
      fireEvent.change(screen.getByRole('textbox', { name: 'Tactic filter' }), { target: { value: 'Execution' } })
      fireEvent.change(screen.getByRole('textbox', { name: 'Host filter' }), { target: { value: 'WS-' } })
      await waitFor(() => {
        expect(lastListParams()?.tactic).toBe('Execution')
        expect(lastListParams()?.host).toBe('WS-')
      })
    })

    it('returns to page 1 when a filter changes', async () => {
      listMock.mockResolvedValue(pageOf(DETECTIONS, { total: 60, total_pages: 3 }))
      await renderLoaded()
      fireEvent.click(screen.getByRole('button', { name: 'Next page' }))
      await waitFor(() => expect(lastListParams()?.page).toBe(2))

      fireEvent.click(screen.getByRole('button', { name: 'Low' }))
      await waitFor(() => expect(lastListParams()).toMatchObject({ page: 1, severity: ['low'] }))
    })
  })

  describe('sorting and paging', () => {
    it('sorts by a column, then flips the order on a second click', async () => {
      await renderLoaded()
      fireEvent.click(screen.getByRole('button', { name: 'Host' }))
      await waitFor(() => expect(lastListParams()).toMatchObject({ sort: 'host', order: 'desc' }))
      expect(screen.getByRole('columnheader', { name: 'Host' })).toHaveAttribute('aria-sort', 'descending')

      fireEvent.click(screen.getByRole('button', { name: 'Host' }))
      await waitFor(() => expect(lastListParams()).toMatchObject({ sort: 'host', order: 'asc' }))
    })

    it('moves between pages and disables the buttons at the ends', async () => {
      listMock.mockImplementation(async (params = {}) =>
        pageOf(DETECTIONS, { page: params.page ?? 1, total: 50, total_pages: 2 }),
      )
      await renderLoaded()
      expect(screen.getByRole('button', { name: 'Previous page' })).toBeDisabled()
      expect(screen.getByText('1–25 of 50')).toBeInTheDocument()

      fireEvent.click(screen.getByRole('button', { name: 'Next page' }))
      expect(await screen.findByText('Page 2 of 2')).toBeInTheDocument()
      expect(lastListParams()?.page).toBe(2)
      expect(screen.getByRole('button', { name: 'Next page' })).toBeDisabled()
    })

    it('changes the page size', async () => {
      await renderLoaded()
      await chooseOption('Rows per page', '50 per page')
      await waitFor(() => expect(lastListParams()).toMatchObject({ page_size: 50, page: 1 }))
    })
  })

  describe('detail panel', () => {
    it('opens the panel for the clicked row and closes it again', async () => {
      await renderLoaded()
      fireEvent.click(screen.getByText('Encoded PowerShell command'))
      expect(screen.getByTestId('detection-panel')).toHaveTextContent('Panel: Encoded PowerShell command')

      fireEvent.click(screen.getByRole('button', { name: 'Close panel' }))
      expect(screen.queryByTestId('detection-panel')).not.toBeInTheDocument()
    })

    it('does not open the panel when a row checkbox is clicked', async () => {
      await renderLoaded()
      fireEvent.click(screen.getByRole('checkbox', { name: 'Select Suspicious LSASS access' }))
      expect(screen.queryByTestId('detection-panel')).not.toBeInTheDocument()
    })
  })

  describe('bulk actions', () => {
    it('shows the toolbar with the number of selected rows', async () => {
      await renderLoaded()
      expect(screen.queryByRole('toolbar', { name: 'Bulk actions' })).not.toBeInTheDocument()

      fireEvent.click(screen.getByRole('checkbox', { name: 'Select Suspicious LSASS access' }))
      expect(within(screen.getByRole('toolbar', { name: 'Bulk actions' })).getByText('1 selected')).toBeInTheDocument()

      fireEvent.click(screen.getByRole('checkbox', { name: 'Select all on this page' }))
      expect(screen.getByText('3 selected')).toBeInTheDocument()

      fireEvent.click(screen.getByRole('button', { name: 'Clear selection' }))
      expect(screen.queryByRole('toolbar', { name: 'Bulk actions' })).not.toBeInTheDocument()
    })

    it('sends the selected IDs and the status after confirmation', async () => {
      bulkMock.mockResolvedValue({ updated: 2, not_found: [] })
      await renderLoaded()
      fireEvent.click(screen.getByRole('checkbox', { name: 'Select Suspicious LSASS access' }))
      fireEvent.click(screen.getByRole('checkbox', { name: 'Select Encoded PowerShell command' }))
      fireEvent.click(within(screen.getByRole('toolbar')).getByRole('button', { name: 'Resolve' }))

      const dialog = screen.getByRole('dialog')
      expect(within(dialog).getByText('Set 2 detections to resolved?')).toBeInTheDocument()
      expect(bulkMock).not.toHaveBeenCalled()

      fireEvent.click(within(dialog).getByRole('button', { name: 'Confirm' }))
      await waitFor(() =>
        expect(bulkMock).toHaveBeenCalledWith({ ids: ['det-001', 'det-002'], status: 'resolved' }),
      )
      await waitFor(() => expect(screen.queryByRole('toolbar')).not.toBeInTheDocument())
      expect(notifications()).toEqual([
        expect.objectContaining({ type: 'success', title: '2 detections set to resolved' }),
      ])
    })

    it('warns when some detections no longer exist', async () => {
      bulkMock.mockResolvedValue({ updated: 1, not_found: ['det-002'] })
      await renderLoaded()
      fireEvent.click(screen.getByRole('checkbox', { name: 'Select all on this page' }))
      fireEvent.click(within(screen.getByRole('toolbar')).getByRole('button', { name: 'False positive' }))
      fireEvent.click(screen.getByRole('button', { name: 'Confirm' }))

      await waitFor(() =>
        expect(notifications()).toEqual([
          expect.objectContaining({
            type: 'warning',
            title: '1 detection set to false positive',
            message: '1 detection no longer exist.',
          }),
        ]),
      )
    })

    it('does nothing when the confirmation is cancelled', async () => {
      await renderLoaded()
      fireEvent.click(screen.getByRole('checkbox', { name: 'Select Suspicious LSASS access' }))
      fireEvent.click(within(screen.getByRole('toolbar')).getByRole('button', { name: 'Investigate' }))
      fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))

      await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
      expect(bulkMock).not.toHaveBeenCalled()
      expect(screen.getByText('1 selected')).toBeInTheDocument()
    })

    it('reports a failed bulk update and keeps the selection', async () => {
      bulkMock.mockRejectedValue(new Error('Server error'))
      await renderLoaded()
      fireEvent.click(screen.getByRole('checkbox', { name: 'Select Suspicious LSASS access' }))
      fireEvent.click(within(screen.getByRole('toolbar')).getByRole('button', { name: 'Reopen' }))
      fireEvent.click(screen.getByRole('button', { name: 'Confirm' }))

      await waitFor(() =>
        expect(notifications()).toEqual([
          expect.objectContaining({ type: 'error', title: 'Bulk update failed', message: 'Server error' }),
        ]),
      )
      expect(screen.getByText('1 selected')).toBeInTheDocument()
    })

    it('hides selection for a viewer, who cannot change detections', async () => {
      useAuthStore.setState({ user: { email: 'viewer@mxtac.local', role: 'viewer' } })
      await renderLoaded()
      expect(screen.queryByRole('checkbox')).not.toBeInTheDocument()
    })
  })

  describe('create incident from selection', () => {
    it('creates an incident linked to the selected detections', async () => {
      createIncidentMock.mockResolvedValue(makeIncident())
      await renderLoaded()
      fireEvent.click(screen.getByRole('checkbox', { name: 'Select Encoded PowerShell command' }))
      fireEvent.click(screen.getByRole('checkbox', { name: 'Select New local admin account' }))
      fireEvent.click(screen.getByRole('button', { name: 'Create incident' }))

      const dialog = screen.getByRole('dialog')
      expect(within(dialog).getByText(/2 selected detections will be linked/)).toBeInTheDocument()
      const submit = within(dialog).getByRole('button', { name: 'Create incident' })
      expect(submit).toBeDisabled()

      fireEvent.change(within(dialog).getByLabelText('Title'), { target: { value: 'Credential theft' } })
      fireEvent.click(submit)

      // Severity defaults to the most severe selected detection.
      await waitFor(() =>
        expect(createIncidentMock).toHaveBeenCalledWith({
          title: 'Credential theft',
          severity: 'high',
          description: null,
          assigned_to: null,
          detection_ids: ['det-002', 'det-003'],
        }),
      )
      await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
      expect(screen.queryByRole('toolbar')).not.toBeInTheDocument()
      expect(notifications()).toEqual([
        expect.objectContaining({ type: 'success', title: 'Incident INC-42 created' }),
      ])
    })

    it('reports a failure and keeps the dialog open', async () => {
      createIncidentMock.mockRejectedValue(new Error('Detection not found'))
      await renderLoaded()
      fireEvent.click(screen.getByRole('checkbox', { name: 'Select Suspicious LSASS access' }))
      fireEvent.click(screen.getByRole('button', { name: 'Create incident' }))
      const dialog = screen.getByRole('dialog')
      fireEvent.change(within(dialog).getByLabelText('Title'), { target: { value: 'Test' } })
      fireEvent.click(within(dialog).getByRole('button', { name: 'Create incident' }))

      await waitFor(() =>
        expect(notifications()).toEqual([
          expect.objectContaining({
            type: 'error',
            title: 'Could not create the incident',
            message: 'Detection not found',
          }),
        ]),
      )
      expect(screen.getByRole('dialog')).toBeInTheDocument()
    })
  })

  describe('export', () => {
    it('exports with the current filters and sort, and downloads the file', async () => {
      const createObjectURL = vi.fn(() => 'blob:detections')
      const revokeObjectURL = vi.fn()
      vi.stubGlobal('URL', Object.assign(URL, { createObjectURL, revokeObjectURL }))
      const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
      const blob = new Blob(['id,name'], { type: 'text/csv' })
      exportMock.mockResolvedValue(blob)

      await renderLoaded()
      fireEvent.click(screen.getByRole('button', { name: 'Critical' }))
      fireEvent.click(screen.getByRole('button', { name: /export csv/i }))

      await waitFor(() => expect(createObjectURL).toHaveBeenCalledWith(blob))
      expect(exportMock).toHaveBeenCalledWith({
        severity: ['critical'],
        status: undefined,
        tactic: undefined,
        host: undefined,
        search: undefined,
        sort: 'time',
        order: 'desc',
      })
      expect(click).toHaveBeenCalledTimes(1)
      expect(revokeObjectURL).toHaveBeenCalledWith('blob:detections')
      click.mockRestore()
    })

    it('reports a failed export', async () => {
      exportMock.mockRejectedValue(new Error('Forbidden'))
      await renderLoaded()
      fireEvent.click(screen.getByRole('button', { name: /export csv/i }))
      await waitFor(() =>
        expect(notifications()).toEqual([
          expect.objectContaining({ type: 'error', title: 'Export failed', message: 'Forbidden' }),
        ]),
      )
    })
  })

  describe('live alerts', () => {
    it('marks a row that has just arrived over the alert stream', async () => {
      await renderLoaded()
      expect(screen.queryByText('LIVE')).not.toBeInTheDocument()

      act(() => {
        useDetectionStore.getState().addLiveAlert(DETECTIONS[1])
      })
      const row = screen.getByText('Encoded PowerShell command').closest('tr')
      expect(row).not.toBeNull()
      expect(within(row as HTMLElement).getByText('LIVE')).toBeInTheDocument()
    })

    it('announces new live alerts and reloads the list on request', async () => {
      await renderLoaded()
      expect(screen.queryByRole('status')).not.toBeInTheDocument()

      act(() => {
        useDetectionStore.getState().addLiveAlert(makeDetection({ id: 'det-live-1' }))
        useDetectionStore.getState().addLiveAlert(makeDetection({ id: 'det-live-2' }))
      })
      expect(screen.getByRole('status')).toHaveTextContent('2 new live alerts since the list was loaded')

      const callsBefore = listMock.mock.calls.length
      fireEvent.click(screen.getByRole('button', { name: 'Show' }))
      await waitFor(() => expect(listMock.mock.calls.length).toBeGreaterThan(callsBefore))
      expect(screen.queryByRole('status')).not.toBeInTheDocument()
    })

    it('clears the unread counter while the page is open', async () => {
      useDetectionStore.setState({ unreadCount: 4 })
      await renderLoaded()
      expect(useDetectionStore.getState().unreadCount).toBe(0)

      act(() => {
        useDetectionStore.getState().addLiveAlert(makeDetection({ id: 'det-live-3' }))
      })
      await waitFor(() => expect(useDetectionStore.getState().unreadCount).toBe(0))
    })
  })
})
