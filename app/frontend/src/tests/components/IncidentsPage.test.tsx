// vi.mock is hoisted before imports — declare all module mocks first.

vi.mock('../../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof ApiModule>()),
  authApi: {},
  incidentsApi: {
    list: vi.fn(),
    metrics: vi.fn(),
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

vi.mock('../../components/features/incidents/IncidentPanel', () => ({
  IncidentPanel: ({ incident, onClose }: { incident: Incident | null; onClose: () => void }) =>
    incident ? (
      <div data-testid="incident-panel">
        <span>Panel: {incident.title}</span>
        <button onClick={onClose}>Close panel</button>
      </div>
    ) : null,
}))

import type { ReactNode } from 'react'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { IncidentsPage } from '../../components/features/incidents/IncidentsPage'
import type * as ApiModule from '../../lib/api'
import { incidentsApi } from '../../lib/api'
import { useAuthStore } from '../../stores/authStore'
import { useUIStore } from '../../stores/uiStore'
import type { Incident, IncidentMetrics, PaginatedResponse } from '../../types/api'
import { chooseOption } from '../mocks/radixSelect'

const listMock = vi.mocked(incidentsApi.list)
const metricsMock = vi.mocked(incidentsApi.metrics)
const createMock = vi.mocked(incidentsApi.create)

function makeIncident(overrides: Partial<Incident> = {}): Incident {
  return {
    id: 101,
    title: 'Credential theft on the domain controller',
    description: 'LSASS dump followed by lateral movement.',
    severity: 'critical',
    status: 'new',
    priority: 2,
    assigned_to: 'kim@mxtac.local',
    created_by: 'analyst@mxtac.local',
    detection_ids: ['det-001', 'det-002'],
    technique_ids: ['T1003.001'],
    tactic_ids: ['TA0006'],
    hosts: ['WIN-DC01', 'WS-114', 'SRV-FILE02'],
    ttd_seconds: 120,
    ttr_seconds: null,
    closed_at: null,
    created_at: '2026-02-19T09:00:00Z',
    updated_at: '2026-02-19T09:30:00Z',
    ...overrides,
  }
}

const INCIDENTS: Incident[] = [
  makeIncident(),
  makeIncident({
    id: 102,
    title: 'Phishing campaign against finance',
    severity: 'high',
    status: 'investigating',
    assigned_to: null,
    hosts: [],
    tactic_ids: [],
    detection_ids: [],
  }),
]

const METRICS: IncidentMetrics = {
  total_incidents: { new: 3, investigating: 2, contained: 1, resolved: 4, closed: 5 },
  mttr_seconds: 7200,
  mttd_seconds: 300,
  open_incidents_count: 6,
  incidents_by_severity: { critical: 2, high: 5, medium: 6, low: 2 },
  incidents_this_week: 4,
  incidents_this_month: 11,
  from_date: '2026-01-20T00:00:00Z',
  to_date: '2026-02-19T00:00:00Z',
}

function pageOf(items: Incident[], pagination: Partial<PaginatedResponse<Incident>['pagination']> = {}) {
  return {
    items,
    pagination: { page: 1, page_size: 20, total: items.length, total_pages: 1, ...pagination },
  }
}

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <IncidentsPage />
    </QueryClientProvider>,
  )
}

async function renderLoaded() {
  const view = renderPage()
  await screen.findByText('Credential theft on the domain controller')
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
  listMock.mockResolvedValue(pageOf(INCIDENTS))
  metricsMock.mockResolvedValue(METRICS)
  useAuthStore.setState({ user: { email: 'analyst@mxtac.local', role: 'analyst' } })
  useUIStore.setState({ notifications: [] })
})

describe('IncidentsPage', () => {
  describe('metrics', () => {
    it('shows the figures from the metrics endpoint', async () => {
      renderPage()
      const open = (await screen.findByText('Open incidents')).parentElement as HTMLElement
      expect(open).toHaveTextContent('6')
      expect(open).toHaveTextContent('15 in the last 30 days: 2 critical · 5 high · 6 medium · 2 low')

      const week = screen.getByText('New this week').parentElement as HTMLElement
      expect(week).toHaveTextContent('4')
      expect(week).toHaveTextContent('11 this month')

      expect(screen.getByText('Mean time to resolve').parentElement).toHaveTextContent('2.0 h')
      const mttd = screen.getByText('Mean time to detect').parentElement as HTMLElement
      expect(mttd).toHaveTextContent('5 min')
      expect(mttd).toHaveTextContent('First event to incident, last 30 days')
    })

    it('explains a missing time to detect and leaves out severities without incidents', async () => {
      metricsMock.mockResolvedValue({
        ...METRICS, mttd_seconds: null, incidents_by_severity: { critical: 0, high: 13, medium: 0, low: 0 },
      })
      renderPage()
      const mttd = (await screen.findByText('Mean time to detect')).parentElement as HTMLElement
      expect(mttd).toHaveTextContent('—')
      expect(mttd).toHaveTextContent('No incidents with linked detections in range')
      const open = screen.getByText('Open incidents').parentElement as HTMLElement
      expect(open).toHaveTextContent('15 in the last 30 days: 13 high')
      expect(open).not.toHaveTextContent('0 critical')
    })

    it('shows the tactic of an incident by name', async () => {
      renderPage()
      const first = (await screen.findAllByRole('row'))[1]
      expect(first).toHaveTextContent('Credential Access')
      expect(first).not.toHaveTextContent('TA0006')
    })

    it('shows a dash when there is no resolve time yet', async () => {
      metricsMock.mockResolvedValue({ ...METRICS, mttr_seconds: null })
      renderPage()
      const mttr = (await screen.findByText('Mean time to resolve')).parentElement as HTMLElement
      expect(mttr).toHaveTextContent('—')
      expect(mttr).toHaveTextContent('No closed incidents in range')
    })

    it('shows an error with a retry when the metrics fail, and keeps the list', async () => {
      metricsMock.mockRejectedValueOnce(new Error('Metrics unavailable'))
      await renderLoaded()
      const alert = await screen.findByRole('alert')
      expect(alert).toHaveTextContent('Could not load incident metrics')
      expect(alert).toHaveTextContent('Metrics unavailable')

      fireEvent.click(within(alert).getByRole('button', { name: /retry/i }))
      expect(await screen.findByText('Open incidents')).toBeInTheDocument()
    })
  })

  describe('list', () => {
    it('shows one row per incident', async () => {
      await renderLoaded()
      expect(screen.getByRole('heading', { name: 'Incidents' })).toBeInTheDocument()

      const first = screen.getByText('INC-101').closest('tr') as HTMLElement
      expect(first).toHaveTextContent('Credential theft on the domain controller')
      expect(first).toHaveTextContent('Critical')
      expect(first).toHaveTextContent('New')
      expect(first).toHaveTextContent('kim@mxtac.local')
      expect(first).toHaveTextContent('WIN-DC01, WS-114 +1')

      const second = screen.getByText('INC-102').closest('tr') as HTMLElement
      expect(second).toHaveTextContent('Investigating')
      expect(second).toHaveTextContent('Unassigned')
    })

    it('requests the first page, newest first, with no filters', async () => {
      await renderLoaded()
      expect(lastListParams()).toEqual({
        severity: undefined,
        status: undefined,
        assigned_to: undefined,
        search: undefined,
        sort: 'created_at',
        page: 1,
        page_size: 20,
      })
    })

    it('shows a loading placeholder until the first response', () => {
      listMock.mockReturnValue(new Promise(() => {}))
      renderPage()
      expect(screen.getByLabelText('Loading incidents')).toBeInTheDocument()
    })

    it('shows an error card and retries on request', async () => {
      listMock.mockRejectedValueOnce(new Error('Network down'))
      renderPage()
      const title = await screen.findByText('Could not load incidents')
      const alert = title.closest('[role="alert"]') as HTMLElement
      expect(alert).toHaveTextContent('Network down')

      fireEvent.click(within(alert).getByRole('button', { name: /retry/i }))
      expect(await screen.findByText('INC-101')).toBeInTheDocument()
    })

    it('shows an empty state when there are no incidents', async () => {
      listMock.mockResolvedValue(pageOf([]))
      renderPage()
      expect(await screen.findByText('No incidents yet')).toBeInTheDocument()
    })

    it('moves to the next page', async () => {
      listMock.mockImplementation(async (params = {}) =>
        pageOf(INCIDENTS, { page: params.page ?? 1, total: 40, total_pages: 2 }),
      )
      await renderLoaded()
      fireEvent.click(screen.getByRole('button', { name: 'Next page' }))
      expect(await screen.findByText('Page 2 of 2')).toBeInTheDocument()
      expect(lastListParams()?.page).toBe(2)
    })
  })

  describe('filters', () => {
    it('sends severities and statuses as lists', async () => {
      await renderLoaded()
      fireEvent.click(within(screen.getByRole('group', { name: 'Severity' })).getByRole('button', { name: 'High' }))
      const statusGroup = screen.getByRole('group', { name: 'Status' })
      fireEvent.click(within(statusGroup).getByRole('button', { name: 'New' }))
      fireEvent.click(within(statusGroup).getByRole('button', { name: 'Contained' }))

      await waitFor(() =>
        expect(lastListParams()).toMatchObject({ severity: ['high'], status: ['new', 'contained'], page: 1 }),
      )
    })

    it('sends the search text and clears it on Escape', async () => {
      await renderLoaded()
      const input = screen.getByRole('textbox', { name: 'Search incidents' })
      fireEvent.change(input, { target: { value: 'phishing' } })
      await waitFor(() => expect(lastListParams()?.search).toBe('phishing'))

      fireEvent.keyDown(input, { key: 'Escape' })
      expect(input).toHaveValue('')
      await waitFor(() => expect(lastListParams()?.search).toBeUndefined())
    })

    it('filters by assignee, with a shortcut for the signed-in user', async () => {
      await renderLoaded()
      fireEvent.change(screen.getByRole('textbox', { name: 'Assignee filter' }), {
        target: { value: 'kim@mxtac.local' },
      })
      await waitFor(() => expect(lastListParams()?.assigned_to).toBe('kim@mxtac.local'))

      const mine = screen.getByRole('button', { name: 'Assigned to me' })
      fireEvent.click(mine)
      await waitFor(() => expect(lastListParams()?.assigned_to).toBe('analyst@mxtac.local'))
      expect(mine).toHaveAttribute('aria-pressed', 'true')

      fireEvent.click(mine)
      await waitFor(() => expect(lastListParams()?.assigned_to).toBeUndefined())
    })

    it('changes the sort field', async () => {
      await renderLoaded()
      await chooseOption('Sort incidents', 'Sort: severity')
      await waitFor(() => expect(lastListParams()?.sort).toBe('severity'))
    })

    it('clears every filter at once', async () => {
      listMock.mockResolvedValue(pageOf([]))
      renderPage()
      await screen.findByText('No incidents yet')
      fireEvent.click(screen.getByRole('button', { name: 'Low' }))
      fireEvent.click(screen.getByRole('button', { name: 'Closed' }))
      expect(await screen.findByText('No incidents match the filters')).toBeInTheDocument()

      fireEvent.click(screen.getByRole('button', { name: 'Clear filters (2)' }))
      await waitFor(() => expect(lastListParams()).toMatchObject({ severity: undefined, status: undefined }))
    })
  })

  describe('detail panel', () => {
    it('opens the panel for the clicked incident and closes it again', async () => {
      await renderLoaded()
      fireEvent.click(screen.getByText('Phishing campaign against finance'))
      expect(screen.getByTestId('incident-panel')).toHaveTextContent('Panel: Phishing campaign against finance')

      fireEvent.click(screen.getByRole('button', { name: 'Close panel' }))
      expect(screen.queryByTestId('incident-panel')).not.toBeInTheDocument()
    })
  })

  describe('create incident', () => {
    async function openDialog() {
      await renderLoaded()
      fireEvent.click(screen.getByRole('button', { name: /new incident/i }))
      return screen.getByRole('dialog', { name: 'Create incident' })
    }

    it('creates an incident from the form', async () => {
      createMock.mockResolvedValue(makeIncident({ id: 103, detection_ids: ['det-9', 'det-10'] }))
      const dialog = await openDialog()

      fireEvent.change(within(dialog).getByLabelText('Title'), { target: { value: ' Ransomware precursor ' } })
      await chooseOption('Incident severity', 'Critical')
      fireEvent.change(within(dialog).getByLabelText('Description'), { target: { value: 'Shadow copies deleted.' } })
      fireEvent.change(within(dialog).getByLabelText('Assignee email'), { target: { value: 'lee@mxtac.local' } })
      fireEvent.change(within(dialog).getByLabelText('Detection IDs'), { target: { value: 'det-9, det-10 det-9' } })
      fireEvent.click(within(dialog).getByRole('button', { name: 'Create incident' }))

      await waitFor(() =>
        expect(createMock).toHaveBeenCalledWith({
          title: 'Ransomware precursor',
          severity: 'critical',
          description: 'Shadow copies deleted.',
          assigned_to: 'lee@mxtac.local',
          detection_ids: ['det-9', 'det-10'],
        }),
      )
      await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
      expect(notifications()).toEqual([
        expect.objectContaining({
          type: 'success',
          title: 'Incident INC-103 created',
          message: '2 detections linked.',
        }),
      ])
    })

    it('sends null for the optional fields left empty', async () => {
      createMock.mockResolvedValue(makeIncident({ detection_ids: [] }))
      const dialog = await openDialog()
      fireEvent.change(within(dialog).getByLabelText('Title'), { target: { value: 'Minimal' } })
      fireEvent.click(within(dialog).getByRole('button', { name: 'Create incident' }))

      await waitFor(() =>
        expect(createMock).toHaveBeenCalledWith({
          title: 'Minimal',
          severity: 'medium',
          description: null,
          assigned_to: null,
          detection_ids: [],
        }),
      )
    })

    it('requires a title and a valid assignee email', async () => {
      const dialog = await openDialog()
      const submit = within(dialog).getByRole('button', { name: 'Create incident' })
      expect(submit).toBeDisabled()

      fireEvent.change(within(dialog).getByLabelText('Title'), { target: { value: 'Has a title' } })
      expect(submit).toBeEnabled()

      fireEvent.change(within(dialog).getByLabelText('Assignee email'), { target: { value: 'not-an-email' } })
      expect(submit).toBeDisabled()
      expect(within(dialog).getByText('Enter a valid email address.')).toBeInTheDocument()
      expect(createMock).not.toHaveBeenCalled()
    })

    it('reports a failure and keeps the form open', async () => {
      createMock.mockRejectedValue(new Error("Detection 'det-x' not found"))
      const dialog = await openDialog()
      fireEvent.change(within(dialog).getByLabelText('Title'), { target: { value: 'Broken link' } })
      fireEvent.click(within(dialog).getByRole('button', { name: 'Create incident' }))

      await waitFor(() =>
        expect(notifications()).toEqual([
          expect.objectContaining({
            type: 'error',
            title: 'Could not create the incident',
            message: "Detection 'det-x' not found",
          }),
        ]),
      )
      expect(screen.getByRole('dialog')).toBeInTheDocument()
      expect(within(dialog).getByLabelText('Title')).toHaveValue('Broken link')
    })

    it('closes without saving on Cancel', async () => {
      const dialog = await openDialog()
      fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }))
      await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
      expect(createMock).not.toHaveBeenCalled()
    })

    it('is not offered to a viewer', async () => {
      useAuthStore.setState({ user: { email: 'viewer@mxtac.local', role: 'viewer' } })
      await renderLoaded()
      expect(screen.queryByRole('button', { name: /new incident/i })).not.toBeInTheDocument()
    })
  })
})
