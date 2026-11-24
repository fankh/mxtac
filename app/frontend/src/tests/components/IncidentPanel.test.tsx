// vi.mock is hoisted before imports — declare all module mocks first.

vi.mock('../../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof ApiModule>()),
  authApi: {},
  incidentsApi: {
    get: vi.fn(),
    update: vi.fn(),
    addNote: vi.fn(),
  },
}))

import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { IncidentPanel } from '../../components/features/incidents/IncidentPanel'
import type * as ApiModule from '../../lib/api'
import { incidentsApi } from '../../lib/api'
import { useAuthStore } from '../../stores/authStore'
import { useUIStore } from '../../stores/uiStore'
import type { Detection, Incident, IncidentDetail, IncidentNote } from '../../types/api'
import { chooseOption, openSelect } from '../mocks/radixSelect'

const getMock = vi.mocked(incidentsApi.get)
const updateMock = vi.mocked(incidentsApi.update)
const addNoteMock = vi.mocked(incidentsApi.addNote)

function makeIncident(overrides: Partial<Incident> = {}): Incident {
  return {
    id: 101,
    title: 'Credential theft on the domain controller',
    description: 'LSASS dump followed by lateral movement.',
    severity: 'high',
    status: 'investigating',
    priority: 2,
    assigned_to: 'kim@mxtac.local',
    created_by: 'analyst@mxtac.local',
    detection_ids: ['det-001', 'det-002', 'det-gone'],
    technique_ids: ['T1003.001', 'T1021.002'],
    tactic_ids: ['TA0006'],
    hosts: ['WIN-DC01', 'WS-114'],
    ttd_seconds: 120,
    ttr_seconds: null,
    closed_at: null,
    created_at: '2026-02-19T09:00:00Z',
    updated_at: '2026-02-19T09:30:00Z',
    ...overrides,
  }
}

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
    related_technique_ids: [],
    ...overrides,
  }
}

const NOTES: IncidentNote[] = [
  {
    id: 'note-2',
    author: 'kim@mxtac.local',
    content: 'Memory image collected from WIN-DC01.',
    note_type: 'evidence',
    created_at: '2026-02-19T10:00:00+00:00',
  },
  {
    id: 'note-1',
    author: 'analyst@mxtac.local',
    content: 'Status changed from new to investigating by analyst@mxtac.local',
    note_type: 'status_change',
    created_at: '2026-02-19T09:10:00+00:00',
  },
]

function makeDetail(overrides: Partial<IncidentDetail> = {}): IncidentDetail {
  return {
    ...makeIncident(),
    detections: [
      makeDetection(),
      makeDetection({ id: 'det-002', name: 'SMB admin share access', host: 'WS-114', status: 'investigating' }),
    ],
    notes: NOTES,
    duration_seconds: 5400,
    ...overrides,
  }
}

function renderPanel(incident: Incident | null = makeIncident(), onClose: () => void = vi.fn()) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const invalidate = vi.spyOn(client, 'invalidateQueries')
  const view = render(
    <QueryClientProvider client={client}>
      <IncidentPanel incident={incident} onClose={onClose} />
    </QueryClientProvider>,
  )
  return { ...view, invalidate, onClose }
}

/** Renders the panel and waits until the detail request has filled the tabs. */
async function renderLoaded(incident: Incident = makeIncident()) {
  const view = renderPanel(incident)
  await screen.findByRole('tab', { name: 'Timeline (2)' })
  return view
}

function notifications() {
  return useUIStore.getState().notifications
}

beforeEach(() => {
  vi.clearAllMocks()
  getMock.mockResolvedValue(makeDetail())
  useAuthStore.setState({ user: { email: 'analyst@mxtac.local', role: 'analyst' } })
  useUIStore.setState({ notifications: [] })
})

describe('IncidentPanel', () => {
  describe('content', () => {
    it('renders nothing while no incident is selected', () => {
      renderPanel(null)
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
      expect(getMock).not.toHaveBeenCalled()
    })

    it('names the techniques of the incident next to their IDs', async () => {
      await renderLoaded()
      const dialog = screen.getByRole('dialog')
      // From GET /attack/techniques (MSW handler in tests/mocks/handlers.ts)
      expect(await within(dialog).findByText('OS Credential Dumping: LSASS Memory')).toBeInTheDocument()
      expect(within(dialog).getByText('Remote Services: SMB/Windows Admin Shares')).toBeInTheDocument()
      expect(within(dialog).getByText('T1021.002')).toBeInTheDocument()
    })

    it('shows the incident as a labelled side panel and loads its detail', async () => {
      await renderLoaded()
      const dialog = screen.getByRole('dialog', { name: 'Credential theft on the domain controller' })
      expect(dialog).toHaveTextContent('INC-101')
      expect(dialog).toHaveTextContent('Opened by analyst@mxtac.local')
      expect(getMock).toHaveBeenCalledWith(101)
    })

    it('lists the detail fields', async () => {
      await renderLoaded()
      const panel = screen.getByRole('tabpanel')
      expect(panel).toHaveTextContent('LSASS dump followed by lateral movement.')
      expect(panel).toHaveTextContent('kim@mxtac.local')
      expect(panel).toHaveTextContent('P2')
      expect(within(panel).getByText('WIN-DC01')).toBeInTheDocument()
      expect(within(panel).getByText('T1021.002')).toBeInTheDocument()
      // The tactic is shown by name; the ID stays available as a tooltip.
      expect(within(panel).getByText('Credential Access')).toHaveAttribute('title', 'TA0006')
      expect(within(panel).queryByText('TA0006')).not.toBeInTheDocument()
      expect(within(panel).getByText('Open for').nextElementSibling).toHaveTextContent('1.5 h')
      expect(within(panel).getByText('Time to detect').nextElementSibling).toHaveTextContent('2 min')
      expect(within(panel).getByText('Time to resolve').nextElementSibling).toHaveTextContent('—')
    })

    it('calls onClose from the close button', async () => {
      const { onClose } = await renderLoaded()
      fireEvent.click(screen.getByRole('button', { name: 'Close' }))
      expect(onClose).toHaveBeenCalledTimes(1)
    })

    it('shows an error with a retry when the detail request fails', async () => {
      getMock.mockRejectedValueOnce(new Error('Incident 101 not found'))
      renderPanel()
      fireEvent.click(screen.getByRole('tab', { name: 'Timeline' }))
      const alert = await screen.findByRole('alert')
      expect(alert).toHaveTextContent('Could not load the incident detail')
      expect(alert).toHaveTextContent('Incident 101 not found')

      fireEvent.click(within(alert).getByRole('button', { name: /retry/i }))
      expect(await screen.findByText('Memory image collected from WIN-DC01.')).toBeInTheDocument()
    })
  })

  describe('status and severity', () => {
    it('offers only the current status and later ones', async () => {
      await renderLoaded()
      expect(await openSelect('Incident status')).toEqual(['Investigating', 'Contained', 'Resolved', 'Closed'])
    })

    it('moves the incident forward and refreshes the lists', async () => {
      updateMock.mockResolvedValue(makeIncident({ status: 'contained' }))
      const { invalidate } = await renderLoaded()
      await chooseOption('Incident status', 'Contained')

      await waitFor(() => expect(updateMock).toHaveBeenCalledWith(101, { status: 'contained' }))
      await waitFor(() =>
        expect(notifications()).toEqual([
          expect.objectContaining({ type: 'success', title: 'Incident INC-101 updated' }),
        ]),
      )
      expect(invalidate).toHaveBeenCalledWith({ queryKey: ['incidents'] })
      expect(invalidate).toHaveBeenCalledWith({ queryKey: ['incident-metrics'] })
      expect(invalidate).toHaveBeenCalledWith({ queryKey: ['incident-detail', 101] })
    })

    it('does not send an update when the same status is chosen', async () => {
      await renderLoaded()
      await chooseOption('Incident status', 'Investigating')
      expect(updateMock).not.toHaveBeenCalled()
    })

    it('locks the status of a closed incident', async () => {
      getMock.mockResolvedValue(makeDetail({ status: 'closed' }))
      await renderLoaded(makeIncident({ status: 'closed' }))
      expect(screen.getByRole('combobox', { name: 'Incident status' })).toBeDisabled()
    })

    it('changes the severity', async () => {
      updateMock.mockResolvedValue(makeIncident({ severity: 'critical' }))
      await renderLoaded()
      await chooseOption('Incident severity', 'Critical')
      await waitFor(() => expect(updateMock).toHaveBeenCalledWith(101, { severity: 'critical' }))
    })

    it('reports a rejected update', async () => {
      updateMock.mockRejectedValue(new Error('Invalid status transition'))
      await renderLoaded()
      await chooseOption('Incident status', 'Resolved')
      await waitFor(() =>
        expect(notifications()).toEqual([
          expect.objectContaining({
            type: 'error',
            title: 'Could not update the incident',
            message: 'Invalid status transition',
          }),
        ]),
      )
    })
  })

  describe('assignee', () => {
    it('assigns the incident to a new email address', async () => {
      updateMock.mockResolvedValue(makeIncident({ assigned_to: 'lee@mxtac.local' }))
      await renderLoaded()
      const input = screen.getByLabelText('Assignee email')
      const assign = screen.getByRole('button', { name: 'Assign' })
      expect(input).toHaveValue('kim@mxtac.local')
      expect(assign).toBeDisabled()

      fireEvent.change(input, { target: { value: 'lee@mxtac.local' } })
      fireEvent.click(assign)
      await waitFor(() => expect(updateMock).toHaveBeenCalledWith(101, { assigned_to: 'lee@mxtac.local' }))
    })

    it('rejects a value that is not an email address', async () => {
      await renderLoaded()
      fireEvent.change(screen.getByLabelText('Assignee email'), { target: { value: 'lee' } })
      expect(screen.getByRole('button', { name: 'Assign' })).toBeDisabled()
      expect(screen.getByText('Enter a valid email address.')).toBeInTheDocument()
    })

    it('unassigns by sending null', async () => {
      updateMock.mockResolvedValue(makeIncident({ assigned_to: null }))
      await renderLoaded()
      fireEvent.click(screen.getByRole('button', { name: 'Unassign' }))
      await waitFor(() => expect(updateMock).toHaveBeenCalledWith(101, { assigned_to: null }))
      await waitFor(() => expect(screen.getByLabelText('Assignee email')).toHaveValue(''))
    })

    it('has no Unassign button when nobody is assigned', async () => {
      getMock.mockResolvedValue(makeDetail({ assigned_to: null }))
      await renderLoaded(makeIncident({ assigned_to: null }))
      expect(screen.queryByRole('button', { name: 'Unassign' })).not.toBeInTheDocument()
    })
  })

  describe('timeline', () => {
    async function openTimeline() {
      const view = await renderLoaded()
      fireEvent.click(screen.getByRole('tab', { name: 'Timeline (2)' }))
      return view
    }

    it('lists the notes oldest first with author and type', async () => {
      await openTimeline()
      const items = within(screen.getByRole('tabpanel')).getAllByRole('listitem')
      expect(items).toHaveLength(2)
      expect(items[0]).toHaveTextContent('Status changed from new to investigating')
      expect(items[0]).toHaveTextContent('Status change')
      expect(items[1]).toHaveTextContent('Memory image collected from WIN-DC01.')
      expect(items[1]).toHaveTextContent('kim@mxtac.local')
      expect(items[1]).toHaveTextContent('Evidence')
    })

    it('adds a comment and clears the draft', async () => {
      addNoteMock.mockResolvedValue({
        id: 'note-3',
        author: 'analyst@mxtac.local',
        content: 'Password reset requested.',
        note_type: 'comment',
        created_at: '2026-02-19T11:00:00+00:00',
      })
      const { invalidate } = await openTimeline()
      const draft = screen.getByRole('textbox', { name: 'New note' })
      const add = screen.getByRole('button', { name: 'Add note' })
      expect(add).toBeDisabled()

      fireEvent.change(draft, { target: { value: '  Password reset requested. ' } })
      fireEvent.click(add)

      await waitFor(() => expect(addNoteMock).toHaveBeenCalledWith(101, 'Password reset requested.', 'comment'))
      await waitFor(() => expect(draft).toHaveValue(''))
      expect(invalidate).toHaveBeenCalledWith({ queryKey: ['incident-detail', 101] })
    })

    it('adds a note marked as evidence', async () => {
      addNoteMock.mockResolvedValue({ ...NOTES[0], id: 'note-4' })
      await openTimeline()
      fireEvent.change(screen.getByRole('textbox', { name: 'New note' }), { target: { value: 'pcap attached' } })
      await chooseOption('Note type', 'Evidence')
      fireEvent.click(screen.getByRole('button', { name: 'Add note' }))
      await waitFor(() => expect(addNoteMock).toHaveBeenCalledWith(101, 'pcap attached', 'evidence'))
    })

    it('reports a failed note and keeps the draft', async () => {
      addNoteMock.mockRejectedValue(new Error('Server error'))
      await openTimeline()
      const draft = screen.getByRole('textbox', { name: 'New note' })
      fireEvent.change(draft, { target: { value: 'Keep me' } })
      fireEvent.click(screen.getByRole('button', { name: 'Add note' }))

      await waitFor(() =>
        expect(notifications()).toEqual([
          expect.objectContaining({ type: 'error', title: 'Could not add the note', message: 'Server error' }),
        ]),
      )
      expect(draft).toHaveValue('Keep me')
    })

    it('shows an empty state when there are no notes', async () => {
      getMock.mockResolvedValue(makeDetail({ notes: [] }))
      renderPanel()
      fireEvent.click(await screen.findByRole('tab', { name: 'Timeline (0)' }))
      expect(screen.getByText('No notes yet')).toBeInTheDocument()
    })
  })

  describe('linked detections', () => {
    it('lists the linked detections and counts deleted ones', async () => {
      await renderLoaded()
      fireEvent.click(screen.getByRole('tab', { name: 'Detections (2)' }))
      const panel = screen.getByRole('tabpanel')
      expect(within(panel).getByText('Suspicious LSASS access')).toBeInTheDocument()
      expect(within(panel).getByText('SMB admin share access')).toBeInTheDocument()
      expect(panel).toHaveTextContent('1 linked detection has been deleted.')
    })

    it('shows an empty state when nothing is linked', async () => {
      getMock.mockResolvedValue(makeDetail({ detection_ids: [], detections: [] }))
      await renderLoaded(makeIncident({ detection_ids: [] }))
      fireEvent.click(screen.getByRole('tab', { name: 'Detections (0)' }))
      expect(screen.getByText('No linked detections')).toBeInTheDocument()
    })
  })

  describe('read-only roles', () => {
    it('hides every control that changes the incident for a viewer', async () => {
      useAuthStore.setState({ user: { email: 'viewer@mxtac.local', role: 'viewer' } })
      await renderLoaded()
      expect(screen.queryByRole('combobox')).not.toBeInTheDocument()
      expect(screen.queryByRole('button', { name: 'Assign' })).not.toBeInTheDocument()

      fireEvent.click(screen.getByRole('tab', { name: 'Timeline (2)' }))
      expect(screen.getByText('Memory image collected from WIN-DC01.')).toBeInTheDocument()
      expect(screen.queryByRole('textbox', { name: 'New note' })).not.toBeInTheDocument()
    })
  })
})
