// vi.mock is hoisted before imports — declare all module mocks first.

vi.mock('../../lib/api', () => ({
  incidentsApi: {
    get:     vi.fn(),
    update:  vi.fn(),
    addNote: vi.fn(),
  },
}))

import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { IncidentPanel } from '../../components/features/incidents/IncidentPanel'
import { incidentsApi } from '../../lib/api'
import type { Incident, Detection } from '../../types/api'

// ---------------------------------------------------------------------------
// Typed mock references
// ---------------------------------------------------------------------------

const mockApi = incidentsApi as {
  get:     ReturnType<typeof vi.fn>
  update:  ReturnType<typeof vi.fn>
  addNote: ReturnType<typeof vi.fn>
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const makeIncident = (overrides: Partial<Incident> = {}): Incident => ({
  id: 42,
  title: 'Lateral Movement via Pass-the-Hash',
  description: null,
  severity: 'high',
  status: 'new',
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
  updated_at: '2026-02-19T09:00:00Z',
  ...overrides,
})

const makeDetection = (overrides: Partial<Detection> = {}): Detection => ({
  id: 'det-001',
  score: 8.5,
  severity: 'high',
  technique_id: 'T1550.002',
  technique_name: 'Pass-the-Hash',
  tactic: 'Lateral Movement',
  name: 'Suspicious NTLM Authentication',
  host: 'WIN-DC01',
  status: 'active',
  time: '2026-02-19T08:00:00Z',
  related_technique_ids: [],
  ...overrides,
})

const makeDetail = (
  incidentOverrides: Partial<Incident> = {},
  detections: Detection[] = [],
  notes: object[] = [],
) => ({
  ...makeIncident(incidentOverrides),
  detections,
  notes,
  duration_seconds: 1800,
})

// ---------------------------------------------------------------------------
// Render helper
// ---------------------------------------------------------------------------

function renderPanel(
  incident: Incident | null,
  {
    onClose = vi.fn(),
    onDetectionClick,
  }: {
    onClose?: () => void
    onDetectionClick?: (d: Detection) => void
  } = {},
) {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries:   { retry: false },
      mutations: { retry: false },
    },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <IncidentPanel
        incident={incident}
        onClose={onClose}
        onDetectionClick={onDetectionClick}
      />
    </QueryClientProvider>,
  )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('IncidentPanel', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockApi.get.mockResolvedValue(makeDetail())
    mockApi.update.mockResolvedValue(makeIncident())
    mockApi.addNote.mockResolvedValue({
      id: 'note-1', content: 'test', author: 'analyst',
      note_type: 'comment', created_at: '2026-02-19T09:00:00Z',
    })
  })

  // =========================================================================
  // Null incident
  // =========================================================================
  describe('when incident is null', () => {
    it('renders nothing', () => {
      const { container } = renderPanel(null)
      expect(container).toBeEmptyDOMElement()
    })
  })

  // =========================================================================
  // Header
  // =========================================================================
  describe('header', () => {
    it('renders the panel with incident title', () => {
      renderPanel(makeIncident())
      expect(screen.getByText('Lateral Movement via Pass-the-Hash')).toBeInTheDocument()
    })

    it('renders INC-{id} in the header badge', () => {
      renderPanel(makeIncident({ id: 42 }))
      // INC-42 appears in both header badge and Details tab ID row — check it exists at least once
      expect(screen.getAllByText('INC-42').length).toBeGreaterThan(0)
    })

    it('shows "Unassigned" when assigned_to is null', () => {
      renderPanel(makeIncident({ assigned_to: null }))
      // Appears in header and in AssignedToField in Details tab
      expect(screen.getAllByText('Unassigned').length).toBeGreaterThan(0)
    })

    it('shows the assigned_to value when set', () => {
      renderPanel(makeIncident({ assigned_to: 'soc@mxtac.local' }))
      // Appears in header paragraph and AssignedToField in Details tab
      expect(screen.getAllByText('soc@mxtac.local').length).toBeGreaterThan(0)
    })

    it('shows "Assigned:" prefix label in header when assigned_to is set', () => {
      renderPanel(makeIncident({ assigned_to: 'soc@mxtac.local' }))
      // The header paragraph contains "Assigned: soc@mxtac.local"
      expect(screen.getByText(/^Assigned:/)).toBeInTheDocument()
    })

    it('renders the close button with title "Close"', () => {
      renderPanel(makeIncident())
      expect(screen.getByTitle('Close')).toBeInTheDocument()
    })

    it('calls onClose when the × button is clicked', () => {
      const onClose = vi.fn()
      renderPanel(makeIncident(), { onClose })
      fireEvent.click(screen.getByTitle('Close'))
      expect(onClose).toHaveBeenCalledOnce()
    })

    it('calls onClose when the backdrop is clicked', () => {
      const onClose = vi.fn()
      const { container } = renderPanel(makeIncident(), { onClose })
      const backdrop = container.querySelector('.fixed.inset-0')
      expect(backdrop).not.toBeNull()
      fireEvent.click(backdrop!)
      expect(onClose).toHaveBeenCalledOnce()
    })
  })

  // =========================================================================
  // Quick action bar — next-status button
  // =========================================================================
  describe('next status button', () => {
    it('shows the next status button for non-closed incidents', () => {
      renderPanel(makeIncident({ status: 'new' }))
      expect(screen.getByText('→ Investigating')).toBeInTheDocument()
    })

    it('shows "→ Contained" when status is investigating', () => {
      renderPanel(makeIncident({ status: 'investigating' }))
      expect(screen.getByText('→ Contained')).toBeInTheDocument()
    })

    it('does not show next-status button when status is closed', () => {
      renderPanel(makeIncident({ status: 'closed' }))
      expect(screen.queryByText(/^→ /)).not.toBeInTheDocument()
    })

    it('calls update with next status when next-status button is clicked', async () => {
      renderPanel(makeIncident({ status: 'new' }))
      fireEvent.click(screen.getByText('→ Investigating'))
      await waitFor(() =>
        expect(mockApi.update).toHaveBeenCalledWith(42, { status: 'investigating' }),
      )
    })
  })

  // =========================================================================
  // Status change dropdown
  // =========================================================================
  describe('Set Status dropdown', () => {
    it('renders the "Set Status ▾" button', () => {
      renderPanel(makeIncident())
      expect(screen.getByText('Set Status ▾')).toBeInTheDocument()
    })

    it('does not show status options by default', () => {
      renderPanel(makeIncident({ status: 'new' }))
      // Dropdown is closed — no duplicate status options visible
      expect(screen.queryByText('Contained')).not.toBeInTheDocument()
    })

    it('shows all status options when "Set Status ▾" is clicked', () => {
      renderPanel(makeIncident({ status: 'new' }))
      fireEvent.click(screen.getByText('Set Status ▾'))
      // Multiple Investigating badges: one in header, one in dropdown
      expect(screen.getAllByText('Investigating').length).toBeGreaterThan(0)
      expect(screen.getByText('Contained')).toBeInTheDocument()
      expect(screen.getByText('Resolved')).toBeInTheDocument()
    })

    it('shows a confirmation bar when a status is selected from dropdown', () => {
      renderPanel(makeIncident({ status: 'new' }))
      fireEvent.click(screen.getByText('Set Status ▾'))
      // Click "Contained" in the dropdown (not in header)
      const buttons = screen.getAllByText('Contained')
      fireEvent.click(buttons[0])
      expect(screen.getByTestId('status-confirm-bar')).toBeInTheDocument()
    })

    it('shows Confirm and Cancel buttons in the confirmation bar', () => {
      renderPanel(makeIncident({ status: 'new' }))
      fireEvent.click(screen.getByText('Set Status ▾'))
      const contained = screen.getAllByText('Contained')
      fireEvent.click(contained[0])
      const bar = screen.getByTestId('status-confirm-bar')
      expect(within(bar).getByRole('button', { name: 'Confirm' })).toBeInTheDocument()
      expect(within(bar).getByRole('button', { name: 'Cancel' })).toBeInTheDocument()
    })

    it('shows "Change to" text in the confirmation bar', () => {
      renderPanel(makeIncident({ status: 'new' }))
      fireEvent.click(screen.getByText('Set Status ▾'))
      fireEvent.click(screen.getAllByText('Contained')[0])
      const bar = screen.getByTestId('status-confirm-bar')
      expect(bar).toHaveTextContent(/Change to/)
    })

    it('calls update mutation when Confirm is clicked', async () => {
      renderPanel(makeIncident({ status: 'new' }))
      fireEvent.click(screen.getByText('Set Status ▾'))
      fireEvent.click(screen.getAllByText('Contained')[0])
      const bar = screen.getByTestId('status-confirm-bar')
      fireEvent.click(within(bar).getByRole('button', { name: 'Confirm' }))
      await waitFor(() =>
        expect(mockApi.update).toHaveBeenCalledWith(42, { status: 'contained' }),
      )
    })

    it('hides the confirmation bar when Cancel is clicked', () => {
      renderPanel(makeIncident({ status: 'new' }))
      fireEvent.click(screen.getByText('Set Status ▾'))
      fireEvent.click(screen.getAllByText('Contained')[0])
      expect(screen.getByTestId('status-confirm-bar')).toBeInTheDocument()
      fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
      expect(screen.queryByTestId('status-confirm-bar')).not.toBeInTheDocument()
    })

    it('does not call update when Cancel is clicked', async () => {
      renderPanel(makeIncident({ status: 'new' }))
      fireEvent.click(screen.getByText('Set Status ▾'))
      fireEvent.click(screen.getAllByText('Contained')[0])
      fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
      await new Promise(r => setTimeout(r, 50))
      expect(mockApi.update).not.toHaveBeenCalled()
    })
  })

  // =========================================================================
  // Metrics strip
  // =========================================================================
  describe('metrics strip', () => {
    function getMetrics() {
      return screen.getByTestId('metrics-strip')
    }

    it('renders the TTD label in the metrics strip', () => {
      renderPanel(makeIncident())
      expect(within(getMetrics()).getByText('TTD')).toBeInTheDocument()
    })

    it('renders the TTR label in the metrics strip', () => {
      renderPanel(makeIncident())
      expect(within(getMetrics()).getByText('TTR')).toBeInTheDocument()
    })

    it('renders the Time Open label', () => {
      renderPanel(makeIncident())
      expect(within(getMetrics()).getByText('Time Open')).toBeInTheDocument()
    })

    it('shows "—" for TTD in the metrics strip when ttd_seconds is null', () => {
      renderPanel(makeIncident({ ttd_seconds: null }))
      const ttdLabel = within(getMetrics()).getByText('TTD')
      expect(ttdLabel.nextElementSibling?.textContent).toBe('—')
    })

    it('shows formatted TTD in the metrics strip when ttd_seconds is set', () => {
      renderPanel(makeIncident({ ttd_seconds: 3600 }))
      expect(within(getMetrics()).getByText('1.0h')).toBeInTheDocument()
    })

    it('shows "Open" for TTR in the metrics strip when ttr_seconds is null', () => {
      renderPanel(makeIncident({ ttr_seconds: null }))
      const ttrLabel = within(getMetrics()).getByText('TTR')
      expect(ttrLabel.nextElementSibling?.textContent).toBe('Open')
    })

    it('shows formatted TTR in the metrics strip when ttr_seconds is set', () => {
      renderPanel(makeIncident({ ttr_seconds: 7200 }))
      expect(within(getMetrics()).getByText('2.0h')).toBeInTheDocument()
    })

    it('shows "—" for Time Open when detail is not yet loaded', () => {
      mockApi.get.mockReturnValue(new Promise(() => {}))
      renderPanel(makeIncident())
      const timeOpenLabel = within(getMetrics()).getByText('Time Open')
      expect(timeOpenLabel.nextElementSibling?.textContent).toBe('—')
    })
  })

  // =========================================================================
  // Tabs
  // =========================================================================
  describe('tab navigation', () => {
    it('renders the Details tab', () => {
      renderPanel(makeIncident())
      expect(screen.getByRole('button', { name: 'Details' })).toBeInTheDocument()
    })

    it('renders the Timeline tab', () => {
      renderPanel(makeIncident())
      expect(screen.getByRole('button', { name: /Timeline/ })).toBeInTheDocument()
    })

    it('renders the Detections tab', () => {
      renderPanel(makeIncident())
      expect(screen.getByRole('button', { name: /Detections/ })).toBeInTheDocument()
    })

    it('Details tab is active by default', () => {
      renderPanel(makeIncident())
      expect(screen.getByRole('button', { name: 'Details' })).toHaveClass('border-blue')
    })

    it('switches to Timeline tab when clicked', () => {
      renderPanel(makeIncident())
      fireEvent.click(screen.getByRole('button', { name: /Timeline/ }))
      expect(screen.getByRole('button', { name: /Timeline/ })).toHaveClass('border-blue')
    })

    it('switches to Detections tab when clicked', () => {
      renderPanel(makeIncident())
      fireEvent.click(screen.getByRole('button', { name: /Detections/ }))
      expect(screen.getByRole('button', { name: /Detections/ })).toHaveClass('border-blue')
    })
  })

  // =========================================================================
  // Details tab
  // =========================================================================
  describe('details tab', () => {
    it('renders the Priority row', () => {
      renderPanel(makeIncident({ priority: 2 }))
      expect(screen.getByText('Priority')).toBeInTheDocument()
    })

    it('renders the Created By row', () => {
      renderPanel(makeIncident({ created_by: 'analyst@mxtac.local' }))
      expect(screen.getByText('Created By')).toBeInTheDocument()
    })

    it('renders technique IDs as tags', () => {
      renderPanel(makeIncident({ technique_ids: ['T1550.002', 'T1003.001'] }))
      expect(screen.getAllByText('T1550.002').length).toBeGreaterThan(0)
      expect(screen.getByText('T1003.001')).toBeInTheDocument()
    })

    it('renders host tags', () => {
      renderPanel(makeIncident({ hosts: ['WIN-DC01', 'WIN-WS02'] }))
      expect(screen.getAllByText('WIN-DC01').length).toBeGreaterThan(0)
      expect(screen.getByText('WIN-WS02')).toBeInTheDocument()
    })

    it('renders the description when set', () => {
      renderPanel(makeIncident({ description: 'Attacker used PtH to move laterally.' }))
      expect(screen.getByText('Attacker used PtH to move laterally.')).toBeInTheDocument()
    })

    it('renders the closed_at row label when incident is closed and has closed_at', () => {
      renderPanel(makeIncident({
        status: 'closed',
        closed_at: '2026-02-20T10:00:00Z',
      }))
      // "Closed" appears in StatusBadge (header) and in the row label — use getAllByText
      const closedElements = screen.getAllByText('Closed')
      expect(closedElements.length).toBeGreaterThan(0)
    })

    it('does not render the closed_at row when closed_at is null', () => {
      renderPanel(makeIncident({ status: 'new', closed_at: null }))
      // Only StatusBadge might show "New" - but "Closed" should not appear at all
      expect(screen.queryByText('Closed')).not.toBeInTheDocument()
    })
  })

  // =========================================================================
  // Timeline tab
  // =========================================================================
  describe('timeline tab', () => {
    it('shows loading state while detail is loading', () => {
      mockApi.get.mockReturnValue(new Promise(() => {}))
      renderPanel(makeIncident())
      fireEvent.click(screen.getByRole('button', { name: /Timeline/ }))
      expect(screen.getByText('Loading…')).toBeInTheDocument()
    })

    it('shows empty state when there are no notes', async () => {
      mockApi.get.mockResolvedValue(makeDetail({}, [], []))
      renderPanel(makeIncident())
      fireEvent.click(screen.getByRole('button', { name: /Timeline/ }))
      await waitFor(() => {
        expect(screen.getByText('No timeline events yet.')).toBeInTheDocument()
      })
    })

    it('renders note content in the timeline', async () => {
      mockApi.get.mockResolvedValue(makeDetail({}, [], [
        {
          id: 'note-1',
          author: 'analyst@mxtac.local',
          content: 'Initial triage completed.',
          note_type: 'comment',
          created_at: '2026-02-19T08:35:00Z',
        },
      ]))
      renderPanel(makeIncident())
      fireEvent.click(screen.getByRole('button', { name: /Timeline/ }))
      await waitFor(() => {
        expect(screen.getByText('Initial triage completed.')).toBeInTheDocument()
      })
    })

    it('renders note author', async () => {
      mockApi.get.mockResolvedValue(makeDetail({}, [], [
        {
          id: 'note-1',
          author: 'timeline-author@mxtac.local',
          content: 'Triage done.',
          note_type: 'comment',
          created_at: '2026-02-19T08:35:00Z',
        },
      ]))
      renderPanel(makeIncident())
      fireEvent.click(screen.getByRole('button', { name: /Timeline/ }))
      await waitFor(() => {
        expect(screen.getByText('timeline-author@mxtac.local')).toBeInTheDocument()
      })
    })

    it('shows "Status Change" badge for status_change notes', async () => {
      mockApi.get.mockResolvedValue(makeDetail({}, [], [
        {
          id: 'note-1',
          author: 'analyst@mxtac.local',
          content: 'Status changed to Investigating.',
          note_type: 'status_change',
          created_at: '2026-02-19T08:35:00Z',
        },
      ]))
      renderPanel(makeIncident())
      fireEvent.click(screen.getByRole('button', { name: /Timeline/ }))
      await waitFor(() => {
        expect(screen.getByText('Status Change')).toBeInTheDocument()
      })
    })

    it('shows "Evidence" badge for evidence notes', async () => {
      mockApi.get.mockResolvedValue(makeDetail({}, [], [
        {
          id: 'note-1',
          author: 'analyst@mxtac.local',
          content: 'Packet capture attached.',
          note_type: 'evidence',
          created_at: '2026-02-19T08:35:00Z',
        },
      ]))
      renderPanel(makeIncident())
      fireEvent.click(screen.getByRole('button', { name: /Timeline/ }))
      await waitFor(() => {
        expect(screen.getByText('Evidence')).toBeInTheDocument()
      })
    })

    it('does not show type badge for regular comment notes', async () => {
      mockApi.get.mockResolvedValue(makeDetail({}, [], [
        {
          id: 'note-1',
          author: 'analyst@mxtac.local',
          content: 'Regular comment.',
          note_type: 'comment',
          created_at: '2026-02-19T08:35:00Z',
        },
      ]))
      renderPanel(makeIncident())
      fireEvent.click(screen.getByRole('button', { name: /Timeline/ }))
      await waitFor(() => {
        expect(screen.queryByText('Status Change')).not.toBeInTheDocument()
        expect(screen.queryByText('Evidence')).not.toBeInTheDocument()
      })
    })

    it('shows the Timeline tab note count when notes are loaded', async () => {
      mockApi.get.mockResolvedValue(makeDetail({}, [], [
        { id: 'n1', author: 'a', content: 'c1', note_type: 'comment', created_at: '2026-02-19T08:35:00Z' },
        { id: 'n2', author: 'b', content: 'c2', note_type: 'comment', created_at: '2026-02-19T08:36:00Z' },
      ]))
      renderPanel(makeIncident())
      await waitFor(() => {
        expect(screen.getByRole('button', { name: /Timeline \(2\)/ })).toBeInTheDocument()
      })
    })
  })

  // =========================================================================
  // Add note form
  // =========================================================================
  describe('add note form', () => {
    it('renders the note textarea in the Timeline tab', () => {
      renderPanel(makeIncident())
      fireEvent.click(screen.getByRole('button', { name: /Timeline/ }))
      expect(screen.getByPlaceholderText('Add a comment or observation…')).toBeInTheDocument()
    })

    it('renders the Add Note button', () => {
      renderPanel(makeIncident())
      fireEvent.click(screen.getByRole('button', { name: /Timeline/ }))
      expect(screen.getByRole('button', { name: 'Add Note' })).toBeInTheDocument()
    })

    it('Add Note button is disabled when textarea is empty', () => {
      renderPanel(makeIncident())
      fireEvent.click(screen.getByRole('button', { name: /Timeline/ }))
      expect(screen.getByRole('button', { name: 'Add Note' })).toBeDisabled()
    })

    it('Add Note button is enabled when textarea has text', () => {
      renderPanel(makeIncident())
      fireEvent.click(screen.getByRole('button', { name: /Timeline/ }))
      fireEvent.change(
        screen.getByPlaceholderText('Add a comment or observation…'),
        { target: { value: 'New observation' } },
      )
      expect(screen.getByRole('button', { name: 'Add Note' })).not.toBeDisabled()
    })

    it('calls addNote with the textarea content', async () => {
      renderPanel(makeIncident())
      fireEvent.click(screen.getByRole('button', { name: /Timeline/ }))
      fireEvent.change(
        screen.getByPlaceholderText('Add a comment or observation…'),
        { target: { value: 'Checked firewall logs.' } },
      )
      fireEvent.click(screen.getByRole('button', { name: 'Add Note' }))
      await waitFor(() =>
        expect(mockApi.addNote).toHaveBeenCalledWith(42, 'Checked firewall logs.'),
      )
    })

    it('clears the textarea after successful note addition', async () => {
      renderPanel(makeIncident())
      fireEvent.click(screen.getByRole('button', { name: /Timeline/ }))
      const textarea = screen.getByPlaceholderText('Add a comment or observation…')
      fireEvent.change(textarea, { target: { value: 'Done.' } })
      fireEvent.click(screen.getByRole('button', { name: 'Add Note' }))
      await waitFor(() => {
        expect((textarea as HTMLTextAreaElement).value).toBe('')
      })
    })
  })

  // =========================================================================
  // Detections tab
  // =========================================================================
  describe('detections tab', () => {
    it('shows loading state while detail is loading', () => {
      mockApi.get.mockReturnValue(new Promise(() => {}))
      renderPanel(makeIncident())
      fireEvent.click(screen.getByRole('button', { name: /Detections/ }))
      expect(screen.getByText('Loading…')).toBeInTheDocument()
    })

    it('shows empty state when there are no linked detections', async () => {
      mockApi.get.mockResolvedValue(makeDetail({}, []))
      renderPanel(makeIncident())
      fireEvent.click(screen.getByRole('button', { name: /Detections/ }))
      await waitFor(() => {
        expect(screen.getByText('No linked detections.')).toBeInTheDocument()
      })
    })

    it('renders linked detection names', async () => {
      mockApi.get.mockResolvedValue(makeDetail({}, [
        makeDetection({ name: 'Suspicious NTLM Authentication' }),
      ]))
      renderPanel(makeIncident())
      fireEvent.click(screen.getByRole('button', { name: /Detections/ }))
      await waitFor(() => {
        expect(screen.getByText('Suspicious NTLM Authentication')).toBeInTheDocument()
      })
    })

    it('renders detection technique_id when detections tab is active', async () => {
      mockApi.get.mockResolvedValue(makeDetail({}, [
        makeDetection({ technique_id: 'T1550.002' }),
      ]))
      renderPanel(makeIncident())
      fireEvent.click(screen.getByRole('button', { name: /Detections/ }))
      // When Detections tab is active, Details tab is hidden so T1550.002 only appears here
      await waitFor(() => {
        expect(screen.getAllByText('T1550.002').length).toBeGreaterThan(0)
      })
    })

    it('shows the Detections tab count when loaded', async () => {
      mockApi.get.mockResolvedValue(makeDetail({}, [
        makeDetection(),
        makeDetection({ id: 'det-002', name: 'Second Detection' }),
      ]))
      renderPanel(makeIncident())
      await waitFor(() => {
        expect(screen.getByRole('button', { name: /Detections \(2\)/ })).toBeInTheDocument()
      })
    })

    it('expands inline detection detail when clicked (no onDetectionClick)', async () => {
      mockApi.get.mockResolvedValue(makeDetail({}, [makeDetection()]))
      renderPanel(makeIncident())
      fireEvent.click(screen.getByRole('button', { name: /Detections/ }))
      await waitFor(() => {
        expect(screen.getByText('Suspicious NTLM Authentication')).toBeInTheDocument()
      })
      fireEvent.click(screen.getByText('Suspicious NTLM Authentication'))
      // Expanded: shows the "Technique" and "Tactic" row labels
      expect(screen.getByText('Technique')).toBeInTheDocument()
      expect(screen.getByText('Tactic')).toBeInTheDocument()
      // The technique value contains the full string "T1550.002 – Pass-the-Hash"
      expect(screen.getByText('T1550.002 – Pass-the-Hash')).toBeInTheDocument()
    })

    it('collapses expanded detection when clicked again', async () => {
      mockApi.get.mockResolvedValue(makeDetail({}, [makeDetection()]))
      renderPanel(makeIncident())
      fireEvent.click(screen.getByRole('button', { name: /Detections/ }))
      await waitFor(() => expect(screen.getByText('Suspicious NTLM Authentication')).toBeInTheDocument())
      fireEvent.click(screen.getByText('Suspicious NTLM Authentication')) // expand
      expect(screen.getByText('Technique')).toBeInTheDocument()
      fireEvent.click(screen.getByText('Suspicious NTLM Authentication')) // collapse
      expect(screen.queryByText('Technique')).not.toBeInTheDocument()
    })

    it('calls onDetectionClick when provided and detection row is clicked', async () => {
      const onDetectionClick = vi.fn()
      const det = makeDetection()
      mockApi.get.mockResolvedValue(makeDetail({}, [det]))
      renderPanel(makeIncident(), { onDetectionClick })
      fireEvent.click(screen.getByRole('button', { name: /Detections/ }))
      await waitFor(() => expect(screen.getByText('Suspicious NTLM Authentication')).toBeInTheDocument())
      fireEvent.click(screen.getByText('Suspicious NTLM Authentication'))
      expect(onDetectionClick).toHaveBeenCalledWith(det)
    })

    it('does not inline-expand when onDetectionClick is provided', async () => {
      const onDetectionClick = vi.fn()
      mockApi.get.mockResolvedValue(makeDetail({}, [makeDetection()]))
      renderPanel(makeIncident(), { onDetectionClick })
      fireEvent.click(screen.getByRole('button', { name: /Detections/ }))
      await waitFor(() => expect(screen.getByText('Suspicious NTLM Authentication')).toBeInTheDocument())
      fireEvent.click(screen.getByText('Suspicious NTLM Authentication'))
      // Inline detail should NOT appear when onDetectionClick is provided
      expect(screen.queryByText(/T1550\.002 – Pass-the-Hash/)).not.toBeInTheDocument()
    })
  })

  // =========================================================================
  // AssignedTo inline editor in Details tab
  // =========================================================================
  describe('assigned-to inline editor', () => {
    it('renders the Assigned To row label in Details tab', () => {
      renderPanel(makeIncident())
      expect(screen.getByText('Assigned To')).toBeInTheDocument()
    })

    it('shows edit input when the assigned-to value is clicked', () => {
      renderPanel(makeIncident({ assigned_to: 'analyst@mxtac.local' }))
      // Find the clickable span with title="Click to edit"
      const editableSpan = screen.getByTitle('Click to edit')
      expect(editableSpan).toBeInTheDocument()
      fireEvent.click(editableSpan)
      expect(screen.getByPlaceholderText('analyst@org.com')).toBeInTheDocument()
    })
  })

  // =========================================================================
  // Different severity/status rendering
  // =========================================================================
  describe('severity and status variants', () => {
    it.each(['critical', 'high', 'medium', 'low'] as const)(
      'renders without error for severity=%s',
      (severity) => {
        expect(() => renderPanel(makeIncident({ severity }))).not.toThrow()
      },
    )

    it.each(['new', 'investigating', 'contained', 'resolved', 'closed'] as const)(
      'renders without error for status=%s',
      (status) => {
        expect(() => renderPanel(makeIncident({ status }))).not.toThrow()
      },
    )
  })
})
