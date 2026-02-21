// vi.mock is hoisted before imports — declare all module mocks first.

vi.mock('../../lib/api', () => ({
  incidentsApi: {
    get:     vi.fn(),
    update:  vi.fn(),
    addNote: vi.fn(),
  },
}))

import { render, screen, fireEvent, waitFor } from '@testing-library/react'
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
    mockApi.addNote.mockResolvedValue({ id: 'note-1', content: 'test', author: 'analyst', note_type: 'comment', created_at: '2026-02-19T09:00:00Z' })
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

    it('renders the incident ID as INC-{id}', () => {
      renderPanel(makeIncident({ id: 42 }))
      expect(screen.getByText('INC-42')).toBeInTheDocument()
    })

    it('shows "Unassigned" when assigned_to is null', () => {
      renderPanel(makeIncident({ assigned_to: null }))
      expect(screen.getByText('Unassigned')).toBeInTheDocument()
    })

    it('shows the assigned_to value in the header when set', () => {
      renderPanel(makeIncident({ assigned_to: 'soc@mxtac.local' }))
      expect(screen.getByText('soc@mxtac.local')).toBeInTheDocument()
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
      expect(screen.queryByText(/→ /)).not.toBeInTheDocument()
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
    it('renders the "Set Status" button', () => {
      renderPanel(makeIncident())
      expect(screen.getByRole('button', { name: 'Set Status ▾' })).toBeInTheDocument()
    })

    it('does not show status options by default', () => {
      renderPanel(makeIncident())
      expect(screen.queryByText('Investigating')).not.toBeInTheDocument()
    })

    it('shows status options when "Set Status" is clicked', () => {
      renderPanel(makeIncident({ status: 'new' }))
      fireEvent.click(screen.getByRole('button', { name: 'Set Status ▾' }))
      expect(screen.getByText('Investigating')).toBeInTheDocument()
      expect(screen.getByText('Contained')).toBeInTheDocument()
      expect(screen.getByText('Resolved')).toBeInTheDocument()
    })

    it('shows a confirmation bar when a status is selected from dropdown', () => {
      renderPanel(makeIncident({ status: 'new' }))
      fireEvent.click(screen.getByRole('button', { name: 'Set Status ▾' }))
      fireEvent.click(screen.getByText('Investigating'))
      expect(screen.getByText('Confirm')).toBeInTheDocument()
      expect(screen.getByText('Cancel')).toBeInTheDocument()
    })

    it('shows a "Change to [Status]?" confirmation message', () => {
      renderPanel(makeIncident({ status: 'new' }))
      fireEvent.click(screen.getByRole('button', { name: 'Set Status ▾' }))
      fireEvent.click(screen.getByText('Investigating'))
      // The confirmation area shows "Change to" text
      expect(screen.getByText('Change to')).toBeInTheDocument()
    })

    it('calls update mutation when Confirm is clicked', async () => {
      renderPanel(makeIncident({ status: 'new' }))
      fireEvent.click(screen.getByRole('button', { name: 'Set Status ▾' }))
      fireEvent.click(screen.getByText('Investigating'))
      fireEvent.click(screen.getByRole('button', { name: 'Confirm' }))
      await waitFor(() =>
        expect(mockApi.update).toHaveBeenCalledWith(42, { status: 'investigating' }),
      )
    })

    it('hides the confirmation bar when Cancel is clicked', () => {
      renderPanel(makeIncident({ status: 'new' }))
      fireEvent.click(screen.getByRole('button', { name: 'Set Status ▾' }))
      fireEvent.click(screen.getByText('Investigating'))
      expect(screen.getByText('Confirm')).toBeInTheDocument()
      fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
      expect(screen.queryByText('Confirm')).not.toBeInTheDocument()
    })

    it('does not call update when Cancel is clicked', async () => {
      renderPanel(makeIncident({ status: 'new' }))
      fireEvent.click(screen.getByRole('button', { name: 'Set Status ▾' }))
      fireEvent.click(screen.getByText('Investigating'))
      fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
      await new Promise(r => setTimeout(r, 50))
      expect(mockApi.update).not.toHaveBeenCalled()
    })
  })

  // =========================================================================
  // Metrics strip
  // =========================================================================
  describe('metrics strip', () => {
    it('renders the TTD label', () => {
      renderPanel(makeIncident())
      expect(screen.getByText('TTD')).toBeInTheDocument()
    })

    it('renders the TTR label', () => {
      renderPanel(makeIncident())
      expect(screen.getByText('TTR')).toBeInTheDocument()
    })

    it('renders the Time Open label', () => {
      renderPanel(makeIncident())
      expect(screen.getByText('Time Open')).toBeInTheDocument()
    })

    it('shows "—" for TTD when ttd_seconds is null', () => {
      renderPanel(makeIncident({ ttd_seconds: null }))
      // TTD cell shows —
      const ttdLabel = screen.getByText('TTD')
      expect(ttdLabel.nextElementSibling?.textContent).toBe('—')
    })

    it('shows formatted TTD when ttd_seconds is set', () => {
      renderPanel(makeIncident({ ttd_seconds: 3600 }))
      expect(screen.getByText('1.0h')).toBeInTheDocument()
    })

    it('shows "Open" for TTR when ttr_seconds is null', () => {
      renderPanel(makeIncident({ ttr_seconds: null }))
      const ttrLabel = screen.getByText('TTR')
      expect(ttrLabel.nextElementSibling?.textContent).toBe('Open')
    })

    it('shows formatted TTR when ttr_seconds is set', () => {
      renderPanel(makeIncident({ ttr_seconds: 7200 }))
      expect(screen.getByText('2.0h')).toBeInTheDocument()
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
      const detailsTab = screen.getByRole('button', { name: 'Details' })
      expect(detailsTab).toHaveClass('border-blue')
    })

    it('switches to Timeline tab when clicked', () => {
      renderPanel(makeIncident())
      fireEvent.click(screen.getByRole('button', { name: /Timeline/ }))
      const timelineTab = screen.getByRole('button', { name: /Timeline/ })
      expect(timelineTab).toHaveClass('border-blue')
    })
  })

  // =========================================================================
  // Details tab
  // =========================================================================
  describe('details tab', () => {
    it('renders the ID row', () => {
      renderPanel(makeIncident({ id: 42 }))
      expect(screen.getByText('ID')).toBeInTheDocument()
    })

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
      expect(screen.getByText('T1550.002')).toBeInTheDocument()
      expect(screen.getByText('T1003.001')).toBeInTheDocument()
    })

    it('renders host tags', () => {
      renderPanel(makeIncident({ hosts: ['WIN-DC01', 'WIN-WS02'] }))
      expect(screen.getByText('WIN-DC01')).toBeInTheDocument()
      expect(screen.getByText('WIN-WS02')).toBeInTheDocument()
    })

    it('renders the description when set', () => {
      renderPanel(makeIncident({ description: 'Attacker used PtH to move laterally.' }))
      expect(screen.getByText('Attacker used PtH to move laterally.')).toBeInTheDocument()
    })

    it('renders closed_at row when incident is closed', () => {
      renderPanel(makeIncident({ status: 'closed', closed_at: '2026-02-20T10:00:00Z' }))
      expect(screen.getByText('Closed')).toBeInTheDocument()
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
          author: 'analyst@mxtac.local',
          content: 'Triage done.',
          note_type: 'comment',
          created_at: '2026-02-19T08:35:00Z',
        },
      ]))
      renderPanel(makeIncident())
      fireEvent.click(screen.getByRole('button', { name: /Timeline/ }))
      await waitFor(() => {
        expect(screen.getByText('analyst@mxtac.local')).toBeInTheDocument()
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

    it('shows the Timeline tab count when notes are loaded', async () => {
      mockApi.get.mockResolvedValue(makeDetail({}, [], [
        { id: 'n1', author: 'a', content: 'c', note_type: 'comment', created_at: '2026-02-19T08:35:00Z' },
        { id: 'n2', author: 'b', content: 'd', note_type: 'comment', created_at: '2026-02-19T08:36:00Z' },
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
      const btn = screen.getByRole('button', { name: 'Add Note' })
      expect(btn).toBeDisabled()
    })

    it('Add Note button is enabled when textarea has text', () => {
      renderPanel(makeIncident())
      fireEvent.click(screen.getByRole('button', { name: /Timeline/ }))
      const textarea = screen.getByPlaceholderText('Add a comment or observation…')
      fireEvent.change(textarea, { target: { value: 'New observation' } })
      const btn = screen.getByRole('button', { name: 'Add Note' })
      expect(btn).not.toBeDisabled()
    })

    it('calls addNote when Add Note is clicked with content', async () => {
      renderPanel(makeIncident())
      fireEvent.click(screen.getByRole('button', { name: /Timeline/ }))
      const textarea = screen.getByPlaceholderText('Add a comment or observation…')
      fireEvent.change(textarea, { target: { value: 'Checked firewall logs.' } })
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
      mockApi.get.mockResolvedValue(makeDetail({}, [makeDetection({ name: 'Suspicious NTLM Authentication' })]))
      renderPanel(makeIncident())
      fireEvent.click(screen.getByRole('button', { name: /Detections/ }))
      await waitFor(() => {
        expect(screen.getByText('Suspicious NTLM Authentication')).toBeInTheDocument()
      })
    })

    it('renders detection technique_id and host', async () => {
      mockApi.get.mockResolvedValue(makeDetail({}, [
        makeDetection({ technique_id: 'T1550.002', host: 'WIN-DC01' }),
      ]))
      renderPanel(makeIncident())
      fireEvent.click(screen.getByRole('button', { name: /Detections/ }))
      await waitFor(() => {
        expect(screen.getByText('T1550.002')).toBeInTheDocument()
        expect(screen.getByText('WIN-DC01')).toBeInTheDocument()
      })
    })

    it('shows the Detections tab count when loaded', async () => {
      mockApi.get.mockResolvedValue(makeDetail({}, [makeDetection(), makeDetection({ id: 'det-002', name: 'Second Detection' })]))
      renderPanel(makeIncident())
      await waitFor(() => {
        expect(screen.getByRole('button', { name: /Detections \(2\)/ })).toBeInTheDocument()
      })
    })

    it('expands inline detection detail when detection row is clicked (no onDetectionClick)', async () => {
      mockApi.get.mockResolvedValue(makeDetail({}, [makeDetection()]))
      renderPanel(makeIncident())
      fireEvent.click(screen.getByRole('button', { name: /Detections/ }))
      await waitFor(() => {
        expect(screen.getByText('Suspicious NTLM Authentication')).toBeInTheDocument()
      })
      fireEvent.click(screen.getByText('Suspicious NTLM Authentication'))
      expect(screen.getByText('Pass-the-Hash')).toBeInTheDocument()
      expect(screen.getByText('Lateral Movement')).toBeInTheDocument()
    })

    it('collapses expanded detection when clicked again', async () => {
      mockApi.get.mockResolvedValue(makeDetail({}, [makeDetection()]))
      renderPanel(makeIncident())
      fireEvent.click(screen.getByRole('button', { name: /Detections/ }))
      await waitFor(() => expect(screen.getByText('Suspicious NTLM Authentication')).toBeInTheDocument())
      fireEvent.click(screen.getByText('Suspicious NTLM Authentication')) // expand
      expect(screen.getByText('Lateral Movement')).toBeInTheDocument()
      fireEvent.click(screen.getByText('Suspicious NTLM Authentication')) // collapse
      expect(screen.queryByText('Lateral Movement')).not.toBeInTheDocument()
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
      const det = makeDetection({ technique_name: 'Pass-the-Hash' })
      mockApi.get.mockResolvedValue(makeDetail({}, [det]))
      renderPanel(makeIncident(), { onDetectionClick })
      fireEvent.click(screen.getByRole('button', { name: /Detections/ }))
      await waitFor(() => expect(screen.getByText('Suspicious NTLM Authentication')).toBeInTheDocument())
      fireEvent.click(screen.getByText('Suspicious NTLM Authentication'))
      // Technique name should NOT appear as expanded detail
      expect(screen.queryByText('Pass-the-Hash')).not.toBeInTheDocument()
    })
  })

  // =========================================================================
  // AssignedTo inline editor
  // =========================================================================
  describe('assigned-to field in Details tab', () => {
    it('shows "Unassigned" when assigned_to is null in Details tab', () => {
      renderPanel(makeIncident({ assigned_to: null }))
      // The Details tab also has Assigned To row
      expect(screen.getByText('Assigned To')).toBeInTheDocument()
    })

    it('shows edit input when assigned-to field is clicked in Details tab', () => {
      renderPanel(makeIncident({ assigned_to: 'analyst@mxtac.local' }))
      // Find the assigned_to value in the Details tab (click the span)
      const spans = screen.getAllByText('analyst@mxtac.local')
      // The one in the Details tab Row is a clickable span
      const editableSpan = spans.find(el => el.tagName === 'SPAN' && el.getAttribute('title') === 'Click to edit')
      expect(editableSpan).not.toBeUndefined()
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
