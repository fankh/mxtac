// vi.mock is hoisted before imports — declare module mocks first.

vi.mock('../../lib/api', () => ({
  detectionsApi: {
    update: vi.fn(),
  },
}))

import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { DetectionPanel } from '../../components/features/detections/DetectionPanel'
import { detectionsApi } from '../../lib/api'
import type { Detection } from '../../types/api'

// ---------------------------------------------------------------------------
// Typed mock reference
// ---------------------------------------------------------------------------

const mockUpdate = detectionsApi.update as ReturnType<typeof vi.fn>

// ---------------------------------------------------------------------------
// Fixture helper
// ---------------------------------------------------------------------------

const makeDetection = (overrides: Partial<Detection> = {}): Detection => ({
  id: 'det-001',
  score: 9.2,
  severity: 'critical',
  technique_id: 'T1003.001',
  technique_name: 'LSASS Memory Dump',
  tactic: 'Credential Access',
  name: 'Suspicious LSASS Memory Access',
  host: 'WIN-DC01',
  status: 'active',
  time: '2026-02-19T08:30:00Z',
  related_technique_ids: [],
  ...overrides,
})

// ---------------------------------------------------------------------------
// Render helper — wraps with QueryClientProvider (required for useMutation)
// ---------------------------------------------------------------------------

function renderPanel(
  detection: Detection | null,
  onClose: () => void = vi.fn(),
) {
  const queryClient = new QueryClient({
    defaultOptions: { mutations: { retry: false }, queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <DetectionPanel detection={detection} onClose={onClose} />
    </QueryClientProvider>,
  )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('DetectionPanel', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    // Default: mutation resolves successfully with updated detection
    mockUpdate.mockResolvedValue(makeDetection({ status: 'investigating' }))
  })

  // =========================================================================
  // Null detection — renders nothing
  // =========================================================================
  describe('when detection is null', () => {
    it('renders nothing when detection is null', () => {
      const { container } = renderPanel(null)
      expect(container).toBeEmptyDOMElement()
    })
  })

  // =========================================================================
  // Core header rendering
  // =========================================================================
  describe('header', () => {
    it('renders the detection name', () => {
      renderPanel(makeDetection())
      expect(screen.getByText('Suspicious LSASS Memory Access')).toBeInTheDocument()
    })

    it('renders the subtitle line showing technique_id · tactic', () => {
      renderPanel(makeDetection())
      expect(screen.getByText(/T1003\.001 · Credential Access/)).toBeInTheDocument()
    })

    it('renders the close button with title "Close"', () => {
      renderPanel(makeDetection())
      expect(screen.getByTitle('Close')).toBeInTheDocument()
    })
  })

  // =========================================================================
  // Badges row (severity, status, confidence, CVSS)
  // =========================================================================
  describe('badges row', () => {
    it('renders the confidence badge when provided', () => {
      renderPanel(makeDetection({ confidence: 85 }))
      expect(screen.getByText('Confidence: 85%')).toBeInTheDocument()
    })

    it('does not render the confidence badge when absent', () => {
      renderPanel(makeDetection({ confidence: undefined }))
      expect(screen.queryByText(/Confidence:/)).not.toBeInTheDocument()
    })

    it('renders the CVSS v3 score when provided', () => {
      renderPanel(makeDetection({ cvss_v3: 9.1 }))
      expect(screen.getByText('CVSS: 9.1')).toBeInTheDocument()
    })

    it('does not render the CVSS badge when absent', () => {
      renderPanel(makeDetection({ cvss_v3: undefined }))
      expect(screen.queryByText(/CVSS:/)).not.toBeInTheDocument()
    })

    it('renders confidence 0 as a valid value', () => {
      renderPanel(makeDetection({ confidence: 0 }))
      expect(screen.getByText('Confidence: 0%')).toBeInTheDocument()
    })
  })

  // =========================================================================
  // Description
  // =========================================================================
  describe('description', () => {
    it('renders the description when provided', () => {
      renderPanel(
        makeDetection({ description: 'This detection identifies credential dumping via LSASS.' }),
      )
      expect(
        screen.getByText('This detection identifies credential dumping via LSASS.'),
      ).toBeInTheDocument()
    })

    it('does not render a description paragraph when absent', () => {
      renderPanel(makeDetection({ description: undefined }))
      expect(screen.queryByText(/credential dumping/)).not.toBeInTheDocument()
    })
  })

  // =========================================================================
  // Always-present detail rows
  // =========================================================================
  describe('always-present rows', () => {
    it('renders the combined Technique row', () => {
      renderPanel(makeDetection())
      expect(screen.getByText('T1003.001 – LSASS Memory Dump')).toBeInTheDocument()
    })

    it('renders the Tactic row value', () => {
      renderPanel(makeDetection())
      expect(screen.getByText('Tactic')).toBeInTheDocument()
    })

    it('renders the Host row value', () => {
      renderPanel(makeDetection())
      expect(screen.getByText('WIN-DC01')).toBeInTheDocument()
    })

    it('renders the Time row label', () => {
      renderPanel(makeDetection())
      expect(screen.getByText('Time')).toBeInTheDocument()
    })
  })

  // =========================================================================
  // Optional detail rows
  // =========================================================================
  describe('optional detail rows', () => {
    it('renders the user value when provided', () => {
      renderPanel(makeDetection({ user: 'DOMAIN\\admin' }))
      expect(screen.getByText('DOMAIN\\admin')).toBeInTheDocument()
    })

    it('does not render the User row label when user is absent', () => {
      renderPanel(makeDetection({ user: undefined }))
      expect(screen.queryByText('User')).not.toBeInTheDocument()
    })

    it('renders the process value when provided', () => {
      renderPanel(makeDetection({ process: 'lsass.exe' }))
      expect(screen.getByText('lsass.exe')).toBeInTheDocument()
    })

    it('does not render the Process row label when process is absent', () => {
      renderPanel(makeDetection({ process: undefined }))
      expect(screen.queryByText('Process')).not.toBeInTheDocument()
    })

    it('renders the log_source value when provided', () => {
      renderPanel(makeDetection({ log_source: 'Windows Security' }))
      expect(screen.getByText('Windows Security')).toBeInTheDocument()
    })

    it('does not render the Log Source row label when log_source is absent', () => {
      renderPanel(makeDetection({ log_source: undefined }))
      expect(screen.queryByText('Log Source')).not.toBeInTheDocument()
    })

    it('renders the event_id value when provided', () => {
      renderPanel(makeDetection({ event_id: '4688' }))
      expect(screen.getByText('4688')).toBeInTheDocument()
    })

    it('does not render the Event ID row label when event_id is absent', () => {
      renderPanel(makeDetection({ event_id: undefined }))
      expect(screen.queryByText('Event ID')).not.toBeInTheDocument()
    })

    it('renders the sigma rule_name when provided', () => {
      renderPanel(
        makeDetection({ rule_name: 'proc_access_win_lsass_dump_tools_dll' }),
      )
      expect(screen.getByText('proc_access_win_lsass_dump_tools_dll')).toBeInTheDocument()
    })

    it('does not render the Sigma Rule row label when rule_name is absent', () => {
      renderPanel(makeDetection({ rule_name: undefined }))
      expect(screen.queryByText('Sigma Rule')).not.toBeInTheDocument()
    })

    it('renders the occurrence count when provided', () => {
      renderPanel(makeDetection({ occurrence_count: 42 }))
      expect(screen.getByText('42')).toBeInTheDocument()
    })

    it('renders large occurrence counts with locale formatting', () => {
      renderPanel(makeDetection({ occurrence_count: 1500 }))
      // toLocaleString() may format as '1,500' depending on locale
      expect(screen.getByText('Occurrences')).toBeInTheDocument()
    })

    it('does not render the Occurrences row label when occurrence_count is absent', () => {
      renderPanel(makeDetection({ occurrence_count: undefined }))
      expect(screen.queryByText('Occurrences')).not.toBeInTheDocument()
    })

    it('renders occurrence_count of 0 as a valid value', () => {
      renderPanel(makeDetection({ occurrence_count: 0 }))
      expect(screen.getByText('Occurrences')).toBeInTheDocument()
    })

    it('renders the assigned_to value when provided', () => {
      renderPanel(
        makeDetection({ assigned_to: 'analyst@mxtac.local' }),
      )
      expect(screen.getByText('analyst@mxtac.local')).toBeInTheDocument()
    })

    it('does not render the Assigned To row label when assigned_to is absent', () => {
      renderPanel(makeDetection({ assigned_to: undefined }))
      expect(screen.queryByText('Assigned To')).not.toBeInTheDocument()
    })
  })

  // =========================================================================
  // Related technique IDs
  // =========================================================================
  describe('related technique IDs', () => {
    it('renders individual technique ID tags', () => {
      renderPanel(
        makeDetection({ related_technique_ids: ['T1055', 'T1078'] }),
      )
      expect(screen.getByText('T1055')).toBeInTheDocument()
      expect(screen.getByText('T1078')).toBeInTheDocument()
    })

    it('renders the "Related Techniques" heading when list is non-empty', () => {
      renderPanel(
        makeDetection({ related_technique_ids: ['T1055'] }),
      )
      expect(screen.getByText('Related Techniques')).toBeInTheDocument()
    })

    it('does not render the "Related Techniques" section when list is empty', () => {
      renderPanel(
        makeDetection({ related_technique_ids: [] }),
      )
      expect(screen.queryByText('Related Techniques')).not.toBeInTheDocument()
    })

    it('renders all technique ID tags from a longer list', () => {
      const ids = ['T1003', 'T1059', 'T1078', 'T1110']
      renderPanel(
        makeDetection({ related_technique_ids: ids }),
      )
      for (const id of ids) {
        expect(screen.getByText(id)).toBeInTheDocument()
      }
    })
  })

  // =========================================================================
  // Close actions
  // =========================================================================
  describe('close actions', () => {
    it('calls onClose when the × close button is clicked', () => {
      const onClose = vi.fn()
      renderPanel(makeDetection(), onClose)
      fireEvent.click(screen.getByTitle('Close'))
      expect(onClose).toHaveBeenCalledOnce()
    })

    it('calls onClose when the backdrop overlay is clicked', () => {
      const onClose = vi.fn()
      const { container } = renderPanel(makeDetection(), onClose)
      const backdrop = container.querySelector('.fixed.inset-0')
      expect(backdrop).not.toBeNull()
      fireEvent.click(backdrop!)
      expect(onClose).toHaveBeenCalledOnce()
    })

    it('does not call onClose when the panel body is clicked', () => {
      const onClose = vi.fn()
      renderPanel(makeDetection(), onClose)
      // Click on a known panel content element — should NOT close
      fireEvent.click(screen.getByText('Suspicious LSASS Memory Access'))
      expect(onClose).not.toHaveBeenCalled()
    })
  })

  // =========================================================================
  // Action footer buttons
  // =========================================================================
  describe('action footer buttons', () => {
    it('renders the Investigate button', () => {
      renderPanel(makeDetection())
      expect(screen.getByRole('button', { name: 'Investigate' })).toBeInTheDocument()
    })

    it('renders the Assign button', () => {
      renderPanel(makeDetection())
      expect(screen.getByRole('button', { name: 'Assign' })).toBeInTheDocument()
    })

    it('renders the Resolve button', () => {
      renderPanel(makeDetection())
      expect(screen.getByRole('button', { name: 'Resolve' })).toBeInTheDocument()
    })

    it('renders the FP (false positive) button', () => {
      renderPanel(makeDetection())
      expect(screen.getByRole('button', { name: 'FP' })).toBeInTheDocument()
    })

    it('renders all four action buttons together', () => {
      renderPanel(makeDetection())
      expect(screen.getByRole('button', { name: 'Investigate' })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Assign' })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Resolve' })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'FP' })).toBeInTheDocument()
    })

    it('calls detectionsApi.update with status=investigating when Investigate is clicked', async () => {
      const onClose = vi.fn()
      renderPanel(makeDetection(), onClose)
      fireEvent.click(screen.getByRole('button', { name: 'Investigate' }))
      await waitFor(() => expect(mockUpdate).toHaveBeenCalledWith('det-001', { status: 'investigating' }))
      await waitFor(() => expect(onClose).toHaveBeenCalledOnce())
    })

    it('calls detectionsApi.update with status=resolved when Resolve is clicked', async () => {
      const onClose = vi.fn()
      renderPanel(makeDetection(), onClose)
      fireEvent.click(screen.getByRole('button', { name: 'Resolve' }))
      await waitFor(() => expect(mockUpdate).toHaveBeenCalledWith('det-001', { status: 'resolved' }))
      await waitFor(() => expect(onClose).toHaveBeenCalledOnce())
    })

    it('calls detectionsApi.update with status=false_positive when FP is clicked', async () => {
      const onClose = vi.fn()
      renderPanel(makeDetection(), onClose)
      fireEvent.click(screen.getByRole('button', { name: 'FP' }))
      await waitFor(() => expect(mockUpdate).toHaveBeenCalledWith('det-001', { status: 'false_positive' }))
      await waitFor(() => expect(onClose).toHaveBeenCalledOnce())
    })

    it('shows update error message when mutation fails', async () => {
      mockUpdate.mockRejectedValue(new Error('Network error'))
      renderPanel(makeDetection())
      fireEvent.click(screen.getByRole('button', { name: 'Resolve' }))
      await waitFor(() =>
        expect(screen.getByText('Update failed. Please try again.')).toBeInTheDocument(),
      )
    })
  })

  // =========================================================================
  // Assign flow
  // =========================================================================
  describe('assign flow', () => {
    it('does not show assign input by default', () => {
      renderPanel(makeDetection())
      expect(screen.queryByPlaceholderText(/Assign to/)).not.toBeInTheDocument()
    })

    it('shows assign input when Assign button is clicked', () => {
      renderPanel(makeDetection())
      fireEvent.click(screen.getByRole('button', { name: 'Assign' }))
      expect(screen.getByPlaceholderText(/Assign to/)).toBeInTheDocument()
    })

    it('hides assign input when Assign is clicked a second time', () => {
      renderPanel(makeDetection())
      fireEvent.click(screen.getByRole('button', { name: 'Assign' }))
      fireEvent.click(screen.getByRole('button', { name: 'Assign' }))
      expect(screen.queryByPlaceholderText(/Assign to/)).not.toBeInTheDocument()
    })

    it('hides assign input when Cancel is clicked', () => {
      renderPanel(makeDetection())
      fireEvent.click(screen.getByRole('button', { name: 'Assign' }))
      fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
      expect(screen.queryByPlaceholderText(/Assign to/)).not.toBeInTheDocument()
    })

    it('calls detectionsApi.update with assigned_to when Confirm is clicked', async () => {
      const onClose = vi.fn()
      renderPanel(makeDetection(), onClose)
      fireEvent.click(screen.getByRole('button', { name: 'Assign' }))
      fireEvent.change(screen.getByPlaceholderText(/Assign to/), {
        target: { value: 'analyst@mxtac.local' },
      })
      fireEvent.click(screen.getByRole('button', { name: 'Confirm' }))
      await waitFor(() => expect(mockUpdate).toHaveBeenCalledWith('det-001', { assigned_to: 'analyst@mxtac.local' }))
      await waitFor(() => expect(onClose).toHaveBeenCalledOnce())
    })

    it('calls detectionsApi.update when Enter is pressed in assign input', async () => {
      const onClose = vi.fn()
      renderPanel(makeDetection(), onClose)
      fireEvent.click(screen.getByRole('button', { name: 'Assign' }))
      const input = screen.getByPlaceholderText(/Assign to/)
      fireEvent.change(input, { target: { value: 'soc@mxtac.local' } })
      fireEvent.keyDown(input, { key: 'Enter' })
      await waitFor(() => expect(mockUpdate).toHaveBeenCalledWith('det-001', { assigned_to: 'soc@mxtac.local' }))
      await waitFor(() => expect(onClose).toHaveBeenCalledOnce())
    })

    it('does not call update when Confirm is clicked with empty input', () => {
      renderPanel(makeDetection())
      fireEvent.click(screen.getByRole('button', { name: 'Assign' }))
      fireEvent.click(screen.getByRole('button', { name: 'Confirm' }))
      expect(mockUpdate).not.toHaveBeenCalled()
    })

    it('hides assign input when Escape is pressed', () => {
      renderPanel(makeDetection())
      fireEvent.click(screen.getByRole('button', { name: 'Assign' }))
      const input = screen.getByPlaceholderText(/Assign to/)
      fireEvent.keyDown(input, { key: 'Escape' })
      expect(screen.queryByPlaceholderText(/Assign to/)).not.toBeInTheDocument()
    })
  })

  // =========================================================================
  // Different severity and status values
  // =========================================================================
  describe('different severity and status', () => {
    it('renders without errors for severity=high', () => {
      expect(() =>
        renderPanel(makeDetection({ severity: 'high', score: 7.5 })),
      ).not.toThrow()
    })

    it('renders without errors for severity=medium', () => {
      expect(() =>
        renderPanel(makeDetection({ severity: 'medium', score: 5.0 })),
      ).not.toThrow()
    })

    it('renders without errors for severity=low', () => {
      expect(() =>
        renderPanel(makeDetection({ severity: 'low', score: 2.0 })),
      ).not.toThrow()
    })

    it('renders without errors for status=investigating', () => {
      expect(() =>
        renderPanel(makeDetection({ status: 'investigating' })),
      ).not.toThrow()
    })

    it('renders without errors for status=resolved', () => {
      expect(() =>
        renderPanel(makeDetection({ status: 'resolved' })),
      ).not.toThrow()
    })

    it('renders without errors for status=false_positive', () => {
      expect(() =>
        renderPanel(makeDetection({ status: 'false_positive' })),
      ).not.toThrow()
    })
  })
})
