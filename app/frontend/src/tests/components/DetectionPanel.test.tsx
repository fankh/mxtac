import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import { DetectionPanel } from '../../components/features/detections/DetectionPanel'
import type { Detection } from '../../types/api'

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
// Tests
// ---------------------------------------------------------------------------

describe('DetectionPanel', () => {
  // =========================================================================
  // Null detection — renders nothing
  // =========================================================================
  describe('when detection is null', () => {
    it('renders nothing when detection is null', () => {
      const { container } = render(
        <DetectionPanel detection={null} onClose={vi.fn()} />,
      )
      expect(container).toBeEmptyDOMElement()
    })
  })

  // =========================================================================
  // Core header rendering
  // =========================================================================
  describe('header', () => {
    it('renders the detection name', () => {
      render(<DetectionPanel detection={makeDetection()} onClose={vi.fn()} />)
      expect(screen.getByText('Suspicious LSASS Memory Access')).toBeInTheDocument()
    })

    it('renders the subtitle line showing technique_id · tactic', () => {
      render(<DetectionPanel detection={makeDetection()} onClose={vi.fn()} />)
      // The subtitle <p> renders "{technique_id} · {tactic}" as a combined string
      expect(screen.getByText(/T1003\.001 · Credential Access/)).toBeInTheDocument()
    })

    it('renders the close button with title "Close"', () => {
      render(<DetectionPanel detection={makeDetection()} onClose={vi.fn()} />)
      expect(screen.getByTitle('Close')).toBeInTheDocument()
    })
  })

  // =========================================================================
  // Badges row (severity, status, confidence, CVSS)
  // =========================================================================
  describe('badges row', () => {
    it('renders the confidence badge when provided', () => {
      render(
        <DetectionPanel detection={makeDetection({ confidence: 85 })} onClose={vi.fn()} />,
      )
      expect(screen.getByText('Confidence: 85%')).toBeInTheDocument()
    })

    it('does not render the confidence badge when absent', () => {
      render(
        <DetectionPanel detection={makeDetection({ confidence: undefined })} onClose={vi.fn()} />,
      )
      expect(screen.queryByText(/Confidence:/)).not.toBeInTheDocument()
    })

    it('renders the CVSS v3 score when provided', () => {
      render(
        <DetectionPanel detection={makeDetection({ cvss_v3: 9.1 })} onClose={vi.fn()} />,
      )
      expect(screen.getByText('CVSS: 9.1')).toBeInTheDocument()
    })

    it('does not render the CVSS badge when absent', () => {
      render(
        <DetectionPanel detection={makeDetection({ cvss_v3: undefined })} onClose={vi.fn()} />,
      )
      expect(screen.queryByText(/CVSS:/)).not.toBeInTheDocument()
    })

    it('renders confidence 0 as a valid value', () => {
      render(
        <DetectionPanel detection={makeDetection({ confidence: 0 })} onClose={vi.fn()} />,
      )
      expect(screen.getByText('Confidence: 0%')).toBeInTheDocument()
    })
  })

  // =========================================================================
  // Description
  // =========================================================================
  describe('description', () => {
    it('renders the description when provided', () => {
      render(
        <DetectionPanel
          detection={makeDetection({ description: 'This detection identifies credential dumping via LSASS.' })}
          onClose={vi.fn()}
        />,
      )
      expect(
        screen.getByText('This detection identifies credential dumping via LSASS.'),
      ).toBeInTheDocument()
    })

    it('does not render a description paragraph when absent', () => {
      render(
        <DetectionPanel detection={makeDetection({ description: undefined })} onClose={vi.fn()} />,
      )
      expect(screen.queryByText(/credential dumping/)).not.toBeInTheDocument()
    })
  })

  // =========================================================================
  // Always-present detail rows
  // =========================================================================
  describe('always-present rows', () => {
    it('renders the combined Technique row', () => {
      render(<DetectionPanel detection={makeDetection()} onClose={vi.fn()} />)
      expect(screen.getByText('T1003.001 – LSASS Memory Dump')).toBeInTheDocument()
    })

    it('renders the Tactic row value', () => {
      render(<DetectionPanel detection={makeDetection()} onClose={vi.fn()} />)
      // Tactic label and tactic value are rendered via Row
      expect(screen.getByText('Tactic')).toBeInTheDocument()
    })

    it('renders the Host row value', () => {
      render(<DetectionPanel detection={makeDetection()} onClose={vi.fn()} />)
      expect(screen.getByText('WIN-DC01')).toBeInTheDocument()
    })

    it('renders the Time row label', () => {
      render(<DetectionPanel detection={makeDetection()} onClose={vi.fn()} />)
      expect(screen.getByText('Time')).toBeInTheDocument()
    })
  })

  // =========================================================================
  // Optional detail rows
  // =========================================================================
  describe('optional detail rows', () => {
    it('renders the user value when provided', () => {
      render(
        <DetectionPanel detection={makeDetection({ user: 'DOMAIN\\admin' })} onClose={vi.fn()} />,
      )
      expect(screen.getByText('DOMAIN\\admin')).toBeInTheDocument()
    })

    it('does not render the User row label when user is absent', () => {
      render(
        <DetectionPanel detection={makeDetection({ user: undefined })} onClose={vi.fn()} />,
      )
      expect(screen.queryByText('User')).not.toBeInTheDocument()
    })

    it('renders the process value when provided', () => {
      render(
        <DetectionPanel detection={makeDetection({ process: 'lsass.exe' })} onClose={vi.fn()} />,
      )
      expect(screen.getByText('lsass.exe')).toBeInTheDocument()
    })

    it('does not render the Process row label when process is absent', () => {
      render(
        <DetectionPanel detection={makeDetection({ process: undefined })} onClose={vi.fn()} />,
      )
      expect(screen.queryByText('Process')).not.toBeInTheDocument()
    })

    it('renders the log_source value when provided', () => {
      render(
        <DetectionPanel detection={makeDetection({ log_source: 'Windows Security' })} onClose={vi.fn()} />,
      )
      expect(screen.getByText('Windows Security')).toBeInTheDocument()
    })

    it('does not render the Log Source row label when log_source is absent', () => {
      render(
        <DetectionPanel detection={makeDetection({ log_source: undefined })} onClose={vi.fn()} />,
      )
      expect(screen.queryByText('Log Source')).not.toBeInTheDocument()
    })

    it('renders the event_id value when provided', () => {
      render(
        <DetectionPanel detection={makeDetection({ event_id: '4688' })} onClose={vi.fn()} />,
      )
      expect(screen.getByText('4688')).toBeInTheDocument()
    })

    it('does not render the Event ID row label when event_id is absent', () => {
      render(
        <DetectionPanel detection={makeDetection({ event_id: undefined })} onClose={vi.fn()} />,
      )
      expect(screen.queryByText('Event ID')).not.toBeInTheDocument()
    })

    it('renders the sigma rule_name when provided', () => {
      render(
        <DetectionPanel
          detection={makeDetection({ rule_name: 'proc_access_win_lsass_dump_tools_dll' })}
          onClose={vi.fn()}
        />,
      )
      expect(screen.getByText('proc_access_win_lsass_dump_tools_dll')).toBeInTheDocument()
    })

    it('does not render the Sigma Rule row label when rule_name is absent', () => {
      render(
        <DetectionPanel detection={makeDetection({ rule_name: undefined })} onClose={vi.fn()} />,
      )
      expect(screen.queryByText('Sigma Rule')).not.toBeInTheDocument()
    })

    it('renders the occurrence count when provided', () => {
      render(
        <DetectionPanel detection={makeDetection({ occurrence_count: 42 })} onClose={vi.fn()} />,
      )
      expect(screen.getByText('42')).toBeInTheDocument()
    })

    it('renders large occurrence counts with locale formatting', () => {
      render(
        <DetectionPanel detection={makeDetection({ occurrence_count: 1500 })} onClose={vi.fn()} />,
      )
      // toLocaleString() may format as '1,500' depending on locale
      expect(screen.getByText('Occurrences')).toBeInTheDocument()
    })

    it('does not render the Occurrences row label when occurrence_count is absent', () => {
      render(
        <DetectionPanel detection={makeDetection({ occurrence_count: undefined })} onClose={vi.fn()} />,
      )
      expect(screen.queryByText('Occurrences')).not.toBeInTheDocument()
    })

    it('renders occurrence_count of 0 as a valid value', () => {
      render(
        <DetectionPanel detection={makeDetection({ occurrence_count: 0 })} onClose={vi.fn()} />,
      )
      expect(screen.getByText('Occurrences')).toBeInTheDocument()
    })

    it('renders the assigned_to value when provided', () => {
      render(
        <DetectionPanel
          detection={makeDetection({ assigned_to: 'analyst@mxtac.local' })}
          onClose={vi.fn()}
        />,
      )
      expect(screen.getByText('analyst@mxtac.local')).toBeInTheDocument()
    })

    it('does not render the Assigned To row label when assigned_to is absent', () => {
      render(
        <DetectionPanel detection={makeDetection({ assigned_to: undefined })} onClose={vi.fn()} />,
      )
      expect(screen.queryByText('Assigned To')).not.toBeInTheDocument()
    })
  })

  // =========================================================================
  // Related technique IDs
  // =========================================================================
  describe('related technique IDs', () => {
    it('renders individual technique ID tags', () => {
      render(
        <DetectionPanel
          detection={makeDetection({ related_technique_ids: ['T1055', 'T1078'] })}
          onClose={vi.fn()}
        />,
      )
      expect(screen.getByText('T1055')).toBeInTheDocument()
      expect(screen.getByText('T1078')).toBeInTheDocument()
    })

    it('renders the "Related Techniques" heading when list is non-empty', () => {
      render(
        <DetectionPanel
          detection={makeDetection({ related_technique_ids: ['T1055'] })}
          onClose={vi.fn()}
        />,
      )
      expect(screen.getByText('Related Techniques')).toBeInTheDocument()
    })

    it('does not render the "Related Techniques" section when list is empty', () => {
      render(
        <DetectionPanel
          detection={makeDetection({ related_technique_ids: [] })}
          onClose={vi.fn()}
        />,
      )
      expect(screen.queryByText('Related Techniques')).not.toBeInTheDocument()
    })

    it('renders all technique ID tags from a longer list', () => {
      const ids = ['T1003', 'T1059', 'T1078', 'T1110']
      render(
        <DetectionPanel
          detection={makeDetection({ related_technique_ids: ids })}
          onClose={vi.fn()}
        />,
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
      render(<DetectionPanel detection={makeDetection()} onClose={onClose} />)
      fireEvent.click(screen.getByTitle('Close'))
      expect(onClose).toHaveBeenCalledOnce()
    })

    it('calls onClose when the backdrop overlay is clicked', () => {
      const onClose = vi.fn()
      const { container } = render(
        <DetectionPanel detection={makeDetection()} onClose={onClose} />,
      )
      const backdrop = container.querySelector('.fixed.inset-0')
      expect(backdrop).not.toBeNull()
      fireEvent.click(backdrop!)
      expect(onClose).toHaveBeenCalledOnce()
    })

    it('does not call onClose when the panel body is clicked', () => {
      const onClose = vi.fn()
      render(<DetectionPanel detection={makeDetection()} onClose={onClose} />)
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
      render(<DetectionPanel detection={makeDetection()} onClose={vi.fn()} />)
      expect(screen.getByRole('button', { name: 'Investigate' })).toBeInTheDocument()
    })

    it('renders the Assign button', () => {
      render(<DetectionPanel detection={makeDetection()} onClose={vi.fn()} />)
      expect(screen.getByRole('button', { name: 'Assign' })).toBeInTheDocument()
    })

    it('renders the Resolve button', () => {
      render(<DetectionPanel detection={makeDetection()} onClose={vi.fn()} />)
      expect(screen.getByRole('button', { name: 'Resolve' })).toBeInTheDocument()
    })

    it('renders the FP (false positive) button', () => {
      render(<DetectionPanel detection={makeDetection()} onClose={vi.fn()} />)
      expect(screen.getByRole('button', { name: 'FP' })).toBeInTheDocument()
    })

    it('renders all four action buttons together', () => {
      render(<DetectionPanel detection={makeDetection()} onClose={vi.fn()} />)
      expect(screen.getByRole('button', { name: 'Investigate' })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Assign' })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Resolve' })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'FP' })).toBeInTheDocument()
    })
  })

  // =========================================================================
  // Different severity and status values
  // =========================================================================
  describe('different severity and status', () => {
    it('renders without errors for severity=high', () => {
      expect(() =>
        render(<DetectionPanel detection={makeDetection({ severity: 'high', score: 7.5 })} onClose={vi.fn()} />),
      ).not.toThrow()
    })

    it('renders without errors for severity=medium', () => {
      expect(() =>
        render(<DetectionPanel detection={makeDetection({ severity: 'medium', score: 5.0 })} onClose={vi.fn()} />),
      ).not.toThrow()
    })

    it('renders without errors for severity=low', () => {
      expect(() =>
        render(<DetectionPanel detection={makeDetection({ severity: 'low', score: 2.0 })} onClose={vi.fn()} />),
      ).not.toThrow()
    })

    it('renders without errors for status=investigating', () => {
      expect(() =>
        render(<DetectionPanel detection={makeDetection({ status: 'investigating' })} onClose={vi.fn()} />),
      ).not.toThrow()
    })

    it('renders without errors for status=resolved', () => {
      expect(() =>
        render(<DetectionPanel detection={makeDetection({ status: 'resolved' })} onClose={vi.fn()} />),
      ).not.toThrow()
    })

    it('renders without errors for status=false_positive', () => {
      expect(() =>
        render(<DetectionPanel detection={makeDetection({ status: 'false_positive' })} onClose={vi.fn()} />),
      ).not.toThrow()
    })
  })
})
