import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import { RecentDetectionsTable } from '../../components/features/overview/RecentDetectionsTable'
import type { Detection } from '../../types/api'

const makeDetection = (overrides: Partial<Detection> = {}): Detection => ({
  id: 'd1',
  score: 9.1,
  severity: 'critical',
  technique_id: 'T1059',
  technique_name: 'Command and Scripting Interpreter',
  name: 'PowerShell Execution',
  host: 'ws-001',
  tactic: 'Execution',
  status: 'active',
  time: '2024-01-15T14:30:00Z',
  related_technique_ids: [],
  ...overrides,
})

describe('RecentDetectionsTable', () => {
  // ---------------------------------------------------------------------------
  // Header
  // ---------------------------------------------------------------------------
  describe('header', () => {
    it('renders "Recent Critical Detections" heading', () => {
      render(<RecentDetectionsTable data={[]} />)
      expect(screen.getByText('Recent Critical Detections')).toBeInTheDocument()
    })

    it('renders the subtitle text', () => {
      render(<RecentDetectionsTable data={[]} />)
      expect(screen.getByText('Highest-priority alerts requiring attention')).toBeInTheDocument()
    })

    it('renders a "View all →" link pointing to /detections', () => {
      render(<RecentDetectionsTable data={[]} />)
      const link = screen.getByText('View all →')
      expect(link).toBeInTheDocument()
      expect(link).toHaveAttribute('href', '/detections')
    })

    it('renders all 6 column headers', () => {
      render(<RecentDetectionsTable data={[]} />)
      for (const header of ['Score', 'Detection', 'Technique', 'Host', 'Status', 'Time']) {
        expect(screen.getByText(header)).toBeInTheDocument()
      }
    })
  })

  // ---------------------------------------------------------------------------
  // Empty state
  // ---------------------------------------------------------------------------
  describe('empty state', () => {
    it('renders no data rows when data is empty', () => {
      const { container } = render(<RecentDetectionsTable data={[]} />)
      // Only the header row should be present inside the grid
      const gridRows = container.querySelectorAll('.grid.grid-cols-\\[40px_1fr_160px_100px_80px_90px\\]')
      expect(gridRows).toHaveLength(1) // header only
    })
  })

  // ---------------------------------------------------------------------------
  // Row rendering
  // ---------------------------------------------------------------------------
  describe('row rendering', () => {
    it('renders the detection name', () => {
      render(<RecentDetectionsTable data={[makeDetection()]} />)
      expect(screen.getByText('PowerShell Execution')).toBeInTheDocument()
    })

    it('renders the tactic name', () => {
      render(<RecentDetectionsTable data={[makeDetection()]} />)
      expect(screen.getByText('Execution')).toBeInTheDocument()
    })

    it('renders the technique ID', () => {
      render(<RecentDetectionsTable data={[makeDetection()]} />)
      expect(screen.getByText('T1059')).toBeInTheDocument()
    })

    it('renders the technique name', () => {
      render(<RecentDetectionsTable data={[makeDetection()]} />)
      expect(screen.getByText('Command and Scripting Interpreter')).toBeInTheDocument()
    })

    it('renders the host name', () => {
      render(<RecentDetectionsTable data={[makeDetection()]} />)
      expect(screen.getByText('ws-001')).toBeInTheDocument()
    })

    it('renders the status pill', () => {
      render(<RecentDetectionsTable data={[makeDetection({ status: 'active' })]} />)
      expect(screen.getByText('Active')).toBeInTheDocument()
    })

    it('renders multiple rows', () => {
      const rows = [
        makeDetection({ id: '1', name: 'First', host: 'host-1' }),
        makeDetection({ id: '2', name: 'Second', host: 'host-2' }),
      ]
      render(<RecentDetectionsTable data={rows} />)
      expect(screen.getByText('First')).toBeInTheDocument()
      expect(screen.getByText('Second')).toBeInTheDocument()
    })
  })

  // ---------------------------------------------------------------------------
  // onSelect callback
  // ---------------------------------------------------------------------------
  describe('onSelect callback', () => {
    it('calls onSelect when a row is clicked', () => {
      const onSelect = vi.fn()
      const detection = makeDetection()
      render(<RecentDetectionsTable data={[detection]} onSelect={onSelect} />)
      fireEvent.click(screen.getByText('PowerShell Execution'))
      expect(onSelect).toHaveBeenCalledWith(detection)
    })

    it('does not throw when onSelect is not provided and a row is clicked', () => {
      render(<RecentDetectionsTable data={[makeDetection()]} />)
      expect(() => fireEvent.click(screen.getByText('PowerShell Execution'))).not.toThrow()
    })
  })
})
