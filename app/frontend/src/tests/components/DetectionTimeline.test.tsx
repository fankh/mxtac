import { render, screen } from '@testing-library/react'
import { describe, it, expect, vi, beforeAll } from 'vitest'
import { DetectionTimeline } from '../../components/features/overview/DetectionTimeline'
import type { TimelinePoint } from '../../types/api'

// Recharts' ResponsiveContainer uses ResizeObserver internally.
// Provide a no-op implementation for jsdom.
beforeAll(() => {
  vi.stubGlobal(
    'ResizeObserver',
    vi.fn().mockImplementation(() => ({
      observe: vi.fn(),
      unobserve: vi.fn(),
      disconnect: vi.fn(),
    })),
  )
})

// ---------------------------------------------------------------------------
// Mock data
// ---------------------------------------------------------------------------

const mockData: TimelinePoint[] = [
  { date: 'Mon', critical: 5,  high: 12, medium: 20, total: 37 },
  { date: 'Tue', critical: 3,  high: 8,  medium: 15, total: 26 },
  { date: 'Wed', critical: 7,  high: 14, medium: 22, total: 43 },
  { date: 'Thu', critical: 2,  high: 6,  medium: 10, total: 18 },
  { date: 'Fri', critical: 9,  high: 18, medium: 30, total: 57 },
  { date: 'Sat', critical: 1,  high: 4,  medium: 8,  total: 13 },
  { date: 'Sun', critical: 4,  high: 10, medium: 17, total: 31 },
]

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('DetectionTimeline', () => {
  // -------------------------------------------------------------------------
  // Header
  // -------------------------------------------------------------------------
  describe('header', () => {
    it('renders "Detection Timeline" heading', () => {
      render(<DetectionTimeline data={mockData} />)
      expect(screen.getByText('Detection Timeline')).toBeInTheDocument()
    })

    it('renders "Alerts over past 7 days" subtitle', () => {
      render(<DetectionTimeline data={mockData} />)
      expect(screen.getByText('Alerts over past 7 days')).toBeInTheDocument()
    })
  })

  // -------------------------------------------------------------------------
  // Legend
  // -------------------------------------------------------------------------
  describe('legend', () => {
    it('renders the "Critical" legend label', () => {
      render(<DetectionTimeline data={mockData} />)
      expect(screen.getByText('Critical')).toBeInTheDocument()
    })

    it('renders the "Other" legend label', () => {
      render(<DetectionTimeline data={mockData} />)
      expect(screen.getByText('Other')).toBeInTheDocument()
    })

    it('renders both legend items together', () => {
      render(<DetectionTimeline data={mockData} />)
      expect(screen.getByText('Critical')).toBeInTheDocument()
      expect(screen.getByText('Other')).toBeInTheDocument()
    })
  })

  // -------------------------------------------------------------------------
  // Chart rendering
  // -------------------------------------------------------------------------
  describe('chart rendering', () => {
    it('renders without crashing with typical 7-day data', () => {
      expect(() => render(<DetectionTimeline data={mockData} />)).not.toThrow()
    })

    it('renders without crashing with empty data', () => {
      expect(() => render(<DetectionTimeline data={[]} />)).not.toThrow()
    })

    it('renders without crashing with a single data point', () => {
      const single: TimelinePoint[] = [
        { date: 'Mon', critical: 1, high: 2, medium: 3, total: 6 },
      ]
      expect(() => render(<DetectionTimeline data={single} />)).not.toThrow()
    })

    it('renders without crashing when all values are zero', () => {
      const zeros: TimelinePoint[] = [
        { date: 'Mon', critical: 0, high: 0, medium: 0, total: 0 },
      ]
      expect(() => render(<DetectionTimeline data={zeros} />)).not.toThrow()
    })

    it('renders without crashing with large values', () => {
      const large: TimelinePoint[] = [
        { date: 'Mon', critical: 10000, high: 50000, medium: 100000, total: 160000 },
      ]
      expect(() => render(<DetectionTimeline data={large} />)).not.toThrow()
    })
  })

  // -------------------------------------------------------------------------
  // Layout structure
  // -------------------------------------------------------------------------
  describe('layout structure', () => {
    it('renders the outer surface card container', () => {
      const { container } = render(<DetectionTimeline data={mockData} />)
      expect(container.querySelector('.bg-surface')).toBeInTheDocument()
    })

    it('renders the header flex row with heading and legend side-by-side', () => {
      const { container } = render(<DetectionTimeline data={mockData} />)
      const flexRow = container.querySelector('.flex.items-start.justify-between')
      expect(flexRow).toBeInTheDocument()
    })

    it('heading and legend are both inside the flex header row', () => {
      const { container } = render(<DetectionTimeline data={mockData} />)
      const flexRow = container.querySelector('.flex.items-start.justify-between')
      expect(flexRow).not.toBeNull()
      expect(flexRow!.querySelector('h3')).toBeInTheDocument()
    })

    it('renders the chart wrapper div', () => {
      const { container } = render(<DetectionTimeline data={mockData} />)
      // ResponsiveContainer renders a div wrapper
      expect(container.querySelector('.recharts-responsive-container')).toBeInTheDocument()
    })
  })

  // -------------------------------------------------------------------------
  // Edge cases
  // -------------------------------------------------------------------------
  describe('edge cases', () => {
    it('re-renders without error when data changes from empty to populated', () => {
      const { rerender } = render(<DetectionTimeline data={[]} />)
      expect(() => rerender(<DetectionTimeline data={mockData} />)).not.toThrow()
      expect(screen.getByText('Detection Timeline')).toBeInTheDocument()
    })

    it('re-renders without error when data changes from populated to empty', () => {
      const { rerender } = render(<DetectionTimeline data={mockData} />)
      expect(() => rerender(<DetectionTimeline data={[]} />)).not.toThrow()
      expect(screen.getByText('Detection Timeline')).toBeInTheDocument()
    })
  })
})
