import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { TacticsTable } from '../../components/features/overview/TacticsTable'
import type { TacticBar } from '../../types/api'

const mockData: TacticBar[] = [
  { tactic: 'Execution', count: 450, trend_pct: 12 },
  { tactic: 'Persistence', count: 210, trend_pct: -3 },
  { tactic: 'Defense Evasion', count: 670, trend_pct: 6 },
]

describe('TacticsTable', () => {
  // ---------------------------------------------------------------------------
  // Header
  // ---------------------------------------------------------------------------
  describe('header', () => {
    it('renders "Top ATT&CK Tactics" heading', () => {
      render(<TacticsTable data={mockData} />)
      expect(screen.getByText('Top ATT&CK Tactics')).toBeInTheDocument()
    })

    it('renders the subtitle text', () => {
      render(<TacticsTable data={mockData} />)
      expect(screen.getByText('Detections this week by tactic')).toBeInTheDocument()
    })

    it('renders Tactic column header', () => {
      render(<TacticsTable data={mockData} />)
      expect(screen.getByText('Tactic')).toBeInTheDocument()
    })

    it('renders Count column header', () => {
      render(<TacticsTable data={mockData} />)
      expect(screen.getByText('Count')).toBeInTheDocument()
    })

    it('renders Trend column header', () => {
      render(<TacticsTable data={mockData} />)
      expect(screen.getByText('Trend')).toBeInTheDocument()
    })
  })

  // ---------------------------------------------------------------------------
  // Row rendering
  // ---------------------------------------------------------------------------
  describe('row rendering', () => {
    it('renders each tactic name', () => {
      render(<TacticsTable data={mockData} />)
      expect(screen.getByText('Execution')).toBeInTheDocument()
      expect(screen.getByText('Persistence')).toBeInTheDocument()
      expect(screen.getByText('Defense Evasion')).toBeInTheDocument()
    })

    it('renders a positive trend with a + prefix', () => {
      render(<TacticsTable data={mockData} />)
      expect(screen.getByText('+12%')).toBeInTheDocument()
    })

    it('renders a negative trend without a + prefix', () => {
      render(<TacticsTable data={mockData} />)
      expect(screen.getByText('-3%')).toBeInTheDocument()
    })

    it('renders trend values for all rows', () => {
      render(<TacticsTable data={mockData} />)
      expect(screen.getByText('+6%')).toBeInTheDocument()
    })

    it('renders an empty table body when data is empty', () => {
      render(<TacticsTable data={[]} />)
      expect(screen.queryByText('Execution')).not.toBeInTheDocument()
    })

    it('renders a single row', () => {
      const single: TacticBar[] = [{ tactic: 'Command and Control', count: 100, trend_pct: 0 }]
      render(<TacticsTable data={single} />)
      expect(screen.getByText('Command and Control')).toBeInTheDocument()
    })

    it('applies crit-text color class when trend > 5%', () => {
      // trend_pct=12 for Execution — isUp=true → text-crit-text
      render(<TacticsTable data={mockData} />)
      const trendEl = screen.getByText('+12%')
      expect(trendEl.className).toContain('text-crit-text')
    })

    it('applies muted color class when trend is not significantly up', () => {
      // trend_pct=-3 for Persistence — isUp=false → text-text-muted
      render(<TacticsTable data={mockData} />)
      const trendEl = screen.getByText('-3%')
      expect(trendEl.className).toContain('text-text-muted')
    })
  })
})
