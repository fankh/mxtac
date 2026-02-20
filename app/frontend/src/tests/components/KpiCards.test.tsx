import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { KpiCards } from '../../components/features/overview/KpiCards'
import type { KpiMetrics } from '../../types/api'

const mockKpi: KpiMetrics = {
  total_detections: 1234,
  total_detections_delta_pct: 12.5,
  critical_alerts: 7,
  critical_alerts_new_today: 2,
  attack_coverage_pct: 42,
  attack_covered: 84,
  attack_total: 200,
  attack_coverage_delta: 3,
  mttd_minutes: 14,
  mttd_delta_minutes: -3,
  integrations_active: 5,
  integrations_total: 6,
  sigma_rules_active: 2890,
  sigma_rules_critical: 45,
  sigma_rules_high: 180,
  sigma_rules_deployed_this_week: 12,
}

describe('KpiCards', () => {
  // ---------------------------------------------------------------------------
  // Total Detections card
  // ---------------------------------------------------------------------------
  describe('Total Detections card', () => {
    it('renders the "Total Detections" label', () => {
      render(<KpiCards data={mockKpi} />)
      expect(screen.getByText('Total Detections')).toBeInTheDocument()
    })

    it('renders the formatted detection count', () => {
      render(<KpiCards data={mockKpi} />)
      // toLocaleString() is locale-dependent — match digit grouping flexibly
      expect(screen.getByText(/1[,.]?234/)).toBeInTheDocument()
    })

    it('renders the delta percentage', () => {
      render(<KpiCards data={mockKpi} />)
      expect(screen.getByText(/12\.5% vs prev week/)).toBeInTheDocument()
    })
  })

  // ---------------------------------------------------------------------------
  // Critical Alerts card
  // ---------------------------------------------------------------------------
  describe('Critical Alerts card', () => {
    it('renders the "Critical Alerts" label', () => {
      render(<KpiCards data={mockKpi} />)
      expect(screen.getByText('Critical Alerts')).toBeInTheDocument()
    })

    it('renders the critical alert count', () => {
      render(<KpiCards data={mockKpi} />)
      expect(screen.getByText('7')).toBeInTheDocument()
    })

    it('renders new-today sub-label', () => {
      render(<KpiCards data={mockKpi} />)
      expect(screen.getByText('2 new today')).toBeInTheDocument()
    })
  })

  // ---------------------------------------------------------------------------
  // ATT&CK Coverage card
  // ---------------------------------------------------------------------------
  describe('ATT&CK Coverage card', () => {
    it('renders the "ATT&CK Coverage" label', () => {
      render(<KpiCards data={mockKpi} />)
      expect(screen.getByText('ATT&CK Coverage')).toBeInTheDocument()
    })

    it('renders the coverage percentage in the ring gauge', () => {
      render(<KpiCards data={mockKpi} />)
      // attack_covered(84) / attack_total(200) * 100 = 42 → Math.round(42) = 42
      expect(screen.getByText('42%')).toBeInTheDocument()
    })

    it('renders covered/total techniques text', () => {
      render(<KpiCards data={mockKpi} />)
      expect(screen.getByText('84 / 200 techniques')).toBeInTheDocument()
    })

    it('renders the weekly coverage delta', () => {
      render(<KpiCards data={mockKpi} />)
      expect(screen.getByText('+3 this week')).toBeInTheDocument()
    })
  })

  // ---------------------------------------------------------------------------
  // MTTD card
  // ---------------------------------------------------------------------------
  describe('Mean Time to Detect card', () => {
    it('renders the "Mean Time to Detect" label', () => {
      render(<KpiCards data={mockKpi} />)
      expect(screen.getByText('Mean Time to Detect')).toBeInTheDocument()
    })

    it('renders the MTTD value', () => {
      render(<KpiCards data={mockKpi} />)
      expect(screen.getByText('14')).toBeInTheDocument()
    })

    it('renders the "min" unit label', () => {
      render(<KpiCards data={mockKpi} />)
      expect(screen.getByText('min')).toBeInTheDocument()
    })

    it('renders the MTTD improvement label', () => {
      render(<KpiCards data={mockKpi} />)
      // Math.abs(-3) = 3 → "↓ 3m improved"
      expect(screen.getByText(/3m improved/)).toBeInTheDocument()
    })
  })

  // ---------------------------------------------------------------------------
  // Integrations card
  // ---------------------------------------------------------------------------
  describe('Integrations card', () => {
    it('renders the "Integrations" label', () => {
      render(<KpiCards data={mockKpi} />)
      expect(screen.getByText('Integrations')).toBeInTheDocument()
    })

    it('renders the total integrations denominator', () => {
      render(<KpiCards data={mockKpi} />)
      expect(screen.getByText('/ 6')).toBeInTheDocument()
    })
  })

  // ---------------------------------------------------------------------------
  // Sigma Rules card
  // ---------------------------------------------------------------------------
  describe('Sigma Rules Active card', () => {
    it('renders the "Sigma Rules Active" label', () => {
      render(<KpiCards data={mockKpi} />)
      expect(screen.getByText('Sigma Rules Active')).toBeInTheDocument()
    })

    it('renders the formatted sigma rules count', () => {
      render(<KpiCards data={mockKpi} />)
      expect(screen.getByText(/2[,.]?890/)).toBeInTheDocument()
    })

    it('renders the critical and high rule counts', () => {
      render(<KpiCards data={mockKpi} />)
      expect(screen.getByText(/45 critical/)).toBeInTheDocument()
      expect(screen.getByText(/180 high/)).toBeInTheDocument()
    })

    it('renders deployed-this-week note', () => {
      render(<KpiCards data={mockKpi} />)
      expect(screen.getByText('+12 deployed this week')).toBeInTheDocument()
    })
  })

  // ---------------------------------------------------------------------------
  // Grid layout
  // ---------------------------------------------------------------------------
  describe('Grid layout', () => {
    it('renders exactly 6 KPI cards', () => {
      const { container } = render(<KpiCards data={mockKpi} />)
      const grid = container.firstChild as HTMLElement
      expect(grid.children).toHaveLength(6)
    })
  })
})
