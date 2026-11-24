import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { KpiCards, formatDuration } from '../../components/features/overview/KpiCards'
import type { KpiMetrics } from '../../types/api'

const kpi: KpiMetrics = {
  total_detections: 4821,
  total_detections_delta_pct: 12,
  critical_alerts: 23,
  critical_alerts_new_today: 5,
  attack_coverage_pct: 25,
  attack_covered: 185,
  attack_total: 740,
  attack_coverage_delta: 4,
  mttd_minutes: 8,
  mttd_delta_minutes: -2,
  integrations_active: 6,
  integrations_total: 8,
  sigma_rules_active: 1247,
  sigma_rules_critical: 89,
  sigma_rules_high: 312,
  sigma_rules_deployed_this_week: 14,
  open_incidents_count: 3,
  mttr_minutes: 210,
}

const renderKpis = (overrides: Partial<KpiMetrics> = {}) => render(<KpiCards data={{ ...kpi, ...overrides }} />)

/** The card that holds a given label. */
const card = (label: string) => screen.getByText(label).parentElement as HTMLElement

describe('KpiCards', () => {
  it('shows the six metric labels', () => {
    renderKpis()
    for (const label of [
      'Detections', 'Critical alerts', 'Open incidents', 'ATT&CK coverage', 'Mean time to detect', 'Active Sigma rules',
    ]) {
      expect(screen.getByText(label)).toBeInTheDocument()
    }
  })

  it('shows the values with thousands separators and their hints', () => {
    renderKpis()
    expect(card('Detections')).toHaveTextContent('4,821')
    expect(card('Critical alerts')).toHaveTextContent('23')
    expect(card('Critical alerts')).toHaveTextContent('5 new today')
    expect(card('Open incidents')).toHaveTextContent('3')
    expect(card('Open incidents')).toHaveTextContent('Mean time to resolve: 3.5 h')
    expect(card('Mean time to detect')).toHaveTextContent('8 min')
    expect(card('Active Sigma rules')).toHaveTextContent('1,247')
    expect(card('Active Sigma rules')).toHaveTextContent('89 critical · 312 high')
  })

  it.each([
    [12, '12% vs previous period'],
    [-7, '7% vs previous period'],
    [0, 'No change vs previous period'],
  ])('describes a detections delta of %i%% as "%s"', (pct, text) => {
    renderKpis({ total_detections_delta_pct: pct })
    expect(card('Detections')).toHaveTextContent(text)
  })

  it('derives the coverage percentage from covered and total techniques', () => {
    renderKpis()
    expect(card('ATT&CK coverage')).toHaveTextContent('25%')
    expect(card('ATT&CK coverage')).toHaveTextContent('185 of 740 techniques')
    expect(screen.getByRole('img', { name: '25% covered' })).toBeInTheDocument()
  })

  it('shows 0% coverage when there are no techniques at all', () => {
    renderKpis({ attack_covered: 0, attack_total: 0 })
    expect(card('ATT&CK coverage')).toHaveTextContent('0%')
    expect(card('ATT&CK coverage')).toHaveTextContent('0 of 0 techniques')
  })

  it('shows a dash and a hint when there is no time-to-detect data', () => {
    renderKpis({ mttd_minutes: null })
    expect(card('Mean time to detect')).toHaveTextContent('–')
    expect(card('Mean time to detect')).toHaveTextContent('No incident data yet')
  })

  it('has no "no data" hint when time-to-detect is known', () => {
    renderKpis()
    expect(screen.queryByText('No incident data yet')).not.toBeInTheDocument()
  })

  it('shows a dash when there is no time-to-resolve data', () => {
    renderKpis({ mttr_minutes: null })
    expect(card('Open incidents')).toHaveTextContent('Mean time to resolve: –')
  })
})

describe('formatDuration', () => {
  it.each<[number | null | undefined, string]>([
    [null, '–'],
    [undefined, '–'],
    [0, '0 min'],
    [8.4, '8 min'],
    [89, '89 min'],
    [90, '1.5 h'],
    [210, '3.5 h'],
  ])('formats %s as "%s"', (minutes, text) => {
    expect(formatDuration(minutes)).toBe(text)
  })
})
