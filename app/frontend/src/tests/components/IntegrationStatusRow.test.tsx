import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { IntegrationStatusRow } from '../../components/features/overview/IntegrationStatusRow'
import type { IntegrationStatus } from '../../types/api'

const mockData: IntegrationStatus[] = [
  { id: '1', name: 'Splunk', status: 'connected', metric: '1000 eps' },
  { id: '2', name: 'CrowdStrike', status: 'warning', metric: '50 eps' },
  { id: '3', name: 'Sentinel', status: 'disabled', metric: '0 eps' },
]

describe('IntegrationStatusRow', () => {
  it('renders "Integration Status" heading', () => {
    render(<IntegrationStatusRow data={mockData} />)
    expect(screen.getByText('Integration Status')).toBeInTheDocument()
  })

  it('renders "Connected data sources" subtitle', () => {
    render(<IntegrationStatusRow data={mockData} />)
    expect(screen.getByText('Connected data sources')).toBeInTheDocument()
  })

  it('renders each integration name', () => {
    render(<IntegrationStatusRow data={mockData} />)
    expect(screen.getByText('Splunk')).toBeInTheDocument()
    expect(screen.getByText('CrowdStrike')).toBeInTheDocument()
    expect(screen.getByText('Sentinel')).toBeInTheDocument()
  })

  it('renders an empty integration list when data is empty', () => {
    render(<IntegrationStatusRow data={[]} />)
    expect(screen.queryByText('Splunk')).not.toBeInTheDocument()
  })

  it('renders a single integration', () => {
    const single: IntegrationStatus[] = [
      { id: '1', name: 'Elastic', status: 'connected', metric: '500 eps' },
    ]
    render(<IntegrationStatusRow data={single} />)
    expect(screen.getByText('Elastic')).toBeInTheDocument()
  })

  it('renders one status dot per integration', () => {
    const { container } = render(<IntegrationStatusRow data={mockData} />)
    // Each badge div contains one status dot span (w-[6px] h-[6px] rounded-full)
    const dots = container.querySelectorAll('.rounded-full')
    expect(dots.length).toBeGreaterThanOrEqual(mockData.length)
  })
})
