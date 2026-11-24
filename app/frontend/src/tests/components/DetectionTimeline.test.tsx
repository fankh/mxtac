import type { ReactNode } from 'react'
import { render, screen } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import { DetectionTimeline } from '../../components/features/overview/DetectionTimeline'
import type { TimelinePoint } from '../../types/api'

// Recharts does not lay out in jsdom (ResponsiveContainer has zero size), so the chart
// is replaced by markers that expose what it was given.
vi.mock('recharts', () => ({
  ResponsiveContainer: ({ children }: { children: ReactNode }) => <div data-testid="chart">{children}</div>,
  BarChart: ({ data, children }: { data: unknown[]; children: ReactNode }) => (
    <div data-testid="bar-chart" data-rows={JSON.stringify(data)}>{children}</div>
  ),
  Bar: ({ dataKey, name }: { dataKey: string; name: string }) => <div data-testid="bar" data-key={dataKey}>{name}</div>,
  CartesianGrid: () => null,
  Tooltip: () => null,
  XAxis: () => null,
  YAxis: () => null,
}))

const data: TimelinePoint[] = [
  { date: 'Mon', critical: 5, high: 12, medium: 20, total: 40 },
  { date: 'Tue', critical: 3, high: 8, medium: 15, total: 26 },
]

describe('DetectionTimeline', () => {
  it('shows the heading and the selected range', () => {
    render(<DetectionTimeline data={data} rangeLabel="last 7 days" />)
    expect(screen.getByRole('heading', { name: 'Detections over time' })).toBeInTheDocument()
    expect(screen.getByText('Per day, by severity, last 7 days')).toBeInTheDocument()
  })

  it('draws one stacked series per severity', () => {
    render(<DetectionTimeline data={data} rangeLabel="last 7 days" />)
    const bars = screen.getAllByTestId('bar')
    expect(bars.map((b) => b.textContent)).toEqual(['Critical', 'High', 'Medium', 'Low'])
    expect(bars.map((b) => b.dataset.key)).toEqual(['critical', 'high', 'medium', 'other'])
  })

  it('charts the remainder of the total as the low series, never below zero', () => {
    render(
      <DetectionTimeline
        data={[...data, { date: 'Wed', critical: 4, high: 4, medium: 4, total: 10 }]}
        rangeLabel="last 7 days"
      />,
    )
    const rows = JSON.parse(screen.getByTestId('bar-chart').dataset.rows ?? '[]') as { date: string; other: number }[]
    expect(rows.map((r) => [r.date, r.other])).toEqual([['Mon', 3], ['Tue', 0], ['Wed', 0]])
  })

  it('shows the legend in the empty state too', () => {
    render(<DetectionTimeline data={[]} rangeLabel="last 24 hours" />)
    for (const label of ['Critical', 'High', 'Medium', 'Low']) {
      expect(screen.getByText(label)).toBeInTheDocument()
    }
  })

  it('shows an empty state instead of the chart when there is no data', () => {
    render(<DetectionTimeline data={[]} rangeLabel="last 24 hours" />)
    expect(screen.getByText('No detections in this period')).toBeInTheDocument()
    expect(screen.queryByTestId('chart')).not.toBeInTheDocument()
  })

  it('shows the empty state when every day has zero detections', () => {
    render(
      <DetectionTimeline
        data={[{ date: 'Mon', critical: 0, high: 0, medium: 0, total: 0 }]}
        rangeLabel="last 24 hours"
      />,
    )
    expect(screen.getByText('No detections in this period')).toBeInTheDocument()
  })

  it('shows the chart and no empty state when there are detections', () => {
    render(<DetectionTimeline data={data} rangeLabel="last 7 days" />)
    expect(screen.getByTestId('chart')).toBeInTheDocument()
    expect(screen.queryByText('No detections in this period')).not.toBeInTheDocument()
  })
})
