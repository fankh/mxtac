import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { AlertCircle } from 'lucide-react'
import { overviewApi } from '../../../lib/api'
import { Page } from '@/components/layout/Page'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { KpiCards } from './KpiCards'
import { DetectionTimeline } from './DetectionTimeline'
import { TacticsTable } from './TacticsTable'
import { AttackHeatmap } from './AttackHeatmap'
import { SourceStatusCard } from './SourceStatusCard'
import { RecentDetectionsTable } from './RecentDetectionsTable'

const RANGES = [
  { value: '24h', label: 'Last 24 hours', phrase: 'last 24 hours' },
  { value: '7d', label: 'Last 7 days', phrase: 'last 7 days' },
  { value: '30d', label: 'Last 30 days', phrase: 'last 30 days' },
  { value: '90d', label: 'Last 90 days', phrase: 'last 90 days' },
]

export function OverviewPage() {
  const [range, setRange] = useState('7d')
  const rangeLabel = RANGES.find((r) => r.value === range)?.phrase ?? ''
  const opts = { staleTime: 30_000, refetchInterval: 60_000 }

  const kpis = useQuery({ queryKey: ['overview', 'kpis', range], queryFn: () => overviewApi.kpis(range), ...opts })
  const timeline = useQuery({ queryKey: ['overview', 'timeline', range], queryFn: () => overviewApi.timeline(range), ...opts })
  const tactics = useQuery({ queryKey: ['overview', 'tactics', range], queryFn: () => overviewApi.tactics(range), ...opts })
  const heatmap = useQuery({ queryKey: ['overview', 'heatmap'], queryFn: () => overviewApi.heatmap(), ...opts })
  const tacticLabels = useQuery({ queryKey: ['overview', 'tacticLabels'], queryFn: () => overviewApi.tacticLabels(), staleTime: Infinity })
  const sources = useQuery({ queryKey: ['overview', 'integrations'], queryFn: () => overviewApi.integrations(), ...opts })
  const recent = useQuery({ queryKey: ['overview', 'recent'], queryFn: () => overviewApi.recentDetections(8), ...opts })

  const rangeSelect = (
    <Select value={range} onValueChange={setRange}>
      <SelectTrigger className="h-8 w-[150px] text-[12px]" aria-label="Time range">
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        {RANGES.map((r) => (
          <SelectItem key={r.value} value={r.value} className="text-[12px]">{r.label}</SelectItem>
        ))}
      </SelectContent>
    </Select>
  )

  return (
    <Page title="Overview" description="Detections, coverage and source health" actions={rangeSelect}>
      {kpis.isLoading && (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-6" aria-label="Loading">
          {Array.from({ length: 6 }, (_, i) => <Skeleton key={i} className="h-[92px] rounded-lg" />)}
        </div>
      )}

      {kpis.isError && (
        <Card>
          <CardContent className="flex items-center gap-3 p-4">
            <AlertCircle className="h-4 w-4 shrink-0 text-destructive" />
            <p className="flex-1 text-[12px]">Could not load the overview. Check that the API is running.</p>
            <Button size="sm" variant="outline" onClick={() => void kpis.refetch()}>Retry</Button>
          </CardContent>
        </Card>
      )}

      {kpis.data && (
        <>
          <KpiCards data={kpis.data} />

          <div className="grid gap-4 xl:grid-cols-3">
            <div className="xl:col-span-2">
              <DetectionTimeline data={timeline.data ?? []} rangeLabel={rangeLabel} />
            </div>
            <TacticsTable data={tactics.data ?? []} rangeLabel={rangeLabel} />
          </div>

          <div className="grid gap-4 xl:grid-cols-3">
            <div className="xl:col-span-2">
              <RecentDetectionsTable data={recent.data ?? []} />
            </div>
            <SourceStatusCard data={sources.data ?? []} />
          </div>

          <AttackHeatmap rows={heatmap.data ?? []} tacticLabels={tacticLabels.data ?? []} />
        </>
      )}
    </Page>
  )
}
