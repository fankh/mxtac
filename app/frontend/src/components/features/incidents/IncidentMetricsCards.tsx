import { useQuery } from '@tanstack/react-query'
import { RefreshCw } from 'lucide-react'
import { apiErrorMessage, incidentsApi } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { SEVERITY_LABELS, SEVERITY_OPTIONS } from '@/lib/severity'
import { formatDuration } from './incidentUtils'

function StatCard({ label, value, hint }: { label: string; value: string; hint: string }) {
  return (
    <Card>
      <CardContent className="p-4">
        <p className="text-[11px] font-medium text-muted-foreground">{label}</p>
        <p className="text-lg font-bold text-foreground">{value}</p>
        <p className="text-[11px] text-muted-foreground">{hint}</p>
      </CardContent>
    </Card>
  )
}

/** Stat cards from GET /incidents/metrics (last 30 days by default). */
export function IncidentMetricsCards() {
  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['incident-metrics'],
    queryFn: () => incidentsApi.metrics(),
  })

  if (isLoading) {
    return (
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4" aria-label="Loading incident metrics">
        {Array.from({ length: 4 }).map((_, index) => (
          <Skeleton key={index} className="h-[84px] rounded-lg" />
        ))}
      </div>
    )
  }

  if (isError || !data) {
    return (
      <Card role="alert">
        <CardContent className="flex flex-wrap items-center justify-between gap-2 p-4">
          <div>
            <p className="text-[12px] font-semibold">Could not load incident metrics</p>
            <p className="text-[11px] text-muted-foreground">{apiErrorMessage(error)}</p>
          </div>
          <Button variant="outline" onClick={() => void refetch()} className="gap-1.5">
            <RefreshCw className="h-3.5 w-3.5" />
            Retry
          </Button>
        </CardContent>
      </Card>
    )
  }

  const total = Object.values(data.total_incidents).reduce((sum, count) => sum + count, 0)
  const bySeverity = SEVERITY_OPTIONS.map(
    (level) => `${data.incidents_by_severity[level] ?? 0} ${SEVERITY_LABELS[level].toLowerCase()}`,
  ).join(' · ')

  return (
    <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
      <StatCard
        label="Open incidents"
        value={data.open_incidents_count.toLocaleString('en-US')}
        hint={`${total.toLocaleString('en-US')} in the last 30 days`}
      />
      <StatCard
        label="New this week"
        value={data.incidents_this_week.toLocaleString('en-US')}
        hint={`${data.incidents_this_month.toLocaleString('en-US')} this month`}
      />
      <StatCard
        label="Mean time to resolve"
        value={formatDuration(data.mttr_seconds)}
        hint={data.mttr_seconds == null ? 'No closed incidents in range' : 'Closed incidents, last 30 days'}
      />
      <StatCard
        label="Mean time to detect"
        value={formatDuration(data.mttd_seconds)}
        hint={bySeverity}
      />
    </div>
  )
}
