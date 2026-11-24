import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { BarChart3, RefreshCw } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { EmptyState } from '@/components/ui/empty-state'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { eventsApi } from '@/lib/api'
import { chartColors } from '@/lib/themeVars'
import { useUIStore } from '@/stores/uiStore'
import { FILTER_FIELDS, formatBucketTime, histogramInterval, timeRangeLabel } from './huntUtils'

interface Props {
  timeFrom: string
  /** Add an `equals` filter for a value picked from the top-values list. */
  onPickValue: (field: string, value: string) => void
}

function ChartError({ onRetry }: { onRetry: () => void }) {
  return (
    <div className="flex h-[140px] flex-col items-center justify-center gap-2 text-center">
      <p className="text-[12px] text-destructive">Could not load this chart.</p>
      <Button variant="outline" size="sm" onClick={onRetry}>
        <RefreshCw className="mr-1 h-3 w-3" />
        Retry
      </Button>
    </div>
  )
}

/** Event volume over time and top field values. Both cover every event in the time range. */
export function HuntCharts({ timeFrom, onPickValue }: Props) {
  // Read the theme so the chart colours are re-read when it changes.
  useUIStore((s) => s.theme)
  const c = chartColors()
  const [termsField, setTermsField] = useState('source')
  const interval = histogramInterval(timeFrom)

  const histogram = useQuery({
    queryKey: ['hunt', 'histogram', timeFrom, interval],
    queryFn: () => eventsApi.aggregate({ agg_type: 'date_histogram', interval, time_from: timeFrom, time_to: 'now' }),
  })

  const terms = useQuery({
    queryKey: ['hunt', 'terms', timeFrom, termsField],
    queryFn: () => eventsApi.aggregate({ agg_type: 'terms', field: termsField, size: 8, time_from: timeFrom, time_to: 'now' }),
  })

  const histData = (histogram.data?.buckets ?? []).map((b) => ({
    label: formatBucketTime(b.key, interval),
    count: b.count,
  }))
  const termBuckets = terms.data?.buckets ?? []
  const maxTerm = Math.max(1, ...termBuckets.map((b) => b.count))

  return (
    <div className="grid gap-4 lg:grid-cols-3">
      <Card className="lg:col-span-2">
        <CardContent className="p-4">
          <div className="mb-3">
            <h3 className="text-[12px] font-semibold">Event volume</h3>
            <p className="text-[11px] text-muted-foreground">
              All events, {timeRangeLabel(timeFrom).toLowerCase()} (not narrowed by the query)
            </p>
          </div>
          {histogram.isLoading ? (
            <Skeleton className="h-[140px] w-full" />
          ) : histogram.isError ? (
            <ChartError onRetry={() => histogram.refetch()} />
          ) : histData.length === 0 ? (
            <EmptyState icon={BarChart3} title="No events in this time range" />
          ) : (
            <ResponsiveContainer width="100%" height={140}>
              <BarChart data={histData} margin={{ top: 4, right: 0, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 0" stroke={c.chartGrid} vertical={false} />
                <XAxis dataKey="label" tick={{ fontSize: 10, fill: c.textMuted }} axisLine={false} tickLine={false} minTickGap={24} />
                <YAxis allowDecimals={false} tick={{ fontSize: 9, fill: c.textFaint }} axisLine={false} tickLine={false} />
                <Tooltip
                  cursor={{ fill: c.border, opacity: 0.4 }}
                  contentStyle={{ fontSize: 11, border: `1px solid ${c.border}`, borderRadius: 6, backgroundColor: c.surface }}
                  labelStyle={{ color: c.textPrimary, fontWeight: 600 }}
                />
                <Bar dataKey="count" name="Events" fill={c.primary} radius={[2, 2, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardContent className="p-4">
          <div className="mb-3 flex items-center justify-between gap-2">
            <h3 className="text-[12px] font-semibold">Top values</h3>
            <Select value={termsField} onValueChange={setTermsField}>
              <SelectTrigger className="w-[140px]" aria-label="Top values field">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {FILTER_FIELDS.map((f) => (
                  <SelectItem key={f.value} value={f.value}>{f.label}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          {terms.isLoading ? (
            <div className="space-y-2">
              {[0, 1, 2, 3].map((i) => <Skeleton key={i} className="h-5 w-full" />)}
            </div>
          ) : terms.isError ? (
            <ChartError onRetry={() => terms.refetch()} />
          ) : termBuckets.length === 0 ? (
            <EmptyState icon={BarChart3} title="No values" />
          ) : (
            <ul className="space-y-1">
              {termBuckets.map((b) => (
                <li key={b.key}>
                  <Button
                    variant="ghost"
                    title={b.key ? `Filter by ${b.key}` : 'Empty value'}
                    disabled={!b.key}
                    onClick={() => onPickValue(termsField, b.key)}
                    className="relative h-6 w-full justify-between overflow-hidden px-2 font-normal"
                  >
                    <span
                      className="absolute inset-y-0 left-0 rounded-sm bg-primary/15"
                      style={{ width: `${(b.count / maxTerm) * 100}%` }}
                    />
                    <span className="relative truncate font-mono text-[11px]">{b.key || '(empty)'}</span>
                    <span className="relative ml-2 text-[11px] tabular-nums text-muted-foreground">{b.count.toLocaleString()}</span>
                  </Button>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
