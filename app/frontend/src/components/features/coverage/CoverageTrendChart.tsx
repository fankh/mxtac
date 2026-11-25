import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  CartesianGrid, Line, LineChart, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts'
import { TrendingUp } from 'lucide-react'
import { EmptyState } from '@/components/ui/empty-state'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { coverageApi } from '@/lib/api'
import { chartColors } from '@/lib/themeVars'
import { useUIStore } from '@/stores/uiStore'
import { CoverageCard } from './CoverageCard'
import { TREND_WINDOWS } from './coverageUtils'

function shortDate(iso: string): string {
  const d = new Date(`${iso}T00:00:00`)
  if (Number.isNaN(d.getTime())) return iso
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
}

/** Daily coverage snapshots from GET /coverage/trend, with the target as a reference line. */
export function CoverageTrendChart({ targetPct }: { targetPct: number | undefined }) {
  // Read the theme so the chart colours are re-read when it changes.
  useUIStore((s) => s.theme)
  const c = chartColors()
  const [days, setDays] = useState('30')

  const trend = useQuery({
    queryKey: ['coverage', 'trend', days],
    queryFn: () => coverageApi.trend(Number(days)),
  })

  const points = (trend.data?.points ?? []).map((p) => ({ ...p, label: shortDate(p.date) }))

  return (
    <CoverageCard
      title="Coverage trend"
      description="Daily snapshots of technique coverage"
      loading={trend.isLoading}
      error={trend.isError}
      onRetry={() => trend.refetch()}
      skeletonClass="h-[200px]"
      className="lg:col-span-2"
      action={
        <Select value={days} onValueChange={setDays}>
          <SelectTrigger className="w-[100px] shrink-0" aria-label="Trend window">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {TREND_WINDOWS.map((w) => (
              <SelectItem key={w.value} value={w.value}>{w.label}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      }
    >
      {points.length === 0 ? (
        <EmptyState icon={TrendingUp} title="No snapshots yet" description="A snapshot is stored each day this page is opened, once an enabled rule maps to a technique." />
      ) : (
        <div data-testid="coverage-trend-chart" data-points={points.length}>
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={points} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 0" stroke={c.chartGrid} vertical={false} />
              <XAxis dataKey="label" tick={{ fontSize: 10, fill: c.textMuted }} axisLine={false} tickLine={false} minTickGap={24} />
              <YAxis
                domain={[0, 100]}
                tickFormatter={(v: number) => `${v}%`}
                tick={{ fontSize: 9, fill: c.textFaint }}
                axisLine={false}
                tickLine={false}
              />
              <Tooltip
                formatter={(v: number) => [`${v}%`, 'Coverage']}
                contentStyle={{ fontSize: 11, border: `1px solid ${c.border}`, borderRadius: 6, backgroundColor: c.surface }}
                labelStyle={{ color: c.textPrimary, fontWeight: 600 }}
              />
              {targetPct !== undefined && (
                <ReferenceLine
                  y={targetPct}
                  stroke={c.textMuted}
                  strokeDasharray="4 4"
                  label={{ value: `Target ${targetPct}%`, position: 'insideTopRight', fontSize: 10, fill: c.textMuted }}
                />
              )}
              <Line type="monotone" dataKey="coverage_pct" name="Coverage" stroke={c.primary} strokeWidth={2} dot={points.length < 2} isAnimationActive={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      )}
    </CoverageCard>
  )
}
