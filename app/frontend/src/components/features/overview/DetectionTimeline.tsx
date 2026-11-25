import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { LineChart } from 'lucide-react'
import type { TimelinePoint } from '../../../types/api'
import { Card, CardContent } from '@/components/ui/card'
import { EmptyState } from '@/components/ui/empty-state'
import { chartColors, cssVar } from '../../../lib/themeVars'
import { useUIStore } from '../../../stores/uiStore'

const SERIES = [
  { key: 'critical', label: 'Critical', color: '--sev-critical-text' },
  { key: 'high', label: 'High', color: '--sev-high-text' },
  { key: 'medium', label: 'Medium', color: '--sev-medium-text' },
  { key: 'other', label: 'Low', color: '--sev-low-text' },
] as const

export function DetectionTimeline({ data, rangeLabel }: { data: TimelinePoint[]; rangeLabel: string }) {
  useUIStore((s) => s.theme) // re-render on theme change so the chart re-reads the colour tokens
  const c = chartColors()
  const rows = data.map((p) => ({ ...p, other: Math.max(0, p.total - p.critical - p.high - p.medium) }))
  const empty = rows.every((p) => p.total === 0)

  return (
    <Card>
      <CardContent className="p-4">
        <div className="mb-3 flex items-start justify-between gap-3">
          <div>
            <h3 className="text-[12px] font-semibold">Detections over time</h3>
            <p className="text-[11px] text-muted-foreground">Per day, by severity, {rangeLabel}</p>
          </div>
          <div className="flex flex-wrap items-center gap-3 text-[11px] text-muted-foreground">
            {SERIES.map((s) => (
              <span key={s.key} className="flex items-center gap-1">
                <span className="inline-block h-2 w-2 rounded-sm" style={{ background: `var(${s.color})` }} />
                {s.label}
              </span>
            ))}
          </div>
        </div>
        {empty ? (
          <EmptyState icon={LineChart} title="No detections in this period" />
        ) : (
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={rows} margin={{ top: 4, right: 0, left: -20, bottom: 0 }}>
              <CartesianGrid stroke={c.chartGrid} vertical={false} />
              <XAxis dataKey="date" tick={{ fontSize: 10, fill: c.textMuted }} axisLine={false} tickLine={false} minTickGap={16} />
              <YAxis tick={{ fontSize: 10, fill: c.textMuted }} axisLine={false} tickLine={false} allowDecimals={false} />
              <Tooltip
                cursor={{ fill: c.border, opacity: 0.4 }}
                contentStyle={{ fontSize: 11, border: `1px solid ${c.border}`, borderRadius: 6, backgroundColor: c.surface }}
                labelStyle={{ color: c.textPrimary, fontWeight: 600 }}
              />
              {SERIES.map((s, i) => (
                <Bar
                  key={s.key}
                  dataKey={s.key}
                  name={s.label}
                  stackId="sev"
                  fill={cssVar(s.color)}
                  maxBarSize={28}
                  radius={i === SERIES.length - 1 ? [3, 3, 0, 0] : 0}
                />
              ))}
            </BarChart>
          </ResponsiveContainer>
        )}
      </CardContent>
    </Card>
  )
}
