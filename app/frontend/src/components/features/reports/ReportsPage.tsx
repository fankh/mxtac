import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  AreaChart, Area, BarChart, Bar,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from 'recharts'
import { overviewApi, coverageApi, incidentsApi } from '../../../lib/api'
import { chartColors } from '../../../lib/themeVars'
import { useUIStore } from '../../../stores/uiStore'
import { TopBar } from '../../layout/TopBar'
import type { SeverityLevel } from '../../../types/api'

// ── Types ──────────────────────────────────────────────────────────────────────

type ReportTab = 'coverage' | 'alerts' | 'incidents'
type TimeRange = '7d' | '30d' | '90d'

// ── Helpers ────────────────────────────────────────────────────────────────────

function fmtDuration(seconds: number | null): string {
  if (seconds === null) return '—'
  const m = Math.floor(seconds / 60)
  const h = Math.floor(m / 60)
  if (h > 0) return `${h}h ${m % 60}m`
  return `${m}m`
}

function fmtPct(n: number): string {
  return `${n.toFixed(1)}%`
}

function formatDate(isoDate: string): string {
  const d = new Date(isoDate + 'T00:00:00')
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
}

function daysBack(range: TimeRange): number {
  return range === '7d' ? 7 : range === '30d' ? 30 : 90
}

function fromDate(range: TimeRange): string {
  return new Date(Date.now() - daysBack(range) * 86_400_000).toISOString().slice(0, 10)
}

// ── Sub-components ─────────────────────────────────────────────────────────────

function SeverityBadge({ severity }: { severity: string }) {
  const cls =
    severity === 'critical' ? 'bg-crit-bg text-crit-text' :
    severity === 'high'     ? 'bg-high-bg text-high-text' :
    severity === 'medium'   ? 'bg-med-bg text-med-text'   :
                              'bg-low-bg text-low-text'
  return (
    <span className={`text-[10px] px-1.5 py-[2px] rounded-[3px] font-medium ${cls}`}>
      {severity}
    </span>
  )
}

// ── Stats cards ────────────────────────────────────────────────────────────────

function StatsCards({
  coveragePct, mttdMinutes, mttrSeconds, openIncidents,
}: {
  coveragePct:   number
  mttdMinutes:   number
  mttrSeconds:   number | null
  openIncidents: number
}) {
  return (
    <div className="grid grid-cols-4 gap-3 mb-4">
      {[
        { label: 'ATT&CK Coverage',      value: fmtPct(coveragePct),        sub: 'techniques covered'       },
        { label: 'Mean Time to Detect',  value: `${mttdMinutes}m`,          sub: 'avg detection latency'    },
        { label: 'Mean Time to Resolve', value: fmtDuration(mttrSeconds),   sub: 'avg incident resolution'  },
        { label: 'Open Incidents',       value: openIncidents.toString(),    sub: 'requiring attention'      },
      ].map(({ label, value, sub }) => (
        <div key={label} className="bg-surface rounded-md shadow-card px-4 py-3">
          <p className="text-[10px] text-text-muted uppercase font-medium">{label}</p>
          <p className="text-[22px] font-semibold text-text-primary leading-tight mt-0.5">{value}</p>
          <p className="text-[10px] text-text-muted mt-0.5">{sub}</p>
        </div>
      ))}
    </div>
  )
}

// ── Coverage report ────────────────────────────────────────────────────────────

function CoverageReport({ range }: { range: TimeRange }) {
  const days  = daysBack(range)
  const theme = useUIStore((s) => s.theme)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const c = useMemo(() => chartColors(), [theme])

  const { data: trend, isLoading, isError } = useQuery({
    queryKey: ['reports-coverage-trend', days],
    queryFn:  () => coverageApi.trend(days),
  })

  const chartData = (trend?.points ?? []).map((p) => ({
    date:         formatDate(p.date),
    coverage_pct: p.coverage_pct,
    covered:      p.covered_count,
    total:        p.total_count,
  }))

  const latest = chartData[chartData.length - 1]
  const first  = chartData[0]
  const delta  = latest && first ? latest.coverage_pct - first.coverage_pct : null

  return (
    <div className="space-y-4">
      {/* Trend chart */}
      <div className="bg-surface rounded-md shadow-card">
        <div className="px-4 py-3 border-b border-border">
          <h3 className="text-[12px] font-semibold text-text-primary">ATT&amp;CK Coverage Trend</h3>
          <p className="text-[11px] text-text-muted">Daily coverage percentage snapshots</p>
        </div>
        <div className="px-4 py-4">
          {isLoading && (
            <div className="flex items-center justify-center h-[180px] text-text-muted text-sm">Loading…</div>
          )}
          {isError && (
            <div className="flex items-center justify-center h-[180px] text-crit-text text-sm">
              Failed to load coverage data.
            </div>
          )}
          {!isLoading && !isError && chartData.length === 0 && (
            <div className="flex items-center justify-center h-[180px] text-text-muted text-sm">
              No snapshots yet — coverage will be recorded daily.
            </div>
          )}
          {!isLoading && !isError && chartData.length > 0 && (
            <ResponsiveContainer width="100%" height={180}>
              <AreaChart data={chartData} margin={{ top: 8, right: 0, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="rpt-grad-cov" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%"   stopColor={c.primary} stopOpacity={0.25} />
                    <stop offset="100%" stopColor={c.primary} stopOpacity={0.02} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 0" stroke={c.chartGrid} vertical={false} />
                <XAxis
                  dataKey="date"
                  tick={{ fontSize: 10, fill: c.textMuted }}
                  axisLine={false}
                  tickLine={false}
                  interval="preserveStartEnd"
                />
                <YAxis
                  domain={[0, 100]}
                  tick={{ fontSize: 9, fill: c.textFaint }}
                  axisLine={false}
                  tickLine={false}
                  tickFormatter={(v) => `${v}%`}
                />
                <Tooltip
                  contentStyle={{ fontSize: 11, border: `1px solid ${c.border}`, borderRadius: 6, backgroundColor: c.surface }}
                  labelStyle={{ color: c.textPrimary, fontWeight: 600 }}
                  formatter={(value: number, name: string) => {
                    if (name === 'coverage_pct') return [`${value}%`, 'Coverage']
                    if (name === 'covered')      return [value, 'Techniques covered']
                    return [value, name]
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="coverage_pct"
                  fill="url(#rpt-grad-cov)"
                  stroke={c.primary}
                  strokeWidth={1.5}
                  dot={false}
                  name="coverage_pct"
                />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* Summary */}
      {latest && (
        <div className="bg-surface rounded-md shadow-card px-4 py-4">
          <h3 className="text-[12px] font-semibold text-text-primary mb-3">Coverage Summary</h3>
          <div className="grid grid-cols-3 gap-4">
            <div>
              <p className="text-[10px] text-text-muted uppercase font-medium">Current Coverage</p>
              <p className="text-[20px] font-semibold text-text-primary">{fmtPct(latest.coverage_pct)}</p>
            </div>
            <div>
              <p className="text-[10px] text-text-muted uppercase font-medium">Techniques Covered</p>
              <p className="text-[20px] font-semibold text-text-primary">{latest.covered} / {latest.total}</p>
            </div>
            <div>
              <p className="text-[10px] text-text-muted uppercase font-medium">Trend ({range})</p>
              <p className={`text-[20px] font-semibold ${delta !== null && delta >= 0 ? 'text-low-text' : 'text-crit-text'}`}>
                {delta !== null ? `${delta >= 0 ? '+' : ''}${delta.toFixed(1)}%` : '—'}
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// ── Alert trends report ────────────────────────────────────────────────────────

function AlertTrendsReport({ range }: { range: TimeRange }) {
  const theme = useUIStore((s) => s.theme)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const c = useMemo(() => chartColors(), [theme])

  const { data: timeline, isLoading: tlLoading } = useQuery({
    queryKey: ['reports-timeline', range],
    queryFn:  () => overviewApi.timeline(range),
  })

  const { data: tactics, isLoading: tacLoading } = useQuery({
    queryKey: ['reports-tactics', range],
    queryFn:  () => overviewApi.tactics(range),
  })

  const tlData = (timeline ?? []).map((p) => ({
    date:     formatDate(p.date),
    total:    p.total,
    critical: p.critical,
    high:     p.high,
    medium:   p.medium,
  }))

  const tacData = (tactics ?? []).slice(0, 8).map((t) => ({
    tactic: t.tactic.length > 18 ? t.tactic.slice(0, 18) + '…' : t.tactic,
    count:  t.count,
    trend:  t.trend_pct,
  }))

  return (
    <div className="space-y-4">
      {/* Detection timeline */}
      <div className="bg-surface rounded-md shadow-card">
        <div className="px-4 py-3 border-b border-border flex items-center justify-between">
          <div>
            <h3 className="text-[12px] font-semibold text-text-primary">Detection Timeline</h3>
            <p className="text-[11px] text-text-muted">Alert volume by severity over time</p>
          </div>
          <div className="flex items-center gap-3 text-[10px] text-text-muted">
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded bg-crit-text inline-block" />Critical
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded bg-border inline-block" />Total
            </span>
          </div>
        </div>
        <div className="px-4 py-4">
          {tlLoading && (
            <div className="flex items-center justify-center h-[180px] text-text-muted text-sm">Loading…</div>
          )}
          {!tlLoading && tlData.length === 0 && (
            <div className="flex items-center justify-center h-[180px] text-text-muted text-sm">
              No alert data for this period.
            </div>
          )}
          {!tlLoading && tlData.length > 0 && (
            <ResponsiveContainer width="100%" height={180}>
              <AreaChart data={tlData} margin={{ top: 8, right: 0, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="rpt-grad-total" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%"   stopColor={c.border}   stopOpacity={0.8}  />
                    <stop offset="100%" stopColor={c.border}   stopOpacity={0.1}  />
                  </linearGradient>
                  <linearGradient id="rpt-grad-crit" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%"   stopColor={c.critText} stopOpacity={0.15} />
                    <stop offset="100%" stopColor={c.critText} stopOpacity={0.02} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 0" stroke={c.chartGrid} vertical={false} />
                <XAxis
                  dataKey="date"
                  tick={{ fontSize: 10, fill: c.textMuted }}
                  axisLine={false}
                  tickLine={false}
                  interval="preserveStartEnd"
                />
                <YAxis tick={{ fontSize: 9, fill: c.textFaint }} axisLine={false} tickLine={false} />
                <Tooltip
                  contentStyle={{ fontSize: 11, border: `1px solid ${c.border}`, borderRadius: 6, backgroundColor: c.surface }}
                  labelStyle={{ color: c.textPrimary, fontWeight: 600 }}
                />
                <Area type="monotone" dataKey="total"    fill="url(#rpt-grad-total)" stroke={c.textFaint} strokeWidth={1.5} dot={false} name="Total"    />
                <Area type="monotone" dataKey="critical" fill="url(#rpt-grad-crit)"  stroke={c.critText}  strokeWidth={1.5} dot={false} name="Critical" />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* Top tactics */}
      <div className="bg-surface rounded-md shadow-card">
        <div className="px-4 py-3 border-b border-border">
          <h3 className="text-[12px] font-semibold text-text-primary">Top ATT&amp;CK Tactics</h3>
          <p className="text-[11px] text-text-muted">Most detected tactics by alert count</p>
        </div>
        <div className="px-4 py-4">
          {tacLoading && (
            <div className="flex items-center justify-center h-[160px] text-text-muted text-sm">Loading…</div>
          )}
          {!tacLoading && tacData.length === 0 && (
            <div className="flex items-center justify-center h-[160px] text-text-muted text-sm">
              No tactics data for this period.
            </div>
          )}
          {!tacLoading && tacData.length > 0 && (
            <ResponsiveContainer width="100%" height={Math.max(160, tacData.length * 24)}>
              <BarChart
                data={tacData}
                layout="vertical"
                margin={{ top: 4, right: 16, left: 0, bottom: 4 }}
              >
                <CartesianGrid strokeDasharray="3 0" stroke={c.chartGrid} horizontal={false} />
                <XAxis
                  type="number"
                  tick={{ fontSize: 9, fill: c.textFaint }}
                  axisLine={false}
                  tickLine={false}
                />
                <YAxis
                  type="category"
                  dataKey="tactic"
                  tick={{ fontSize: 10, fill: c.textMuted }}
                  axisLine={false}
                  tickLine={false}
                  width={110}
                />
                <Tooltip
                  contentStyle={{ fontSize: 11, border: `1px solid ${c.border}`, borderRadius: 6, backgroundColor: c.surface }}
                  labelStyle={{ color: c.textPrimary, fontWeight: 600 }}
                />
                <Bar dataKey="count" fill={c.primary} radius={[0, 3, 3, 0]} name="Alerts" />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Incidents report ───────────────────────────────────────────────────────────

function IncidentsReport({ range }: { range: TimeRange }) {
  const today = new Date().toISOString().slice(0, 10)
  const from  = fromDate(range)

  const { data: metrics, isLoading } = useQuery({
    queryKey: ['reports-incident-metrics', from, today],
    queryFn:  () => incidentsApi.metrics(from, today),
  })

  if (isLoading) {
    return <div className="flex items-center justify-center h-40 text-text-muted text-sm">Loading…</div>
  }
  if (!metrics) {
    return <div className="flex items-center justify-center h-40 text-text-muted text-sm">No incident data available.</div>
  }

  const severities: SeverityLevel[] = ['critical', 'high', 'medium', 'low']
  const bySeverity = metrics.incidents_by_severity ?? {}
  const sevTotal   = Object.values(bySeverity).reduce((s, v) => s + (v as number), 0)

  const barCls: Record<SeverityLevel, string> = {
    critical: 'bg-crit-text',
    high:     'bg-high-text',
    medium:   'bg-med-text',
    low:      'bg-low-text',
  }

  return (
    <div className="space-y-4">
      {/* MTTR / MTTD */}
      <div className="bg-surface rounded-md shadow-card px-4 py-4">
        <h3 className="text-[12px] font-semibold text-text-primary mb-3">Response Metrics</h3>
        <div className="grid grid-cols-4 gap-4">
          <div>
            <p className="text-[10px] text-text-muted uppercase font-medium">Mean Time to Detect</p>
            <p className="text-[20px] font-semibold text-text-primary">{fmtDuration(metrics.mttd_seconds)}</p>
            <p className="text-[10px] text-text-muted">avg per incident</p>
          </div>
          <div>
            <p className="text-[10px] text-text-muted uppercase font-medium">Mean Time to Resolve</p>
            <p className="text-[20px] font-semibold text-text-primary">{fmtDuration(metrics.mttr_seconds)}</p>
            <p className="text-[10px] text-text-muted">avg per incident</p>
          </div>
          <div>
            <p className="text-[10px] text-text-muted uppercase font-medium">Incidents this Week</p>
            <p className="text-[20px] font-semibold text-text-primary">{metrics.incidents_this_week}</p>
            <p className="text-[10px] text-text-muted">past 7 days</p>
          </div>
          <div>
            <p className="text-[10px] text-text-muted uppercase font-medium">Incidents this Month</p>
            <p className="text-[20px] font-semibold text-text-primary">{metrics.incidents_this_month}</p>
            <p className="text-[10px] text-text-muted">past 30 days</p>
          </div>
        </div>
      </div>

      {/* Severity breakdown */}
      <div className="bg-surface rounded-md shadow-card overflow-hidden">
        <div className="px-4 py-3 border-b border-border">
          <h3 className="text-[12px] font-semibold text-text-primary">Incidents by Severity</h3>
          <p className="text-[11px] text-text-muted">{from} — {today}</p>
        </div>

        <div className="grid grid-cols-[100px_1fr_60px] gap-2 px-4 py-2 border-b border-section">
          {['Severity', 'Volume', 'Count'].map(h => (
            <span key={h} className="text-[10px] font-medium text-text-muted uppercase">{h}</span>
          ))}
        </div>

        {severities.map((sev) => {
          const count = (bySeverity[sev] as number) ?? 0
          const pct   = sevTotal > 0 ? (count / sevTotal) * 100 : 0
          return (
            <div
              key={sev}
              className="grid grid-cols-[100px_1fr_60px] gap-2 px-4 py-[7px] border-b border-section items-center"
            >
              <SeverityBadge severity={sev} />
              <div className="w-full h-1.5 bg-section rounded-full overflow-hidden">
                <div className={`h-full rounded-full ${barCls[sev]}`} style={{ width: `${pct}%` }} />
              </div>
              <span className="text-[11px] text-text-primary font-medium">{count}</span>
            </div>
          )
        })}

        {/* Status breakdown */}
        <div className="px-4 py-3">
          <p className="text-[10px] text-text-muted uppercase font-medium mb-2">By Status</p>
          <div className="flex flex-wrap gap-2">
            {Object.entries(metrics.total_incidents ?? {}).map(([status, count]) => (
              <div
                key={status}
                className="flex items-center gap-1.5 bg-page border border-border rounded px-2 py-1"
              >
                <span className="text-[10px] text-text-muted capitalize">{status.replace('_', ' ')}</span>
                <span className="text-[11px] font-semibold text-text-primary">{count as number}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Main page ──────────────────────────────────────────────────────────────────

export function ReportsPage() {
  const [tab,   setTab]   = useState<ReportTab>('coverage')
  const [range, setRange] = useState<TimeRange>('30d')

  const { data: kpis } = useQuery({
    queryKey: ['reports-kpis', range],
    queryFn:  () => overviewApi.kpis(range),
  })

  const { data: incMetrics } = useQuery({
    queryKey: ['reports-inc-metrics-kpi'],
    queryFn:  () => incidentsApi.metrics(),
  })

  const tabs: { id: ReportTab; label: string }[] = [
    { id: 'coverage',  label: 'ATT\u0026CK Coverage' },
    { id: 'alerts',    label: 'Alert Trends'         },
    { id: 'incidents', label: 'Incidents'             },
  ]

  return (
    <>
      <TopBar crumb="Reports" />
      <div className="pt-[46px] px-5 pb-6">

        {/* Stats */}
        <StatsCards
          coveragePct={kpis?.attack_coverage_pct ?? 0}
          mttdMinutes={kpis?.mttd_minutes ?? 0}
          mttrSeconds={incMetrics?.mttr_seconds ?? null}
          openIncidents={incMetrics?.open_incidents_count ?? 0}
        />

        {/* Controls */}
        <div className="flex items-center gap-3 mb-4">
          {/* Report tabs */}
          <div className="flex items-center gap-1 bg-section rounded-md p-1">
            {tabs.map((t) => (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                className={`h-[26px] px-3 text-[11px] font-medium rounded transition-colors ${
                  tab === t.id
                    ? 'bg-surface text-text-primary shadow-card'
                    : 'text-text-muted hover:text-text-primary'
                }`}
              >
                {t.label}
              </button>
            ))}
          </div>

          {/* Time range */}
          <div className="flex items-center gap-1.5">
            <span className="text-[10px] text-text-muted">Range:</span>
            {(['7d', '30d', '90d'] as TimeRange[]).map((r) => (
              <button
                key={r}
                onClick={() => setRange(r)}
                className={`text-[10px] px-2 py-[2px] rounded transition-colors ${
                  r === range
                    ? 'bg-blue/20 text-blue font-semibold'
                    : 'text-text-muted hover:text-text-primary'
                }`}
              >
                {r}
              </button>
            ))}
          </div>

          {/* Export placeholder */}
          <div className="ml-auto">
            <button
              className="h-[28px] px-3 text-[11px] border border-border rounded-md text-text-secondary hover:bg-page whitespace-nowrap"
              title="Export — coming soon"
            >
              Export PDF
            </button>
          </div>
        </div>

        {/* Tab content */}
        {tab === 'coverage'  && <CoverageReport      range={range} />}
        {tab === 'alerts'    && <AlertTrendsReport   range={range} />}
        {tab === 'incidents' && <IncidentsReport     range={range} />}
      </div>
    </>
  )
}
