import type { ReactNode } from 'react'
import { ArrowDownRight, ArrowUpRight } from 'lucide-react'
import type { KpiMetrics } from '../../../types/api'
import { Card, CardContent } from '@/components/ui/card'
import { cn, fmtNum } from '@/lib/utils'

function Stat({ label, children, hint }: { label: string; children: ReactNode; hint?: ReactNode }) {
  return (
    <Card>
      <CardContent className="flex h-full flex-col gap-1 p-4">
        <span className="text-[11px] font-medium text-muted-foreground">{label}</span>
        {children}
        {hint && <span className="mt-auto text-[11px] text-muted-foreground">{hint}</span>}
      </CardContent>
    </Card>
  )
}

/** Minutes as "42 min" or "3.5 h"; a dash when there is no data yet. */
export function formatDuration(minutes: number | null | undefined): string {
  if (minutes === null || minutes === undefined) return '–'
  if (minutes < 90) return `${Math.round(minutes)} min`
  return `${(minutes / 60).toFixed(1)} h`
}

function Delta({ pct }: { pct: number }) {
  if (pct === 0) return <>No change vs previous period</>
  const up = pct > 0
  const Icon = up ? ArrowUpRight : ArrowDownRight
  return (
    <span className="inline-flex items-center gap-0.5">
      <Icon className={cn('h-3 w-3', up ? 'text-crit-text' : 'text-status-ok-text')} />
      {Math.abs(pct)}% vs previous period
    </span>
  )
}

function CoverageRing({ pct }: { pct: number }) {
  const r = 20
  const c = 2 * Math.PI * r
  return (
    <svg width="48" height="48" viewBox="0 0 48 48" className="shrink-0" role="img" aria-label={`${Math.round(pct)}% covered`}>
      <circle cx="24" cy="24" r={r} fill="none" strokeWidth="5" className="stroke-muted" />
      <circle
        cx="24" cy="24" r={r} fill="none" strokeWidth="5" strokeLinecap="round"
        className="stroke-primary"
        strokeDasharray={`${(Math.min(pct, 100) / 100) * c} ${c}`}
        transform="rotate(-90 24 24)"
      />
    </svg>
  )
}

export function KpiCards({ data }: { data: KpiMetrics }) {
  const coverage = data.attack_total > 0 ? (data.attack_covered / data.attack_total) * 100 : 0

  return (
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-6">
      <Stat label="Detections" hint={<Delta pct={data.total_detections_delta_pct} />}>
        <span className="text-lg font-bold tabular-nums">{fmtNum(data.total_detections)}</span>
      </Stat>

      <Stat label="Critical alerts" hint={`${fmtNum(data.critical_alerts_new_today)} new today`}>
        <span className={cn('text-lg font-bold tabular-nums', data.critical_alerts > 0 && 'text-crit-text')}>
          {fmtNum(data.critical_alerts)}
        </span>
      </Stat>

      <Stat label="Open incidents" hint={`Mean time to resolve: ${formatDuration(data.mttr_minutes)}`}>
        <span className="text-lg font-bold tabular-nums">{fmtNum(data.open_incidents_count)}</span>
      </Stat>

      <Stat label="ATT&CK coverage">
        <div className="flex items-center gap-3">
          <CoverageRing pct={coverage} />
          <div>
            <div className="text-lg font-bold tabular-nums">{Math.round(coverage)}%</div>
            <div className="text-[11px] text-muted-foreground">
              {fmtNum(data.attack_covered)} of {fmtNum(data.attack_total)} techniques
            </div>
          </div>
        </div>
      </Stat>

      <Stat label="Mean time to detect" hint={data.mttd_minutes === null ? 'No incident data yet' : undefined}>
        <span className="text-lg font-bold tabular-nums">{formatDuration(data.mttd_minutes)}</span>
      </Stat>

      <Stat
        label="Active Sigma rules"
        hint={`${fmtNum(data.sigma_rules_critical)} critical · ${fmtNum(data.sigma_rules_high)} high`}
      >
        <span className="text-lg font-bold tabular-nums">{fmtNum(data.sigma_rules_active)}</span>
      </Stat>
    </div>
  )
}
