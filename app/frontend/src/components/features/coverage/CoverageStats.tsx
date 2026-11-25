import type { ReactNode } from 'react'
import { Pencil } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { cn } from '@/lib/utils'
import type { CoverageGaps, CoverageSummary, CoverageTarget } from '@/types/api'
import { formatPct } from './coverageUtils'

interface Props {
  summary: CoverageSummary | undefined
  gaps: CoverageGaps | undefined
  target: CoverageTarget | undefined
  loading: boolean
  canEditTarget: boolean
  onEditTarget: () => void
}

function Stat({
  label, loading, action, children,
}: {
  label: string
  loading: boolean
  action?: ReactNode
  children: ReactNode
}) {
  return (
    <Card>
      <CardContent className="p-4">
        <div className="flex h-6 items-center justify-between gap-2">
          <p className="text-[11px] font-medium text-muted-foreground">{label}</p>
          {action}
        </div>
        {loading ? <Skeleton className="mt-1 h-10 w-full" /> : children}
      </CardContent>
    </Card>
  )
}

function targetStatus(target: CoverageTarget): { label: string; cls: string } {
  if (!target.enabled) return { label: 'Not flagged', cls: 'sev-info' }
  if (target.is_below_threshold) return { label: 'Below target', cls: 'sev-high' }
  return { label: 'On target', cls: 'status-green' }
}

/** Headline numbers: coverage against the target, the target itself and the gaps. */
export function CoverageStats({ summary, gaps, target, loading, canEditTarget, onEditTarget }: Props) {
  const status = target ? targetStatus(target) : null
  const delta = summary && target ? Math.round((summary.coverage_pct - target.target_pct) * 10) / 10 : null

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <Stat label="Technique coverage" loading={loading}>
        {summary ? (
          <>
            <p className="text-lg font-bold tabular-nums" data-testid="coverage-pct">{formatPct(summary.coverage_pct)}</p>
            <div
              className="relative mt-1 h-2 rounded-full bg-muted"
              role="progressbar"
              aria-label="Technique coverage"
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuenow={summary.coverage_pct}
            >
              <div
                className="h-full rounded-full bg-primary"
                style={{ width: `${Math.min(100, Math.max(0, summary.coverage_pct))}%` }}
              />
              {target && (
                <span
                  className="absolute -top-1 h-4 w-0.5 rounded bg-foreground"
                  style={{ left: `${Math.min(100, Math.max(0, target.target_pct))}%` }}
                  title={`Target ${formatPct(target.target_pct)}`}
                />
              )}
            </div>
            <p className="mt-2 text-[11px] text-muted-foreground">
              {summary.covered_count} of {summary.total_count} techniques have an enabled rule
            </p>
          </>
        ) : (
          <p className="text-lg font-bold">-</p>
        )}
      </Stat>

      <Stat
        label="Target"
        loading={loading}
        action={canEditTarget && (
          <Button variant="ghost" size="sm" onClick={onEditTarget} className="-mr-2">
            <Pencil className="mr-1 h-3 w-3" />
            Edit target
          </Button>
        )}
      >
        {target && status ? (
          <>
            <div className="flex items-center gap-2">
              <p className="text-lg font-bold tabular-nums" data-testid="target-pct">{formatPct(target.target_pct)}</p>
              <span className={cn('inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-medium leading-none', status.cls)}>
                {status.label}
              </span>
            </div>
            <p className="mt-1 text-[11px] text-muted-foreground">
              {target.label ? `${target.label} · ` : ''}
              {delta === null
                ? ''
                : delta >= 0
                  ? `${delta} points above target`
                  : `${Math.abs(delta)} points below target`}
            </p>
          </>
        ) : (
          <p className="text-lg font-bold">-</p>
        )}
      </Stat>

      <Stat label="Techniques without a rule" loading={loading}>
        {gaps ? (
          <>
            <p className="text-lg font-bold tabular-nums" data-testid="gap-count">{gaps.gap_count}</p>
            <p className="mt-1 text-[11px] text-muted-foreground">of {gaps.total_count} in scope</p>
          </>
        ) : (
          <p className="text-lg font-bold">-</p>
        )}
      </Stat>

      <Stat label="Covered only by disabled rules" loading={loading}>
        {gaps ? (
          <>
            <p className="text-lg font-bold tabular-nums" data-testid="disabled-gap-count">{gaps.uncovered_techniques.length}</p>
            <p className="mt-1 text-[11px] text-muted-foreground">Enable those rules to close these gaps</p>
          </>
        ) : (
          <p className="text-lg font-bold">-</p>
        )}
      </Stat>
    </div>
  )
}
