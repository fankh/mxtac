import { Crosshair } from 'lucide-react'
import type { TacticBar } from '../../../types/api'
import { Card, CardContent } from '@/components/ui/card'
import { EmptyState } from '@/components/ui/empty-state'
import { cn, fmtNum } from '@/lib/utils'

export function TacticsTable({ data, rangeLabel }: { data: TacticBar[]; rangeLabel: string }) {
  const max = Math.max(1, ...data.map((r) => r.count))

  return (
    <Card>
      <CardContent className="p-4">
        <div className="mb-3">
          <h3 className="text-[12px] font-semibold">Top ATT&amp;CK tactics</h3>
          <p className="text-[11px] text-muted-foreground">Detections by tactic, {rangeLabel}</p>
        </div>
        {data.length === 0 ? (
          <EmptyState icon={Crosshair} title="No tactics observed yet" />
        ) : (
          <ul className="space-y-2.5">
            {data.map((row) => (
              <li key={row.tactic}>
                <div className="flex items-baseline justify-between gap-2 text-[12px]">
                  <span className="truncate">{row.tactic}</span>
                  <span className="shrink-0 tabular-nums">
                    <span className="font-medium">{fmtNum(row.count)}</span>
                    {row.trend_pct !== 0 && (
                      <span
                        title="Change against the previous period"
                        className={cn('ml-2 text-[11px]', row.trend_pct > 5 ? 'text-crit-text' : 'text-muted-foreground')}
                      >
                        {row.trend_pct > 0 ? '+' : ''}{row.trend_pct}%
                      </span>
                    )}
                  </span>
                </div>
                <div className="mt-1 h-1.5 rounded-full bg-muted">
                  <div className="h-full rounded-full bg-primary" style={{ width: `${(row.count / max) * 100}%` }} />
                </div>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  )
}
