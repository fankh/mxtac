import type { TacticBar } from '../../../types/api'

const MAX_COUNT = 700

interface Props { data: TacticBar[] }

export function TacticsTable({ data }: Props) {
  return (
    <div className="bg-card rounded-md border shadow-sm p-4">
      <div className="mb-3">
        <h3 className="text-[12px] font-semibold text-foreground">Top ATT&amp;CK Tactics</h3>
        <p className="text-[11px] text-muted-foreground">Detections this week by tactic</p>
      </div>

      {/* Header */}
      <div className="grid grid-cols-[1fr_130px_56px_52px] gap-2 pb-1 border-b border-border">
        <span className="text-[10px] font-medium text-muted-foreground uppercase">Tactic</span>
        <span className="text-[10px] font-medium text-muted-foreground uppercase">Bar</span>
        <span className="text-[10px] font-medium text-muted-foreground uppercase">Count</span>
        <span className="text-[10px] font-medium text-muted-foreground uppercase">Trend</span>
      </div>

      {data.map((row) => {
        const barW = Math.round((row.count / MAX_COUNT) * 130)
        const isUp = row.trend_pct > 5
        return (
          <div key={row.tactic} className="grid grid-cols-[1fr_130px_56px_52px] gap-2 py-[6px] border-b border-border items-center">
            <span className="text-[11px] text-foreground">{row.tactic}</span>
            <div className="h-2 rounded bg-border">
              <div className="h-full rounded bg-primary opacity-70" style={{ width: barW }} />
            </div>
            <span className="text-[11px] text-foreground font-medium">{row.count.toLocaleString()}</span>
            <span className={`text-[11px] ${isUp ? 'text-crit-text' : 'text-muted-foreground'}`}>
              {row.trend_pct > 0 ? '+' : ''}{row.trend_pct}%
            </span>
          </div>
        )
      })}
    </div>
  )
}
