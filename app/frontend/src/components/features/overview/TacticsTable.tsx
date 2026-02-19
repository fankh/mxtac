import type { TacticBar } from '../../../types/api'

const MAX_COUNT = 700

interface Props { data: TacticBar[] }

export function TacticsTable({ data }: Props) {
  return (
    <div className="bg-surface rounded-md shadow-card p-4">
      <div className="mb-3">
        <h3 className="text-[12px] font-semibold text-text-primary">Top ATT&amp;CK Tactics</h3>
        <p className="text-[11px] text-text-muted">Detections this week by tactic</p>
      </div>

      {/* Header */}
      <div className="grid grid-cols-[1fr_130px_56px_52px] gap-2 pb-1 border-b border-border">
        <span className="text-[10px] font-medium text-text-muted uppercase">Tactic</span>
        <span className="text-[10px] font-medium text-text-muted uppercase">Bar</span>
        <span className="text-[10px] font-medium text-text-muted uppercase">Count</span>
        <span className="text-[10px] font-medium text-text-muted uppercase">Trend</span>
      </div>

      {data.map((row) => {
        const barW = Math.round((row.count / MAX_COUNT) * 130)
        const isUp = row.trend_pct > 5
        return (
          <div key={row.tactic} className="grid grid-cols-[1fr_130px_56px_52px] gap-2 py-[6px] border-b border-section items-center">
            <span className="text-[11px] text-text-primary">{row.tactic}</span>
            <div className="h-2 rounded bg-border">
              <div className="h-full rounded bg-blue opacity-70" style={{ width: barW }} />
            </div>
            <span className="text-[11px] text-text-primary font-medium">{row.count.toLocaleString()}</span>
            <span className={`text-[11px] ${isUp ? 'text-crit-text' : 'text-text-muted'}`}>
              {row.trend_pct > 0 ? '+' : ''}{row.trend_pct}%
            </span>
          </div>
        )
      })}
    </div>
  )
}
