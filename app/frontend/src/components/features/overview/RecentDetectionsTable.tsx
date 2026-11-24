import type { Detection } from '../../../types/api'
import { ScoreCircle, SeverityPill } from '../../shared/SeverityBadge'
import { StatusPill } from '../../shared/StatusPill'

interface Props {
  data: Detection[]
  onSelect?: (d: Detection) => void
}

export function RecentDetectionsTable({ data, onSelect }: Props) {
  return (
    <div className="bg-card rounded-md border shadow-sm p-4">
      <div className="mb-3 flex items-center justify-between">
        <div>
          <h3 className="text-[12px] font-semibold text-foreground">Recent Critical Detections</h3>
          <p className="text-[11px] text-muted-foreground">Highest-priority alerts requiring attention</p>
        </div>
        <a href="/detections" className="text-[11px] text-primary hover:underline">View all →</a>
      </div>

      {/* Header */}
      <div className="grid grid-cols-[40px_1fr_160px_100px_80px_90px] gap-2 pb-1 border-b border-border">
        {['Score', 'Detection', 'Technique', 'Host', 'Status', 'Time'].map((h) => (
          <span key={h} className="text-[10px] font-medium text-muted-foreground uppercase">{h}</span>
        ))}
      </div>

      {data.map((row) => (
        <div
          key={row.id}
          className="grid grid-cols-[40px_1fr_160px_100px_80px_90px] gap-2 py-[6px] border-b border-border items-center cursor-pointer hover:bg-background transition-colors"
          onClick={() => onSelect?.(row)}
        >
          <ScoreCircle score={row.score} severity={row.severity} />
          <div className="min-w-0">
            <div className="text-[11px] text-foreground truncate">{row.name}</div>
            <div className="text-[10px] text-muted-foreground">{row.tactic}</div>
          </div>
          <div className="min-w-0">
            <div className="text-[11px] text-foreground truncate">{row.technique_id}</div>
            <div className="text-[10px] text-muted-foreground truncate">{row.technique_name}</div>
          </div>
          <span className="text-[11px] text-foreground truncate">{row.host}</span>
          <StatusPill status={row.status} />
          <span className="text-[10px] text-muted-foreground">
            {new Date(row.time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
          </span>
        </div>
      ))}
    </div>
  )
}
