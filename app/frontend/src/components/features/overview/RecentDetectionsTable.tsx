import type { Detection } from '../../../types/api'
import { ScoreCircle, SeverityPill } from '../../shared/SeverityBadge'
import { StatusPill } from '../../shared/StatusPill'

interface Props {
  data: Detection[]
  onSelect?: (d: Detection) => void
}

export function RecentDetectionsTable({ data, onSelect }: Props) {
  return (
    <div className="bg-surface rounded-md shadow-card p-4">
      <div className="mb-3 flex items-center justify-between">
        <div>
          <h3 className="text-[12px] font-semibold text-text-primary">Recent Critical Detections</h3>
          <p className="text-[11px] text-text-muted">Highest-priority alerts requiring attention</p>
        </div>
        <a href="/detections" className="text-[11px] text-blue hover:underline">View all →</a>
      </div>

      {/* Header */}
      <div className="grid grid-cols-[40px_1fr_160px_100px_80px_90px] gap-2 pb-1 border-b border-border">
        {['Score', 'Detection', 'Technique', 'Host', 'Status', 'Time'].map((h) => (
          <span key={h} className="text-[10px] font-medium text-text-muted uppercase">{h}</span>
        ))}
      </div>

      {data.map((row) => (
        <div
          key={row.id}
          className="grid grid-cols-[40px_1fr_160px_100px_80px_90px] gap-2 py-[6px] border-b border-section items-center cursor-pointer hover:bg-page transition-colors"
          onClick={() => onSelect?.(row)}
        >
          <ScoreCircle score={row.score} severity={row.severity} />
          <div className="min-w-0">
            <div className="text-[11px] text-text-primary truncate">{row.name}</div>
            <div className="text-[10px] text-text-muted">{row.tactic}</div>
          </div>
          <div className="min-w-0">
            <div className="text-[11px] text-text-primary truncate">{row.technique_id}</div>
            <div className="text-[10px] text-text-muted truncate">{row.technique_name}</div>
          </div>
          <span className="text-[11px] text-text-primary truncate">{row.host}</span>
          <StatusPill status={row.status} />
          <span className="text-[10px] text-text-muted">
            {new Date(row.time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
          </span>
        </div>
      ))}
    </div>
  )
}
