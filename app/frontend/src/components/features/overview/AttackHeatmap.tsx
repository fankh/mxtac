import type { HeatRow } from '../../../types/api'

interface Props {
  rows: HeatRow[]
  tacticLabels: string[]
}

export function AttackHeatmap({ rows, tacticLabels }: Props) {
  return (
    <div className="bg-surface rounded-md shadow-card p-4">
      <div className="mb-3">
        <h3 className="text-[12px] font-semibold text-text-primary">ATT&amp;CK Coverage Heatmap</h3>
        <p className="text-[11px] text-text-muted">Detection coverage by tactic &amp; sub-technique</p>
      </div>

      {/* Tactic column headers */}
      <div className="grid gap-[3px] mb-1" style={{ gridTemplateColumns: `80px repeat(${tacticLabels.length}, 1fr)` }}>
        <div />
        {tacticLabels.map((label) => (
          <div key={label} className="text-[9px] text-text-muted text-center leading-tight truncate" title={label}>
            {label}
          </div>
        ))}
      </div>

      {/* Rows */}
      <div className="flex flex-col gap-[3px]">
        {rows.map((row) => (
          <div key={row.technique_id} className="grid gap-[3px] items-center" style={{ gridTemplateColumns: `80px repeat(${row.cells.length}, 1fr)` }}>
            <span className="text-[9px] text-text-muted truncate pr-1" title={row.technique_id}>{row.technique_id}</span>
            {row.cells.map((cell, i) => (
              <div
                key={i}
                className="h-[18px] rounded-[2px]"
                style={{
                  backgroundColor: cell.opacity === 0
                    ? '#F0F2F5'
                    : `rgba(0, 102, 204, ${Math.max(0.12, cell.opacity)})`,
                }}
                title={cell.opacity === 0 ? 'No coverage' : `Coverage: ${Math.round(cell.opacity * 100)}%`}
              />
            ))}
          </div>
        ))}
      </div>

      {/* Legend */}
      <div className="flex items-center gap-2 mt-3">
        <span className="text-[10px] text-text-muted">Coverage:</span>
        <div className="flex items-center gap-[2px]">
          {[0, 0.15, 0.35, 0.6, 0.85].map((op) => (
            <div
              key={op}
              className="w-4 h-[10px] rounded-[2px]"
              style={{ backgroundColor: op === 0 ? '#F0F2F5' : `rgba(0, 102, 204, ${op})` }}
            />
          ))}
        </div>
        <span className="text-[10px] text-text-muted">None → Full</span>
      </div>
    </div>
  )
}
