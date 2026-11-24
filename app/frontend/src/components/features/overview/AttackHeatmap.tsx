import { Link } from 'react-router-dom'
import type { HeatRow } from '../../../types/api'
import { Card, CardContent } from '@/components/ui/card'

interface Props {
  rows: HeatRow[]
  tacticLabels: string[]
}

const LEGEND = [0, 0.2, 0.4, 0.65, 0.9]

/** Background tint for a cell; none when nothing is covered (the API's opacity has a 0.1 floor). */
function cellStyle(opacity: number, covered = 1) {
  return covered === 0 || opacity === 0 ? undefined : { backgroundColor: `hsl(var(--primary) / ${Math.max(0.15, opacity)})` }
}

export function AttackHeatmap({ rows, tacticLabels }: Props) {
  const columns = { gridTemplateColumns: `72px repeat(${tacticLabels.length || 1}, minmax(0, 1fr))` }

  return (
    <Card>
      <CardContent className="p-4">
        <div className="mb-3 flex items-start justify-between gap-3">
          <div>
            <h3 className="text-[12px] font-semibold">ATT&amp;CK coverage heatmap</h3>
            <p className="text-[11px] text-muted-foreground">Detected sub-techniques by tactic and technique family</p>
          </div>
          <Link to="/coverage" className="shrink-0 text-[11px] text-primary transition-colors hover:underline">
            Open coverage
          </Link>
        </div>

        <div className="grid gap-1" style={columns}>
          <div />
          {tacticLabels.map((label) => (
            <div key={label} className="truncate text-center text-[10px] text-muted-foreground" title={label}>
              {label}
            </div>
          ))}
        </div>

        <div className="mt-1 flex flex-col gap-1">
          {rows.map((row) => (
            <div key={row.technique_id} className="grid items-center gap-1" style={columns}>
              <span className="truncate pr-1 font-mono text-[10px] text-muted-foreground" title={row.technique_id}>
                {row.technique_id}
              </span>
              {row.cells.map((cell) => (
                <div
                  key={cell.tactic}
                  data-testid="heat-cell"
                  className="h-5 rounded-sm bg-muted"
                  style={cellStyle(cell.opacity, cell.covered)}
                  title={`${row.technique_id} · ${cell.tactic}: ${cell.covered} of ${cell.total}`}
                />
              ))}
            </div>
          ))}
        </div>

        <div className="mt-3 flex items-center gap-2 text-[11px] text-muted-foreground">
          <span>None</span>
          <div className="flex items-center gap-0.5">
            {LEGEND.map((op) => (
              <div key={op} className="h-2.5 w-4 rounded-sm bg-muted" style={cellStyle(op)} />
            ))}
          </div>
          <span>Full</span>
        </div>
      </CardContent>
    </Card>
  )
}
