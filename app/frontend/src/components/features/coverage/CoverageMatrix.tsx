import { useQuery } from '@tanstack/react-query'
import { Grid3x3 } from 'lucide-react'
import { EmptyState } from '@/components/ui/empty-state'
import { overviewApi } from '@/lib/api'
import { CoverageCard } from './CoverageCard'
import { heatOpacity } from './coverageUtils'

/**
 * Tactic × technique-family heatmap from GET /overview/coverage/heatmap. Each cell is the
 * number of distinct techniques of that family seen in detections for the tactic, out of the
 * tactic's technique count.
 */
export function CoverageMatrix() {
  const heatmap = useQuery({
    queryKey: ['coverage', 'heatmap'],
    queryFn: () => overviewApi.heatmap(),
  })
  const labels = useQuery({
    queryKey: ['coverage', 'tactic-labels'],
    queryFn: () => overviewApi.tacticLabels(),
  })

  const rows = [...(heatmap.data ?? [])].sort((a, b) => a.row - b.row)
  const tactics = labels.data?.length ? labels.data : rows[0]?.cells.map((c) => c.tactic) ?? []

  return (
    <CoverageCard
      title="Tactic and technique matrix"
      description="Distinct techniques seen in detections, by tactic and technique family"
      loading={heatmap.isLoading || labels.isLoading}
      error={heatmap.isError}
      onRetry={() => { heatmap.refetch(); labels.refetch() }}
      skeletonClass="h-[180px]"
    >
      {rows.length === 0 || tactics.length === 0 ? (
        <EmptyState icon={Grid3x3} title="No matrix data" />
      ) : (
        <>
          <div className="overflow-x-auto">
            <table className="w-full border-separate border-spacing-1" data-testid="coverage-matrix">
              <thead>
                <tr>
                  <th className="w-[72px] text-left text-[11px] font-medium text-muted-foreground sm:w-[260px]">Technique</th>
                  {tactics.map((t) => (
                    <th key={t} scope="col" className="min-w-[56px] text-center text-[11px] font-medium text-muted-foreground">{t}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <tr key={row.technique_id}>
                    <th scope="row" className="text-left text-[12px] font-medium" title={row.technique_name ?? undefined}>
                      <span className="font-mono">{row.technique_id}</span>
                      {row.technique_name && (
                        <span className="ml-1.5 font-normal text-muted-foreground max-sm:hidden">{row.technique_name}</span>
                      )}
                    </th>
                    {tactics.map((tactic) => {
                      const cell = row.cells.find((c) => c.tactic === tactic)
                      if (!cell) return <td key={tactic} className="text-center text-[12px] text-muted-foreground">-</td>
                      return (
                        <td key={tactic} className="p-0">
                          <div
                            className="relative flex h-8 items-center justify-center overflow-hidden rounded-md border border-border"
                            title={`${[row.technique_id, row.technique_name].filter(Boolean).join(' ')} · ${tactic}: ${cell.covered} of ${cell.total} techniques`}
                          >
                            <span
                              className="absolute inset-0 bg-primary"
                              style={{ opacity: heatOpacity(cell.covered, cell.total) * 0.6 }}
                            />
                            <span className="relative text-[12px] tabular-nums text-foreground">
                              {cell.covered}/{cell.total}
                            </span>
                          </div>
                        </td>
                      )
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="mt-3 flex items-center gap-2 text-[11px] text-muted-foreground">
            <span>Fewer</span>
            {[0.15, 0.4, 0.7, 1].map((o) => (
              <span key={o} className="relative h-3 w-5 overflow-hidden rounded-sm border border-border">
                <span className="absolute inset-0 bg-primary" style={{ opacity: o * 0.6 }} />
              </span>
            ))}
            <span>More techniques seen</span>
          </div>
        </>
      )}
    </CoverageCard>
  )
}
