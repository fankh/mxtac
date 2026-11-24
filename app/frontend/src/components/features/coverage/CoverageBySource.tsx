import { useQuery } from '@tanstack/react-query'
import { Database } from 'lucide-react'
import { EmptyState } from '@/components/ui/empty-state'
import { coverageApi } from '@/lib/api'
import { CoverageCard } from './CoverageCard'
import { formatPct, sourceLabel } from './coverageUtils'

/** Coverage per data source (GET /coverage/by-datasource), from the log source of enabled rules. */
export function CoverageBySource() {
  const query = useQuery({
    queryKey: ['coverage', 'by-datasource'],
    queryFn: () => coverageApi.byDatasource(),
  })
  const sources = query.data?.sources ?? []

  return (
    <CoverageCard
      title="Coverage by data source"
      description="Techniques covered by enabled rules for each source"
      loading={query.isLoading}
      error={query.isError}
      onRetry={() => query.refetch()}
      skeletonClass="h-[200px]"
    >
      {sources.length === 0 ? (
        <EmptyState icon={Database} title="No data sources" />
      ) : (
        <>
          <ul className="space-y-3">
            {sources.map((s) => (
              <li key={s.source} data-testid={`source-${s.source}`}>
                <div className="flex items-baseline justify-between gap-2">
                  <span className="text-[12px] font-medium">{sourceLabel(s.source)}</span>
                  <span className="text-[11px] tabular-nums text-muted-foreground">
                    {s.covered_count} of {s.total_count} · {formatPct(s.coverage_pct)}
                  </span>
                </div>
                <div className="mt-1 h-2 rounded-full bg-muted">
                  <div
                    className="h-full rounded-full bg-primary"
                    style={{ width: `${Math.min(100, Math.max(0, s.coverage_pct))}%` }}
                  />
                </div>
                <p className="mt-1 text-[11px] text-muted-foreground">
                  {s.rule_count} enabled {s.rule_count === 1 ? 'rule' : 'rules'}
                </p>
              </li>
            ))}
          </ul>
          {query.data && (
            <p className="mt-3 border-t border-border pt-3 text-[11px] text-muted-foreground">
              All sources combined: {query.data.total_covered_count} of {query.data.total_count} techniques
              ({formatPct(query.data.total_coverage_pct)}). Rules with another log source are not counted here.
            </p>
          )}
        </>
      )}
    </CoverageCard>
  )
}
