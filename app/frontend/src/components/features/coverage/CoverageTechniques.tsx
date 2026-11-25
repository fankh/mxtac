import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Search, SearchX, ShieldCheck, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { EmptyState } from '@/components/ui/empty-state'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import type { CoverageGaps, NavigatorLayer } from '@/types/api'
import { useTechniqueNames } from '@/hooks/useTechniqueNames'
import { attackUrl, groupTechniques, heatOpacity, shortTechniqueName } from './coverageUtils'

interface QueryState<T> {
  data: T | undefined
  isLoading: boolean
  isError: boolean
  refetch: () => unknown
}

interface Props {
  layer: QueryState<NavigatorLayer>
  gaps: QueryState<CoverageGaps>
}

function LoadError({ what, onRetry }: { what: string; onRetry: () => unknown }) {
  return (
    <div className="flex flex-col items-center gap-2 py-6 text-center" role="alert">
      <p className="text-[12px] text-destructive">Could not load {what}.</p>
      <Button variant="outline" size="sm" onClick={() => onRetry()}>Retry</Button>
    </div>
  )
}

function CoveredTechniques({ layer }: { layer: QueryState<NavigatorLayer> }) {
  const [search, setSearch] = useState('')
  const techniqueName = useTechniqueNames()

  if (layer.isLoading) return <Skeleton className="h-[200px] w-full" />
  if (layer.isError) return <LoadError what="covered techniques" onRetry={layer.refetch} />

  const all = layer.data?.techniques ?? []
  if (all.length === 0) {
    return (
      <EmptyState
        icon={ShieldCheck}
        title="No technique is covered yet"
        description="Enable rules that are mapped to ATT&CK techniques."
      />
    )
  }

  const term = search.trim().toLowerCase()
  const matches = (id: string) =>
    id.toLowerCase().includes(term) || (techniqueName(id) ?? '').toLowerCase().includes(term)
  const groups = groupTechniques(term ? all.filter((t) => matches(t.techniqueID)) : all)
  const maxScore = Math.max(1, ...all.map((t) => t.score))

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="relative w-full max-w-xs">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Escape') setSearch('') }}
            placeholder="Find a technique ID or name"
            aria-label="Find a technique ID or name"
            className="h-8 px-8 text-[12px]"
          />
          {search && (
            <Button
              variant="ghost"
              size="icon"
              title="Clear search"
              onClick={() => setSearch('')}
              className="absolute right-1 top-1/2 h-6 w-6 -translate-y-1/2 text-muted-foreground"
            >
              <X className="h-3.5 w-3.5" />
            </Button>
          )}
        </div>
        <p className="text-[11px] text-muted-foreground">Shade and number: enabled rules per technique (most: {maxScore})</p>
      </div>

      {groups.length === 0 ? (
        <EmptyState icon={SearchX} title="No covered technique matches" />
      ) : (
        <ul className="divide-y divide-border" data-testid="covered-techniques">
          {groups.map((g) => (
            <li key={g.parent} className="flex flex-col gap-1 py-1.5 sm:flex-row sm:items-start sm:gap-3">
              <div className="shrink-0 pt-1 sm:w-[240px]">
                <span className="font-mono text-[12px] font-medium">{g.parent}</span>
                {techniqueName(g.parent) && (
                  <span className="ml-1.5 text-[12px] text-muted-foreground">{techniqueName(g.parent)}</span>
                )}
              </div>
              <div className="flex flex-wrap gap-1">
                {g.techniques.map((t) => (
                  <a
                    key={t.techniqueID}
                    href={attackUrl(t.techniqueID)}
                    target="_blank"
                    rel="noreferrer"
                    title={`${[t.techniqueID, techniqueName(t.techniqueID)].filter(Boolean).join(' ')}: ${t.score} enabled ${t.score === 1 ? 'rule' : 'rules'}`}
                    className="relative inline-flex h-6 items-center gap-1.5 overflow-hidden rounded-md border border-border px-2 transition-colors hover:border-primary"
                  >
                    <span className="absolute inset-0 bg-primary" style={{ opacity: heatOpacity(t.score, maxScore) * 0.6 }} />
                    <span className="relative font-mono text-[11px] text-foreground">{t.techniqueID}</span>
                    {t.techniqueID !== g.parent && techniqueName(t.techniqueID) && (
                      <span className="relative text-[11px] text-foreground">{shortTechniqueName(techniqueName(t.techniqueID))}</span>
                    )}
                    <span className="relative text-[11px] tabular-nums text-foreground">{t.score}</span>
                  </a>
                ))}
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

function GapList({ gaps }: { gaps: QueryState<CoverageGaps> }) {
  const techniqueName = useTechniqueNames()
  if (gaps.isLoading) return <Skeleton className="h-[200px] w-full" />
  if (gaps.isError) return <LoadError what="coverage gaps" onRetry={gaps.refetch} />
  if (!gaps.data) return null

  const ids = [...gaps.data.uncovered_techniques].sort((a, b) => a.localeCompare(b))

  return (
    <div className="space-y-3">
      <p className="text-[12px] text-muted-foreground">
        {gaps.data.gap_count} of {gaps.data.total_count} in-scope techniques have no enabled rule.
        The techniques below already have a rule, but it is disabled.
      </p>
      {ids.length === 0 ? (
        <EmptyState
          icon={ShieldCheck}
          title="No gap can be closed by enabling a rule"
          description="Every technique that a rule in the library covers has at least one enabled rule."
        />
      ) : (
        <>
          <ul className="flex flex-wrap gap-1" data-testid="gap-techniques">
            {ids.map((id) => (
              <li key={id}>
                <a
                  href={attackUrl(id)}
                  target="_blank"
                  rel="noreferrer"
                  title={`${[id, techniqueName(id)].filter(Boolean).join(' ')}: covered only by disabled rules`}
                  className="sev-high inline-flex h-6 items-center gap-1.5 rounded-md border px-2 text-[11px] transition-colors hover:opacity-80"
                >
                  <span className="font-mono">{id}</span>
                  {techniqueName(id) && <span>{techniqueName(id)}</span>}
                </a>
              </li>
            ))}
          </ul>
          <Button asChild variant="outline" size="sm">
            <Link to="/rules">Open rules</Link>
          </Button>
        </>
      )}
    </div>
  )
}

/** Technique-level view: what enabled rules cover (Navigator layer) and the gaps list. */
export function CoverageTechniques({ layer, gaps }: Props) {
  const coveredCount = layer.data?.techniques.length
  const gapCount = gaps.data?.uncovered_techniques.length

  return (
    <Card>
      <CardContent className="p-4">
        <Tabs defaultValue="covered">
          <div className="mb-1 flex flex-wrap items-center justify-between gap-2">
            <h3 className="text-[12px] font-semibold">Techniques</h3>
            <TabsList>
              <TabsTrigger value="covered">Covered{coveredCount !== undefined ? ` (${coveredCount})` : ''}</TabsTrigger>
              <TabsTrigger value="gaps">Gaps{gapCount !== undefined ? ` (${gapCount})` : ''}</TabsTrigger>
            </TabsList>
          </div>
          <TabsContent value="covered"><CoveredTechniques layer={layer} /></TabsContent>
          <TabsContent value="gaps"><GapList gaps={gaps} /></TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  )
}
