import { useState } from 'react'
import { keepPreviousData, useMutation, useQuery } from '@tanstack/react-query'
import { BookmarkPlus, Download, Lock } from 'lucide-react'
import { Page } from '@/components/layout/Page'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import { EmptyState } from '@/components/ui/empty-state'
import { apiErrorMessage, eventsApi } from '@/lib/api'
import { useAuthStore } from '@/stores/authStore'
import { useUIStore } from '@/stores/uiStore'
import type { EventItem, SavedQuery, SearchRequest } from '@/types/api'
import { EventDetailSheet } from './EventDetailSheet'
import { HuntCharts } from './HuntCharts'
import { HuntResults } from './HuntResults'
import { HuntSearchForm } from './HuntSearchForm'
import { SaveQueryDialog, SavedQueriesPanel } from './SavedQueries'
import { HUNT_ROLES, PAGE_SIZE, buildSearchRequest, newFilterRow, toFilterRows, type FilterRow } from './huntUtils'
import { downloadBlob } from '@/lib/download'

const TITLE = 'Hunt'
const DESCRIPTION = 'Search raw events and keep the queries you reuse'
const DEFAULT_TIME_FROM = 'now-24h'

function HuntWorkspace() {
  const addNotification = useUIStore((s) => s.addNotification)

  // Form state (what the user is editing) and the search that was last run.
  const [query, setQuery] = useState('')
  const [timeFrom, setTimeFrom] = useState(DEFAULT_TIME_FROM)
  const [filters, setFilters] = useState<FilterRow[]>([])
  const [submitted, setSubmitted] = useState<SearchRequest>(() => buildSearchRequest('', [], DEFAULT_TIME_FROM))
  const [page, setPage] = useState(0)

  const [selected, setSelected] = useState<EventItem | null>(null)
  const [saveOpen, setSaveOpen] = useState(false)
  const [activeSavedId, setActiveSavedId] = useState<string | null>(null)

  const search = useQuery({
    queryKey: ['hunt', 'search', submitted, page],
    queryFn: () => eventsApi.search({ ...submitted, size: PAGE_SIZE, from_: page * PAGE_SIZE }),
    placeholderData: keepPreviousData,
  })

  const dsl = useQuery({
    queryKey: ['hunt', 'dsl', submitted],
    queryFn: () => eventsApi.queryDsl(submitted),
  })

  const exportMutation = useMutation({
    mutationFn: () => eventsApi.exportCsv(submitted),
    onSuccess: (blob) => {
      downloadBlob(blob, `events_${new Date().toISOString().slice(0, 10)}.csv`)
    },
    onError: (e: unknown) => {
      addNotification({ type: 'error', title: 'Could not export events', message: apiErrorMessage(e) })
    },
  })

  function run(nextQuery: string, nextFilters: FilterRow[], nextTimeFrom: string) {
    const request = buildSearchRequest(nextQuery, nextFilters, nextTimeFrom)
    const unchanged = JSON.stringify(request) === JSON.stringify(submitted)
    setSubmitted(request)
    setPage(0)
    // Same search again: the query key does not change, so ask for fresh results.
    if (unchanged && page === 0) search.refetch()
  }

  function handleSearch() {
    setActiveSavedId(null)
    run(query, filters, timeFrom)
  }

  function handleTimeFromChange(value: string) {
    setTimeFrom(value)
    run(query, filters, value)
  }

  function addFilterAndRun(field: string, value: string) {
    const next = [...filters, newFilterRow({ field, operator: 'eq', value })]
    setFilters(next)
    setSelected(null)
    setActiveSavedId(null)
    run(query, next, timeFrom)
  }

  function loadSavedQuery(saved: SavedQuery) {
    const rows = toFilterRows(saved.filters)
    setQuery(saved.query ?? '')
    setFilters(rows)
    setTimeFrom(saved.time_from)
    setActiveSavedId(saved.id)
    run(saved.query ?? '', rows, saved.time_from)
  }

  const formSearch = buildSearchRequest(query, filters, timeFrom)
  const ranTimeFrom = submitted.time_from ?? DEFAULT_TIME_FROM

  return (
    <Page
      title={TITLE}
      description={DESCRIPTION}
      actions={
        <>
          <Button
            variant="outline"
            onClick={() => exportMutation.mutate()}
            disabled={exportMutation.isPending || (search.data?.total ?? 0) === 0}
            title="Export the matching events as CSV (up to 10,000 rows)"
          >
            <Download className="mr-1 h-3.5 w-3.5" />
            {exportMutation.isPending ? 'Exporting…' : 'Export CSV'}
          </Button>
          <Button onClick={() => setSaveOpen(true)}>
            <BookmarkPlus className="mr-1 h-3.5 w-3.5" />
            Save query
          </Button>
        </>
      }
    >
      <HuntSearchForm
        query={query}
        onQueryChange={setQuery}
        timeFrom={timeFrom}
        onTimeFromChange={handleTimeFromChange}
        filters={filters}
        onFiltersChange={setFilters}
        onSearch={handleSearch}
        searching={search.isFetching}
      />

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1fr)_280px]">
        <div className="min-w-0">
          <HuntCharts timeFrom={ranTimeFrom} onPickValue={addFilterAndRun} />
        </div>
        <div>
          <SavedQueriesPanel search={formSearch} activeId={activeSavedId} onLoad={loadSavedQuery} />
        </div>
      </div>

      {/* Below the charts and at full width: the summary column needs the room. */}
      <HuntResults
        data={search.data}
        loading={search.isLoading}
        error={search.isError}
        errorMessage={search.isError ? apiErrorMessage(search.error, '') : undefined}
        onRetry={() => search.refetch()}
        page={page}
        onPageChange={setPage}
        onSelect={setSelected}
        lucene={dsl.data?.lucene}
      />

      <EventDetailSheet
        event={selected}
        timeFrom={ranTimeFrom}
        onClose={() => setSelected(null)}
        onAddFilter={addFilterAndRun}
      />

      <SaveQueryDialog
        open={saveOpen}
        onOpenChange={setSaveOpen}
        search={formSearch}
        onSaved={(saved) => setActiveSavedId(saved.id)}
      />
    </Page>
  )
}

/** Event search with saved queries. The backend limits it to hunter, engineer and admin. */
export function HuntPage() {
  const role = useAuthStore((s) => s.user?.role)

  if (role && !HUNT_ROLES.includes(role)) {
    return (
      <Page title={TITLE} description={DESCRIPTION}>
        <Card>
          <EmptyState
            icon={Lock}
            title="Hunting needs the hunter role"
            description="Event search and saved queries are open to hunter, engineer and admin accounts."
          />
        </Card>
      </Page>
    )
  }
  return <HuntWorkspace />
}
