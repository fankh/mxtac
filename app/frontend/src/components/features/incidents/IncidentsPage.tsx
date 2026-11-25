import { useState } from 'react'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { Plus, RefreshCw, Siren, X } from 'lucide-react'
import type { Incident, IncidentSortField, IncidentStatus, SeverityLevel } from '@/types/api'
import { apiErrorMessage, type IncidentListParams, incidentsApi } from '@/lib/api'
import { useAuthStore } from '@/stores/authStore'
import { Page } from '@/components/layout/Page'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { EmptyState } from '@/components/ui/empty-state'
import { Skeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { SeverityPill } from '@/components/shared/SeverityBadge'
import { ErrorCard, FilterChip, FilterGroup, Pager, SearchInput } from '@/components/shared/ListControls'
import { OptionSelect } from '@/components/shared/OptionSelect'
import { SEVERITY_LABELS, SEVERITY_OPTIONS } from '@/lib/severity'
import { canWrite } from '@/lib/roles'
import { tacticName } from '@/lib/attack'
import { formatDateTime } from '@/lib/format'
import { useDebouncedValue } from '@/hooks/useDebouncedValue'
import { CreateIncidentDialog } from '@/components/shared/CreateIncidentDialog'
import { IncidentMetricsCards } from './IncidentMetricsCards'
import { IncidentPanel } from './IncidentPanel'
import { IncidentStatusPill } from './IncidentStatusPill'
import { INCIDENT_SORT_LABELS, INCIDENT_STATUS_FLOW, INCIDENT_STATUS_LABELS } from './incidentUtils'

const PAGE_SIZE = 20

const SORT_OPTIONS: { value: IncidentSortField; label: string }[] = [
  { value: 'created_at', label: `Sort: ${INCIDENT_SORT_LABELS.created_at.toLowerCase()}` },
  { value: 'severity', label: `Sort: ${INCIDENT_SORT_LABELS.severity.toLowerCase()}` },
  { value: 'status', label: `Sort: ${INCIDENT_SORT_LABELS.status.toLowerCase()}` },
]

function toggle<T>(list: T[], item: T): T[] {
  return list.includes(item) ? list.filter((entry) => entry !== item) : [...list, item]
}

export function IncidentsPage() {
  const user = useAuthStore((s) => s.user)
  const writable = canWrite(user?.role)

  const [search, setSearch] = useState('')
  const [assignee, setAssignee] = useState('')
  const [severities, setSeverities] = useState<SeverityLevel[]>([])
  const [statuses, setStatuses] = useState<IncidentStatus[]>([])
  const [sort, setSort] = useState<IncidentSortField>('created_at')
  const [page, setPage] = useState(1)
  const [selected, setSelected] = useState<Incident | null>(null)
  const [createOpen, setCreateOpen] = useState(false)

  const debouncedSearch = useDebouncedValue(search.trim())
  const debouncedAssignee = useDebouncedValue(assignee.trim())

  const params: IncidentListParams = {
    severity: severities.length > 0 ? severities : undefined,
    status: statuses.length > 0 ? statuses : undefined,
    assigned_to: debouncedAssignee || undefined,
    search: debouncedSearch || undefined,
    sort,
    page,
    page_size: PAGE_SIZE,
  }

  const { data, isLoading, isError, error, isFetching, refetch } = useQuery({
    queryKey: ['incidents', params],
    queryFn: () => incidentsApi.list(params),
    placeholderData: keepPreviousData,
  })

  const incidents = data?.items ?? []
  const pagination = data?.pagination
  const activeFilters =
    severities.length + statuses.length + (search.trim() ? 1 : 0) + (assignee.trim() ? 1 : 0)

  function resetFilters() {
    setSearch('')
    setAssignee('')
    setSeverities([])
    setStatuses([])
    setPage(1)
  }

  const myEmail = user?.email ?? ''
  const mineActive = myEmail !== '' && assignee.trim() === myEmail

  return (
    <Page
      title="Incidents"
      description="Investigations that group related detections"
      actions={
        <>
          <Button variant="outline" size="icon" title="Refresh" onClick={() => void refetch()} disabled={isFetching}>
            <RefreshCw className={`h-3.5 w-3.5 ${isFetching ? 'animate-spin' : ''}`} />
          </Button>
          {writable && (
            <Button onClick={() => setCreateOpen(true)} className="gap-1.5">
              <Plus className="h-3.5 w-3.5" />
              New incident
            </Button>
          )}
        </>
      }
    >
      <IncidentMetricsCards />

      <Card>
        <CardContent className="space-y-3 p-4">
          <div className="flex flex-wrap items-center gap-2">
            <SearchInput
              value={search}
              onChange={(value) => { setSearch(value); setPage(1) }}
              placeholder="Search title or description"
              label="Search incidents"
              className="sm:w-72"
            />
            <SearchInput
              value={assignee}
              onChange={(value) => { setAssignee(value); setPage(1) }}
              placeholder="Assignee email (exact)"
              label="Assignee filter"
              icon={false}
              className="sm:w-52"
            />
            {myEmail && (
              <FilterChip
                label="Assigned to me"
                active={mineActive}
                onClick={() => { setAssignee(mineActive ? '' : myEmail); setPage(1) }}
              />
            )}
            <OptionSelect
              label="Sort incidents"
              value={sort}
              options={SORT_OPTIONS}
              onChange={(value) => { setSort(value); setPage(1) }}
            />
            {activeFilters > 0 && (
              <Button variant="ghost" onClick={resetFilters} className="ml-auto gap-1 text-muted-foreground">
                <X className="h-3.5 w-3.5" />
                Clear filters ({activeFilters})
              </Button>
            )}
          </div>
          <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
            <FilterGroup label="Severity">
              {SEVERITY_OPTIONS.map((severity) => (
                <FilterChip
                  key={severity}
                  label={SEVERITY_LABELS[severity]}
                  active={severities.includes(severity)}
                  onClick={() => { setSeverities((prev) => toggle(prev, severity)); setPage(1) }}
                />
              ))}
            </FilterGroup>
            <FilterGroup label="Status">
              {INCIDENT_STATUS_FLOW.map((status) => (
                <FilterChip
                  key={status}
                  label={INCIDENT_STATUS_LABELS[status]}
                  active={statuses.includes(status)}
                  onClick={() => { setStatuses((prev) => toggle(prev, status)); setPage(1) }}
                />
              ))}
            </FilterGroup>
          </div>
        </CardContent>
      </Card>

      {isError ? (
        <ErrorCard
          title="Could not load incidents"
          message={apiErrorMessage(error)}
          onRetry={() => void refetch()}
        />
      ) : (
        <Card className="overflow-hidden">
          {isLoading ? (
            <div className="space-y-2 p-4" aria-label="Loading incidents">
              {Array.from({ length: 6 }).map((_, index) => (
                <Skeleton key={index} className="h-8 w-full" />
              ))}
            </div>
          ) : incidents.length === 0 ? (
            <EmptyState
              icon={Siren}
              title={activeFilters > 0 ? 'No incidents match the filters' : 'No incidents yet'}
              description={
                activeFilters > 0
                  ? 'Change or clear the filters to see more.'
                  : 'Create an incident here or from selected detections.'
              }
              action={
                activeFilters > 0 ? (
                  <Button variant="outline" onClick={resetFilters}>
                    Clear filters
                  </Button>
                ) : undefined
              }
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="w-20">ID</TableHead>
                  <TableHead>Title</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Assigned to</TableHead>
                  <TableHead>Hosts</TableHead>
                  <TableHead>Detections</TableHead>
                  <TableHead>Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {incidents.map((incident) => (
                  <TableRow
                    key={incident.id}
                    tabIndex={0}
                    data-state={selected?.id === incident.id ? 'selected' : undefined}
                    onClick={() => setSelected(incident)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' && e.target === e.currentTarget) setSelected(incident)
                    }}
                    className="cursor-pointer text-[12px] focus-visible:bg-muted/50 focus-visible:outline-none"
                  >
                    <TableCell className="font-mono text-muted-foreground">INC-{incident.id}</TableCell>
                    <TableCell className="max-w-[440px]">
                      <div className="truncate font-medium text-foreground" title={incident.title}>{incident.title}</div>
                      {incident.tactic_ids.length > 0 && (
                        <div className="truncate text-[11px] text-muted-foreground">
                          {incident.tactic_ids.map(tacticName).join(', ')}
                        </div>
                      )}
                    </TableCell>
                    <TableCell><SeverityPill severity={incident.severity} /></TableCell>
                    <TableCell><IncidentStatusPill status={incident.status} /></TableCell>
                    <TableCell className="max-w-[180px] truncate">
                      {incident.assigned_to ?? <span className="text-muted-foreground">Unassigned</span>}
                    </TableCell>
                    <TableCell className="max-w-[160px] truncate text-muted-foreground">
                      {incident.hosts.length === 0
                        ? '—'
                        : incident.hosts.slice(0, 2).join(', ') +
                          (incident.hosts.length > 2 ? ` +${incident.hosts.length - 2}` : '')}
                    </TableCell>
                    <TableCell className="tabular-nums text-muted-foreground">
                      {incident.detection_ids.length}
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-muted-foreground">
                      {formatDateTime(incident.created_at)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </Card>
      )}

      {pagination && !isError && pagination.total > 0 && (
        <Pager pagination={pagination} onPageChange={setPage} />
      )}

      <IncidentPanel incident={selected} onClose={() => setSelected(null)} />

      <CreateIncidentDialog open={createOpen} onClose={() => setCreateOpen(false)} />
    </Page>
  )
}
