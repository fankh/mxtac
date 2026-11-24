import { useEffect, useState } from 'react'
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Download, Radio, RefreshCw, ShieldAlert } from 'lucide-react'
import type {
  BulkDetectionRequest,
  Detection,
  DetectionSortField,
  DetectionStatus,
  SeverityLevel,
} from '@/types/api'
import { detectionsApi, type DetectionExportParams } from '@/lib/api'
import { useNewAlertIds } from '@/hooks/useNewAlertIds'
import { useAuthStore } from '@/stores/authStore'
import { useDetectionStore } from '@/stores/detectionStore'
import { useUIStore } from '@/stores/uiStore'
import { Page } from '@/components/layout/Page'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { EmptyState } from '@/components/ui/empty-state'
import { Skeleton } from '@/components/ui/skeleton'
import { CreateIncidentDialog } from '../incidents/CreateIncidentDialog'
import { BulkStatusDialog } from './BulkStatusDialog'
import {
  DetectionFilters,
  EMPTY_DETECTION_FILTERS,
  countActiveFilters,
  type DetectionFilterState,
} from './DetectionFilters'
import { DetectionPanel } from './DetectionPanel'
import { DetectionsTable, type SortOrder } from './DetectionsTable'
import { ErrorCard, Pager } from './ListControls'
import { OptionSelect } from './OptionSelect'
import {
  DETECTION_STATUS_LABELS,
  SEVERITY_OPTIONS,
  apiErrorMessage,
  canWrite,
  plural,
  useDebouncedValue,
} from './utils'

/** Backend limit on `ids` for POST /detections/bulk and `detection_ids` for POST /incidents. */
const MAX_BULK_IDS = 500

const PAGE_SIZE_OPTIONS = [
  { value: '25', label: '25 per page' },
  { value: '50', label: '50 per page' },
  { value: '100', label: '100 per page' },
]

const BULK_ACTIONS: { status: DetectionStatus; label: string }[] = [
  { status: 'investigating', label: 'Investigate' },
  { status: 'resolved', label: 'Resolve' },
  { status: 'false_positive', label: 'False positive' },
  { status: 'active', label: 'Reopen' },
]

function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(url)
}

export function DetectionsPage() {
  const queryClient = useQueryClient()
  const addNotification = useUIStore((s) => s.addNotification)
  const writable = canWrite(useAuthStore((s) => s.user?.role))

  const [filters, setFilters] = useState<DetectionFilterState>(EMPTY_DETECTION_FILTERS)
  const [sort, setSort] = useState<DetectionSortField>('time')
  const [order, setOrder] = useState<SortOrder>('desc')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState('25')

  const [selected, setSelected] = useState<Detection | null>(null)
  const [checked, setChecked] = useState<ReadonlyMap<string, SeverityLevel>>(new Map())
  const [bulkStatus, setBulkStatus] = useState<DetectionStatus | null>(null)
  const [incidentOpen, setIncidentOpen] = useState(false)

  // ── Live alerts (WebSocket) ───────────────────────────────────────────────
  const liveIds = useNewAlertIds()
  const liveAlerts = useDetectionStore((s) => s.liveAlerts)
  const clearUnread = useDetectionStore((s) => s.clearUnread)
  const [ackLiveId, setAckLiveId] = useState<string | undefined>(() => liveAlerts[0]?.id)

  // The user is looking at detections, so nothing streamed in counts as unread.
  useEffect(() => {
    clearUnread()
  }, [clearUnread, liveAlerts])

  const ackIndex = ackLiveId === undefined ? -1 : liveAlerts.findIndex((alert) => alert.id === ackLiveId)
  const pendingLive = ackIndex === -1 ? liveAlerts.length : ackIndex

  // ── List query ────────────────────────────────────────────────────────────
  const search = useDebouncedValue(filters.search.trim())
  const tactic = useDebouncedValue(filters.tactic.trim())
  const host = useDebouncedValue(filters.host.trim())

  const filterParams: DetectionExportParams = {
    severity: filters.severities.length > 0 ? filters.severities : undefined,
    status: filters.statuses.length > 0 ? filters.statuses : undefined,
    tactic: tactic || undefined,
    host: host || undefined,
    search: search || undefined,
    sort,
    order,
  }
  const listParams = { ...filterParams, page, page_size: Number(pageSize) }

  const { data, isLoading, isError, error, isFetching, refetch } = useQuery({
    queryKey: ['detections', listParams],
    queryFn: () => detectionsApi.list(listParams),
    placeholderData: keepPreviousData,
  })

  const detections = data?.items ?? []
  const pagination = data?.pagination

  function refresh() {
    setAckLiveId(liveAlerts[0]?.id)
    void refetch()
  }

  function changeFilters(patch: Partial<DetectionFilterState>) {
    setFilters((prev) => ({ ...prev, ...patch }))
    setPage(1)
  }

  function resetFilters() {
    setFilters(EMPTY_DETECTION_FILTERS)
    setPage(1)
  }

  function changeSort(field: DetectionSortField) {
    if (field === sort) {
      setOrder((prev) => (prev === 'desc' ? 'asc' : 'desc'))
    } else {
      setSort(field)
      setOrder('desc')
    }
    setPage(1)
  }

  // ── Selection ─────────────────────────────────────────────────────────────
  const checkedIds = new Set(checked.keys())
  const checkedCount = checked.size
  const overLimit = checkedCount > MAX_BULK_IDS

  function toggleOne(id: string) {
    const detection = detections.find((d) => d.id === id)
    setChecked((prev) => {
      const next = new Map(prev)
      if (next.has(id)) next.delete(id)
      else if (detection) next.set(id, detection.severity)
      return next
    })
  }

  function toggleAllOnPage() {
    const allChecked = detections.length > 0 && detections.every((d) => checked.has(d.id))
    setChecked((prev) => {
      const next = new Map(prev)
      for (const d of detections) {
        if (allChecked) next.delete(d.id)
        else next.set(d.id, d.severity)
      }
      return next
    })
  }

  /** Most severe level among the selected detections, used as the incident default. */
  const selectedSeverities = new Set(checked.values())
  const worstSeverity = SEVERITY_OPTIONS.find((level) => selectedSeverities.has(level)) ?? 'high'

  // ── Mutations ─────────────────────────────────────────────────────────────
  const bulkMutation = useMutation({
    mutationFn: (body: BulkDetectionRequest) => detectionsApi.bulk(body),
    onSuccess: (result, body) => {
      const missing = result.not_found.length
      addNotification({
        type: missing > 0 ? 'warning' : 'success',
        title: `${plural(result.updated, 'detection')} set to ${DETECTION_STATUS_LABELS[body.status].toLowerCase()}`,
        message: missing > 0 ? `${plural(missing, 'detection')} no longer exist.` : undefined,
      })
      setChecked(new Map())
      setBulkStatus(null)
      queryClient.invalidateQueries({ queryKey: ['detections'] })
    },
    onError: (err: unknown) => {
      addNotification({ type: 'error', title: 'Bulk update failed', message: apiErrorMessage(err) })
      setBulkStatus(null)
    },
  })

  const exportMutation = useMutation({
    mutationFn: () => detectionsApi.export(filterParams),
    onSuccess: (blob) => {
      downloadBlob(blob, `detections_${new Date().toISOString().slice(0, 10)}.csv`)
    },
    onError: (err: unknown) => {
      addNotification({ type: 'error', title: 'Export failed', message: apiErrorMessage(err) })
    },
  })

  const activeFilters = countActiveFilters(filters)

  return (
    <Page
      title="Detections"
      description="Alerts raised by detection rules, mapped to ATT&CK"
      actions={
        <>
          <Button
            variant="outline"
            onClick={() => exportMutation.mutate()}
            disabled={exportMutation.isPending}
            title="Export the filtered detections as CSV (up to 10,000 rows)"
            className="gap-1.5"
          >
            <Download className="h-3.5 w-3.5" />
            {exportMutation.isPending ? 'Exporting…' : 'Export CSV'}
          </Button>
          <Button variant="outline" size="icon" title="Refresh" onClick={refresh} disabled={isFetching}>
            <RefreshCw className={`h-3.5 w-3.5 ${isFetching ? 'animate-spin' : ''}`} />
          </Button>
        </>
      }
    >
      <DetectionFilters filters={filters} onChange={changeFilters} onReset={resetFilters} />

      {pendingLive > 0 && (
        <div
          role="status"
          className="status-green flex items-center justify-between gap-2 rounded-lg border px-4 py-2 text-[12px]"
        >
          <span className="flex items-center gap-2">
            <Radio className="h-3.5 w-3.5" />
            {plural(pendingLive, 'new live alert')} since the list was loaded
          </span>
          <Button variant="outline" size="sm" onClick={refresh}>
            Show
          </Button>
        </div>
      )}

      {writable && checkedCount > 0 && (
        <Card>
          <CardContent role="toolbar" aria-label="Bulk actions" className="flex flex-wrap items-center gap-2 p-4 py-2">
            <span className="text-[12px] font-semibold">{checkedCount.toLocaleString('en-US')} selected</span>
            {BULK_ACTIONS.map((action) => (
              <Button
                key={action.status}
                variant="outline"
                size="sm"
                disabled={overLimit}
                onClick={() => setBulkStatus(action.status)}
              >
                {action.label}
              </Button>
            ))}
            <Button size="sm" disabled={overLimit} onClick={() => setIncidentOpen(true)}>
              Create incident
            </Button>
            {overLimit && (
              <span className="text-[11px] text-destructive">
                Select at most {MAX_BULK_IDS} detections for one action.
              </span>
            )}
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setChecked(new Map())}
              className="ml-auto text-muted-foreground"
            >
              Clear selection
            </Button>
          </CardContent>
        </Card>
      )}

      {isError ? (
        <ErrorCard
          title="Could not load detections"
          message={apiErrorMessage(error)}
          onRetry={() => void refetch()}
        />
      ) : (
        <Card className="overflow-hidden">
          {isLoading ? (
            <div className="space-y-2 p-4" aria-label="Loading detections">
              {Array.from({ length: 8 }).map((_, index) => (
                <Skeleton key={index} className="h-8 w-full" />
              ))}
            </div>
          ) : detections.length === 0 ? (
            <EmptyState
              icon={ShieldAlert}
              title={activeFilters > 0 ? 'No detections match the filters' : 'No detections yet'}
              description={
                activeFilters > 0
                  ? 'Change or clear the filters to see more.'
                  : 'Detections appear here when a rule matches an ingested event.'
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
            <DetectionsTable
              detections={detections}
              sort={sort}
              order={order}
              onSort={changeSort}
              activeId={selected?.id ?? null}
              onOpen={setSelected}
              selectable={writable}
              checkedIds={checkedIds}
              onToggle={toggleOne}
              onToggleAll={toggleAllOnPage}
              liveIds={liveIds}
            />
          )}
        </Card>
      )}

      {pagination && !isError && pagination.total > 0 && (
        <Pager pagination={pagination} onPageChange={setPage}>
          <OptionSelect
            label="Rows per page"
            value={pageSize}
            options={PAGE_SIZE_OPTIONS}
            onChange={(size) => {
              setPageSize(size)
              setPage(1)
            }}
          />
        </Pager>
      )}

      <DetectionPanel detection={selected} onClose={() => setSelected(null)} onUpdated={setSelected} />

      <BulkStatusDialog
        status={bulkStatus}
        count={checkedCount}
        pending={bulkMutation.isPending}
        onConfirm={() => {
          if (bulkStatus) bulkMutation.mutate({ ids: [...checked.keys()], status: bulkStatus })
        }}
        onClose={() => setBulkStatus(null)}
      />

      <CreateIncidentDialog
        open={incidentOpen}
        onClose={() => setIncidentOpen(false)}
        detectionIds={[...checked.keys()]}
        defaultSeverity={worstSeverity}
        onCreated={() => setChecked(new Map())}
      />
    </Page>
  )
}
