import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from 'recharts'
import { eventsApi, savedQueriesApi, huntingApi } from '../../../lib/api'
import type {
  EventFilter, EventItem, SearchRequest, AggregationBucket, SavedQuery,
  HuntSuggestion, SuggestedQuery,
} from '../../../types/api'
import { TopBar } from '../../layout/TopBar'
import { chartColors } from '../../../lib/themeVars'
import { useUIStore } from '../../../stores/uiStore'

// ── Constants ─────────────────────────────────────────────────────────────────

const PAGE_SIZE = 50

const FIELD_OPTIONS = [
  { value: 'hostname',     label: 'Hostname' },
  { value: 'src_ip',       label: 'Source IP' },
  { value: 'dst_ip',       label: 'Dest IP' },
  { value: 'username',     label: 'Username' },
  { value: 'process_hash', label: 'Process Hash' },
  { value: 'source',       label: 'Source' },
  { value: 'class_name',   label: 'Event Class' },
  { value: 'severity_id',  label: 'Severity ID' },
]

const OPERATOR_OPTIONS = [
  { value: 'eq',       label: '= equals' },
  { value: 'ne',       label: '≠ not equals' },
  { value: 'contains', label: '~ contains' },
  { value: 'gt',       label: '> greater than' },
  { value: 'lt',       label: '< less than' },
  { value: 'gte',      label: '≥ at least' },
  { value: 'lte',      label: '≤ at most' },
]

const TIME_RANGES = [
  { value: 'now-1h',  label: '1h' },
  { value: 'now-6h',  label: '6h' },
  { value: 'now-24h', label: '24h' },
  { value: 'now-7d',  label: '7d' },
  { value: 'now-30d', label: '30d' },
]

const SEV_LABELS: Record<number, string> = {
  0: 'Unknown', 1: 'Info', 2: 'Low', 3: 'Medium', 4: 'High', 5: 'Critical', 99: 'Other',
}

const SEV_COLORS: Record<number, string> = {
  0: 'text-text-muted',
  1: 'text-blue',
  2: 'text-status-ok',
  3: 'text-status-warn',
  4: 'text-orange-400',
  5: 'text-crit-text',
  99: 'text-text-muted',
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function getHistInterval(timeRange: string): string {
  switch (timeRange) {
    case 'now-1h':  return '1m'
    case 'now-6h':  return '1h'
    case 'now-24h': return '1h'
    case 'now-7d':  return '1d'
    case 'now-30d': return '1d'
    default:        return '1h'
  }
}

function formatBucketKey(key: string): string {
  const d = new Date(key)
  if (!isNaN(d.getTime())) {
    return d.toLocaleString([], {
      month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
    })
  }
  return key
}

function formatEventTime(iso: string): string {
  return new Date(iso).toLocaleString([], {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
  })
}

function formatRelativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return `${Math.floor(hrs / 24)}d ago`
}

// ── Local filter type (adds a stable `id` for React keys) ────────────────────

type LocalFilter = { id: number; field: string; operator: string; value: string }
let _nextFilterId = 0

// ── Save Query Dialog ─────────────────────────────────────────────────────────

function SaveQueryDialog({
  onSave,
  onCancel,
}: {
  onSave: (name: string, description: string) => void
  onCancel: () => void
}) {
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
      <div className="bg-surface border border-border rounded-lg shadow-panel w-[400px] p-5">
        <p className="text-[13px] font-semibold text-text-primary mb-4">Save Hunt Query</p>

        <div className="space-y-3">
          <div>
            <label className="text-[11px] text-text-muted block mb-1">Name <span className="text-crit-text">*</span></label>
            <input
              autoFocus
              type="text"
              placeholder="e.g. Lateral movement from 10.0.x.x"
              value={name}
              onChange={e => setName(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter' && name.trim()) onSave(name.trim(), description.trim()) }}
              className="w-full h-[32px] px-3 text-[12px] border border-border rounded-md bg-page text-text-primary placeholder-text-muted focus:outline-none focus:border-blue"
            />
          </div>

          <div>
            <label className="text-[11px] text-text-muted block mb-1">Description <span className="text-text-muted">(optional)</span></label>
            <textarea
              placeholder="Brief note about what this query hunts for…"
              value={description}
              onChange={e => setDescription(e.target.value)}
              rows={2}
              className="w-full px-3 py-2 text-[12px] border border-border rounded-md bg-page text-text-primary placeholder-text-muted focus:outline-none focus:border-blue resize-none"
            />
          </div>
        </div>

        <div className="flex gap-2 justify-end mt-4">
          <button
            onClick={onCancel}
            className="h-[30px] px-4 text-[11px] border border-border rounded-md text-text-secondary hover:bg-page"
          >
            Cancel
          </button>
          <button
            disabled={!name.trim()}
            onClick={() => onSave(name.trim(), description.trim())}
            className="h-[30px] px-4 text-[11px] bg-blue text-white rounded-md hover:opacity-90 disabled:opacity-40"
          >
            Save
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Saved Queries Panel ───────────────────────────────────────────────────────

function SavedQueriesPanel({
  onLoad,
  onClose,
}: {
  onLoad: (sq: SavedQuery) => void
  onClose: () => void
}) {
  const qc = useQueryClient()
  const { data, isLoading, isError } = useQuery({
    queryKey: ['saved-queries'],
    queryFn: () => savedQueriesApi.list(),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => savedQueriesApi.delete(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['saved-queries'] }),
  })

  const queries = data?.items ?? []

  return (
    <div className="fixed inset-y-0 right-0 w-[360px] bg-surface border-l border-border shadow-panel z-40 flex flex-col">
      <div className="flex items-center justify-between px-4 py-3 border-b border-border">
        <span className="text-[12px] font-semibold text-text-primary">Saved Queries</span>
        <button
          onClick={onClose}
          className="text-text-muted hover:text-text-primary text-lg leading-none"
        >
          ×
        </button>
      </div>

      <div className="flex-1 overflow-y-auto px-3 py-2">
        {isLoading && (
          <div className="flex items-center justify-center h-24 text-text-muted text-sm">Loading…</div>
        )}
        {isError && (
          <div className="flex items-center justify-center h-24 text-crit-text text-sm">
            Failed to load saved queries.
          </div>
        )}
        {!isLoading && !isError && queries.length === 0 && (
          <div className="flex flex-col items-center justify-center h-32 text-center">
            <p className="text-[12px] text-text-muted">No saved queries yet.</p>
            <p className="text-[11px] text-text-muted mt-1">Run a hunt and click "Save Query" to bookmark it.</p>
          </div>
        )}
        {!isLoading && !isError && queries.map(sq => (
          <div
            key={sq.id}
            className="group flex items-start justify-between gap-2 px-3 py-2.5 rounded-md hover:bg-page border border-transparent hover:border-border mb-1"
          >
            <button
              className="flex-1 text-left min-w-0"
              onClick={() => onLoad(sq)}
            >
              <p className="text-[12px] font-medium text-text-primary truncate">{sq.name}</p>
              {sq.description && (
                <p className="text-[10px] text-text-muted truncate mt-0.5">{sq.description}</p>
              )}
              <p className="text-[10px] text-text-muted mt-0.5">
                {sq.time_from.replace('now-', '')} window · {formatRelativeTime(sq.created_at)}
              </p>
            </button>
            <button
              onClick={() => deleteMutation.mutate(sq.id)}
              className="text-text-muted hover:text-crit-text text-sm opacity-0 group-hover:opacity-100 transition-opacity shrink-0 mt-0.5"
              title="Delete"
            >
              ×
            </button>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Event Detail Panel ────────────────────────────────────────────────────────

function EventDetailPanel({
  event, onClose,
}: {
  event: EventItem | null
  onClose: () => void
}) {
  if (!event) return null
  const sevId = typeof event.severity_id === 'number' ? event.severity_id : -1

  return (
    <div className="fixed inset-y-0 right-0 w-[480px] bg-surface border-l border-border shadow-panel z-40 flex flex-col">
      <div className="flex items-center justify-between px-4 py-3 border-b border-border">
        <div className="flex items-center gap-2">
          <span className="text-[12px] font-semibold text-text-primary">Event Detail</span>
          {sevId >= 0 && (
            <span className={`text-[10px] font-medium ${SEV_COLORS[sevId] ?? 'text-text-muted'}`}>
              {SEV_LABELS[sevId] ?? `Sev ${sevId}`}
            </span>
          )}
        </div>
        <button
          onClick={onClose}
          className="text-text-muted hover:text-text-primary text-lg leading-none"
        >
          ×
        </button>
      </div>

      <div className="flex-1 overflow-y-auto px-4 py-3 space-y-3">
        {/* Identity */}
        <section>
          <p className="text-[10px] font-medium text-text-muted uppercase mb-1.5">Identity</p>
          <div className="space-y-1">
            {([
              ['Event ID', event.id],
              ['Time', event.time ? new Date(event.time).toLocaleString() : undefined],
              ['Class', event.class_name],
              ['Source', event.source],
            ] as [string, string | undefined][]).filter(([, v]) => !!v).map(([label, value]) => (
              <div key={label} className="flex gap-2 text-[11px]">
                <span className="w-16 shrink-0 text-text-muted">{label}</span>
                <span className="text-text-primary font-mono break-all">{value}</span>
              </div>
            ))}
          </div>
        </section>

        <div className="border-t border-section" />

        {/* Network */}
        <section>
          <p className="text-[10px] font-medium text-text-muted uppercase mb-1.5">Network</p>
          <div className="space-y-1">
            {([
              ['Src IP', event.src_ip],
              ['Dst IP', event.dst_ip],
              ['Hostname', event.hostname],
            ] as [string, string | undefined][]).filter(([, v]) => !!v).map(([label, value]) => (
              <div key={label} className="flex gap-2 text-[11px]">
                <span className="w-16 shrink-0 text-text-muted">{label}</span>
                <span className="text-text-primary font-mono">{value}</span>
              </div>
            ))}
          </div>
        </section>

        <div className="border-t border-section" />

        {/* User & Process */}
        <section>
          <p className="text-[10px] font-medium text-text-muted uppercase mb-1.5">User & Process</p>
          <div className="space-y-1">
            {([
              ['Username', event.username],
              ['Hash', event.process_hash],
            ] as [string, string | undefined][]).filter(([, v]) => !!v).map(([label, value]) => (
              <div key={label} className="flex gap-2 text-[11px]">
                <span className="w-16 shrink-0 text-text-muted">{label}</span>
                <span className="text-text-primary font-mono break-all">{value}</span>
              </div>
            ))}
          </div>
        </section>

        {event.summary && (
          <>
            <div className="border-t border-section" />
            <section>
              <p className="text-[10px] font-medium text-text-muted uppercase mb-1.5">Summary</p>
              <p className="text-[11px] text-text-primary leading-relaxed">{event.summary}</p>
            </section>
          </>
        )}

        {/* Raw payload */}
        <div className="border-t border-section" />
        <section>
          <p className="text-[10px] font-medium text-text-muted uppercase mb-1.5">Raw Payload</p>
          <pre className="text-[10px] text-text-secondary font-mono bg-page rounded p-2 overflow-x-auto whitespace-pre-wrap break-all">
            {JSON.stringify(event, null, 2)}
          </pre>
        </section>
      </div>
    </div>
  )
}

// ── Entity Timeline Panel ─────────────────────────────────────────────────────

function EntityPanel({
  entityType, entityValue, timeFrom, onClose, onEventClick,
}: {
  entityType: string
  entityValue: string
  timeFrom: string
  onClose: () => void
  onEventClick: (e: EventItem) => void
}) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ['entity-timeline', entityType, entityValue, timeFrom],
    queryFn: () => eventsApi.entity(entityType, entityValue, timeFrom),
  })

  return (
    <div className="fixed inset-y-0 right-0 w-[540px] bg-surface border-l border-border shadow-panel z-40 flex flex-col">
      <div className="flex items-center justify-between px-4 py-3 border-b border-border">
        <div>
          <span className="text-[12px] font-semibold text-text-primary">Entity Timeline</span>
          <span className="ml-2 text-[11px] text-text-muted">
            {entityType}: <span className="text-blue font-mono">{entityValue}</span>
          </span>
        </div>
        <button
          onClick={onClose}
          className="text-text-muted hover:text-text-primary text-lg leading-none"
        >
          ×
        </button>
      </div>

      <div className="flex-1 overflow-y-auto">
        {isLoading && (
          <div className="flex items-center justify-center h-32 text-text-muted text-sm">Loading…</div>
        )}
        {isError && (
          <div className="flex items-center justify-center h-32 text-crit-text text-sm">
            Failed to load entity timeline.
          </div>
        )}
        {data && (
          <div className="px-4 py-3">
            <p className="text-[11px] text-text-muted mb-3">
              {data.total.toLocaleString()} events — click to inspect
            </p>
            <div className="space-y-0.5">
              {data.events.map((ev) => (
                <div
                  key={ev.id}
                  onClick={() => onEventClick(ev)}
                  className="flex items-start gap-2 px-3 py-2 rounded-md hover:bg-page cursor-pointer"
                >
                  <span className="text-[10px] text-text-muted w-[100px] shrink-0 pt-0.5">
                    {formatEventTime(ev.time)}
                  </span>
                  <div className="min-w-0">
                    <div className="text-[11px] text-text-primary">{ev.class_name ?? 'Event'}</div>
                    {ev.summary && (
                      <div className="text-[10px] text-text-muted truncate">{ev.summary}</div>
                    )}
                  </div>
                </div>
              ))}
              {data.events.length === 0 && (
                <p className="text-[11px] text-text-muted py-4 text-center">
                  No events found for this entity in the selected time range.
                </p>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

// ── ATT&CK Hunting Suggestions Panel ──────────────────────────────────────────

const PRIORITY_STYLES: Record<string, string> = {
  high:   'bg-crit-bg text-crit-text border-crit-border',
  medium: 'bg-orange-50 text-orange-600 border-orange-200',
  low:    'bg-surface text-text-muted border-border',
}

function HuntingSuggestionsPanel({
  onLoadQuery,
  onClose,
}: {
  onLoadQuery: (query: string, timeFrom: string) => void
  onClose: () => void
}) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ['hunt-suggestions'],
    queryFn: () => huntingApi.suggestions(24, 10),
    staleTime: 60_000,
  })

  const suggestions: HuntSuggestion[] = data?.suggestions ?? []

  return (
    <div className="fixed inset-y-0 right-0 w-[400px] bg-surface border-l border-border shadow-panel z-40 flex flex-col">
      <div className="flex items-center justify-between px-4 py-3 border-b border-border">
        <div>
          <span className="text-[12px] font-semibold text-text-primary">ATT&CK Hunting Suggestions</span>
          {data && (
            <span className="ml-2 text-[10px] text-text-muted">
              last {data.window_hours}h · {suggestions.length} suggestion{suggestions.length !== 1 ? 's' : ''}
            </span>
          )}
        </div>
        <button
          onClick={onClose}
          className="text-text-muted hover:text-text-primary text-lg leading-none"
        >
          ×
        </button>
      </div>

      <div className="flex-1 overflow-y-auto px-3 py-2 space-y-2">
        {isLoading && (
          <div className="flex items-center justify-center h-24 text-text-muted text-sm">
            Analyzing detections…
          </div>
        )}
        {isError && (
          <div className="flex items-center justify-center h-24 text-crit-text text-sm">
            Failed to load suggestions.
          </div>
        )}
        {!isLoading && !isError && suggestions.length === 0 && (
          <div className="flex flex-col items-center justify-center h-32 text-center">
            <p className="text-[12px] text-text-muted">No suggestions available.</p>
            <p className="text-[11px] text-text-muted mt-1">Ingest some events and detections to generate ATT&CK-guided hunt ideas.</p>
          </div>
        )}
        {!isLoading && !isError && suggestions.map((s: HuntSuggestion) => (
          <div
            key={s.technique_id}
            className="rounded-md border border-border bg-page p-3"
          >
            {/* Header row */}
            <div className="flex items-start justify-between gap-2 mb-1.5">
              <div className="min-w-0">
                <span className="text-[12px] font-semibold text-text-primary font-mono">{s.technique_id}</span>
                <span className="ml-1.5 text-[11px] text-text-secondary">{s.technique_name}</span>
              </div>
              <span className={`shrink-0 text-[9px] font-semibold uppercase px-1.5 py-0.5 rounded border ${PRIORITY_STYLES[s.priority] ?? PRIORITY_STYLES.low}`}>
                {s.priority}
              </span>
            </div>

            {/* Tactic + stats */}
            <div className="flex items-center gap-2 mb-1.5">
              <span className="text-[10px] text-text-muted">{s.tactic}</span>
              {s.detection_count > 0 && (
                <span className="text-[10px] text-text-muted">· {s.detection_count} detection{s.detection_count !== 1 ? 's' : ''}</span>
              )}
              <span className="text-[10px] text-text-muted">· {s.rule_count} rule{s.rule_count !== 1 ? 's' : ''}</span>
            </div>

            {/* Reason */}
            <p className="text-[10px] text-text-muted leading-relaxed mb-2">{s.reason}</p>

            {/* Suggested queries */}
            <div className="flex flex-wrap gap-1">
              {s.suggested_queries.map((q: SuggestedQuery) => (
                <button
                  key={q.label}
                  onClick={() => onLoadQuery(q.query, q.time_from)}
                  className="h-[22px] px-2 text-[10px] border border-border rounded-md text-blue hover:bg-blue-faint transition-colors bg-surface"
                  title={`Query: ${q.query} | Time: ${q.time_from}`}
                >
                  {q.label}
                </button>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── HuntPage ──────────────────────────────────────────────────────────────────

export function HuntPage() {
  // Subscribe to theme changes so chartColors() stays in sync with CSS vars
  const theme = useUIStore(s => s.theme)
  const c = chartColors()
  const qc = useQueryClient()

  const [query, setQuery]           = useState('')
  const [timeRange, setTimeRange]   = useState('now-24h')
  const [localFilters, setLocalFilters] = useState<LocalFilter[]>([])
  const [submitted, setSubmitted]   = useState<SearchRequest | null>(null)
  const [page, setPage]             = useState(0)
  const [selected, setSelected]     = useState<EventItem | null>(null)
  const [entityView, setEntityView] = useState<{ type: string; value: string } | null>(null)
  const [showDsl, setShowDsl]       = useState(false)
  const [showSaveDialog, setShowSaveDialog]           = useState(false)
  const [showSavedPanel, setShowSavedPanel]           = useState(false)
  const [showSuggestionsPanel, setShowSuggestionsPanel] = useState(false)

  // ── Queries ────────────────────────────────────────────────────────────────

  const { data: searchData, isLoading, isError } = useQuery({
    queryKey: ['events-search', submitted, page],
    queryFn: () => eventsApi.search({ ...submitted!, from_: page * PAGE_SIZE }),
    enabled: submitted !== null,
  })

  const { data: histData } = useQuery({
    queryKey: ['events-histogram', submitted?.time_from],
    queryFn: () => eventsApi.aggregate({
      agg_type: 'date_histogram',
      interval: getHistInterval(submitted?.time_from ?? 'now-24h'),
      time_from: submitted?.time_from ?? 'now-24h',
      time_to: 'now',
    }),
    enabled: submitted !== null,
  })

  const { data: dslData } = useQuery({
    queryKey: ['events-dsl', submitted],
    queryFn: () => eventsApi.queryDsl(submitted!),
    enabled: submitted !== null && showDsl,
  })

  // ── Save mutation ──────────────────────────────────────────────────────────

  const saveMutation = useMutation({
    mutationFn: (payload: { name: string; description: string }) =>
      savedQueriesApi.create({
        name: payload.name,
        description: payload.description || undefined,
        query: submitted?.query,
        filters: submitted?.filters ?? [],
        time_from: submitted?.time_from ?? 'now-24h',
        time_to: submitted?.time_to ?? 'now',
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['saved-queries'] })
      setShowSaveDialog(false)
    },
  })

  // ── Actions ────────────────────────────────────────────────────────────────

  function buildRequest(): SearchRequest {
    return {
      query: query.trim() || undefined,
      filters: localFilters
        .filter(f => f.field && f.value.trim())
        .map(f => ({
          field: f.field,
          operator: f.operator as EventFilter['operator'],
          value: f.value,
        })),
      time_from: timeRange,
      time_to: 'now',
      size: PAGE_SIZE,
      from_: 0,
    }
  }

  function handleSearch() {
    setPage(0)
    setSubmitted(buildRequest())
    setEntityView(null)
    setSelected(null)
  }

  function addFilter() {
    setLocalFilters(prev => [
      ...prev,
      { id: ++_nextFilterId, field: 'hostname', operator: 'eq', value: '' },
    ])
  }

  function removeFilter(id: number) {
    setLocalFilters(prev => prev.filter(f => f.id !== id))
  }

  function updateFilter(id: number, key: keyof LocalFilter, value: string) {
    setLocalFilters(prev =>
      prev.map(f => f.id === id ? { ...f, [key]: value } : f)
    )
  }

  function handleEntityPivot(type: string, value: string | undefined) {
    if (!value) return
    setEntityView({ type, value })
    setSelected(null)
  }

  function loadSavedQuery(sq: SavedQuery) {
    setQuery(sq.query ?? '')
    setTimeRange(sq.time_from)
    setLocalFilters(
      (sq.filters ?? []).map(f => ({
        id: ++_nextFilterId,
        field: f.field,
        operator: f.operator,
        value: String(f.value),
      }))
    )
    setShowSavedPanel(false)
    // Auto-run the loaded query
    const req: SearchRequest = {
      query: sq.query || undefined,
      filters: (sq.filters ?? []).map(f => ({
        field: f.field,
        operator: f.operator as EventFilter['operator'],
        value: f.value,
      })),
      time_from: sq.time_from,
      time_to: sq.time_to,
      size: PAGE_SIZE,
      from_: 0,
    }
    setPage(0)
    setSubmitted(req)
    setEntityView(null)
    setSelected(null)
  }

  function loadSuggestedQuery(suggestedQuery: string, timeFrom: string) {
    setQuery(suggestedQuery)
    setTimeRange(timeFrom)
    setLocalFilters([])
    setShowSuggestionsPanel(false)
    const req: SearchRequest = {
      query: suggestedQuery || undefined,
      filters: [],
      time_from: timeFrom,
      time_to: 'now',
      size: PAGE_SIZE,
      from_: 0,
    }
    setPage(0)
    setSubmitted(req)
    setEntityView(null)
    setSelected(null)
  }

  // ── Derived ────────────────────────────────────────────────────────────────

  const events = searchData?.items ?? []
  const totalEvents = searchData?.total ?? 0
  const totalPages = Math.ceil(totalEvents / PAGE_SIZE)
  const histBuckets: AggregationBucket[] = histData?.buckets ?? []

  // Suppress unused-var warning on theme — it drives chartColors() reactivity
  void theme

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <>
      <TopBar crumb="Event Hunt" />
      <div className="pt-[46px] px-5 pb-6">

        {/* ── Search bar + time range ── */}
        <div className="flex items-center gap-2 py-3 flex-wrap">
          <div className="relative flex-1 min-w-[280px]">
            <span className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted text-[13px] select-none">
              ⌕
            </span>
            <input
              type="text"
              placeholder="Search events — Lucene syntax (e.g. apache* AND src_ip:10.0.*)"
              value={query}
              onChange={e => setQuery(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter') handleSearch() }}
              className="w-full h-[32px] pl-8 pr-3 text-[12px] border border-border rounded-md bg-surface text-text-primary placeholder-text-muted focus:outline-none focus:border-blue"
            />
          </div>

          {/* Time range chips */}
          <div className="flex items-center border border-border rounded-md overflow-hidden">
            {TIME_RANGES.map(({ value, label }) => (
              <button
                key={value}
                onClick={() => setTimeRange(value)}
                className={`px-3 h-[32px] text-[11px] font-medium border-r border-border last:border-r-0 transition-colors ${
                  timeRange === value
                    ? 'bg-blue text-white'
                    : 'bg-surface text-text-secondary hover:bg-page'
                }`}
              >
                {label}
              </button>
            ))}
          </div>

          <button
            onClick={handleSearch}
            className="h-[32px] px-4 text-[12px] font-medium bg-blue text-white rounded-md hover:opacity-90 transition-opacity"
          >
            Run Query
          </button>
        </div>

        {/* ── Structured filter rows ── */}
        {localFilters.length > 0 && (
          <div className="flex flex-col gap-1.5 mb-2">
            {localFilters.map(f => (
              <div key={f.id} className="flex items-center gap-2">
                <select
                  value={f.field}
                  onChange={e => updateFilter(f.id, 'field', e.target.value)}
                  className="h-[26px] px-2 text-[11px] border border-border rounded-md bg-surface text-text-primary focus:outline-none focus:border-blue"
                >
                  {FIELD_OPTIONS.map(o => (
                    <option key={o.value} value={o.value}>{o.label}</option>
                  ))}
                </select>

                <select
                  value={f.operator}
                  onChange={e => updateFilter(f.id, 'operator', e.target.value)}
                  className="h-[26px] px-2 text-[11px] border border-border rounded-md bg-surface text-text-primary focus:outline-none focus:border-blue"
                >
                  {OPERATOR_OPTIONS.map(o => (
                    <option key={o.value} value={o.value}>{o.label}</option>
                  ))}
                </select>

                <input
                  type="text"
                  placeholder="value"
                  value={f.value}
                  onChange={e => updateFilter(f.id, 'value', e.target.value)}
                  onKeyDown={e => { if (e.key === 'Enter') handleSearch() }}
                  className="h-[26px] px-2 text-[11px] border border-border rounded-md bg-surface text-text-primary placeholder-text-muted focus:outline-none focus:border-blue w-[200px]"
                />

                <button
                  onClick={() => removeFilter(f.id)}
                  className="text-text-muted hover:text-crit-text text-base leading-none w-5 h-5 flex items-center justify-center"
                >
                  ×
                </button>
              </div>
            ))}
          </div>
        )}

        {/* ── Toolbar: Add Filter, Save, Saved Queries, DSL, count ── */}
        <div className="flex items-center gap-2 mb-3">
          <button
            onClick={addFilter}
            className="h-[26px] px-3 text-[11px] border border-border rounded-md text-text-secondary hover:border-blue hover:text-blue bg-surface transition-colors"
          >
            + Add Filter
          </button>

          {submitted && (
            <button
              onClick={() => setShowSaveDialog(true)}
              className="h-[26px] px-3 text-[11px] border border-border rounded-md text-text-secondary hover:border-blue hover:text-blue bg-surface transition-colors"
            >
              Save Query
            </button>
          )}

          <button
            onClick={() => { setShowSavedPanel(!showSavedPanel); setSelected(null); setEntityView(null); setShowSuggestionsPanel(false) }}
            className={`h-[26px] px-3 text-[11px] border rounded-md transition-colors ${
              showSavedPanel
                ? 'border-blue text-blue bg-blue-faint'
                : 'border-border text-text-secondary hover:border-blue hover:text-blue bg-surface'
            }`}
          >
            Saved
          </button>

          <button
            onClick={() => { setShowSuggestionsPanel(!showSuggestionsPanel); setSelected(null); setEntityView(null); setShowSavedPanel(false) }}
            className={`h-[26px] px-3 text-[11px] border rounded-md transition-colors ${
              showSuggestionsPanel
                ? 'border-blue text-blue bg-blue-faint'
                : 'border-border text-text-secondary hover:border-blue hover:text-blue bg-surface'
            }`}
          >
            ATT&amp;CK Suggestions
          </button>

          {submitted && (
            <button
              onClick={() => setShowDsl(!showDsl)}
              className={`h-[26px] px-3 text-[11px] border rounded-md transition-colors ${
                showDsl
                  ? 'border-blue text-blue bg-blue-faint'
                  : 'border-border text-text-secondary hover:border-blue hover:text-blue bg-surface'
              }`}
            >
              {showDsl ? 'Hide DSL' : 'Show DSL'}
            </button>
          )}

          {submitted && totalEvents > 0 && (
            <span className="text-[11px] text-text-muted ml-auto">
              {totalEvents.toLocaleString()} events
              {searchData?.backend && (
                <span className="ml-1 text-[10px]">· {searchData.backend}</span>
              )}
            </span>
          )}
        </div>

        {/* ── DSL box ── */}
        {showDsl && dslData && (
          <div className="mb-3 bg-page rounded-md border border-border p-3">
            <p className="text-[10px] font-medium text-text-muted uppercase mb-1.5">Lucene DSL</p>
            <pre className="text-[11px] text-text-primary font-mono whitespace-pre-wrap break-all">
              {dslData.lucene}
            </pre>
          </div>
        )}

        {/* ── Empty state ── */}
        {!submitted && (
          <div className="flex flex-col items-center justify-center h-48 text-center">
            <span className="text-3xl mb-3 text-text-muted">⌕</span>
            <p className="text-[13px] font-semibold text-text-primary mb-1">Start Hunting</p>
            <p className="text-[11px] text-text-muted max-w-[400px] leading-relaxed">
              Enter a free-text query or add structured filters, choose a time range,
              then click <span className="text-blue font-medium">Run Query</span>.
              Click any hostname, IP, or username to pivot to an entity timeline.
            </p>
          </div>
        )}

        {/* ── Histogram ── */}
        {submitted && histBuckets.length > 0 && (
          <div className="bg-surface rounded-md shadow-card p-4 mb-3">
            <p className="text-[11px] font-semibold text-text-primary mb-2">Event Distribution</p>
            <ResponsiveContainer width="100%" height={90}>
              <BarChart data={histBuckets} margin={{ top: 0, right: 0, left: -24, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 0" stroke={c.chartGrid} vertical={false} />
                <XAxis
                  dataKey="key"
                  tickFormatter={formatBucketKey}
                  tick={{ fontSize: 9, fill: c.textMuted }}
                  axisLine={false}
                  tickLine={false}
                />
                <YAxis tick={{ fontSize: 9, fill: c.textFaint }} axisLine={false} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    fontSize: 11,
                    border: `1px solid ${c.border}`,
                    borderRadius: 6,
                    backgroundColor: c.surface,
                  }}
                  labelFormatter={formatBucketKey}
                  formatter={(v: number) => [v.toLocaleString(), 'Events']}
                />
                <Bar dataKey="count" fill={c.primary} radius={[2, 2, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}

        {/* ── Results table ── */}
        {submitted && (
          <div className="bg-surface rounded-md shadow-card overflow-hidden">
            {/* Table header */}
            <div className="grid grid-cols-[110px_44px_120px_110px_110px_110px_1fr] gap-2 px-3 py-2 border-b border-border">
              <span className="text-[10px] font-medium text-text-muted uppercase">Time</span>
              <span className="text-[10px] font-medium text-text-muted uppercase">Sev</span>
              <span className="text-[10px] font-medium text-text-muted uppercase">Class</span>
              <span className="text-[10px] font-medium text-text-muted uppercase">Host</span>
              <span className="text-[10px] font-medium text-text-muted uppercase">Src IP</span>
              <span className="text-[10px] font-medium text-text-muted uppercase">Dst IP</span>
              <span className="text-[10px] font-medium text-text-muted uppercase">Summary</span>
            </div>

            {isLoading && (
              <div className="flex items-center justify-center h-32 text-text-muted text-sm">
                Hunting…
              </div>
            )}

            {isError && (
              <div className="flex items-center justify-center h-32 text-crit-text text-sm">
                Search failed. Is the backend running?
              </div>
            )}

            {!isLoading && !isError && events.length === 0 && (
              <div className="flex items-center justify-center h-32 text-text-muted text-sm">
                No events matched the query.
              </div>
            )}

            {!isLoading && !isError && events.map((ev) => {
              const sevId = typeof ev.severity_id === 'number' ? ev.severity_id : -1
              const isSelected = selected?.id === ev.id
              return (
                <div
                  key={ev.id}
                  onClick={() => {
                    setSelected(isSelected ? null : ev)
                    setEntityView(null)
                  }}
                  className={`grid grid-cols-[110px_44px_120px_110px_110px_110px_1fr] gap-2 px-3 py-[6px] border-b border-section items-center cursor-pointer transition-colors ${
                    isSelected
                      ? 'bg-blue-faint border-l-[3px] border-l-blue'
                      : 'hover:bg-page'
                  }`}
                >
                  <span className="text-[10px] text-text-muted">{formatEventTime(ev.time)}</span>

                  <span className={`text-[10px] font-medium ${SEV_COLORS[sevId] ?? 'text-text-muted'}`}>
                    {sevId >= 0 ? (SEV_LABELS[sevId] ?? `${sevId}`) : '—'}
                  </span>

                  <span className="text-[10px] text-text-secondary truncate">
                    {ev.class_name ?? '—'}
                  </span>

                  {/* Hostname — pivot to entity timeline on click */}
                  <button
                    onClick={e => { e.stopPropagation(); handleEntityPivot('host', ev.hostname) }}
                    className={`text-[10px] truncate text-left ${
                      ev.hostname ? 'text-blue hover:underline' : 'text-text-muted cursor-default'
                    }`}
                    title={ev.hostname}
                  >
                    {ev.hostname ?? '—'}
                  </button>

                  {/* Source IP — pivot to entity timeline on click */}
                  <button
                    onClick={e => { e.stopPropagation(); handleEntityPivot('ip', ev.src_ip) }}
                    className={`text-[10px] font-mono truncate text-left ${
                      ev.src_ip ? 'text-blue hover:underline' : 'text-text-muted cursor-default'
                    }`}
                    title={ev.src_ip}
                  >
                    {ev.src_ip ?? '—'}
                  </button>

                  {/* Dest IP — pivot to entity timeline on click */}
                  <button
                    onClick={e => { e.stopPropagation(); handleEntityPivot('ip', ev.dst_ip) }}
                    className={`text-[10px] font-mono truncate text-left ${
                      ev.dst_ip ? 'text-blue hover:underline' : 'text-text-muted cursor-default'
                    }`}
                    title={ev.dst_ip}
                  >
                    {ev.dst_ip ?? '—'}
                  </button>

                  <span className="text-[10px] text-text-muted truncate">{ev.summary ?? '—'}</span>
                </div>
              )
            })}
          </div>
        )}

        {/* ── Pagination ── */}
        {submitted && totalPages > 1 && (
          <div className="flex items-center justify-center gap-2 mt-4">
            <button
              disabled={page <= 0}
              onClick={() => setPage(p => p - 1)}
              className="h-[28px] px-3 text-[11px] border border-border rounded-md text-text-secondary disabled:opacity-40 hover:bg-page"
            >
              ← Prev
            </button>
            <span className="text-[11px] text-text-muted">
              Page {page + 1} of {totalPages}
            </span>
            <button
              disabled={page >= totalPages - 1}
              onClick={() => setPage(p => p + 1)}
              className="h-[28px] px-3 text-[11px] border border-border rounded-md text-text-secondary disabled:opacity-40 hover:bg-page"
            >
              Next →
            </button>
          </div>
        )}
      </div>

      {/* ── Save query dialog ── */}
      {showSaveDialog && (
        <SaveQueryDialog
          onSave={(name, description) => saveMutation.mutate({ name, description })}
          onCancel={() => setShowSaveDialog(false)}
        />
      )}

      {/* ── Slide-out: Saved queries panel ── */}
      {showSavedPanel && (
        <SavedQueriesPanel
          onLoad={loadSavedQuery}
          onClose={() => setShowSavedPanel(false)}
        />
      )}

      {/* ── Slide-out: ATT&CK hunting suggestions ── */}
      {showSuggestionsPanel && (
        <HuntingSuggestionsPanel
          onLoadQuery={loadSuggestedQuery}
          onClose={() => setShowSuggestionsPanel(false)}
        />
      )}

      {/* ── Slide-out: Event detail ── */}
      {selected && !entityView && !showSavedPanel && (
        <EventDetailPanel event={selected} onClose={() => setSelected(null)} />
      )}

      {/* ── Slide-out: Entity timeline ── */}
      {entityView && !showSavedPanel && (
        <EntityPanel
          entityType={entityView.type}
          entityValue={entityView.value}
          timeFrom={submitted?.time_from ?? 'now-24h'}
          onClose={() => setEntityView(null)}
          onEventClick={ev => {
            setSelected(ev)
            setEntityView(null)
          }}
        />
      )}
    </>
  )
}
