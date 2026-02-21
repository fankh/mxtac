import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import type { Detection, SeverityLevel, DetectionStatus } from '../../../types/api'
import { detectionsApi, incidentsApi } from '../../../lib/api'
import { useUIStore } from '../../../stores/uiStore'
import { TopBar } from '../../layout/TopBar'
import { ScoreCircle, SeverityPill } from '../../shared/SeverityBadge'
import { StatusPill } from '../../shared/StatusPill'
import { LiveBadge } from '../../shared/LiveBadge'
import { DetectionPanel } from './DetectionPanel'
import { useNewAlertIds } from '../../../hooks/useNewAlertIds'

const SEVERITY_OPTIONS: SeverityLevel[] = ['critical', 'high', 'medium', 'low']
const STATUS_OPTIONS: DetectionStatus[]  = ['active', 'investigating', 'resolved', 'false_positive']

type SortKey = 'score' | 'time' | 'severity' | 'host' | 'tactic'
type BulkAction = 'resolve' | 'false_positive' | 'assign' | 'create_incident'

interface ConfirmState {
  action: BulkAction
  assignee?: string
}

// Grid column template — checkbox | score | detection | technique | host | tactic | status | time
const GRID = 'grid-cols-[32px_44px_1fr_160px_110px_90px_100px_80px]'

function FilterChip({
  label,
  active,
  onClick,
}: {
  label: string
  active: boolean
  onClick: () => void
}) {
  return (
    <button
      onClick={onClick}
      className={`px-3 h-[26px] rounded-[5px] text-[11px] font-medium border transition-colors ${
        active
          ? 'bg-blue text-white border-blue'
          : 'bg-surface text-text-secondary border-border hover:border-blue hover:text-blue'
      }`}
    >
      {label}
    </button>
  )
}

export function DetectionsPage() {
  const [severities, setSeverities] = useState<SeverityLevel[]>([])
  const [status, setStatus]         = useState<DetectionStatus | undefined>()
  const [search, setSearch]         = useState('')
  const [sortKey, setSortKey]       = useState<SortKey>('score')
  const [sortOrder, setSortOrder]   = useState<'asc' | 'desc'>('desc')
  const [selected, setSelected]     = useState<Detection | null>(null)
  const [page, setPage]             = useState(1)

  // Bulk selection state
  const [checkedIds, setCheckedIds]     = useState<Set<string>>(new Set())
  const [confirmState, setConfirmState] = useState<ConfirmState | null>(null)
  const [assignInput, setAssignInput]   = useState('')

  // Incident creation form (used inside confirm modal for create_incident action)
  const [incidentTitle, setIncidentTitle]       = useState('')
  const [incidentSeverity, setIncidentSeverity] = useState<SeverityLevel>('high')

  const newIds          = useNewAlertIds()
  const queryClient     = useQueryClient()
  const addNotification = useUIStore((s) => s.addNotification)

  function toggleSeverity(s: SeverityLevel) {
    setSeverities((prev) =>
      prev.includes(s) ? prev.filter((x) => x !== s) : [...prev, s]
    )
    setPage(1)
  }

  const { data, isLoading, isError } = useQuery({
    queryKey: ['detections', { severities, status, search, sortKey, sortOrder, page }],
    queryFn: () =>
      detectionsApi.list({
        severity: severities.length > 0 ? severities : undefined,
        status,
        search: search || undefined,
        sort: sortKey,
        order: sortOrder,
        page,
        page_size: 20,
      }),
  })

  const detections = data?.items ?? []
  const pagination = data?.pagination

  // ── Bulk mutations ────────────────────────────────────────────────────────

  const bulkMutation = useMutation({
    mutationFn: (req: Parameters<typeof detectionsApi.bulk>[0]) =>
      detectionsApi.bulk(req),
    onSuccess: (_, req) => {
      const count = req.ids.length
      let title = `Updated ${count} detection${count !== 1 ? 's' : ''}`
      if (req.data.status === 'resolved')
        title = `Resolved ${count} detection${count !== 1 ? 's' : ''}`
      else if (req.data.status === 'false_positive')
        title = `Marked ${count} detection${count !== 1 ? 's' : ''} as false positive`
      else if (req.data.assigned_to)
        title = `Assigned ${count} detection${count !== 1 ? 's' : ''} to ${req.data.assigned_to}`
      addNotification({ type: 'success', title })
      setCheckedIds(new Set())
      setAssignInput('')
      setConfirmState(null)
      queryClient.invalidateQueries({ queryKey: ['detections'] })
    },
    onError: () => {
      addNotification({ type: 'error', title: 'Bulk action failed' })
      setConfirmState(null)
    },
  })

  const createIncidentMutation = useMutation({
    mutationFn: (req: Parameters<typeof incidentsApi.create>[0]) =>
      incidentsApi.create(req),
    onSuccess: (_, req) => {
      const count = req.detection_ids?.length ?? 0
      addNotification({
        type: 'success',
        title: `Incident created from ${count} detection${count !== 1 ? 's' : ''}`,
      })
      setCheckedIds(new Set())
      setIncidentTitle('')
      setIncidentSeverity('high')
      setConfirmState(null)
      queryClient.invalidateQueries({ queryKey: ['detections'] })
    },
    onError: () => {
      addNotification({ type: 'error', title: 'Failed to create incident' })
      setConfirmState(null)
    },
  })

  const isMutating = bulkMutation.isPending || createIncidentMutation.isPending

  // ── Helpers ───────────────────────────────────────────────────────────────

  function toggleSort(key: SortKey) {
    if (sortKey === key) {
      setSortOrder((o) => (o === 'desc' ? 'asc' : 'desc'))
    } else {
      setSortKey(key)
      setSortOrder('desc')
    }
    setPage(1)
  }

  function toggleCheck(id: string) {
    setCheckedIds((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const allOnPageChecked  = detections.length > 0 && detections.every((d) => checkedIds.has(d.id))
  const someOnPageChecked = detections.some((d) => checkedIds.has(d.id))

  function toggleAllOnPage() {
    if (allOnPageChecked) {
      setCheckedIds((prev) => {
        const next = new Set(prev)
        detections.forEach((d) => next.delete(d.id))
        return next
      })
    } else {
      setCheckedIds((prev) => {
        const next = new Set(prev)
        detections.forEach((d) => next.add(d.id))
        return next
      })
    }
  }

  function executeAction() {
    if (!confirmState) return
    const ids = [...checkedIds]
    if (confirmState.action === 'create_incident') {
      createIncidentMutation.mutate({
        title: incidentTitle,
        severity: incidentSeverity,
        detection_ids: ids,
      })
    } else if (confirmState.action === 'resolve') {
      bulkMutation.mutate({ ids, action: 'update', data: { status: 'resolved' } })
    } else if (confirmState.action === 'false_positive') {
      bulkMutation.mutate({ ids, action: 'update', data: { status: 'false_positive' } })
    } else if (confirmState.action === 'assign') {
      bulkMutation.mutate({ ids, action: 'update', data: { assigned_to: confirmState.assignee! } })
    }
  }

  const checkedCount = checkedIds.size

  function SortHeader({ col, label }: { col: SortKey; label: string }) {
    const active = sortKey === col
    return (
      <button
        onClick={() => toggleSort(col)}
        className={`text-[10px] font-medium uppercase text-left flex items-center gap-1 ${
          active ? 'text-blue' : 'text-text-muted hover:text-text-secondary'
        }`}
      >
        {label}
        {active && <span className="text-[9px]">{sortOrder === 'desc' ? '↓' : '↑'}</span>}
      </button>
    )
  }

  return (
    <>
      <TopBar crumb="Detections" updatedAt="just now" />
      <div className="pt-[46px] px-5 pb-6">

        {/* Filter bar */}
        <div className="flex items-center gap-2 py-3 flex-wrap">
          <div className="flex items-center gap-1">
            <span className="text-[10px] text-text-muted mr-1">Severity:</span>
            {SEVERITY_OPTIONS.map((s) => (
              <FilterChip
                key={s}
                label={s.charAt(0).toUpperCase() + s.slice(1)}
                active={severities.includes(s)}
                onClick={() => toggleSeverity(s)}
              />
            ))}
          </div>

          <div className="w-px h-[20px] bg-border mx-1" />

          <div className="flex items-center gap-1">
            <span className="text-[10px] text-text-muted mr-1">Status:</span>
            {STATUS_OPTIONS.map((s) => (
              <FilterChip
                key={s}
                label={s === 'false_positive' ? 'FP' : s.charAt(0).toUpperCase() + s.slice(1)}
                active={status === s}
                onClick={() => { setStatus(status === s ? undefined : s); setPage(1) }}
              />
            ))}
          </div>

          <div className="ml-auto">
            <input
              type="text"
              placeholder="Search detections…"
              value={search}
              onChange={(e) => { setSearch(e.target.value); setPage(1) }}
              className="h-[28px] px-3 text-[11px] border border-border rounded-md bg-surface text-text-primary placeholder-text-muted focus:outline-none focus:border-blue w-[220px]"
            />
          </div>
        </div>

        {/* Summary row / Bulk toolbar */}
        <div className="flex items-center gap-3 mb-2 min-h-[26px]">
          {checkedCount > 0 ? (
            <div className="flex items-center gap-2 flex-wrap w-full" data-testid="bulk-toolbar">
              <span className="text-[11px] font-medium text-blue whitespace-nowrap" data-testid="checked-count">
                {checkedCount} selected
              </span>
              <div className="w-px h-[16px] bg-border" />

              <button
                onClick={() => setConfirmState({ action: 'resolve' })}
                className="h-[26px] px-3 text-[11px] font-medium border border-border rounded-md text-text-secondary hover:bg-page hover:border-blue hover:text-blue"
                data-testid="bulk-resolve"
              >
                Resolve Selected
              </button>

              <button
                onClick={() => setConfirmState({ action: 'false_positive' })}
                className="h-[26px] px-3 text-[11px] font-medium border border-border rounded-md text-text-secondary hover:bg-page hover:border-blue hover:text-blue"
                data-testid="bulk-fp"
              >
                Mark False Positive
              </button>

              <div className="flex items-center gap-1">
                <input
                  type="text"
                  placeholder="Assign to…"
                  value={assignInput}
                  onChange={(e) => setAssignInput(e.target.value)}
                  className="h-[26px] px-2 text-[11px] border border-border rounded-md bg-surface text-text-primary placeholder-text-muted focus:outline-none focus:border-blue w-[120px]"
                  data-testid="assign-input"
                />
                <button
                  onClick={() => {
                    if (assignInput.trim()) {
                      setConfirmState({ action: 'assign', assignee: assignInput.trim() })
                    }
                  }}
                  disabled={!assignInput.trim()}
                  className="h-[26px] px-2 text-[11px] font-medium border border-border rounded-md text-text-secondary hover:bg-page hover:border-blue hover:text-blue disabled:opacity-40"
                  data-testid="assign-apply"
                >
                  Assign
                </button>
              </div>

              <button
                onClick={() => setConfirmState({ action: 'create_incident' })}
                className="h-[26px] px-3 text-[11px] font-medium border border-border rounded-md text-text-secondary hover:bg-page hover:border-blue hover:text-blue"
                data-testid="bulk-create-incident"
              >
                Create Incident
              </button>

              <button
                onClick={() => { setCheckedIds(new Set()); setAssignInput('') }}
                className="ml-auto text-[11px] text-text-muted hover:text-text-secondary"
                data-testid="clear-selection"
              >
                Clear selection
              </button>
            </div>
          ) : (
            pagination && (
              <span className="text-[11px] text-text-muted">
                {pagination.total.toLocaleString()} detections
                {severities.length > 0 && ` · ${severities.join(', ')}`}
                {status && ` · ${status}`}
              </span>
            )
          )}
        </div>

        {/* Table */}
        <div className="bg-surface rounded-md shadow-card overflow-hidden">
          {/* Header */}
          <div className={`grid ${GRID} gap-2 px-3 py-2 border-b border-border items-center`}>
            <div className="flex items-center justify-center">
              <input
                type="checkbox"
                data-testid="select-all-checkbox"
                checked={allOnPageChecked}
                ref={(el) => {
                  if (el) el.indeterminate = someOnPageChecked && !allOnPageChecked
                }}
                onChange={toggleAllOnPage}
                className="w-[13px] h-[13px] cursor-pointer"
                aria-label="Select all on page"
              />
            </div>
            <span className="text-[10px] font-medium text-text-muted uppercase">Score</span>
            <span className="text-[10px] font-medium text-text-muted uppercase">Detection</span>
            <span className="text-[10px] font-medium text-text-muted uppercase">Technique</span>
            <SortHeader col="host"   label="Host" />
            <SortHeader col="tactic" label="Tactic" />
            <span className="text-[10px] font-medium text-text-muted uppercase">Status</span>
            <SortHeader col="time"   label="Time" />
          </div>

          {isLoading && (
            <div className="flex items-center justify-center h-40 text-text-muted text-sm">Loading…</div>
          )}
          {isError && (
            <div className="flex items-center justify-center h-40 text-crit-text text-sm">
              Failed to load. Is the backend running?
            </div>
          )}

          {!isLoading && !isError && detections.map((d) => {
            const isSelected = selected?.id === d.id
            const isChecked  = checkedIds.has(d.id)
            return (
              <div
                key={d.id}
                onClick={() => setSelected(isSelected ? null : d)}
                className={`grid ${GRID} gap-2 px-3 py-[7px] border-b border-section items-center cursor-pointer transition-colors ${
                  isSelected
                    ? 'bg-blue-faint border-l-[3px] border-l-blue'
                    : 'hover:bg-page'
                }`}
              >
                <div className="flex items-center justify-center">
                  <input
                    type="checkbox"
                    checked={isChecked}
                    onChange={() => toggleCheck(d.id)}
                    onClick={(e) => e.stopPropagation()}
                    className="w-[13px] h-[13px] cursor-pointer"
                    aria-label={`Select ${d.name}`}
                    data-testid={`row-checkbox-${d.id}`}
                  />
                </div>
                <ScoreCircle score={d.score} severity={d.severity} />
                <div className="min-w-0">
                  <div className="text-[11px] text-text-primary font-medium flex items-center gap-1.5 min-w-0">
                    <span className="truncate">{d.name}</span>
                    {newIds.has(d.id) && <LiveBadge />}
                  </div>
                  <div className="text-[10px] text-text-muted truncate">{d.rule_name}</div>
                </div>
                <div className="min-w-0">
                  <div className="text-[11px] text-text-primary truncate">{d.technique_id}</div>
                  <div className="text-[10px] text-text-muted truncate">{d.technique_name}</div>
                </div>
                <span className="text-[11px] text-text-primary truncate">{d.host}</span>
                <span className="text-[10px] text-text-muted truncate">{d.tactic}</span>
                <StatusPill status={d.status} />
                <span className="text-[10px] text-text-muted">
                  {new Date(d.time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                </span>
              </div>
            )
          })}

          {!isLoading && !isError && detections.length === 0 && (
            <div className="flex items-center justify-center h-32 text-text-muted text-sm">
              No detections match the current filters.
            </div>
          )}
        </div>

        {/* Pagination */}
        {pagination && pagination.total_pages > 1 && (
          <div className="flex items-center justify-center gap-2 mt-4">
            <button
              disabled={page <= 1}
              onClick={() => setPage((p) => p - 1)}
              className="h-[28px] px-3 text-[11px] border border-border rounded-md text-text-secondary disabled:opacity-40 hover:bg-page"
            >
              ← Prev
            </button>
            <span className="text-[11px] text-text-muted">
              Page {pagination.page} of {pagination.total_pages}
            </span>
            <button
              disabled={page >= pagination.total_pages}
              onClick={() => setPage((p) => p + 1)}
              className="h-[28px] px-3 text-[11px] border border-border rounded-md text-text-secondary disabled:opacity-40 hover:bg-page"
            >
              Next →
            </button>
          </div>
        )}
      </div>

      {/* Slide-out panel */}
      <DetectionPanel detection={selected} onClose={() => setSelected(null)} />

      {/* ── Confirmation Modal ─────────────────────────────────────────────── */}
      {confirmState && (
        <>
          <div
            className="fixed inset-0 z-40 bg-black/40"
            onClick={() => setConfirmState(null)}
            data-testid="modal-overlay"
          />
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 pointer-events-none">
            <div
              className="bg-surface rounded-lg shadow-panel border border-border w-full max-w-sm pointer-events-auto"
              data-testid="confirm-modal"
            >
              {/* Header */}
              <div className="flex items-center justify-between px-4 py-3 border-b border-border">
                <h3 className="text-[13px] font-semibold text-text-primary">
                  {confirmState.action === 'resolve'         && 'Resolve Detections'}
                  {confirmState.action === 'false_positive'  && 'Mark as False Positive'}
                  {confirmState.action === 'assign'          && 'Assign Detections'}
                  {confirmState.action === 'create_incident' && 'Create Incident'}
                </h3>
                <button
                  onClick={() => setConfirmState(null)}
                  className="text-text-muted hover:text-text-secondary text-[16px] leading-none"
                  data-testid="modal-close"
                >
                  ×
                </button>
              </div>

              {/* Body */}
              <div className="px-4 py-4 space-y-3">
                {confirmState.action === 'resolve' && (
                  <p className="text-[12px] text-text-secondary">
                    Resolve{' '}
                    <span className="font-medium text-text-primary">{checkedCount}</span>{' '}
                    detection{checkedCount !== 1 ? 's' : ''}? This will set their status to{' '}
                    <span className="font-medium">resolved</span>.
                  </p>
                )}
                {confirmState.action === 'false_positive' && (
                  <p className="text-[12px] text-text-secondary">
                    Mark{' '}
                    <span className="font-medium text-text-primary">{checkedCount}</span>{' '}
                    detection{checkedCount !== 1 ? 's' : ''} as{' '}
                    <span className="font-medium">false positive</span>?
                  </p>
                )}
                {confirmState.action === 'assign' && (
                  <p className="text-[12px] text-text-secondary">
                    Assign{' '}
                    <span className="font-medium text-text-primary">{checkedCount}</span>{' '}
                    detection{checkedCount !== 1 ? 's' : ''} to{' '}
                    <span className="font-medium text-text-primary">{confirmState.assignee}</span>?
                  </p>
                )}
                {confirmState.action === 'create_incident' && (
                  <div className="space-y-3">
                    <p className="text-[12px] text-text-secondary">
                      Create an incident from{' '}
                      <span className="font-medium text-text-primary">{checkedCount}</span>{' '}
                      detection{checkedCount !== 1 ? 's' : ''}.
                    </p>
                    <div>
                      <label className="text-[11px] text-text-muted block mb-1">Incident Title</label>
                      <input
                        type="text"
                        placeholder="Enter incident title…"
                        value={incidentTitle}
                        onChange={(e) => setIncidentTitle(e.target.value)}
                        className="w-full h-[32px] px-3 text-[12px] border border-border rounded-md bg-surface text-text-primary placeholder-text-muted focus:outline-none focus:border-blue"
                        data-testid="incident-title-input"
                      />
                    </div>
                    <div>
                      <label className="text-[11px] text-text-muted block mb-1">Severity</label>
                      <select
                        value={incidentSeverity}
                        onChange={(e) => setIncidentSeverity(e.target.value as SeverityLevel)}
                        className="w-full h-[32px] px-3 text-[12px] border border-border rounded-md bg-surface text-text-primary focus:outline-none focus:border-blue"
                        data-testid="incident-severity-select"
                      >
                        {SEVERITY_OPTIONS.map((s) => (
                          <option key={s} value={s}>
                            {s.charAt(0).toUpperCase() + s.slice(1)}
                          </option>
                        ))}
                      </select>
                    </div>
                  </div>
                )}
              </div>

              {/* Footer */}
              <div className="flex justify-end gap-2 px-4 py-3 border-t border-border">
                <button
                  onClick={() => setConfirmState(null)}
                  className="h-[30px] px-4 text-[12px] font-medium border border-border rounded-md text-text-secondary hover:bg-page"
                  data-testid="modal-cancel"
                >
                  Cancel
                </button>
                <button
                  onClick={executeAction}
                  disabled={
                    isMutating ||
                    (confirmState.action === 'create_incident' && !incidentTitle.trim())
                  }
                  className="h-[30px] px-4 text-[12px] font-medium bg-blue text-white rounded-md hover:opacity-90 disabled:opacity-40"
                  data-testid="confirm-button"
                >
                  {isMutating ? 'Working…' : 'Confirm'}
                </button>
              </div>
            </div>
          </div>
        </>
      )}
    </>
  )
}
