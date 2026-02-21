import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import type { Incident, IncidentStatus, SeverityLevel, IncidentCreate } from '../../../types/api'
import { incidentsApi } from '../../../lib/api'
import { TopBar } from '../../layout/TopBar'
import { SeverityPill } from '../../shared/SeverityBadge'
import { IncidentPanel } from './IncidentPanel'

// ── Type maps ─────────────────────────────────────────────────────────────────

const SEVERITY_OPTIONS: SeverityLevel[] = ['critical', 'high', 'medium', 'low']
const STATUS_OPTIONS: IncidentStatus[]  = ['new', 'investigating', 'contained', 'resolved', 'closed']

const STATUS_COLORS: Record<IncidentStatus, string> = {
  new:           'bg-blue-light text-blue',
  investigating: 'bg-high-bg text-high-text',
  contained:     'bg-med-bg text-med-text',
  resolved:      'bg-resolved-bg text-resolved-text',
  closed:        'bg-section text-text-muted',
}

const STATUS_LABELS: Record<IncidentStatus, string> = {
  new:           'New',
  investigating: 'Investigating',
  contained:     'Contained',
  resolved:      'Resolved',
  closed:        'Closed',
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function StatusPill({ status }: { status: IncidentStatus }) {
  return (
    <span className={`inline-block px-2 py-0.5 rounded-full text-[9px] font-medium ${STATUS_COLORS[status]}`}>
      {STATUS_LABELS[status]}
    </span>
  )
}

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

function fmtDuration(seconds: number | null): string {
  if (seconds == null) return '—'
  if (seconds < 60) return `${seconds}s`
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`
  if (seconds < 86400) return `${(seconds / 3600).toFixed(1)}h`
  return `${(seconds / 86400).toFixed(1)}d`
}

// ── Stats cards ───────────────────────────────────────────────────────────────

function StatsCards({
  total,
  open,
  mttr,
  bySeverity,
}: {
  total: number
  open: number
  mttr: number | null
  bySeverity: Record<string, number>
}) {
  const critical = bySeverity['critical'] ?? 0
  const high     = bySeverity['high'] ?? 0

  return (
    <div className="grid grid-cols-4 gap-3 mb-4">
      {[
        { label: 'Total Incidents',    value: total,                  sub: 'last 30 days' },
        { label: 'Open',               value: open,                   sub: 'active incidents' },
        { label: 'Avg MTTR',           value: fmtDuration(mttr),      sub: 'mean time to resolve' },
        { label: 'Critical / High',    value: `${critical} / ${high}`, sub: 'by severity' },
      ].map(({ label, value, sub }) => (
        <div key={label} className="bg-surface rounded-md shadow-card px-4 py-3">
          <p className="text-[10px] text-text-muted uppercase font-medium">{label}</p>
          <p className="text-[22px] font-semibold text-text-primary leading-tight mt-0.5">{value}</p>
          <p className="text-[10px] text-text-muted mt-0.5">{sub}</p>
        </div>
      ))}
    </div>
  )
}

// ── Create incident modal ─────────────────────────────────────────────────────

const BLANK_FORM: IncidentCreate = {
  title: '',
  description: '',
  severity: 'medium',
  detection_ids: [],
  assigned_to: null,
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="block text-[10px] font-medium text-text-muted uppercase mb-1">{label}</label>
      {children}
    </div>
  )
}

function CreateIncidentModal({ onClose }: { onClose: () => void }) {
  const queryClient = useQueryClient()
  const [form, setForm] = useState<IncidentCreate>({ ...BLANK_FORM })
  const [detIds, setDetIds] = useState('')

  const mutation = useMutation({
    mutationFn: (body: IncidentCreate) => incidentsApi.create(body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['incidents'] })
      queryClient.invalidateQueries({ queryKey: ['incident-metrics'] })
      onClose()
    },
  })

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    const ids = detIds.split(',').map(s => s.trim()).filter(Boolean)
    mutation.mutate({
      ...form,
      detection_ids: ids,
      description:  form.description || null,
      assigned_to:  form.assigned_to || null,
    })
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
      <div className="bg-surface rounded-lg shadow-panel w-[480px] max-h-[90vh] flex flex-col border border-border">
        <div className="flex items-center justify-between px-5 py-3 border-b border-border">
          <h2 className="text-[13px] font-semibold text-text-primary">Create Incident</h2>
          <button onClick={onClose} className="text-text-muted hover:text-text-primary text-lg leading-none">×</button>
        </div>
        <form onSubmit={handleSubmit} className="flex-1 overflow-y-auto px-5 py-4 space-y-3">
          <Field label="Title *">
            <input
              required
              value={form.title}
              onChange={e => setForm(f => ({ ...f, title: e.target.value }))}
              className="h-[28px] px-2 text-[11px] border border-border rounded-md bg-page w-full text-text-primary placeholder-text-muted focus:outline-none focus:border-blue"
              placeholder="e.g. Lateral Movement via Pass-the-Hash"
            />
          </Field>

          <Field label="Severity *">
            <select
              value={form.severity}
              onChange={e => setForm(f => ({ ...f, severity: e.target.value as SeverityLevel }))}
              className="h-[28px] px-2 text-[11px] border border-border rounded-md bg-page w-full text-text-primary focus:outline-none focus:border-blue"
            >
              {SEVERITY_OPTIONS.map(s => (
                <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
              ))}
            </select>
          </Field>

          <Field label="Description">
            <textarea
              value={form.description ?? ''}
              onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
              rows={3}
              className="w-full text-[11px] border border-border rounded-md bg-page p-2 text-text-primary placeholder-text-muted focus:outline-none focus:border-blue resize-none"
              placeholder="Describe the incident…"
            />
          </Field>

          <Field label="Assigned To">
            <input
              value={form.assigned_to ?? ''}
              onChange={e => setForm(f => ({ ...f, assigned_to: e.target.value }))}
              className="h-[28px] px-2 text-[11px] border border-border rounded-md bg-page w-full text-text-primary placeholder-text-muted focus:outline-none focus:border-blue"
              placeholder="analyst@org.com"
            />
          </Field>

          <Field label="Linked Detection IDs (comma-separated)">
            <input
              value={detIds}
              onChange={e => setDetIds(e.target.value)}
              className="h-[28px] px-2 text-[11px] border border-border rounded-md bg-page w-full text-text-primary placeholder-text-muted focus:outline-none focus:border-blue"
              placeholder="det-abc123, det-def456"
            />
          </Field>

          {mutation.isError && (
            <p className="text-[11px] text-crit-text">
              {(mutation.error as Error)?.message ?? 'Failed to create incident.'}
            </p>
          )}
        </form>
        <div className="flex items-center justify-end gap-2 px-5 py-3 border-t border-border">
          <button
            onClick={onClose}
            className="h-[30px] px-4 text-[12px] border border-border rounded-md text-text-secondary hover:bg-page"
          >
            Cancel
          </button>
          <button
            onClick={(e) => handleSubmit(e as unknown as React.FormEvent)}
            disabled={mutation.isPending || !form.title}
            className="h-[30px] px-4 text-[12px] bg-blue text-white rounded-md hover:opacity-90 disabled:opacity-50"
          >
            {mutation.isPending ? 'Creating…' : 'Create Incident'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export function IncidentsPage() {
  const [severities, setSeverities] = useState<SeverityLevel[]>([])
  const [statuses,   setStatuses]   = useState<IncidentStatus[]>([])
  const [search,     setSearch]     = useState('')
  const [page,       setPage]       = useState(1)
  const [selected,   setSelected]   = useState<Incident | null>(null)
  const [showCreate, setShowCreate] = useState(false)

  function toggleSeverity(s: SeverityLevel) {
    setSeverities(prev => prev.includes(s) ? prev.filter(x => x !== s) : [...prev, s])
    setPage(1)
  }

  function toggleStatus(s: IncidentStatus) {
    setStatuses(prev => prev.includes(s) ? prev.filter(x => x !== s) : [...prev, s])
    setPage(1)
  }

  const { data, isLoading, isError } = useQuery({
    queryKey: ['incidents', { severities, statuses, search, page }],
    queryFn: () =>
      incidentsApi.list({
        severity:  severities.length > 0 ? severities : undefined,
        status:    statuses.length > 0   ? statuses   : undefined,
        search:    search || undefined,
        page,
        page_size: 20,
        sort:      'created_at',
      }),
  })

  const { data: metrics } = useQuery({
    queryKey: ['incident-metrics'],
    queryFn: () => incidentsApi.metrics(),
  })

  const incidents  = data?.items ?? []
  const pagination = data?.pagination

  return (
    <>
      <TopBar crumb="Incidents" />
      <div className="pt-[46px] px-5 pb-6">

        {/* Stats */}
        {metrics && (
          <StatsCards
            total={Object.values(metrics.total_incidents).reduce((a, b) => a + b, 0)}
            open={metrics.open_incidents_count}
            mttr={metrics.mttr_seconds}
            bySeverity={metrics.incidents_by_severity}
          />
        )}

        {/* Filter bar */}
        <div className="flex items-center gap-2 py-3 flex-wrap">
          {/* Severity chips */}
          <div className="flex items-center gap-1">
            <span className="text-[10px] text-text-muted mr-1">Severity:</span>
            {SEVERITY_OPTIONS.map(s => (
              <FilterChip
                key={s}
                label={s.charAt(0).toUpperCase() + s.slice(1)}
                active={severities.includes(s)}
                onClick={() => toggleSeverity(s)}
              />
            ))}
          </div>

          <div className="w-px h-[20px] bg-border mx-1" />

          {/* Status chips */}
          <div className="flex items-center gap-1">
            <span className="text-[10px] text-text-muted mr-1">Status:</span>
            {STATUS_OPTIONS.map(s => (
              <FilterChip
                key={s}
                label={STATUS_LABELS[s]}
                active={statuses.includes(s)}
                onClick={() => toggleStatus(s)}
              />
            ))}
          </div>

          {/* Search + Create */}
          <div className="ml-auto flex items-center gap-2">
            <input
              type="text"
              placeholder="Search incidents…"
              value={search}
              onChange={e => { setSearch(e.target.value); setPage(1) }}
              className="h-[28px] px-3 text-[11px] border border-border rounded-md bg-surface text-text-primary placeholder-text-muted focus:outline-none focus:border-blue w-[200px]"
            />
            <button
              onClick={() => setShowCreate(true)}
              className="h-[28px] px-3 text-[11px] bg-blue text-white rounded-md hover:opacity-90 whitespace-nowrap"
            >
              + New Incident
            </button>
          </div>
        </div>

        {/* Summary row */}
        {pagination && (
          <div className="flex items-center gap-3 mb-2">
            <span className="text-[11px] text-text-muted">
              {pagination.total.toLocaleString()} incidents
              {severities.length > 0 && ` · ${severities.join(', ')}`}
              {statuses.length > 0   && ` · ${statuses.join(', ')}`}
            </span>
          </div>
        )}

        {/* Table */}
        <div className="bg-surface rounded-md shadow-card overflow-hidden">
          {/* Header */}
          <div className="grid grid-cols-[60px_1fr_100px_120px_130px_110px_80px] gap-2 px-3 py-2 border-b border-border">
            {['ID', 'Title', 'Severity', 'Status', 'Assigned To', 'Hosts', 'Created'].map(h => (
              <span key={h} className="text-[10px] font-medium text-text-muted uppercase">{h}</span>
            ))}
          </div>

          {isLoading && (
            <div className="flex items-center justify-center h-40 text-text-muted text-sm">Loading…</div>
          )}
          {isError && (
            <div className="flex items-center justify-center h-40 text-crit-text text-sm">
              Failed to load. Is the backend running?
            </div>
          )}

          {!isLoading && !isError && incidents.map(inc => {
            const isSelected = selected?.id === inc.id
            return (
              <div
                key={inc.id}
                onClick={() => setSelected(isSelected ? null : inc)}
                className={`grid grid-cols-[60px_1fr_100px_120px_130px_110px_80px] gap-2 px-3 py-[7px] border-b border-section items-center cursor-pointer transition-colors ${
                  isSelected
                    ? 'bg-blue-faint border-l-[3px] border-l-blue'
                    : 'hover:bg-page'
                }`}
              >
                <span className="text-[10px] text-text-muted font-mono">INC-{inc.id}</span>
                <div className="min-w-0">
                  <div className="text-[11px] text-text-primary font-medium truncate">{inc.title}</div>
                  {inc.tactic_ids.length > 0 && (
                    <div className="text-[10px] text-text-muted truncate">{inc.tactic_ids.join(', ')}</div>
                  )}
                </div>
                <SeverityPill severity={inc.severity} />
                <StatusPill status={inc.status} />
                <span className="text-[11px] text-text-secondary truncate">
                  {inc.assigned_to ?? <span className="text-text-muted italic">Unassigned</span>}
                </span>
                <span className="text-[10px] text-text-muted truncate">
                  {inc.hosts.length > 0
                    ? inc.hosts.slice(0, 2).join(', ') + (inc.hosts.length > 2 ? ' …' : '')
                    : '—'}
                </span>
                <span className="text-[10px] text-text-muted">
                  {new Date(inc.created_at).toLocaleDateString([], { month: 'short', day: 'numeric' })}
                </span>
              </div>
            )
          })}

          {!isLoading && !isError && incidents.length === 0 && (
            <div className="flex items-center justify-center h-32 text-text-muted text-sm">
              No incidents match the current filters.
            </div>
          )}
        </div>

        {/* Pagination */}
        {pagination && pagination.total_pages > 1 && (
          <div className="flex items-center justify-center gap-2 mt-4">
            <button
              disabled={page <= 1}
              onClick={() => setPage(p => p - 1)}
              className="h-[28px] px-3 text-[11px] border border-border rounded-md text-text-secondary disabled:opacity-40 hover:bg-page"
            >
              ← Prev
            </button>
            <span className="text-[11px] text-text-muted">
              Page {pagination.page} of {pagination.total_pages}
            </span>
            <button
              disabled={page >= pagination.total_pages}
              onClick={() => setPage(p => p + 1)}
              className="h-[28px] px-3 text-[11px] border border-border rounded-md text-text-secondary disabled:opacity-40 hover:bg-page"
            >
              Next →
            </button>
          </div>
        )}
      </div>

      {/* Slide-out panel */}
      <IncidentPanel incident={selected} onClose={() => setSelected(null)} />

      {/* Create modal */}
      {showCreate && <CreateIncidentModal onClose={() => setShowCreate(false)} />}
    </>
  )
}
