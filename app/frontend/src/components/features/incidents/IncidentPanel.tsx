import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import type { Incident, IncidentStatus } from '../../../types/api'
import { incidentsApi } from '../../../lib/api'
import { SeverityPill } from '../../shared/SeverityBadge'

interface Props {
  incident: Incident | null
  onClose: () => void
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[130px_1fr] gap-2 py-[5px] border-b border-section">
      <span className="text-[10px] font-medium text-text-muted uppercase">{label}</span>
      <span className="text-[11px] text-text-primary break-words">{value ?? '—'}</span>
    </div>
  )
}

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

function StatusBadge({ status }: { status: IncidentStatus }) {
  return (
    <span className={`inline-block px-2 py-0.5 rounded-full text-[9px] font-medium ${STATUS_COLORS[status]}`}>
      {STATUS_LABELS[status]}
    </span>
  )
}

function fmtDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`
  if (seconds < 86400) return `${(seconds / 3600).toFixed(1)}h`
  return `${(seconds / 86400).toFixed(1)}d`
}

type Tab = 'details' | 'notes' | 'detections'

export function IncidentPanel({ incident, onClose }: Props) {
  const [tab, setTab] = useState<Tab>('details')
  const queryClient = useQueryClient()

  const detailQuery = useQuery({
    queryKey: ['incident-detail', incident?.id],
    queryFn: () => incidentsApi.get(incident!.id),
    enabled: !!incident,
  })

  const [noteContent, setNoteContent] = useState('')
  const noteMutation = useMutation({
    mutationFn: (content: string) => incidentsApi.addNote(incident!.id, content),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['incident-detail', incident?.id] })
      setNoteContent('')
    },
  })

  const updateMutation = useMutation({
    mutationFn: (update: { status?: IncidentStatus; assigned_to?: string | null }) =>
      incidentsApi.update(incident!.id, update),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['incidents'] })
      queryClient.invalidateQueries({ queryKey: ['incident-detail', incident?.id] })
    },
  })

  if (!incident) return null

  const detail = detailQuery.data
  const TABS: { key: Tab; label: string }[] = [
    { key: 'details',    label: 'Details' },
    { key: 'notes',      label: `Notes${detail ? ` (${detail.notes.length})` : ''}` },
    { key: 'detections', label: `Detections${detail ? ` (${detail.detections.length})` : ''}` },
  ]

  const STATUS_FLOW: IncidentStatus[] = ['new', 'investigating', 'contained', 'resolved', 'closed']
  const currentIdx = STATUS_FLOW.indexOf(incident.status)
  const nextStatus = currentIdx < STATUS_FLOW.length - 1 ? STATUS_FLOW[currentIdx + 1] : null

  return (
    <>
      {/* Backdrop */}
      <div className="fixed inset-0 z-30 bg-transparent" onClick={onClose} />

      {/* Panel */}
      <div className="fixed top-[46px] right-0 bottom-0 w-[480px] bg-surface shadow-panel z-40 flex flex-col overflow-hidden border-l border-border">
        {/* Header */}
        <div className="flex items-start justify-between px-4 py-3 border-b border-border">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-[10px] text-text-muted font-mono">INC-{incident.id}</span>
              <SeverityPill severity={incident.severity} />
              <StatusBadge status={incident.status} />
            </div>
            <h2 className="text-[13px] font-semibold text-text-primary leading-snug mt-1 pr-2">
              {incident.title}
            </h2>
          </div>
          <button
            className="text-text-muted hover:text-text-primary ml-2 text-lg leading-none flex-shrink-0"
            onClick={onClose}
            title="Close"
          >
            ×
          </button>
        </div>

        {/* Quick action bar */}
        <div className="flex items-center gap-2 px-4 py-2 border-b border-section">
          {nextStatus && (
            <button
              onClick={() => updateMutation.mutate({ status: nextStatus })}
              disabled={updateMutation.isPending}
              className="h-[26px] px-3 text-[11px] bg-blue text-white rounded-md hover:opacity-90 disabled:opacity-50"
            >
              → {STATUS_LABELS[nextStatus]}
            </button>
          )}
          {incident.status === 'closed' && (
            <span className="text-[11px] text-text-muted">Incident closed</span>
          )}
          {detail && detail.duration_seconds > 0 && (
            <span className="text-[10px] text-text-muted ml-auto">
              Open for {fmtDuration(detail.duration_seconds)}
            </span>
          )}
        </div>

        {/* Tabs */}
        <div className="flex border-b border-border">
          {TABS.map(({ key, label }) => (
            <button
              key={key}
              onClick={() => setTab(key)}
              className={`px-4 py-2 text-[11px] font-medium border-b-2 transition-colors ${
                tab === key
                  ? 'border-blue text-blue'
                  : 'border-transparent text-text-muted hover:text-text-secondary'
              }`}
            >
              {label}
            </button>
          ))}
        </div>

        {/* Tab content */}
        <div className="flex-1 overflow-y-auto px-4 py-2">

          {/* Details tab */}
          {tab === 'details' && (
            <div>
              <Row label="ID"          value={`INC-${incident.id}`} />
              <Row label="Severity"    value={<SeverityPill severity={incident.severity} />} />
              <Row label="Status"      value={<StatusBadge status={incident.status} />} />
              <Row label="Priority"    value={incident.priority} />
              <Row label="Assigned To" value={
                <AssignedToField
                  current={incident.assigned_to}
                  onSave={(val) => updateMutation.mutate({ assigned_to: val || null })}
                  pending={updateMutation.isPending}
                />
              } />
              <Row label="Created By"  value={incident.created_by} />
              <Row label="Hosts"       value={
                incident.hosts.length > 0 ? (
                  <div className="flex flex-wrap gap-1">
                    {incident.hosts.map(h => (
                      <span key={h} className="text-[10px] bg-page border border-border rounded px-1.5 py-px text-text-secondary">{h}</span>
                    ))}
                  </div>
                ) : '—'
              } />
              <Row label="Tactics"     value={
                incident.tactic_ids.length > 0
                  ? incident.tactic_ids.join(', ')
                  : '—'
              } />
              <Row label="Techniques"  value={
                incident.technique_ids.length > 0 ? (
                  <div className="flex flex-wrap gap-1">
                    {incident.technique_ids.map(t => (
                      <span key={t} className="text-[10px] bg-page border border-border rounded px-1.5 py-px font-mono text-text-secondary">{t}</span>
                    ))}
                  </div>
                ) : '—'
              } />
              <Row label="TTD"         value={incident.ttd_seconds != null ? fmtDuration(incident.ttd_seconds) : '—'} />
              <Row label="TTR"         value={incident.ttr_seconds != null ? fmtDuration(incident.ttr_seconds) : 'Open'} />
              <Row label="Created"     value={new Date(incident.created_at).toLocaleString()} />
              <Row label="Updated"     value={new Date(incident.updated_at).toLocaleString()} />
              {incident.closed_at && (
                <Row label="Closed"    value={new Date(incident.closed_at).toLocaleString()} />
              )}
              {incident.description && (
                <div className="mt-3">
                  <p className="text-[10px] font-medium text-text-muted uppercase mb-1">Description</p>
                  <p className="text-[11px] text-text-secondary leading-relaxed whitespace-pre-wrap">
                    {incident.description}
                  </p>
                </div>
              )}
            </div>
          )}

          {/* Notes tab */}
          {tab === 'notes' && (
            <div className="flex flex-col gap-0">
              {detailQuery.isLoading && (
                <div className="flex items-center justify-center h-24 text-text-muted text-sm">Loading…</div>
              )}

              {detail && detail.notes.length === 0 && (
                <div className="text-text-muted text-[11px] py-6 text-center">No notes yet.</div>
              )}

              {detail && detail.notes.map(note => (
                <div key={note.id} className="py-3 border-b border-section">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-[10px] font-medium text-text-primary">{note.author}</span>
                    {note.note_type !== 'comment' && (
                      <span className={`text-[9px] px-1.5 py-px rounded font-medium ${
                        note.note_type === 'status_change' ? 'bg-blue-light text-blue' : 'bg-med-bg text-med-text'
                      }`}>
                        {note.note_type === 'status_change' ? 'Status Change' : 'Evidence'}
                      </span>
                    )}
                    <span className="text-[10px] text-text-muted ml-auto">
                      {new Date(note.created_at).toLocaleString()}
                    </span>
                  </div>
                  <p className="text-[11px] text-text-secondary leading-relaxed whitespace-pre-wrap">
                    {note.content}
                  </p>
                </div>
              ))}

              {/* Add note form */}
              <div className="mt-3 pt-3">
                <textarea
                  value={noteContent}
                  onChange={e => setNoteContent(e.target.value)}
                  placeholder="Add a comment or observation…"
                  rows={3}
                  className="w-full text-[11px] bg-page border border-border rounded-md p-2 text-text-primary placeholder-text-muted focus:outline-none focus:border-blue resize-none"
                />
                <div className="flex justify-end mt-1.5">
                  <button
                    onClick={() => noteMutation.mutate(noteContent)}
                    disabled={noteMutation.isPending || !noteContent.trim()}
                    className="h-[28px] px-3 text-[11px] bg-blue text-white rounded-md hover:opacity-90 disabled:opacity-50"
                  >
                    {noteMutation.isPending ? 'Adding…' : 'Add Note'}
                  </button>
                </div>
                {noteMutation.isError && (
                  <p className="text-[11px] text-crit-text mt-1">
                    {(noteMutation.error as Error)?.message ?? 'Failed to add note.'}
                  </p>
                )}
              </div>
            </div>
          )}

          {/* Detections tab */}
          {tab === 'detections' && (
            <div>
              {detailQuery.isLoading && (
                <div className="flex items-center justify-center h-24 text-text-muted text-sm">Loading…</div>
              )}

              {detail && detail.detections.length === 0 && (
                <div className="text-text-muted text-[11px] py-6 text-center">No linked detections.</div>
              )}

              {detail && detail.detections.map(d => (
                <div key={d.id} className="py-2 border-b border-section">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[11px] text-text-primary font-medium truncate">{d.name}</span>
                    <span className={`flex-shrink-0 text-[9px] px-1.5 py-px rounded font-medium ${
                      d.severity === 'critical' ? 'bg-crit-bg text-crit-text' :
                      d.severity === 'high'     ? 'bg-high-bg text-high-text' :
                      d.severity === 'medium'   ? 'bg-med-bg text-med-text'   :
                                                  'bg-low-bg text-low-text'
                    }`}>{d.severity}</span>
                  </div>
                  <div className="text-[10px] text-text-muted mt-0.5">
                    {d.technique_id} · {d.host} · {new Date(d.time).toLocaleString()}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </>
  )
}

// ── Inline assigned-to editor ─────────────────────────────────────────────────

function AssignedToField({
  current,
  onSave,
  pending,
}: {
  current: string | null
  onSave: (val: string) => void
  pending: boolean
}) {
  const [editing, setEditing] = useState(false)
  const [value, setValue] = useState(current ?? '')

  if (!editing) {
    return (
      <span
        className="cursor-pointer hover:text-blue transition-colors"
        onClick={() => { setValue(current ?? ''); setEditing(true) }}
        title="Click to edit"
      >
        {current ?? <span className="text-text-muted italic">Unassigned</span>}
      </span>
    )
  }

  return (
    <div className="flex items-center gap-1.5">
      <input
        autoFocus
        value={value}
        onChange={e => setValue(e.target.value)}
        placeholder="analyst@org.com"
        className="h-[24px] px-2 text-[11px] border border-border rounded bg-page text-text-primary focus:outline-none focus:border-blue flex-1"
        onKeyDown={e => {
          if (e.key === 'Enter') { onSave(value); setEditing(false) }
          if (e.key === 'Escape') setEditing(false)
        }}
      />
      <button
        onClick={() => { onSave(value); setEditing(false) }}
        disabled={pending}
        className="text-[10px] text-blue hover:opacity-80 disabled:opacity-50"
      >
        Save
      </button>
      <button onClick={() => setEditing(false)} className="text-[10px] text-text-muted hover:text-text-secondary">
        ✕
      </button>
    </div>
  )
}
