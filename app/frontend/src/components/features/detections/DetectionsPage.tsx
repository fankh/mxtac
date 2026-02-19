import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import type { Detection, SeverityLevel, DetectionStatus } from '../../../types/api'
import { detectionsApi } from '../../../lib/api'
import { TopBar } from '../../layout/TopBar'
import { ScoreCircle, SeverityPill } from '../../shared/SeverityBadge'
import { StatusPill } from '../../shared/StatusPill'
import { DetectionPanel } from './DetectionPanel'

const SEVERITY_OPTIONS: SeverityLevel[] = ['critical', 'high', 'medium', 'low']
const STATUS_OPTIONS: DetectionStatus[]  = ['active', 'investigating', 'resolved', 'false_positive']

type SortKey = 'score' | 'time' | 'severity' | 'host' | 'tactic'

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
  const [severity, setSeverity]   = useState<SeverityLevel | undefined>()
  const [status, setStatus]       = useState<DetectionStatus | undefined>()
  const [search, setSearch]       = useState('')
  const [sortKey, setSortKey]     = useState<SortKey>('score')
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc')
  const [selected, setSelected]   = useState<Detection | null>(null)
  const [page, setPage]           = useState(1)

  const { data, isLoading, isError } = useQuery({
    queryKey: ['detections', { severity, status, search, sortKey, sortOrder, page }],
    queryFn: () =>
      detectionsApi.list({
        severity,
        status,
        search: search || undefined,
        sort: sortKey,
        order: sortOrder,
        page,
        page_size: 20,
      }),
  })

  function toggleSort(key: SortKey) {
    if (sortKey === key) {
      setSortOrder((o) => (o === 'desc' ? 'asc' : 'desc'))
    } else {
      setSortKey(key)
      setSortOrder('desc')
    }
    setPage(1)
  }

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

  const detections = data?.items ?? []
  const pagination = data?.pagination

  return (
    <>
      <TopBar crumb="Detections" updatedAt="just now" />
      <div className="pt-[46px] px-5 pb-6">

        {/* Filter bar */}
        <div className="flex items-center gap-2 py-3 flex-wrap">
          {/* Severity chips */}
          <div className="flex items-center gap-1">
            <span className="text-[10px] text-text-muted mr-1">Severity:</span>
            {SEVERITY_OPTIONS.map((s) => (
              <FilterChip
                key={s}
                label={s.charAt(0).toUpperCase() + s.slice(1)}
                active={severity === s}
                onClick={() => { setSeverity(severity === s ? undefined : s); setPage(1) }}
              />
            ))}
          </div>

          <div className="w-px h-[20px] bg-border mx-1" />

          {/* Status chips */}
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

        {/* Summary row */}
        {pagination && (
          <div className="flex items-center gap-3 mb-2">
            <span className="text-[11px] text-text-muted">
              {pagination.total.toLocaleString()} detections
              {severity && ` · ${severity}`}
              {status && ` · ${status}`}
            </span>
          </div>
        )}

        {/* Table */}
        <div className="bg-surface rounded-md shadow-card overflow-hidden">
          {/* Table header */}
          <div className="grid grid-cols-[44px_1fr_160px_110px_90px_100px_80px] gap-2 px-3 py-2 border-b border-border">
            <span className="text-[10px] font-medium text-text-muted uppercase">Score</span>
            <span className="text-[10px] font-medium text-text-muted uppercase">Detection</span>
            <span className="text-[10px] font-medium text-text-muted uppercase">Technique</span>
            <SortHeader col="host"    label="Host" />
            <SortHeader col="tactic"  label="Tactic" />
            <span className="text-[10px] font-medium text-text-muted uppercase">Status</span>
            <SortHeader col="time"    label="Time" />
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
            return (
              <div
                key={d.id}
                onClick={() => setSelected(isSelected ? null : d)}
                className={`grid grid-cols-[44px_1fr_160px_110px_90px_100px_80px] gap-2 px-3 py-[7px] border-b border-section items-center cursor-pointer transition-colors ${
                  isSelected
                    ? 'bg-[#F0F6FF] border-l-[3px] border-l-blue'
                    : 'hover:bg-page'
                }`}
              >
                <ScoreCircle score={d.score} severity={d.severity} />
                <div className="min-w-0">
                  <div className="text-[11px] text-text-primary truncate font-medium">{d.name}</div>
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
    </>
  )
}
