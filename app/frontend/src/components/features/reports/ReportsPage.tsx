import { useState, useCallback } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { reportsApi } from '../../../lib/api'
import { TopBar } from '../../layout/TopBar'
import type {
  Report,
  ReportTemplate,
  ReportFormat,
  ReportSchedule,
} from '../../../types/api'

// ── Constants ─────────────────────────────────────────────────────────────────

const TEMPLATE_LABELS: Record<ReportTemplate, string> = {
  executive_summary:  'Executive Summary',
  detection_report:   'Detection Report',
  incident_report:    'Incident Report',
  coverage_report:    'Coverage Report',
  compliance_summary: 'Compliance Summary',
}

const TEMPLATES: ReportTemplate[] = [
  'executive_summary',
  'detection_report',
  'incident_report',
  'coverage_report',
  'compliance_summary',
]

const CRON_PRESETS: { label: string; value: string }[] = [
  { label: 'Daily at midnight',  value: '0 0 * * *'   },
  { label: 'Weekly (Monday)',    value: '0 0 * * 1'   },
  { label: 'Monthly (1st)',      value: '0 0 1 * *'   },
  { label: 'Every 6 hours',      value: '0 */6 * * *' },
  { label: 'Custom…',            value: 'custom'       },
]

// ── Helpers ───────────────────────────────────────────────────────────────────

function fmtDate(iso: string): string {
  return new Date(iso).toLocaleDateString('en-US', {
    month: 'short',
    day:   'numeric',
    year:  'numeric',
  })
}

function fmtDateTime(iso: string): string {
  return new Date(iso).toLocaleString('en-US', {
    month:  'short',
    day:    'numeric',
    hour:   '2-digit',
    minute: '2-digit',
  })
}

function humanCron(expr: string): string {
  const preset = CRON_PRESETS.find(p => p.value === expr)
  if (preset && preset.value !== 'custom') return preset.label
  const parts = expr.split(' ')
  if (parts.length !== 5) return expr
  const [min, hour, day, , weekday] = parts
  if (weekday !== '*') return `Weekly on day ${weekday}`
  if (day     !== '*') return `Monthly on day ${day}`
  if (hour    !== '*') return `Daily at ${hour}:${min === '0' ? '00' : min}`
  return expr
}

// ── Status badge ──────────────────────────────────────────────────────────────

function StatusBadge({ status }: { status: Report['status'] }) {
  const styles: Record<Report['status'], string> = {
    generating: 'bg-med-bg text-med-text',
    ready:      'bg-low-bg text-low-text',
    failed:     'bg-crit-bg text-crit-text',
  }
  return (
    <span className={`inline-flex items-center gap-1 text-[10px] px-1.5 py-[2px] rounded-[3px] font-medium ${styles[status]}`}>
      {status === 'generating' && (
        <span
          style={{ display: 'inline-block', animation: 'spin 1s linear infinite' }}
          aria-hidden="true"
        >
          ⟳
        </span>
      )}
      {status === 'ready'      && '✓ '}
      {status === 'failed'     && '✕ '}
      {status}
    </span>
  )
}

// ── Generate Report modal ─────────────────────────────────────────────────────

interface GenerateModalProps {
  onClose:     () => void
  onGenerated: (id: string) => void
}

function GenerateModal({ onClose, onGenerated }: GenerateModalProps) {
  const qc      = useQueryClient()
  const today   = new Date().toISOString().slice(0, 10)
  const monthAgo = new Date(Date.now() - 30 * 86_400_000).toISOString().slice(0, 10)

  const [template, setTemplate] = useState<ReportTemplate>('executive_summary')
  const [fromDate, setFromDate] = useState(monthAgo)
  const [toDate,   setToDate]   = useState(today)
  const [format,   setFormat]   = useState<ReportFormat>('json')
  const [error,    setError]    = useState<string | null>(null)

  const mutation = useMutation({
    mutationFn: () =>
      reportsApi.generate({
        template_type: template,
        from_date:     `${fromDate}T00:00:00Z`,
        to_date:       `${toDate}T23:59:59Z`,
        format,
      }),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ['reports'] })
      onGenerated(res.report_id)
      onClose()
    },
    onError: (err: Error) => {
      setError(err.message || 'Failed to start report generation')
    },
  })

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40" data-testid="generate-modal">
      <div className="bg-surface border border-border rounded-lg shadow-panel w-[400px] max-w-[calc(100vw-2rem)]">
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-border">
          <h2 className="text-[13px] font-semibold text-text-primary">Generate Report</h2>
          <button onClick={onClose} className="text-text-muted hover:text-text-primary text-lg leading-none" aria-label="Close">×</button>
        </div>

        {/* Body */}
        <div className="px-4 py-4 space-y-4">
          {/* Template */}
          <div>
            <label className="block text-[10px] font-medium text-text-muted uppercase mb-1">Template</label>
            <select
              value={template}
              onChange={e => setTemplate(e.target.value as ReportTemplate)}
              className="w-full h-[30px] px-2 text-[12px] bg-page border border-border rounded text-text-primary focus:border-blue focus:outline-none"
            >
              {TEMPLATES.map(t => (
                <option key={t} value={t}>{TEMPLATE_LABELS[t]}</option>
              ))}
            </select>
          </div>

          {/* Date range */}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-[10px] font-medium text-text-muted uppercase mb-1">From</label>
              <input
                type="date"
                value={fromDate}
                max={toDate}
                onChange={e => setFromDate(e.target.value)}
                className="w-full h-[30px] px-2 text-[12px] bg-page border border-border rounded text-text-primary focus:border-blue focus:outline-none"
              />
            </div>
            <div>
              <label className="block text-[10px] font-medium text-text-muted uppercase mb-1">To</label>
              <input
                type="date"
                value={toDate}
                min={fromDate}
                onChange={e => setToDate(e.target.value)}
                className="w-full h-[30px] px-2 text-[12px] bg-page border border-border rounded text-text-primary focus:border-blue focus:outline-none"
              />
            </div>
          </div>

          {/* Format */}
          <div>
            <label className="block text-[10px] font-medium text-text-muted uppercase mb-1">Format</label>
            <div className="flex items-center gap-2">
              {(['json', 'csv'] as ReportFormat[]).map(f => (
                <button
                  key={f}
                  type="button"
                  onClick={() => setFormat(f)}
                  className={`h-[28px] px-4 text-[11px] rounded border transition-colors font-medium ${
                    format === f
                      ? 'border-blue text-blue bg-blue/10'
                      : 'border-border text-text-muted hover:text-text-primary'
                  }`}
                >
                  {f.toUpperCase()}
                </button>
              ))}
            </div>
          </div>

          {error && (
            <p className="text-[11px] text-crit-text" role="alert">{error}</p>
          )}
        </div>

        {/* Footer */}
        <div className="flex justify-end gap-2 px-4 py-3 border-t border-border">
          <button
            type="button"
            onClick={onClose}
            className="h-[28px] px-3 text-[11px] border border-border rounded text-text-secondary hover:bg-page"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={() => mutation.mutate()}
            disabled={mutation.isPending}
            className="h-[28px] px-4 text-[11px] bg-blue text-white rounded font-medium disabled:opacity-50"
          >
            {mutation.isPending ? 'Generating…' : 'Generate'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Create Schedule modal ─────────────────────────────────────────────────────

interface CreateScheduleModalProps {
  onClose: () => void
}

function CreateScheduleModal({ onClose }: CreateScheduleModalProps) {
  const qc = useQueryClient()

  const [name,       setName]       = useState('')
  const [template,   setTemplate]   = useState<ReportTemplate>('executive_summary')
  const [format,     setFormat]     = useState<ReportFormat>('json')
  const [preset,     setPreset]     = useState(CRON_PRESETS[0].value)
  const [customCron, setCustomCron] = useState('')
  const [error,      setError]      = useState<string | null>(null)

  const cronExpr = preset === 'custom' ? customCron : preset

  const mutation = useMutation({
    mutationFn: () =>
      reportsApi.createSchedule({
        name:            name.trim(),
        template_type:   template,
        format,
        cron_expression: cronExpr,
        enabled:         true,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['report-schedules'] })
      onClose()
    },
    onError: (err: Error) => {
      setError(err.message || 'Failed to create schedule')
    },
  })

  const canSubmit = name.trim().length > 0 && cronExpr.trim().length > 0 && !mutation.isPending

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40" data-testid="schedule-modal">
      <div className="bg-surface border border-border rounded-lg shadow-panel w-[440px] max-w-[calc(100vw-2rem)]">
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-border">
          <h2 className="text-[13px] font-semibold text-text-primary">Create Schedule</h2>
          <button onClick={onClose} className="text-text-muted hover:text-text-primary text-lg leading-none" aria-label="Close">×</button>
        </div>

        {/* Body */}
        <div className="px-4 py-4 space-y-4">
          {/* Name */}
          <div>
            <label className="block text-[10px] font-medium text-text-muted uppercase mb-1">Schedule Name</label>
            <input
              type="text"
              value={name}
              onChange={e => setName(e.target.value)}
              placeholder="e.g. Weekly executive summary"
              className="w-full h-[30px] px-2 text-[12px] bg-page border border-border rounded text-text-primary focus:border-blue focus:outline-none"
            />
          </div>

          {/* Template */}
          <div>
            <label className="block text-[10px] font-medium text-text-muted uppercase mb-1">Template</label>
            <select
              value={template}
              onChange={e => setTemplate(e.target.value as ReportTemplate)}
              className="w-full h-[30px] px-2 text-[12px] bg-page border border-border rounded text-text-primary focus:border-blue focus:outline-none"
            >
              {TEMPLATES.map(t => (
                <option key={t} value={t}>{TEMPLATE_LABELS[t]}</option>
              ))}
            </select>
          </div>

          {/* Format */}
          <div>
            <label className="block text-[10px] font-medium text-text-muted uppercase mb-1">Format</label>
            <div className="flex items-center gap-2">
              {(['json', 'csv'] as ReportFormat[]).map(f => (
                <button
                  key={f}
                  type="button"
                  onClick={() => setFormat(f)}
                  className={`h-[28px] px-4 text-[11px] rounded border transition-colors font-medium ${
                    format === f
                      ? 'border-blue text-blue bg-blue/10'
                      : 'border-border text-text-muted hover:text-text-primary'
                  }`}
                >
                  {f.toUpperCase()}
                </button>
              ))}
            </div>
          </div>

          {/* Cron builder */}
          <div>
            <label className="block text-[10px] font-medium text-text-muted uppercase mb-1">Schedule</label>
            <select
              value={preset}
              onChange={e => setPreset(e.target.value)}
              className="w-full h-[30px] px-2 text-[12px] bg-page border border-border rounded text-text-primary focus:border-blue focus:outline-none mb-2"
            >
              {CRON_PRESETS.map(p => (
                <option key={p.value} value={p.value}>{p.label}</option>
              ))}
            </select>
            {preset === 'custom' ? (
              <input
                type="text"
                value={customCron}
                onChange={e => setCustomCron(e.target.value)}
                placeholder="0 0 * * 1"
                aria-label="Cron expression"
                className="w-full h-[30px] px-2 text-[12px] font-mono bg-page border border-border rounded text-text-primary focus:border-blue focus:outline-none"
              />
            ) : (
              <p className="text-[10px] text-text-muted font-mono">{cronExpr}</p>
            )}
          </div>

          {error && (
            <p className="text-[11px] text-crit-text" role="alert">{error}</p>
          )}
        </div>

        {/* Footer */}
        <div className="flex justify-end gap-2 px-4 py-3 border-t border-border">
          <button
            type="button"
            onClick={onClose}
            className="h-[28px] px-3 text-[11px] border border-border rounded text-text-secondary hover:bg-page"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={() => mutation.mutate()}
            disabled={!canSubmit}
            className="h-[28px] px-4 text-[11px] bg-blue text-white rounded font-medium disabled:opacity-50"
          >
            {mutation.isPending ? 'Creating…' : 'Create Schedule'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Generated Reports tab ─────────────────────────────────────────────────────

interface GeneratedTabProps {
  onOpenGenerate: () => void
}

function GeneratedTab({ onOpenGenerate }: GeneratedTabProps) {
  const qc = useQueryClient()
  const [page,         setPage]         = useState(1)
  const [downloadingId, setDownloadingId] = useState<string | null>(null)

  const { data, isLoading, isError } = useQuery({
    queryKey: ['reports', page],
    queryFn:  () => reportsApi.list({ page, page_size: 20 }),
    refetchInterval: (query) => {
      const items = query.state.data?.items
      return items?.some((r: Report) => r.status === 'generating') ? 3000 : false
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => reportsApi.delete(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['reports'] }),
  })

  const handleDownload = useCallback(async (report: Report) => {
    if (report.status !== 'ready') return
    setDownloadingId(report.id)
    try {
      const { blob, filename } = await reportsApi.download(report.id)
      const url = URL.createObjectURL(blob)
      const a   = document.createElement('a')
      a.href     = url
      a.download = filename
      a.click()
      URL.revokeObjectURL(url)
    } catch {
      // Download error is non-fatal — button will re-enable
    } finally {
      setDownloadingId(null)
    }
  }, [])

  const reports    = data?.items ?? []
  const totalPages = data?.pagination.total_pages ?? 0

  return (
    <div>
      {/* Action row */}
      <div className="flex items-center justify-between mb-3">
        <p className="text-[11px] text-text-muted">
          {data ? `${data.pagination.total} report${data.pagination.total !== 1 ? 's' : ''}` : ''}
        </p>
        <button
          type="button"
          onClick={onOpenGenerate}
          className="h-[28px] px-3 text-[11px] bg-blue text-white rounded font-medium"
        >
          + Generate Report
        </button>
      </div>

      {/* Table */}
      <div className="bg-surface rounded-md shadow-card overflow-hidden">
        {/* Column headers */}
        <div className="grid grid-cols-[1fr_110px_90px_60px_80px] gap-3 px-4 py-2 border-b border-section bg-page">
          {['Template', 'Created', 'Status', 'Format', 'Actions'].map(h => (
            <span key={h} className="text-[10px] font-medium text-text-muted uppercase">{h}</span>
          ))}
        </div>

        {isLoading && (
          <div className="flex items-center justify-center py-12 text-text-muted text-sm">
            Loading…
          </div>
        )}
        {isError && (
          <div className="flex items-center justify-center py-12 text-crit-text text-sm">
            Failed to load reports.
          </div>
        )}
        {!isLoading && !isError && reports.length === 0 && (
          <div className="flex flex-col items-center justify-center py-12 text-text-muted">
            <p className="text-sm">No reports generated yet</p>
            <p className="text-[11px] mt-1">Click "Generate Report" to create your first report</p>
          </div>
        )}

        {!isLoading && !isError && reports.map(report => (
          <div
            key={report.id}
            className="grid grid-cols-[1fr_110px_90px_60px_80px] gap-3 px-4 py-[9px] border-b border-section items-center hover:bg-page/50 transition-colors"
          >
            {/* Template */}
            <div>
              <p className="text-[12px] font-medium text-text-primary">{TEMPLATE_LABELS[report.template_type]}</p>
              <p className="text-[10px] text-text-muted">{report.created_by}</p>
            </div>

            {/* Created */}
            <span className="text-[11px] text-text-secondary">
              {fmtDate(report.created_at)}
            </span>

            {/* Status */}
            <StatusBadge status={report.status} />

            {/* Format */}
            <span className="text-[11px] text-text-secondary uppercase">{report.format}</span>

            {/* Actions */}
            <div className="flex items-center gap-2">
              <button
                type="button"
                title="Download"
                aria-label="Download report"
                disabled={report.status !== 'ready' || downloadingId === report.id}
                onClick={() => handleDownload(report)}
                className={`text-[11px] px-2 py-[2px] rounded border transition-colors ${
                  report.status === 'ready'
                    ? 'border-border text-text-secondary hover:border-blue hover:text-blue'
                    : 'border-transparent text-text-muted opacity-40 cursor-not-allowed'
                }`}
              >
                {downloadingId === report.id ? '…' : '↓'}
              </button>
              <button
                type="button"
                title="Delete report"
                aria-label="Delete report"
                onClick={() => deleteMutation.mutate(report.id)}
                disabled={deleteMutation.isPending}
                className="text-[11px] px-2 py-[2px] rounded border border-transparent text-text-muted hover:border-crit-text hover:text-crit-text transition-colors"
              >
                ×
              </button>
            </div>
          </div>
        ))}

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between px-4 py-2 border-t border-border">
            <span className="text-[10px] text-text-muted">
              Page {page} of {totalPages} · {data?.pagination.total ?? 0} total
            </span>
            <div className="flex items-center gap-1">
              <button
                type="button"
                onClick={() => setPage(p => Math.max(1, p - 1))}
                disabled={page === 1}
                className="h-[24px] px-2 text-[10px] border border-border rounded disabled:opacity-40 hover:bg-page"
              >
                ‹ Prev
              </button>
              <button
                type="button"
                onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                disabled={page === totalPages}
                className="h-[24px] px-2 text-[10px] border border-border rounded disabled:opacity-40 hover:bg-page"
              >
                Next ›
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

// ── Scheduled Reports tab ─────────────────────────────────────────────────────

interface ScheduledTabProps {
  onOpenCreate: () => void
}

function ScheduledTab({ onOpenCreate }: ScheduledTabProps) {
  const qc = useQueryClient()

  const { data, isLoading, isError } = useQuery({
    queryKey: ['report-schedules'],
    queryFn:  () => reportsApi.listSchedules(),
    retry: false,
  })

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      reportsApi.updateSchedule(id, { enabled }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['report-schedules'] }),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => reportsApi.deleteSchedule(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['report-schedules'] }),
  })

  const schedules = data?.items ?? []

  return (
    <div>
      {/* Action row */}
      <div className="flex items-center justify-between mb-3">
        <p className="text-[11px] text-text-muted">
          {data ? `${schedules.length} schedule${schedules.length !== 1 ? 's' : ''}` : ''}
        </p>
        <button
          type="button"
          onClick={onOpenCreate}
          className="h-[28px] px-3 text-[11px] bg-blue text-white rounded font-medium"
        >
          + Create Schedule
        </button>
      </div>

      {/* Table */}
      <div className="bg-surface rounded-md shadow-card overflow-hidden">
        {/* Column headers */}
        <div className="grid grid-cols-[1fr_140px_170px_60px_130px_130px_40px] gap-3 px-4 py-2 border-b border-section bg-page">
          {['Name', 'Template', 'Schedule', 'On', 'Last Run', 'Next Run', ''].map((h, i) => (
            <span key={i} className="text-[10px] font-medium text-text-muted uppercase">{h}</span>
          ))}
        </div>

        {isLoading && (
          <div className="flex items-center justify-center py-12 text-text-muted text-sm">
            Loading…
          </div>
        )}
        {isError && (
          <div className="flex items-center justify-center py-12 text-text-muted text-sm">
            Scheduled reports are not available.
          </div>
        )}
        {!isLoading && !isError && schedules.length === 0 && (
          <div className="flex flex-col items-center justify-center py-12 text-text-muted">
            <p className="text-sm">No scheduled reports</p>
            <p className="text-[11px] mt-1">Click "Create Schedule" to automate report generation</p>
          </div>
        )}

        {!isLoading && !isError && schedules.map((schedule: ReportSchedule) => (
          <div
            key={schedule.id}
            className="grid grid-cols-[1fr_140px_170px_60px_130px_130px_40px] gap-3 px-4 py-[9px] border-b border-section items-center hover:bg-page/50 transition-colors"
          >
            {/* Name */}
            <div>
              <p className="text-[12px] font-medium text-text-primary">{schedule.name}</p>
              <p className="text-[10px] text-text-muted uppercase">{schedule.format}</p>
            </div>

            {/* Template */}
            <span className="text-[11px] text-text-secondary">{TEMPLATE_LABELS[schedule.template_type]}</span>

            {/* Schedule */}
            <div>
              <p className="text-[11px] text-text-secondary">{humanCron(schedule.cron_expression)}</p>
              <p className="text-[10px] text-text-muted font-mono">{schedule.cron_expression}</p>
            </div>

            {/* Enabled toggle */}
            <button
              type="button"
              role="switch"
              aria-checked={schedule.enabled}
              aria-label={schedule.enabled ? 'Disable schedule' : 'Enable schedule'}
              onClick={() => toggleMutation.mutate({ id: schedule.id, enabled: !schedule.enabled })}
              className={`relative w-8 h-4 rounded-full transition-colors focus:outline-none ${
                schedule.enabled ? 'bg-low-text' : 'bg-border'
              }`}
            >
              <span className={`absolute top-0.5 left-0.5 w-3 h-3 bg-white rounded-full shadow transition-transform ${
                schedule.enabled ? 'translate-x-4' : ''
              }`} />
            </button>

            {/* Last run */}
            <span className="text-[11px] text-text-muted">
              {schedule.last_run_at ? fmtDateTime(schedule.last_run_at) : '—'}
            </span>

            {/* Next run */}
            <span className="text-[11px] text-text-muted">
              {schedule.next_run_at ? fmtDateTime(schedule.next_run_at) : '—'}
            </span>

            {/* Delete */}
            <button
              type="button"
              title="Delete schedule"
              aria-label="Delete schedule"
              onClick={() => deleteMutation.mutate(schedule.id)}
              disabled={deleteMutation.isPending}
              className="text-[11px] px-1 py-[2px] rounded border border-transparent text-text-muted hover:border-crit-text hover:text-crit-text transition-colors"
            >
              ×
            </button>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

type Tab = 'generated' | 'scheduled'

export function ReportsPage() {
  const [tab,              setTab]              = useState<Tab>('generated')
  const [showGenerateModal, setShowGenerateModal] = useState(false)
  const [showScheduleModal, setShowScheduleModal] = useState(false)

  return (
    <>
      <TopBar crumb="Reports" />
      <div className="pt-[46px] px-5 pb-6">
        {/* Tab bar */}
        <div className="flex items-center gap-1 bg-section rounded-md p-1 mb-5 w-fit">
          {([
            { id: 'generated' as const, label: 'Generated Reports'  },
            { id: 'scheduled' as const, label: 'Scheduled Reports'  },
          ] as { id: Tab; label: string }[]).map(t => (
            <button
              key={t.id}
              type="button"
              onClick={() => setTab(t.id)}
              className={`h-[26px] px-3 text-[11px] font-medium rounded transition-colors ${
                tab === t.id
                  ? 'bg-surface text-text-primary shadow-card'
                  : 'text-text-muted hover:text-text-primary'
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>

        {/* Tab content */}
        {tab === 'generated' && (
          <GeneratedTab onOpenGenerate={() => setShowGenerateModal(true)} />
        )}
        {tab === 'scheduled' && (
          <ScheduledTab onOpenCreate={() => setShowScheduleModal(true)} />
        )}
      </div>

      {/* Modals */}
      {showGenerateModal && (
        <GenerateModal
          onClose={() => setShowGenerateModal(false)}
          onGenerated={() => { /* polling handles updates */ }}
        />
      )}
      {showScheduleModal && (
        <CreateScheduleModal onClose={() => setShowScheduleModal(false)} />
      )}
    </>
  )
}
