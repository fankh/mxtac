import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import type { IOC, IOCType, IOCCreate, IOCUpdate, SeverityLevel } from '../../../types/api'
import { threatIntelApi, detectionsApi } from '../../../lib/api'
import { TopBar } from '../../layout/TopBar'

// ── Helpers ────────────────────────────────────────────────────────────────────

const IOC_TYPES: IOCType[] = ['ip', 'domain', 'hash_md5', 'hash_sha256', 'url', 'email']
const SEVERITIES: SeverityLevel[] = ['critical', 'high', 'medium', 'low']

const IOC_TYPE_LABELS: Record<IOCType, string> = {
  ip:          'IP',
  domain:      'Domain',
  hash_md5:    'MD5',
  hash_sha256: 'SHA-256',
  url:         'URL',
  email:       'Email',
}

function fmtDate(iso: string | null | undefined): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleDateString([], { month: 'short', day: 'numeric', year: '2-digit' })
}

function fmtDateTime(iso: string | null | undefined): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleString()
}

// ── IOC Type Icons (inline SVG) ────────────────────────────────────────────────

function GlobeIcon() {
  return (
    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10"/>
      <path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/>
      <path d="M2 12h20"/>
    </svg>
  )
}

function LinkIcon() {
  return (
    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/>
      <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>
    </svg>
  )
}

function FingerprintIcon() {
  return (
    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M2 12C2 6.5 6.5 2 12 2a10 10 0 0 1 8 4"/>
      <path d="M5 19.5C5.5 18 6 15 6 12c0-1.9.6-3.7 1.7-5.1"/>
      <path d="M22 12c0 1-.1 1.9-.3 2.8"/>
      <path d="M19 6l-1.7 1.7c-.6.6-.9 1.4-.9 2.3 0 1.8 1.5 3.2 3.3 3.2"/>
      <path d="M13 12c0 1-.1 2-.3 3"/>
      <path d="M10 12a2 2 0 0 1 4 0"/>
    </svg>
  )
}

function ExternalLinkIcon() {
  return (
    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>
      <polyline points="15 3 21 3 21 9"/>
      <line x1="10" y1="14" x2="21" y2="3"/>
    </svg>
  )
}

function MailIcon() {
  return (
    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect width="20" height="16" x="2" y="4" rx="2"/>
      <path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/>
    </svg>
  )
}

type IconComponent = () => React.ReactElement

const IOC_TYPE_ICONS: Record<IOCType, IconComponent> = {
  ip:          GlobeIcon,
  domain:      LinkIcon,
  hash_md5:    FingerprintIcon,
  hash_sha256: FingerprintIcon,
  url:         ExternalLinkIcon,
  email:       MailIcon,
}

const IOC_TYPE_COLORS: Record<IOCType, string> = {
  ip:          'text-blue bg-blue-light',
  domain:      'text-text-secondary bg-section',
  hash_md5:    'text-med-text bg-med-bg',
  hash_sha256: 'text-high-text bg-high-bg',
  url:         'text-low-text bg-low-bg',
  email:       'text-crit-text bg-crit-bg',
}

function TypeBadge({ type }: { type: IOCType }) {
  const Icon = IOC_TYPE_ICONS[type] ?? GlobeIcon
  const cls  = IOC_TYPE_COLORS[type] ?? 'text-text-secondary bg-section'
  return (
    <span className={`inline-flex items-center gap-[3px] text-[10px] px-1.5 py-[2px] rounded-[3px] font-medium ${cls}`}>
      <Icon />
      {IOC_TYPE_LABELS[type] ?? type}
    </span>
  )
}

// ── Sub-components ─────────────────────────────────────────────────────────────

function SeverityBadge({ severity }: { severity: string }) {
  const cls =
    severity === 'critical' ? 'bg-crit-bg text-crit-text' :
    severity === 'high'     ? 'bg-high-bg text-high-text' :
    severity === 'medium'   ? 'bg-med-bg text-med-text'   :
                              'bg-low-bg text-low-text'
  return (
    <span className={`text-[10px] px-1.5 py-[2px] rounded-[3px] font-medium ${cls}`}>
      {severity}
    </span>
  )
}

function ConfidenceBar({ value }: { value: number }) {
  const color =
    value >= 80 ? 'bg-low-text' :
    value >= 50 ? 'bg-med-text' :
                  'bg-high-text'
  return (
    <div className="flex items-center gap-1.5" title={`Confidence: ${value}%`}>
      <div className="w-16 h-1.5 bg-section rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${value}%` }} />
      </div>
      <span className="text-[10px] text-text-muted">{value}%</span>
    </div>
  )
}

// ── Stats cards ────────────────────────────────────────────────────────────────

function StatsCards({ total, active, expired, totalHits }: {
  total: number
  active: number
  expired: number
  totalHits: number
}) {
  return (
    <div className="grid grid-cols-4 gap-3 mb-4">
      {[
        { label: 'Total IOCs', value: total,     sub: 'in database' },
        { label: 'Active',     value: active,    sub: 'currently active' },
        { label: 'Expired',    value: expired,   sub: 'past expiry' },
        { label: 'Total Hits', value: totalHits, sub: 'IOC match events' },
      ].map(({ label, value, sub }) => (
        <div key={label} className="bg-surface rounded-md shadow-card px-4 py-3">
          <p className="text-[10px] text-text-muted uppercase font-medium">{label}</p>
          <p className="text-[22px] font-semibold text-text-primary leading-tight mt-0.5">
            {value.toLocaleString()}
          </p>
          <p className="text-[10px] text-text-muted mt-0.5">{sub}</p>
        </div>
      ))}
    </div>
  )
}

// ── Related Detections (shown in IOC panel) ────────────────────────────────────

function RelatedDetections({ iocValue }: { iocValue: string }) {
  const { data, isLoading } = useQuery({
    queryKey: ['ioc-related-detections', iocValue],
    queryFn:  () => detectionsApi.list({ search: iocValue, page_size: 5 }),
    enabled:  !!iocValue,
  })

  const detections = data?.items ?? []

  if (isLoading) return <p className="text-[10px] text-text-muted italic">Loading…</p>
  if (detections.length === 0) return <p className="text-[10px] text-text-muted italic">No related detections found.</p>

  return (
    <div className="space-y-1">
      {detections.map(d => (
        <div key={d.id} className="bg-page border border-section rounded px-2 py-1.5">
          <div className="flex items-center justify-between gap-2">
            <span className="text-[11px] text-text-primary truncate flex-1">{d.name}</span>
            <SeverityBadge severity={d.severity} />
          </div>
          <div className="text-[10px] text-text-muted mt-0.5">{d.host} · {fmtDate(d.time)}</div>
        </div>
      ))}
    </div>
  )
}

// ── IOC detail panel ───────────────────────────────────────────────────────────

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[120px_1fr] gap-2 py-[5px] border-b border-section">
      <span className="text-[10px] font-medium text-text-muted uppercase">{label}</span>
      <span className="text-[11px] text-text-primary break-all">{value ?? '—'}</span>
    </div>
  )
}

function IOCPanel({ ioc, onClose, onDeactivate }: {
  ioc: IOC | null
  onClose: () => void
  onDeactivate: (id: number) => void
}) {
  if (!ioc) return null

  return (
    <>
      <div className="fixed inset-0 z-30 bg-transparent" onClick={onClose} />
      <div className="fixed top-[46px] right-0 bottom-0 w-[480px] bg-surface shadow-panel z-40 flex flex-col overflow-hidden border-l border-border">
        {/* Header */}
        <div className="flex items-start justify-between px-4 py-3 border-b border-border">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2 flex-wrap">
              <TypeBadge type={ioc.ioc_type} />
              <SeverityBadge severity={ioc.severity} />
              {!ioc.is_active && (
                <span className="text-[10px] px-1.5 py-[2px] rounded-[3px] bg-section text-text-muted font-medium">inactive</span>
              )}
            </div>
            <p className="text-[12px] font-mono text-text-primary mt-1.5 break-all leading-tight">{ioc.value}</p>
          </div>
          <button
            className="text-text-muted hover:text-text-primary ml-2 text-lg leading-none flex-shrink-0"
            onClick={onClose}
            title="Close"
          >
            ×
          </button>
        </div>

        {/* Hit count badge */}
        {ioc.hit_count > 0 && (
          <div className="px-4 py-2 border-b border-section bg-high-bg">
            <span className="text-[11px] text-high-text font-medium">
              {ioc.hit_count} hit{ioc.hit_count !== 1 ? 's' : ''} recorded
              {ioc.last_hit_at && ` · last: ${fmtDateTime(ioc.last_hit_at)}`}
            </span>
          </div>
        )}

        {/* Details */}
        <div className="flex-1 overflow-y-auto px-4 py-2">
          <Row label="Type"       value={<TypeBadge type={ioc.ioc_type} />} />
          <Row label="Value"      value={<span className="font-mono text-[11px]">{ioc.value}</span>} />
          <Row label="Source"     value={ioc.source} />
          <Row label="Severity"   value={<SeverityBadge severity={ioc.severity} />} />
          <Row label="Confidence" value={<ConfidenceBar value={ioc.confidence} />} />
          <Row label="Status"     value={ioc.is_active ? 'Active' : 'Inactive'} />
          <Row label="First Seen" value={fmtDateTime(ioc.first_seen)} />
          <Row label="Last Seen"  value={fmtDateTime(ioc.last_seen)} />
          <Row label="Expires At" value={fmtDateTime(ioc.expires_at)} />
          <Row label="Hit Count"  value={ioc.hit_count} />
          <Row label="Last Hit"   value={fmtDateTime(ioc.last_hit_at)} />
          <Row label="Created"    value={fmtDateTime(ioc.created_at)} />
          <Row label="Updated"    value={fmtDateTime(ioc.updated_at)} />

          {ioc.description && (
            <div className="mt-3">
              <p className="text-[10px] font-medium text-text-muted uppercase mb-1">Description</p>
              <p className="text-[11px] text-text-primary leading-relaxed">{ioc.description}</p>
            </div>
          )}

          {ioc.tags.length > 0 && (
            <div className="mt-3">
              <p className="text-[10px] font-medium text-text-muted uppercase mb-1">Tags</p>
              <div className="flex flex-wrap gap-1">
                {ioc.tags.map(t => (
                  <span key={t} className="text-[10px] bg-page border border-border rounded px-1.5 py-px text-text-secondary">{t}</span>
                ))}
              </div>
            </div>
          )}

          {/* Related detections */}
          <div className="mt-4">
            <p className="text-[10px] font-medium text-text-muted uppercase mb-2">Related Detections</p>
            <RelatedDetections iocValue={ioc.value} />
          </div>
        </div>

        {/* Footer actions */}
        {ioc.is_active && (
          <div className="px-4 py-3 border-t border-border flex items-center justify-end">
            <button
              onClick={() => { onDeactivate(ioc.id); onClose() }}
              className="h-[28px] px-3 text-[11px] border border-crit-text text-crit-text rounded-md hover:bg-crit-bg transition-colors"
            >
              Deactivate IOC
            </button>
          </div>
        )}
      </div>
    </>
  )
}

// ── Field wrapper ──────────────────────────────────────────────────────────────

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="block text-[10px] font-medium text-text-muted uppercase mb-1">{label}</label>
      {children}
    </div>
  )
}

// ── Add IOC modal ──────────────────────────────────────────────────────────────

const TODAY = new Date().toISOString().slice(0, 10)

const BLANK_IOC: IOCCreate = {
  ioc_type:    'ip',
  value:       '',
  source:      'manual',
  confidence:  70,
  severity:    'medium',
  description: null,
  tags:        [],
  first_seen:  TODAY + 'T00:00:00Z',
  last_seen:   TODAY + 'T00:00:00Z',
  expires_at:  null,
  is_active:   true,
}

function AddIOCModal({ onClose }: { onClose: () => void }) {
  const queryClient = useQueryClient()
  const [form, setForm]           = useState<IOCCreate>({ ...BLANK_IOC })
  const [tagsInput, setTagsInput] = useState('')

  const mutation = useMutation({
    mutationFn: (body: IOCCreate) => threatIntelApi.create(body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['threat-intel-iocs'] })
      queryClient.invalidateQueries({ queryKey: ['threat-intel-stats'] })
      onClose()
    },
  })

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    const tags = tagsInput.split(',').map(s => s.trim()).filter(Boolean)
    mutation.mutate({
      ...form,
      tags,
      description: form.description || null,
      expires_at:  form.expires_at  || null,
    })
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
      <div className="bg-surface rounded-lg shadow-panel w-[520px] max-h-[90vh] flex flex-col border border-border">
        <div className="flex items-center justify-between px-5 py-3 border-b border-border">
          <h2 className="text-[13px] font-semibold text-text-primary">Add IOC</h2>
          <button onClick={onClose} className="text-text-muted hover:text-text-primary text-lg leading-none">×</button>
        </div>

        <form onSubmit={handleSubmit} className="flex-1 overflow-y-auto px-5 py-4 space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <Field label="IOC Type *">
              <select
                value={form.ioc_type}
                onChange={e => setForm(f => ({ ...f, ioc_type: e.target.value as IOCType }))}
                className="input-sm w-full"
              >
                {IOC_TYPES.map(t => <option key={t} value={t}>{IOC_TYPE_LABELS[t]}</option>)}
              </select>
            </Field>
            <Field label="Severity *">
              <select
                value={form.severity}
                onChange={e => setForm(f => ({ ...f, severity: e.target.value as SeverityLevel }))}
                className="input-sm w-full"
              >
                {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            </Field>
          </div>

          <Field label="Value *">
            <input
              required
              value={form.value}
              onChange={e => setForm(f => ({ ...f, value: e.target.value }))}
              className="input-sm w-full font-mono"
              placeholder={
                form.ioc_type === 'ip'          ? '192.168.1.1' :
                form.ioc_type === 'domain'      ? 'malicious.example.com' :
                form.ioc_type === 'hash_md5'    ? '32-char hex hash' :
                form.ioc_type === 'hash_sha256' ? '64-char hex hash' :
                form.ioc_type === 'url'         ? 'https://malicious.example.com/path' :
                                                  'user@malicious.example.com'
              }
            />
          </Field>

          <div className="grid grid-cols-2 gap-3">
            <Field label="Source *">
              <input
                required
                value={form.source}
                onChange={e => setForm(f => ({ ...f, source: e.target.value }))}
                className="input-sm w-full"
                placeholder="opencti, manual, stix-feed…"
              />
            </Field>
            <Field label="Confidence (0–100)">
              <input
                type="number"
                min={0}
                max={100}
                value={form.confidence}
                onChange={e => setForm(f => ({ ...f, confidence: Number(e.target.value) }))}
                className="input-sm w-full"
              />
            </Field>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <Field label="First Seen *">
              <input
                type="date"
                required
                value={form.first_seen.slice(0, 10)}
                onChange={e => setForm(f => ({ ...f, first_seen: e.target.value + 'T00:00:00Z' }))}
                className="input-sm w-full"
              />
            </Field>
            <Field label="Last Seen *">
              <input
                type="date"
                required
                value={form.last_seen.slice(0, 10)}
                onChange={e => setForm(f => ({ ...f, last_seen: e.target.value + 'T00:00:00Z' }))}
                className="input-sm w-full"
              />
            </Field>
          </div>

          <Field label="Expires At">
            <input
              type="date"
              value={form.expires_at ? form.expires_at.slice(0, 10) : ''}
              onChange={e => setForm(f => ({ ...f, expires_at: e.target.value ? e.target.value + 'T00:00:00Z' : null }))}
              className="input-sm w-full"
            />
          </Field>

          <Field label="Description">
            <textarea
              value={form.description ?? ''}
              onChange={e => setForm(f => ({ ...f, description: e.target.value || null }))}
              rows={3}
              className="w-full text-[11px] bg-page border border-border rounded-md p-2 text-text-primary placeholder-text-muted focus:outline-none focus:border-blue resize-none"
              placeholder="Optional description…"
            />
          </Field>

          <Field label="Tags (comma-separated)">
            <input
              value={tagsInput}
              onChange={e => setTagsInput(e.target.value)}
              className="input-sm w-full"
              placeholder="apt29, phishing, c2"
            />
          </Field>

          {mutation.isError && (
            <p className="text-[11px] text-crit-text">
              {(mutation.error as Error)?.message ?? 'Failed to create IOC.'}
            </p>
          )}
        </form>

        <div className="flex items-center justify-end gap-2 px-5 py-3 border-t border-border">
          <button type="button" onClick={onClose} className="h-[30px] px-4 text-[12px] border border-border rounded-md text-text-secondary hover:bg-page">
            Cancel
          </button>
          <button
            onClick={(e) => { e.preventDefault(); handleSubmit(e as unknown as React.FormEvent) }}
            disabled={mutation.isPending || !form.value || !form.source}
            className="h-[30px] px-4 text-[12px] bg-blue text-white rounded-md hover:opacity-90 disabled:opacity-50"
          >
            {mutation.isPending ? 'Adding…' : 'Add IOC'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Bulk Import modal ──────────────────────────────────────────────────────────

const BULK_PLACEHOLDER = `Paste JSON array or CSV (one per line).

JSON example:
[{"ioc_type":"ip","value":"1.2.3.4","source":"stix","severity":"high","first_seen":"2024-01-01T00:00:00Z","last_seen":"2024-01-01T00:00:00Z"}]

CSV example (type,value,source,severity[,confidence]):
ip,1.2.3.4,stix,high,80
domain,evil.example.com,manual,medium,60
hash_sha256,aabbcc...,internal,critical`

function parseCsvLine(line: string): IOCCreate | null {
  const parts = line.split(',').map(s => s.trim())
  if (parts.length < 4) return null
  const [ioc_type, value, source, severity, conf] = parts
  if (!ioc_type || !value || !source || !severity) return null
  const today = new Date().toISOString().slice(0, 10) + 'T00:00:00Z'
  return {
    ioc_type:   ioc_type as IOCType,
    value,
    source,
    severity:   severity as SeverityLevel,
    confidence: conf ? Math.min(100, Math.max(0, parseInt(conf, 10))) : 70,
    first_seen: today,
    last_seen:  today,
    is_active:  true,
  }
}

function BulkImportModal({ onClose }: { onClose: () => void }) {
  const queryClient = useQueryClient()
  const [text, setText]             = useState('')
  const [parseError, setParseError] = useState<string | null>(null)
  const [result, setResult]         = useState<{ created: number; skipped: number } | null>(null)

  const mutation = useMutation({
    mutationFn: (items: IOCCreate[]) => threatIntelApi.bulkImport(items),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['threat-intel-iocs'] })
      queryClient.invalidateQueries({ queryKey: ['threat-intel-stats'] })
      setResult(data)
    },
  })

  function handleImport() {
    setParseError(null)
    setResult(null)
    const trimmed = text.trim()
    if (!trimmed) { setParseError('Paste some data first.'); return }

    let items: IOCCreate[]
    if (trimmed.startsWith('[') || trimmed.startsWith('{')) {
      try {
        const parsed = JSON.parse(trimmed)
        items = Array.isArray(parsed) ? parsed : [parsed]
      } catch {
        setParseError('Invalid JSON — check the format and try again.')
        return
      }
    } else {
      items = trimmed
        .split('\n')
        .map(l => l.trim())
        .filter(l => l && !l.startsWith('#'))
        .map(parseCsvLine)
        .filter((x): x is IOCCreate => x !== null)
      if (items.length === 0) {
        setParseError('No valid CSV rows. Expected: type,value,source,severity[,confidence]')
        return
      }
    }
    mutation.mutate(items)
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
      <div className="bg-surface rounded-lg shadow-panel w-[620px] max-h-[90vh] flex flex-col border border-border">
        <div className="flex items-center justify-between px-5 py-3 border-b border-border">
          <h2 className="text-[13px] font-semibold text-text-primary">Bulk Import IOCs</h2>
          <button onClick={onClose} className="text-text-muted hover:text-text-primary text-lg leading-none">×</button>
        </div>

        <div className="flex-1 overflow-y-auto px-5 py-4 space-y-3">
          <textarea
            value={text}
            onChange={e => { setText(e.target.value); setParseError(null); setResult(null) }}
            rows={14}
            className="w-full text-[11px] font-mono bg-page border border-border rounded-md p-3 text-text-primary placeholder-text-muted focus:outline-none focus:border-blue resize-none"
            placeholder={BULK_PLACEHOLDER}
          />
          {parseError && <p className="text-[11px] text-crit-text">{parseError}</p>}
          {mutation.isError && (
            <p className="text-[11px] text-crit-text">
              Import failed: {(mutation.error as Error)?.message ?? 'Unknown error'}
            </p>
          )}
          {result && (
            <div className="bg-low-bg border border-low-text/30 rounded-md px-3 py-2">
              <p className="text-[12px] text-low-text font-medium">
                Import complete: {result.created} created, {result.skipped} skipped (duplicates)
              </p>
            </div>
          )}
        </div>

        <div className="flex items-center justify-end gap-2 px-5 py-3 border-t border-border">
          <button type="button" onClick={onClose} className="h-[30px] px-4 text-[12px] border border-border rounded-md text-text-secondary hover:bg-page">
            {result ? 'Close' : 'Cancel'}
          </button>
          {!result && (
            <button
              onClick={handleImport}
              disabled={mutation.isPending || !text.trim()}
              className="h-[30px] px-4 text-[12px] bg-blue text-white rounded-md hover:opacity-90 disabled:opacity-50"
            >
              {mutation.isPending ? 'Importing…' : 'Import IOCs'}
            </button>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Edit IOC modal ─────────────────────────────────────────────────────────────

function EditIOCModal({ ioc, onClose }: { ioc: IOC; onClose: () => void }) {
  const queryClient = useQueryClient()
  const [form, setForm] = useState<IOCUpdate>({
    severity:    ioc.severity,
    confidence:  ioc.confidence,
    description: ioc.description,
    tags:        ioc.tags,
    last_seen:   ioc.last_seen,
    expires_at:  ioc.expires_at,
    is_active:   ioc.is_active,
  })
  const [tagsInput, setTagsInput] = useState(ioc.tags.join(', '))

  const mutation = useMutation({
    mutationFn: (body: IOCUpdate) => threatIntelApi.update(ioc.id, body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['threat-intel-iocs'] })
      queryClient.invalidateQueries({ queryKey: ['threat-intel-stats'] })
      onClose()
    },
  })

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    const tags = tagsInput.split(',').map(s => s.trim()).filter(Boolean)
    mutation.mutate({ ...form, tags })
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
      <div className="bg-surface rounded-lg shadow-panel w-[480px] max-h-[90vh] flex flex-col border border-border">
        <div className="flex items-center justify-between px-5 py-3 border-b border-border">
          <div>
            <h2 className="text-[13px] font-semibold text-text-primary">Edit IOC</h2>
            <p className="text-[10px] text-text-muted font-mono truncate max-w-[340px]">{ioc.value}</p>
          </div>
          <button onClick={onClose} className="text-text-muted hover:text-text-primary text-lg leading-none">×</button>
        </div>

        <form onSubmit={handleSubmit} className="flex-1 overflow-y-auto px-5 py-4 space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <Field label="Severity">
              <select
                value={form.severity ?? ioc.severity}
                onChange={e => setForm(f => ({ ...f, severity: e.target.value as SeverityLevel }))}
                className="input-sm w-full"
              >
                {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            </Field>
            <Field label="Confidence (0–100)">
              <input
                type="number"
                min={0}
                max={100}
                value={form.confidence ?? ioc.confidence}
                onChange={e => setForm(f => ({ ...f, confidence: Number(e.target.value) }))}
                className="input-sm w-full"
              />
            </Field>
          </div>

          <Field label="Last Seen">
            <input
              type="date"
              value={(form.last_seen ?? ioc.last_seen).slice(0, 10)}
              onChange={e => setForm(f => ({ ...f, last_seen: e.target.value + 'T00:00:00Z' }))}
              className="input-sm w-full"
            />
          </Field>

          <Field label="Expires At">
            <input
              type="date"
              value={form.expires_at ? form.expires_at.slice(0, 10) : ''}
              onChange={e => setForm(f => ({ ...f, expires_at: e.target.value ? e.target.value + 'T00:00:00Z' : null }))}
              className="input-sm w-full"
            />
          </Field>

          <Field label="Description">
            <textarea
              value={form.description ?? ''}
              onChange={e => setForm(f => ({ ...f, description: e.target.value || null }))}
              rows={3}
              className="w-full text-[11px] bg-page border border-border rounded-md p-2 text-text-primary placeholder-text-muted focus:outline-none focus:border-blue resize-none"
            />
          </Field>

          <Field label="Tags (comma-separated)">
            <input
              value={tagsInput}
              onChange={e => setTagsInput(e.target.value)}
              className="input-sm w-full"
            />
          </Field>

          <div className="flex items-center gap-2">
            <input
              id="ioc-active"
              type="checkbox"
              checked={form.is_active ?? ioc.is_active}
              onChange={e => setForm(f => ({ ...f, is_active: e.target.checked }))}
              className="w-[14px] h-[14px]"
            />
            <label htmlFor="ioc-active" className="text-[11px] text-text-primary cursor-pointer">Active</label>
          </div>

          {mutation.isError && (
            <p className="text-[11px] text-crit-text">
              {(mutation.error as Error)?.message ?? 'Update failed.'}
            </p>
          )}
        </form>

        <div className="flex items-center justify-end gap-2 px-5 py-3 border-t border-border">
          <button type="button" onClick={onClose} className="h-[30px] px-4 text-[12px] border border-border rounded-md text-text-secondary hover:bg-page">
            Cancel
          </button>
          <button
            onClick={(e) => { e.preventDefault(); handleSubmit(e as unknown as React.FormEvent) }}
            disabled={mutation.isPending}
            className="h-[30px] px-4 text-[12px] bg-blue text-white rounded-md hover:opacity-90 disabled:opacity-50"
          >
            {mutation.isPending ? 'Saving…' : 'Save Changes'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Main page ──────────────────────────────────────────────────────────────────

export function ThreatIntelPage() {
  const [iocType,  setIocType]  = useState<string>('')
  const [source,   setSource]   = useState<string>('')
  const [isActive, setIsActive] = useState<boolean | undefined>()
  const [search,   setSearch]   = useState('')
  const [page,     setPage]     = useState(1)

  const [selected,   setSelected]   = useState<IOC | null>(null)
  const [editTarget, setEditTarget] = useState<IOC | null>(null)
  const [showAdd,    setShowAdd]    = useState(false)
  const [showBulk,   setShowBulk]   = useState(false)

  const queryClient = useQueryClient()

  const { data, isLoading, isError } = useQuery({
    queryKey: ['threat-intel-iocs', { iocType, source, isActive, search, page }],
    queryFn: () =>
      threatIntelApi.list({
        ioc_type:  iocType  || undefined,
        source:    source   || undefined,
        is_active: isActive ?? undefined,
        search:    search   || undefined,
        page,
        page_size: 25,
      }),
  })

  const { data: stats } = useQuery({
    queryKey: ['threat-intel-stats'],
    queryFn:  () => threatIntelApi.stats(),
  })

  const deactivateMutation = useMutation({
    mutationFn: (id: number) => threatIntelApi.deactivate(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['threat-intel-iocs'] })
      queryClient.invalidateQueries({ queryKey: ['threat-intel-stats'] })
    },
  })

  function resetPage() { setPage(1) }

  const iocs       = data?.items ?? []
  const pagination = data?.pagination

  return (
    <>
      <TopBar crumb="Threat Intel" updatedAt="just now" />
      <div className="pt-[46px] px-5 pb-6">

        {/* Stats */}
        {stats && (
          <StatsCards
            total={stats.total}
            active={stats.active}
            expired={stats.expired}
            totalHits={stats.total_hits}
          />
        )}

        {/* Filter bar */}
        <div className="flex items-center gap-2 py-3 flex-wrap">
          <div className="flex items-center gap-1.5">
            <span className="text-[10px] text-text-muted">Type:</span>
            <select
              value={iocType}
              onChange={e => { setIocType(e.target.value); resetPage() }}
              className="h-[26px] px-2 text-[11px] border border-border rounded-md bg-surface text-text-primary focus:outline-none focus:border-blue"
            >
              <option value="">All</option>
              {IOC_TYPES.map(t => <option key={t} value={t}>{IOC_TYPE_LABELS[t]}</option>)}
            </select>
          </div>

          <div className="w-px h-[20px] bg-border mx-1" />

          <div className="flex items-center gap-1.5">
            <span className="text-[10px] text-text-muted">Source:</span>
            <select
              value={source}
              onChange={e => { setSource(e.target.value); resetPage() }}
              className="h-[26px] px-2 text-[11px] border border-border rounded-md bg-surface text-text-primary focus:outline-none focus:border-blue"
            >
              <option value="">All</option>
              {stats && Object.keys(stats.by_source).map(s => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
          </div>

          <div className="w-px h-[20px] bg-border mx-1" />

          <div className="flex items-center gap-1.5">
            <span className="text-[10px] text-text-muted">Status:</span>
            {([undefined, true, false] as const).map((val) => {
              const label = val === undefined ? 'All' : val ? 'Active' : 'Inactive'
              return (
                <button
                  key={label}
                  onClick={() => { setIsActive(val); resetPage() }}
                  className={`px-3 h-[26px] rounded-[5px] text-[11px] font-medium border transition-colors ${
                    isActive === val
                      ? 'bg-blue text-white border-blue'
                      : 'bg-surface text-text-secondary border-border hover:border-blue hover:text-blue'
                  }`}
                >
                  {label}
                </button>
              )
            })}
          </div>

          {/* Search + actions */}
          <div className="ml-auto flex items-center gap-2">
            <input
              type="text"
              placeholder="Search IOC value, source…"
              value={search}
              onChange={e => { setSearch(e.target.value); resetPage() }}
              className="h-[28px] px-3 text-[11px] border border-border rounded-md bg-surface text-text-primary placeholder-text-muted focus:outline-none focus:border-blue w-[220px]"
            />
            <button
              onClick={() => setShowBulk(true)}
              className="h-[28px] px-3 text-[11px] border border-border rounded-md text-text-secondary hover:bg-page whitespace-nowrap"
            >
              Bulk Import
            </button>
            <button
              onClick={() => setShowAdd(true)}
              className="h-[28px] px-3 text-[11px] bg-blue text-white rounded-md hover:opacity-90 whitespace-nowrap"
            >
              + Add IOC
            </button>
          </div>
        </div>

        {/* Summary row */}
        {pagination && (
          <div className="flex items-center gap-3 mb-2">
            <span className="text-[11px] text-text-muted">
              {pagination.total.toLocaleString()} IOCs
              {iocType   && ` · type: ${IOC_TYPE_LABELS[iocType as IOCType] ?? iocType}`}
              {source    && ` · source: ${source}`}
              {isActive !== undefined && ` · ${isActive ? 'active' : 'inactive'}`}
              {search    && ` · "${search}"`}
            </span>
          </div>
        )}

        {/* Table */}
        <div className="bg-surface rounded-md shadow-card overflow-hidden">
          <div className="grid grid-cols-[100px_1fr_100px_90px_110px_70px_90px_100px] gap-2 px-3 py-2 border-b border-border">
            {['Type', 'Value', 'Source', 'Severity', 'Confidence', 'Hits', 'Last Seen', 'Active / Edit'].map(h => (
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

          {!isLoading && !isError && iocs.map((ioc) => {
            const isSelected = selected?.id === ioc.id
            return (
              <div
                key={ioc.id}
                onClick={() => setSelected(isSelected ? null : ioc)}
                className={`grid grid-cols-[100px_1fr_100px_90px_110px_70px_90px_100px] gap-2 px-3 py-[7px] border-b border-section items-center cursor-pointer transition-colors ${
                  isSelected
                    ? 'bg-blue-faint border-l-[3px] border-l-blue'
                    : ioc.is_active ? 'hover:bg-page' : 'opacity-50 hover:bg-page'
                }`}
              >
                <TypeBadge type={ioc.ioc_type} />

                <div className="min-w-0">
                  <div className="text-[11px] text-text-primary font-mono truncate">{ioc.value}</div>
                  {ioc.tags.length > 0 && (
                    <div className="text-[10px] text-text-muted truncate">{ioc.tags.join(', ')}</div>
                  )}
                </div>

                <span className="text-[10px] text-text-secondary truncate">{ioc.source}</span>

                <SeverityBadge severity={ioc.severity} />

                <ConfidenceBar value={ioc.confidence} />

                <span className={`text-[11px] font-medium ${ioc.hit_count > 0 ? 'text-high-text' : 'text-text-muted'}`}>
                  {ioc.hit_count}
                </span>

                <span className="text-[10px] text-text-muted">{fmtDate(ioc.last_seen)}</span>

                {/* Active toggle + Edit — stop propagation so row click doesn't fire */}
                <div className="flex items-center gap-1.5" onClick={e => e.stopPropagation()}>
                  <button
                    title={ioc.is_active ? 'Click to deactivate' : 'Inactive'}
                    disabled={!ioc.is_active}
                    onClick={() => ioc.is_active && deactivateMutation.mutate(ioc.id)}
                    className={`w-[18px] h-[18px] rounded-full border-2 flex-shrink-0 transition-colors ${
                      ioc.is_active
                        ? 'bg-low-text border-low-text hover:opacity-70 cursor-pointer'
                        : 'bg-section border-border cursor-default'
                    }`}
                  />
                  <button
                    onClick={() => setEditTarget(ioc)}
                    title="Edit"
                    className="h-[22px] px-1.5 text-[10px] border border-border rounded text-text-muted hover:text-text-primary hover:bg-page transition-colors"
                  >
                    Edit
                  </button>
                </div>
              </div>
            )
          })}

          {!isLoading && !isError && iocs.length === 0 && (
            <div className="flex items-center justify-center h-32 text-text-muted text-sm">
              No IOCs match the current filters.
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
      <IOCPanel
        ioc={selected}
        onClose={() => setSelected(null)}
        onDeactivate={(id) => deactivateMutation.mutate(id)}
      />

      {/* Modals */}
      {showAdd    && <AddIOCModal     onClose={() => setShowAdd(false)} />}
      {showBulk   && <BulkImportModal onClose={() => setShowBulk(false)} />}
      {editTarget && <EditIOCModal    ioc={editTarget} onClose={() => setEditTarget(null)} />}
    </>
  )
}
