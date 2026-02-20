import { useState, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import type { Asset, AssetType, AssetCreate } from '../../../types/api'
import { assetsApi } from '../../../lib/api'
import { TopBar } from '../../layout/TopBar'
import { AssetPanel } from './AssetPanel'

// ── Helpers ────────────────────────────────────────────────────────────────────

const ASSET_TYPES: AssetType[] = ['server', 'workstation', 'network', 'cloud', 'container']

function Stars({ n }: { n: number }) {
  const color =
    n >= 5 ? 'text-crit-text' :
    n >= 4 ? 'text-high-text' :
    n >= 3 ? 'text-med-text'  : 'text-low-text'
  return (
    <span className={`${color} text-[13px] leading-none tracking-tight`} title={`Criticality ${n}/5`}>
      {'★'.repeat(n)}<span className="text-border">{'★'.repeat(5 - n)}</span>
    </span>
  )
}

function TypePill({ type }: { type: AssetType }) {
  const cls: Record<AssetType, string> = {
    server:      'bg-blue-light text-blue',
    workstation: 'bg-section text-text-secondary',
    network:     'bg-med-bg text-med-text',
    cloud:       'bg-low-bg text-low-text',
    container:   'bg-high-bg text-high-text',
  }
  return (
    <span className={`text-[10px] px-1.5 py-[2px] rounded-[3px] font-medium ${cls[type]}`}>
      {type}
    </span>
  )
}

// ── Stats cards ────────────────────────────────────────────────────────────────

function StatsCards({ total, byType, byCrit }: {
  total: number
  byType: Record<string, number>
  byCrit: Record<string, number>
}) {
  const critical = (byCrit['5'] ?? 0) + (byCrit['4'] ?? 0)
  const topType  = Object.entries(byType).sort((a, b) => b[1] - a[1])[0]

  return (
    <div className="grid grid-cols-4 gap-3 mb-4">
      {[
        { label: 'Total Assets',       value: total,     sub: 'in inventory' },
        { label: 'Critical / High',    value: critical,  sub: 'criticality ≥ 4' },
        { label: 'Top Type',           value: topType?.[0] ?? '—', sub: topType ? `${topType[1]} assets` : '' },
        { label: 'Crit 5 (Mission)',   value: byCrit['5'] ?? 0,   sub: 'mission-critical' },
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

// ── Add Asset modal ────────────────────────────────────────────────────────────

const BLANK: AssetCreate = {
  hostname: '',
  asset_type: 'server',
  criticality: 3,
  ip_addresses: [],
  os: '',
  os_family: 'linux',
  owner: '',
  department: '',
  location: '',
  tags: [],
  is_active: true,
}

function AddAssetModal({ onClose }: { onClose: () => void }) {
  const queryClient = useQueryClient()
  const [form, setForm] = useState<AssetCreate>({ ...BLANK })
  const [ipsInput, setIpsInput] = useState('')
  const [tagsInput, setTagsInput] = useState('')

  const mutation = useMutation({
    mutationFn: (body: AssetCreate) => assetsApi.create(body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['assets'] })
      queryClient.invalidateQueries({ queryKey: ['asset-stats'] })
      onClose()
    },
  })

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    const ips  = ipsInput.split(',').map(s => s.trim()).filter(Boolean)
    const tags = tagsInput.split(',').map(s => s.trim()).filter(Boolean)
    mutation.mutate({
      ...form,
      ip_addresses: ips,
      tags,
      os:         form.os  || null,
      os_family:  form.os_family || null,
      owner:      form.owner || null,
      department: form.department || null,
      location:   form.location || null,
      agent_id:   null,
    })
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
      <div className="bg-surface rounded-lg shadow-panel w-[480px] max-h-[90vh] flex flex-col border border-border">
        <div className="flex items-center justify-between px-5 py-3 border-b border-border">
          <h2 className="text-[13px] font-semibold text-text-primary">Add Asset</h2>
          <button onClick={onClose} className="text-text-muted hover:text-text-primary text-lg leading-none">×</button>
        </div>
        <form onSubmit={handleSubmit} className="flex-1 overflow-y-auto px-5 py-4 space-y-3">
          <Field label="Hostname *">
            <input required value={form.hostname}
              onChange={e => setForm(f => ({ ...f, hostname: e.target.value }))}
              className="input-sm w-full" placeholder="e.g. web-prod-01" />
          </Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Asset Type *">
              <select value={form.asset_type}
                onChange={e => setForm(f => ({ ...f, asset_type: e.target.value as AssetType }))}
                className="input-sm w-full">
                {ASSET_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
              </select>
            </Field>
            <Field label="Criticality (1–5) *">
              <input type="number" min={1} max={5} value={form.criticality}
                onChange={e => setForm(f => ({ ...f, criticality: Number(e.target.value) }))}
                className="input-sm w-full" />
            </Field>
          </div>
          <Field label="IP Addresses (comma-separated)">
            <input value={ipsInput} onChange={e => setIpsInput(e.target.value)}
              className="input-sm w-full" placeholder="10.0.0.1, 192.168.1.5" />
          </Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="OS">
              <input value={form.os ?? ''} onChange={e => setForm(f => ({ ...f, os: e.target.value }))}
                className="input-sm w-full" placeholder="Ubuntu 22.04" />
            </Field>
            <Field label="OS Family">
              <select value={form.os_family ?? 'linux'}
                onChange={e => setForm(f => ({ ...f, os_family: e.target.value as AssetCreate['os_family'] }))}
                className="input-sm w-full">
                {['linux', 'windows', 'macos', 'other'].map(o => <option key={o} value={o}>{o}</option>)}
              </select>
            </Field>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Owner">
              <input value={form.owner ?? ''} onChange={e => setForm(f => ({ ...f, owner: e.target.value }))}
                className="input-sm w-full" placeholder="john@acme.com" />
            </Field>
            <Field label="Department">
              <input value={form.department ?? ''} onChange={e => setForm(f => ({ ...f, department: e.target.value }))}
                className="input-sm w-full" placeholder="Engineering" />
            </Field>
          </div>
          <Field label="Location">
            <input value={form.location ?? ''} onChange={e => setForm(f => ({ ...f, location: e.target.value }))}
              className="input-sm w-full" placeholder="US-East DC-1" />
          </Field>
          <Field label="Tags (comma-separated)">
            <input value={tagsInput} onChange={e => setTagsInput(e.target.value)}
              className="input-sm w-full" placeholder="production, critical-path" />
          </Field>
          {mutation.isError && (
            <p className="text-[11px] text-crit-text">
              {(mutation.error as Error)?.message ?? 'Failed to create asset.'}
            </p>
          )}
        </form>
        <div className="flex items-center justify-end gap-2 px-5 py-3 border-t border-border">
          <button onClick={onClose} className="h-[30px] px-4 text-[12px] border border-border rounded-md text-text-secondary hover:bg-page">
            Cancel
          </button>
          <button
            onClick={(e) => { e.preventDefault(); handleSubmit(e as unknown as React.FormEvent) }}
            disabled={mutation.isPending || !form.hostname}
            className="h-[30px] px-4 text-[12px] bg-blue text-white rounded-md hover:opacity-90 disabled:opacity-50"
          >
            {mutation.isPending ? 'Creating…' : 'Create Asset'}
          </button>
        </div>
      </div>
    </div>
  )
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="block text-[10px] font-medium text-text-muted uppercase mb-1">{label}</label>
      {children}
    </div>
  )
}

// ── Bulk Import modal ──────────────────────────────────────────────────────────

function BulkImportModal({ onClose }: { onClose: () => void }) {
  const queryClient = useQueryClient()
  const [jsonText, setJsonText]   = useState('')
  const [parseError, setParseError] = useState('')
  const fileRef = useRef<HTMLInputElement>(null)

  const mutation = useMutation({
    mutationFn: (assets: AssetCreate[]) => assetsApi.bulkImport(assets),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ['assets'] })
      queryClient.invalidateQueries({ queryKey: ['asset-stats'] })
      alert(`Import complete: ${result.created} created, ${result.skipped} skipped.`)
      onClose()
    },
  })

  function parseCSV(text: string): AssetCreate[] {
    const lines = text.trim().split('\n')
    const header = lines[0].split(',').map(h => h.trim())
    return lines.slice(1).map(line => {
      const vals = line.split(',').map(v => v.trim())
      const row: Record<string, string> = {}
      header.forEach((h, i) => { row[h] = vals[i] ?? '' })
      return {
        hostname:     row['hostname'] || '',
        asset_type:   (row['asset_type'] as AssetType) || 'server',
        criticality:  row['criticality'] ? Number(row['criticality']) : 3,
        ip_addresses: row['ip_addresses'] ? row['ip_addresses'].split(';') : [],
        os:           row['os']         || null,
        os_family:    (row['os_family'] as AssetCreate['os_family']) || null,
        owner:        row['owner']      || null,
        department:   row['department'] || null,
        location:     row['location']   || null,
        tags:         row['tags']       ? row['tags'].split(';') : [],
        is_active:    row['is_active'] !== 'false',
      }
    }).filter(a => a.hostname)
  }

  function handleFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = (ev) => {
      const text = ev.target?.result as string
      if (file.name.endsWith('.csv')) {
        setJsonText(JSON.stringify(parseCSV(text), null, 2))
      } else {
        setJsonText(text)
      }
      setParseError('')
    }
    reader.readAsText(file)
  }

  function handleImport() {
    setParseError('')
    let assets: AssetCreate[]
    try {
      assets = JSON.parse(jsonText)
      if (!Array.isArray(assets)) throw new Error('Expected a JSON array')
    } catch (err) {
      setParseError((err as Error).message)
      return
    }
    mutation.mutate(assets)
  }

  const CSV_EXAMPLE = `hostname,asset_type,criticality,ip_addresses,os,os_family,owner,department,location,tags
web-prod-01,server,4,10.0.0.1;10.0.0.2,Ubuntu 22.04,linux,ops@acme.com,Engineering,DC-1,production;web
db-prod-01,server,5,10.0.1.10,RHEL 9,linux,dba@acme.com,Engineering,DC-1,production;database`

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
      <div className="bg-surface rounded-lg shadow-panel w-[560px] max-h-[90vh] flex flex-col border border-border">
        <div className="flex items-center justify-between px-5 py-3 border-b border-border">
          <h2 className="text-[13px] font-semibold text-text-primary">Bulk Import Assets</h2>
          <button onClick={onClose} className="text-text-muted hover:text-text-primary text-lg leading-none">×</button>
        </div>
        <div className="flex-1 overflow-y-auto px-5 py-4 space-y-3">
          <p className="text-[11px] text-text-secondary">
            Upload a CSV file or paste a JSON array of assets. CSV columns:{' '}
            <code className="text-[10px] bg-page px-1 rounded">hostname, asset_type, criticality, ip_addresses (semicolon-separated), os, os_family, owner, department, location, tags (semicolon-separated)</code>
          </p>

          <div className="flex items-center gap-2">
            <button
              onClick={() => fileRef.current?.click()}
              className="h-[28px] px-3 text-[11px] border border-border rounded-md text-text-secondary hover:bg-page"
            >
              Upload CSV / JSON
            </button>
            <input ref={fileRef} type="file" accept=".csv,.json" className="hidden" onChange={handleFileChange} />
            <button
              onClick={() => { setJsonText(JSON.stringify(parseCSV(CSV_EXAMPLE), null, 2)); setParseError('') }}
              className="h-[28px] px-3 text-[11px] border border-border rounded-md text-text-muted hover:bg-page"
            >
              Load example
            </button>
          </div>

          <textarea
            value={jsonText}
            onChange={e => { setJsonText(e.target.value); setParseError('') }}
            placeholder='[{"hostname": "web-01", "asset_type": "server", "criticality": 3, ...}]'
            rows={12}
            className="w-full text-[11px] font-mono bg-page border border-border rounded-md p-2 text-text-primary placeholder-text-muted focus:outline-none focus:border-blue resize-none"
          />

          {parseError && <p className="text-[11px] text-crit-text">{parseError}</p>}
          {mutation.isError && (
            <p className="text-[11px] text-crit-text">
              Import failed: {(mutation.error as Error)?.message}
            </p>
          )}
        </div>
        <div className="flex items-center justify-end gap-2 px-5 py-3 border-t border-border">
          <button onClick={onClose} className="h-[30px] px-4 text-[12px] border border-border rounded-md text-text-secondary hover:bg-page">
            Cancel
          </button>
          <button
            onClick={handleImport}
            disabled={mutation.isPending || !jsonText.trim()}
            className="h-[30px] px-4 text-[12px] bg-blue text-white rounded-md hover:opacity-90 disabled:opacity-50"
          >
            {mutation.isPending ? 'Importing…' : 'Import'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Main page ──────────────────────────────────────────────────────────────────

export function AssetsPage() {
  const [assetType,   setAssetType]   = useState<string>('')
  const [criticality, setCriticality] = useState<number | undefined>()
  const [isActive,    setIsActive]    = useState<boolean | undefined>()
  const [search,      setSearch]      = useState('')
  const [page,        setPage]        = useState(1)
  const [selected,    setSelected]    = useState<Asset | null>(null)
  const [showAdd,     setShowAdd]     = useState(false)
  const [showImport,  setShowImport]  = useState(false)

  const { data, isLoading, isError } = useQuery({
    queryKey: ['assets', { assetType, criticality, isActive, search, page }],
    queryFn: () =>
      assetsApi.list({
        asset_type:  assetType  || undefined,
        criticality: criticality ?? undefined,
        is_active:   isActive   ?? undefined,
        search:      search     || undefined,
        page,
        page_size: 25,
      }),
  })

  const { data: stats } = useQuery({
    queryKey: ['asset-stats'],
    queryFn: () => assetsApi.stats(),
  })

  function resetPage() { setPage(1) }

  const assets     = data?.items ?? []
  const pagination = data?.pagination

  return (
    <>
      <TopBar crumb="Assets" updatedAt="just now" />
      <div className="pt-[46px] px-5 pb-6">

        {/* Stats */}
        {stats && (
          <StatsCards
            total={stats.total}
            byType={stats.by_type}
            byCrit={stats.by_criticality}
          />
        )}

        {/* Filter bar */}
        <div className="flex items-center gap-2 py-3 flex-wrap">
          {/* Asset type */}
          <div className="flex items-center gap-1.5">
            <span className="text-[10px] text-text-muted">Type:</span>
            <select
              value={assetType}
              onChange={e => { setAssetType(e.target.value); resetPage() }}
              className="h-[26px] px-2 text-[11px] border border-border rounded-md bg-surface text-text-primary focus:outline-none focus:border-blue"
            >
              <option value="">All</option>
              {ASSET_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
            </select>
          </div>

          <div className="w-px h-[20px] bg-border mx-1" />

          {/* Criticality */}
          <div className="flex items-center gap-1.5">
            <span className="text-[10px] text-text-muted">Criticality:</span>
            <select
              value={criticality ?? ''}
              onChange={e => { setCriticality(e.target.value ? Number(e.target.value) : undefined); resetPage() }}
              className="h-[26px] px-2 text-[11px] border border-border rounded-md bg-surface text-text-primary focus:outline-none focus:border-blue"
            >
              <option value="">All</option>
              {[1, 2, 3, 4, 5].map(n => <option key={n} value={n}>{n} {'★'.repeat(n)}</option>)}
            </select>
          </div>

          <div className="w-px h-[20px] bg-border mx-1" />

          {/* Active toggle */}
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

          {/* Search */}
          <div className="ml-auto flex items-center gap-2">
            <input
              type="text"
              placeholder="Search hostname, owner…"
              value={search}
              onChange={e => { setSearch(e.target.value); resetPage() }}
              className="h-[28px] px-3 text-[11px] border border-border rounded-md bg-surface text-text-primary placeholder-text-muted focus:outline-none focus:border-blue w-[220px]"
            />
            <button
              onClick={() => setShowImport(true)}
              className="h-[28px] px-3 text-[11px] border border-border rounded-md text-text-secondary hover:bg-page whitespace-nowrap"
            >
              Bulk Import
            </button>
            <button
              onClick={() => setShowAdd(true)}
              className="h-[28px] px-3 text-[11px] bg-blue text-white rounded-md hover:opacity-90 whitespace-nowrap"
            >
              + Add Asset
            </button>
          </div>
        </div>

        {/* Summary row */}
        {pagination && (
          <div className="flex items-center gap-3 mb-2">
            <span className="text-[11px] text-text-muted">
              {pagination.total.toLocaleString()} assets
              {assetType   && ` · ${assetType}`}
              {criticality && ` · criticality ${criticality}`}
              {isActive !== undefined && ` · ${isActive ? 'active' : 'inactive'}`}
            </span>
          </div>
        )}

        {/* Table */}
        <div className="bg-surface rounded-md shadow-card overflow-hidden">
          {/* Header */}
          <div className="grid grid-cols-[1fr_130px_110px_90px_70px_110px_60px_70px] gap-2 px-3 py-2 border-b border-border">
            {['Hostname', 'IP Addresses', 'OS', 'Type', 'Criticality', 'Owner', 'Detections', 'Last Seen'].map(h => (
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

          {!isLoading && !isError && assets.map((a) => {
            const isSelected = selected?.id === a.id
            return (
              <div
                key={a.id}
                onClick={() => setSelected(isSelected ? null : a)}
                className={`grid grid-cols-[1fr_130px_110px_90px_70px_110px_60px_70px] gap-2 px-3 py-[7px] border-b border-section items-center cursor-pointer transition-colors ${
                  isSelected
                    ? 'bg-blue-faint border-l-[3px] border-l-blue'
                    : a.is_active ? 'hover:bg-page' : 'opacity-50 hover:bg-page'
                }`}
              >
                <div className="min-w-0">
                  <div className="text-[11px] text-text-primary font-medium truncate">{a.hostname}</div>
                  {a.tags.length > 0 && (
                    <div className="text-[10px] text-text-muted truncate">{a.tags.join(', ')}</div>
                  )}
                </div>
                <span className="text-[10px] text-text-muted truncate">
                  {a.ip_addresses.slice(0, 2).join(', ')}{a.ip_addresses.length > 2 ? ' …' : ''}
                </span>
                <span className="text-[11px] text-text-primary truncate">{a.os ?? '—'}</span>
                <TypePill type={a.asset_type} />
                <Stars n={a.criticality} />
                <span className="text-[11px] text-text-secondary truncate">{a.owner ?? '—'}</span>
                <span className={`text-[11px] font-medium ${a.detection_count > 0 ? 'text-high-text' : 'text-text-muted'}`}>
                  {a.detection_count}
                </span>
                <span className="text-[10px] text-text-muted">
                  {a.last_seen_at
                    ? new Date(a.last_seen_at).toLocaleDateString([], { month: 'short', day: 'numeric' })
                    : '—'}
                </span>
              </div>
            )
          })}

          {!isLoading && !isError && assets.length === 0 && (
            <div className="flex items-center justify-center h-32 text-text-muted text-sm">
              No assets match the current filters.
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
      <AssetPanel asset={selected} onClose={() => setSelected(null)} />

      {/* Modals */}
      {showAdd    && <AddAssetModal    onClose={() => setShowAdd(false)} />}
      {showImport && <BulkImportModal  onClose={() => setShowImport(false)} />}
    </>
  )
}
