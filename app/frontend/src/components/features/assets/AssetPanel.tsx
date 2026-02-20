import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import type { Asset } from '../../../types/api'
import { assetsApi } from '../../../lib/api'

interface Props {
  asset: Asset | null
  onClose: () => void
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[120px_1fr] gap-2 py-[5px] border-b border-section">
      <span className="text-[10px] font-medium text-text-muted uppercase">{label}</span>
      <span className="text-[11px] text-text-primary break-words">{value ?? '—'}</span>
    </div>
  )
}

function Stars({ n }: { n: number }) {
  const color = n >= 5 ? 'text-crit-text' : n >= 4 ? 'text-high-text' : n >= 3 ? 'text-med-text' : 'text-low-text'
  return (
    <span className={`${color} tracking-tight`}>
      {'★'.repeat(n)}
      <span className="text-border">{'★'.repeat(5 - n)}</span>
    </span>
  )
}

type Tab = 'details' | 'detections' | 'incidents'

export function AssetPanel({ asset, onClose }: Props) {
  const [tab, setTab] = useState<Tab>('details')
  const [detPage, setDetPage] = useState(1)
  const [incPage, setIncPage] = useState(1)

  const detQuery = useQuery({
    queryKey: ['asset-detections', asset?.id, detPage],
    queryFn: () => assetsApi.getDetections(asset!.id, { page: detPage, page_size: 10 }),
    enabled: !!asset && tab === 'detections',
  })

  const incQuery = useQuery({
    queryKey: ['asset-incidents', asset?.id, incPage],
    queryFn: () => assetsApi.getIncidents(asset!.id, { page: incPage, page_size: 10 }),
    enabled: !!asset && tab === 'incidents',
  })

  if (!asset) return null

  const TABS: { key: Tab; label: string }[] = [
    { key: 'details',    label: 'Details' },
    { key: 'detections', label: `Detections (${asset.detection_count})` },
    { key: 'incidents',  label: `Incidents (${asset.incident_count})` },
  ]

  return (
    <>
      {/* Backdrop */}
      <div className="fixed inset-0 z-30 bg-transparent" onClick={onClose} />

      {/* Panel */}
      <div className="fixed top-[46px] right-0 bottom-0 w-[460px] bg-surface shadow-panel z-40 flex flex-col overflow-hidden border-l border-border">
        {/* Header */}
        <div className="flex items-start justify-between px-4 py-3 border-b border-border">
          <div className="min-w-0">
            <h2 className="text-[13px] font-semibold text-text-primary leading-snug truncate">{asset.hostname}</h2>
            <p className="text-[11px] text-text-muted mt-[2px]">
              {asset.asset_type} · {asset.os_family ?? 'unknown OS'}
              {!asset.is_active && <span className="ml-2 text-crit-text">(inactive)</span>}
            </p>
          </div>
          <button
            className="text-text-muted hover:text-text-primary ml-2 text-lg leading-none"
            onClick={onClose}
            title="Close"
          >
            ×
          </button>
        </div>

        {/* Badge row */}
        <div className="flex items-center gap-3 px-4 py-2 border-b border-section">
          <Stars n={asset.criticality} />
          <span className="text-[10px] text-text-muted">Criticality {asset.criticality}/5</span>
          {asset.tags.length > 0 && (
            <div className="flex gap-1 flex-wrap">
              {asset.tags.map((t) => (
                <span key={t} className="text-[10px] bg-page border border-border rounded px-1.5 py-px text-text-secondary">{t}</span>
              ))}
            </div>
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
          {tab === 'details' && (
            <div>
              <Row label="Hostname"   value={asset.hostname} />
              <Row label="IP Addresses" value={
                asset.ip_addresses.length > 0
                  ? asset.ip_addresses.join(', ')
                  : '—'
              } />
              <Row label="OS"         value={asset.os} />
              <Row label="OS Family"  value={asset.os_family} />
              <Row label="Type"       value={asset.asset_type} />
              <Row label="Criticality" value={<Stars n={asset.criticality} />} />
              <Row label="Owner"      value={asset.owner} />
              <Row label="Department" value={asset.department} />
              <Row label="Location"   value={asset.location} />
              <Row label="Agent ID"   value={asset.agent_id} />
              <Row label="Status"     value={asset.is_active ? 'Active' : 'Inactive'} />
              <Row label="Last Seen"  value={
                asset.last_seen_at
                  ? new Date(asset.last_seen_at).toLocaleString()
                  : '—'
              } />
              <Row label="Created"    value={new Date(asset.created_at).toLocaleString()} />
              <Row label="Updated"    value={new Date(asset.updated_at).toLocaleString()} />
            </div>
          )}

          {tab === 'detections' && (
            <div>
              {detQuery.isLoading && (
                <div className="flex items-center justify-center h-24 text-text-muted text-sm">Loading…</div>
              )}
              {detQuery.isError && (
                <div className="text-crit-text text-[11px] py-4 text-center">Failed to load detections.</div>
              )}
              {detQuery.data && detQuery.data.items.length === 0 && (
                <div className="text-text-muted text-[11px] py-6 text-center">No detections for this asset.</div>
              )}
              {detQuery.data && detQuery.data.items.map((d, i) => (
                <div key={i} className="py-2 border-b border-section">
                  <div className="flex items-center justify-between">
                    <span className="text-[11px] text-text-primary font-medium">{String(d.name)}</span>
                    <span className={`text-[9px] px-1.5 py-px rounded font-medium ${
                      d.severity === 'critical' ? 'bg-crit-bg text-crit-text' :
                      d.severity === 'high'     ? 'bg-high-bg text-high-text' :
                      d.severity === 'medium'   ? 'bg-med-bg text-med-text'   :
                                                  'bg-low-bg text-low-text'
                    }`}>{String(d.severity)}</span>
                  </div>
                  <div className="text-[10px] text-text-muted mt-0.5">
                    {String(d.technique_id)} · {String(d.tactic)} ·{' '}
                    {d.time ? new Date(String(d.time)).toLocaleString() : ''}
                  </div>
                </div>
              ))}
              {detQuery.data && detQuery.data.pagination.total_pages > 1 && (
                <div className="flex items-center justify-center gap-2 mt-3">
                  <button disabled={detPage <= 1} onClick={() => setDetPage(p => p - 1)}
                    className="h-[24px] px-2 text-[10px] border border-border rounded text-text-secondary disabled:opacity-40 hover:bg-page">← Prev</button>
                  <span className="text-[10px] text-text-muted">{detPage} / {detQuery.data.pagination.total_pages}</span>
                  <button disabled={detPage >= detQuery.data.pagination.total_pages} onClick={() => setDetPage(p => p + 1)}
                    className="h-[24px] px-2 text-[10px] border border-border rounded text-text-secondary disabled:opacity-40 hover:bg-page">Next →</button>
                </div>
              )}
            </div>
          )}

          {tab === 'incidents' && (
            <div>
              {incQuery.isLoading && (
                <div className="flex items-center justify-center h-24 text-text-muted text-sm">Loading…</div>
              )}
              {incQuery.isError && (
                <div className="text-crit-text text-[11px] py-4 text-center">Failed to load incidents.</div>
              )}
              {incQuery.data && incQuery.data.items.length === 0 && (
                <div className="text-text-muted text-[11px] py-6 text-center">No incidents for this asset.</div>
              )}
              {incQuery.data && incQuery.data.items.map((inc, i) => (
                <div key={i} className="py-2 border-b border-section">
                  <div className="flex items-center justify-between">
                    <span className="text-[11px] text-text-primary font-medium">{String(inc.title)}</span>
                    <span className={`text-[9px] px-1.5 py-px rounded font-medium ${
                      inc.severity === 'critical' ? 'bg-crit-bg text-crit-text' :
                      inc.severity === 'high'     ? 'bg-high-bg text-high-text' :
                      inc.severity === 'medium'   ? 'bg-med-bg text-med-text'   :
                                                    'bg-low-bg text-low-text'
                    }`}>{String(inc.severity)}</span>
                  </div>
                  <div className="text-[10px] text-text-muted mt-0.5">
                    {String(inc.status)} · {inc.assigned_to ? String(inc.assigned_to) : 'Unassigned'} ·{' '}
                    {inc.created_at ? new Date(String(inc.created_at)).toLocaleString() : ''}
                  </div>
                </div>
              ))}
              {incQuery.data && incQuery.data.pagination.total_pages > 1 && (
                <div className="flex items-center justify-center gap-2 mt-3">
                  <button disabled={incPage <= 1} onClick={() => setIncPage(p => p - 1)}
                    className="h-[24px] px-2 text-[10px] border border-border rounded text-text-secondary disabled:opacity-40 hover:bg-page">← Prev</button>
                  <span className="text-[10px] text-text-muted">{incPage} / {incQuery.data.pagination.total_pages}</span>
                  <button disabled={incPage >= incQuery.data.pagination.total_pages} onClick={() => setIncPage(p => p + 1)}
                    className="h-[24px] px-2 text-[10px] border border-border rounded text-text-secondary disabled:opacity-40 hover:bg-page">Next →</button>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </>
  )
}
