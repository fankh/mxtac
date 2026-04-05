import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { TopBar } from '../../layout/TopBar'
import { Wifi, Shield, Monitor, Cloud, Server, Plus, Check, AlertTriangle, X } from 'lucide-react'
import type { ComponentType } from 'react'
import type { LucideProps } from 'lucide-react'

interface DataSource {
  id: string
  name: string
  type: 'ndr' | 'edr' | 'siem' | 'cloud'
  Icon: ComponentType<LucideProps>
  description: string
  status: 'connected' | 'disconnected' | 'error'
  eventsPerMin?: number
  lastSeen?: string
  config?: { endpoint?: string; apiKey?: string }
}

const SOURCE_TEMPLATES: Omit<DataSource, 'status' | 'eventsPerMin' | 'lastSeen'>[] = [
  // NDR Sources
  { id: 'zeek', name: 'Zeek', type: 'ndr', Icon: Wifi, description: 'Network security monitoring — DNS, HTTP, TLS, SSH, SMB flow logs', config: { endpoint: '' } },
  { id: 'suricata', name: 'Suricata', type: 'ndr', Icon: Shield, description: 'IDS/IPS — rule-based network threat detection (EVE JSON)', config: { endpoint: '' } },
  { id: 'mxwatch', name: 'MxWatch', type: 'ndr', Icon: Wifi, description: 'MxTac NDR agent — packet capture, protocol parsing, flow extraction', config: { endpoint: '' } },
  // EDR Sources
  { id: 'wazuh', name: 'Wazuh', type: 'edr', Icon: Monitor, description: 'Endpoint security — file integrity, rootkit detection, compliance', config: { endpoint: '' } },
  { id: 'velociraptor', name: 'Velociraptor', type: 'edr', Icon: Monitor, description: 'Endpoint investigation — artifact collection, live forensics', config: { endpoint: '' } },
  { id: 'mxguard', name: 'MxGuard', type: 'edr', Icon: Monitor, description: 'MxTac EDR agent — process monitoring, file integrity, auth tracking', config: { endpoint: '' } },
  // SIEM Sources
  { id: 'elastic', name: 'Elastic SIEM', type: 'siem', Icon: Server, description: 'Elasticsearch-based SIEM — forward alerts and events', config: { endpoint: '' } },
  { id: 'opensearch', name: 'OpenSearch', type: 'siem', Icon: Server, description: 'OpenSearch cluster — direct log ingestion and search', config: { endpoint: '' } },
  // Cloud Sources
  { id: 'prowler', name: 'Prowler', type: 'cloud', Icon: Cloud, description: 'AWS/Azure/GCP security — compliance and misconfiguration findings', config: { endpoint: '' } },
  { id: 'cloudtrail', name: 'CloudTrail', type: 'cloud', Icon: Cloud, description: 'AWS API audit trail — IAM, S3, EC2 activity logs', config: { endpoint: '' } },
]

const TYPE_LABELS: Record<string, { label: string; color: string }> = {
  ndr: { label: 'NDR', color: 'bg-blue/10 text-blue border-blue/20' },
  edr: { label: 'EDR', color: 'bg-green-500/10 text-green-600 border-green-500/20' },
  siem: { label: 'SIEM', color: 'bg-purple-500/10 text-purple-600 border-purple-500/20' },
  cloud: { label: 'Cloud', color: 'bg-orange-500/10 text-orange-600 border-orange-500/20' },
}

const STATUS_ICON: Record<string, { Icon: ComponentType<LucideProps>; color: string }> = {
  connected: { Icon: Check, color: 'text-green-500' },
  disconnected: { Icon: X, color: 'text-text-muted' },
  error: { Icon: AlertTriangle, color: 'text-red-500' },
}

export function SourcesPage() {
  const [filter, setFilter] = useState<string>('all')
  const [configOpen, setConfigOpen] = useState<string | null>(null)

  // Fetch connected sources from backend
  const { data: connectors } = useQuery({
    queryKey: ['connectors'],
    queryFn: async () => {
      const token = localStorage.getItem('access_token')
      if (!token) return []
      const resp = await fetch('/api/v1/connectors', { headers: { Authorization: `Bearer ${token}` } })
      if (!resp.ok) return []
      return resp.json()
    },
    staleTime: 30_000,
  })

  // Merge templates with live connector status
  const sources: DataSource[] = SOURCE_TEMPLATES.map(tpl => {
    const live = Array.isArray(connectors)
      ? connectors.find((c: Record<string, unknown>) =>
          (c.connector_type as string)?.toLowerCase() === tpl.id || (c.name as string)?.toLowerCase() === tpl.id
        )
      : undefined
    return {
      ...tpl,
      status: live ? (live.status === 'active' || live.enabled ? 'connected' : 'error') : 'disconnected',
      eventsPerMin: live?.events_total ? Math.round(Number(live.events_total) / 60) : undefined,
      lastSeen: live?.last_seen_at as string | undefined,
    } as DataSource
  })

  const filtered = filter === 'all' ? sources : sources.filter(s => s.type === filter)
  const connectedCount = sources.filter(s => s.status === 'connected').length

  return (
    <>
      <TopBar crumb="Data Sources" />
      <div className="pt-[46px] p-5 space-y-4">
        {/* Stats */}
        <div className="grid grid-cols-4 gap-3">
          <div className="bg-surface border border-border rounded-lg p-4">
            <p className="text-[10px] font-medium text-text-muted uppercase tracking-wider">Connected</p>
            <p className="text-xl font-bold mt-1 text-green-500">{connectedCount}</p>
          </div>
          <div className="bg-surface border border-border rounded-lg p-4">
            <p className="text-[10px] font-medium text-text-muted uppercase tracking-wider">NDR Sources</p>
            <p className="text-xl font-bold mt-1">{sources.filter(s => s.type === 'ndr').length}</p>
          </div>
          <div className="bg-surface border border-border rounded-lg p-4">
            <p className="text-[10px] font-medium text-text-muted uppercase tracking-wider">EDR Sources</p>
            <p className="text-xl font-bold mt-1">{sources.filter(s => s.type === 'edr').length}</p>
          </div>
          <div className="bg-surface border border-border rounded-lg p-4">
            <p className="text-[10px] font-medium text-text-muted uppercase tracking-wider">Total Sources</p>
            <p className="text-xl font-bold mt-1">{sources.length}</p>
          </div>
        </div>

        {/* Filter tabs */}
        <div className="flex items-center gap-2">
          {[
            { value: 'all', label: 'All' },
            { value: 'ndr', label: 'NDR' },
            { value: 'edr', label: 'EDR' },
            { value: 'siem', label: 'SIEM' },
            { value: 'cloud', label: 'Cloud' },
          ].map(tab => (
            <button
              key={tab.value}
              onClick={() => setFilter(tab.value)}
              className={`px-3 py-1 text-xs font-medium rounded border transition-colors ${
                filter === tab.value
                  ? 'bg-blue text-white border-blue'
                  : 'bg-surface border-border text-text-primary hover:bg-hover'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Source cards */}
        <div className="grid grid-cols-2 gap-3">
          {filtered.map(source => {
            const typeInfo = TYPE_LABELS[source.type]
            const statusInfo = STATUS_ICON[source.status]
            const StatusIcon = statusInfo.Icon

            return (
              <div
                key={source.id}
                className={`bg-surface border rounded-lg p-4 transition-colors hover:border-blue/30 ${
                  source.status === 'connected' ? 'border-green-500/30' : 'border-border'
                }`}
              >
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-3">
                    <div className={`w-9 h-9 rounded-lg flex items-center justify-center ${
                      source.status === 'connected' ? 'bg-green-500/10' : 'bg-section'
                    }`}>
                      <source.Icon className={`w-[18px] h-[18px] ${
                        source.status === 'connected' ? 'text-green-500' : 'text-text-muted'
                      }`} strokeWidth={1.8} />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-semibold">{source.name}</span>
                        <span className={`px-1.5 py-0 text-[9px] font-bold rounded border ${typeInfo.color}`}>
                          {typeInfo.label}
                        </span>
                      </div>
                      <p className="text-[10px] text-text-muted mt-0.5 max-w-[300px]">{source.description}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <StatusIcon className={`w-3.5 h-3.5 ${statusInfo.color}`} />
                    <span className={`text-[10px] font-medium ${statusInfo.color}`}>
                      {source.status === 'connected' ? 'Connected' : source.status === 'error' ? 'Error' : 'Not configured'}
                    </span>
                  </div>
                </div>

                {source.status === 'connected' && source.eventsPerMin != null && (
                  <div className="mt-3 pt-3 border-t border-border flex items-center gap-4 text-[10px] text-text-muted">
                    <span>{source.eventsPerMin.toLocaleString()} events/min</span>
                    {source.lastSeen && <span>Last seen: {new Date(source.lastSeen).toLocaleTimeString()}</span>}
                  </div>
                )}

                {source.status === 'disconnected' && (
                  <div className="mt-3 pt-3 border-t border-border">
                    <button
                      onClick={() => setConfigOpen(source.id)}
                      className="flex items-center gap-1 text-[11px] text-blue hover:text-blue/80 font-medium transition-colors"
                    >
                      <Plus className="w-3 h-3" />
                      Configure
                    </button>
                  </div>
                )}
              </div>
            )
          })}
        </div>

        {/* Config modal placeholder */}
        {configOpen && (
          <div className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center" onClick={() => setConfigOpen(null)}>
            <div className="bg-surface border border-border rounded-lg p-6 w-[480px] max-w-[90vw]" onClick={e => e.stopPropagation()}>
              <h3 className="text-sm font-bold mb-3">Configure {SOURCE_TEMPLATES.find(s => s.id === configOpen)?.name}</h3>
              <div className="space-y-3">
                <div>
                  <label className="text-[11px] font-medium text-text-muted">Endpoint URL</label>
                  <input type="url" placeholder="https://..." autoComplete="off" className="w-full mt-1 h-8 px-3 text-xs bg-page border border-border rounded focus:outline-none focus:border-blue" />
                </div>
                <div>
                  <label className="text-[11px] font-medium text-text-muted">API Key</label>
                  <input type="password" placeholder="sk-..." autoComplete="off" className="w-full mt-1 h-8 px-3 text-xs bg-page border border-border rounded focus:outline-none focus:border-blue" />
                </div>
              </div>
              <div className="flex justify-end gap-2 mt-4">
                <button onClick={() => setConfigOpen(null)} className="px-3 py-1.5 text-xs border border-border rounded hover:bg-hover transition-colors">Cancel</button>
                <button onClick={() => setConfigOpen(null)} className="px-3 py-1.5 text-xs bg-blue text-white rounded hover:bg-blue/90 transition-colors">Connect</button>
              </div>
            </div>
          </div>
        )}
      </div>
    </>
  )
}
