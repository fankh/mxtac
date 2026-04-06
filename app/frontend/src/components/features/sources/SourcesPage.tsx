import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { TopBar } from '../../layout/TopBar'
import { Wifi, Shield, Monitor, Cloud, Server, Plus, Check, AlertTriangle, X } from 'lucide-react'
import type { ComponentType } from 'react'
import type { LucideProps } from 'lucide-react'

interface ConfigField {
  key: string
  label: string
  type: 'text' | 'password' | 'url' | 'number'
  placeholder: string
  required?: boolean
}

interface DataSource {
  id: string
  name: string
  type: 'ndr' | 'edr' | 'siem' | 'cloud'
  Icon: ComponentType<LucideProps>
  description: string
  fields: ConfigField[]
  builtin?: boolean
  status: 'connected' | 'disconnected' | 'error'
  eventsPerMin?: number
  lastSeen?: string
  agentCount?: number
}

const SOURCE_TEMPLATES: Omit<DataSource, 'status' | 'eventsPerMin' | 'lastSeen'>[] = [
  // NDR Sources
  { id: 'zeek', name: 'Zeek', type: 'ndr', Icon: Wifi,
    description: 'Network security monitoring — DNS, HTTP, TLS, SSH, SMB flow logs',
    fields: [
      { key: 'log_directory', label: 'Log Directory', type: 'text', placeholder: '/opt/zeek/logs/current', required: true },
      { key: 'poll_interval', label: 'Poll Interval (sec)', type: 'number', placeholder: '10' },
    ] },
  { id: 'suricata', name: 'Suricata', type: 'ndr', Icon: Shield,
    description: 'IDS/IPS — rule-based network threat detection (EVE JSON)',
    fields: [
      { key: 'eve_json_path', label: 'EVE JSON Path', type: 'text', placeholder: '/var/log/suricata/eve.json', required: true },
      { key: 'syslog_port', label: 'Syslog Port (optional)', type: 'number', placeholder: '5140' },
    ] },
  { id: 'mxwatch', name: 'MxWatch', type: 'ndr', Icon: Wifi,
    description: 'Built-in MxTac NDR agent — packet capture, protocol parsing, flow extraction',
    fields: [], builtin: true },
  // EDR Sources
  { id: 'wazuh', name: 'Wazuh', type: 'edr', Icon: Monitor,
    description: 'Endpoint security — file integrity, rootkit detection, compliance',
    fields: [
      { key: 'manager_url', label: 'Wazuh Manager URL', type: 'url', placeholder: 'https://wazuh-manager:55000', required: true },
      { key: 'username', label: 'Username', type: 'text', placeholder: 'wazuh-wui', required: true },
      { key: 'password', label: 'Password', type: 'password', placeholder: '••••••••', required: true },
    ] },
  { id: 'velociraptor', name: 'Velociraptor', type: 'edr', Icon: Monitor,
    description: 'Endpoint investigation — artifact collection, live forensics',
    fields: [
      { key: 'server_url', label: 'Server URL', type: 'url', placeholder: 'https://velociraptor:8889', required: true },
      { key: 'api_key', label: 'API Key', type: 'password', placeholder: 'vr-api-...', required: true },
    ] },
  { id: 'mxguard', name: 'MxGuard', type: 'edr', Icon: Monitor,
    description: 'Built-in MxTac EDR agent — process monitoring, file integrity, auth tracking',
    fields: [], builtin: true },
  // SIEM Sources
  { id: 'elastic', name: 'Elastic SIEM', type: 'siem', Icon: Server,
    description: 'Elasticsearch-based SIEM — forward alerts and events',
    fields: [
      { key: 'cluster_url', label: 'Cluster URL', type: 'url', placeholder: 'https://elasticsearch:9200', required: true },
      { key: 'username', label: 'Username', type: 'text', placeholder: 'elastic' },
      { key: 'password', label: 'Password', type: 'password', placeholder: '••••••••' },
      { key: 'index_pattern', label: 'Index Pattern', type: 'text', placeholder: 'filebeat-*' },
    ] },
  { id: 'opensearch', name: 'OpenSearch', type: 'siem', Icon: Server,
    description: 'OpenSearch cluster — direct log ingestion and search',
    fields: [
      { key: 'cluster_url', label: 'Cluster URL', type: 'url', placeholder: 'https://opensearch:9200', required: true },
      { key: 'username', label: 'Username', type: 'text', placeholder: 'admin' },
      { key: 'password', label: 'Password', type: 'password', placeholder: '••••••••' },
    ] },
  // Cloud Sources
  { id: 'prowler', name: 'Prowler', type: 'cloud', Icon: Cloud,
    description: 'AWS/Azure/GCP security — compliance and misconfiguration findings',
    fields: [
      { key: 'aws_region', label: 'AWS Region', type: 'text', placeholder: 'ap-northeast-2', required: true },
      { key: 'aws_profile', label: 'AWS Profile', type: 'text', placeholder: 'default' },
      { key: 'scan_interval', label: 'Scan Interval (hours)', type: 'number', placeholder: '24' },
    ] },
  { id: 'cloudtrail', name: 'CloudTrail', type: 'cloud', Icon: Cloud,
    description: 'AWS API audit trail — IAM, S3, EC2 activity logs',
    fields: [
      { key: 's3_bucket', label: 'S3 Bucket', type: 'text', placeholder: 'my-cloudtrail-logs', required: true },
      { key: 'aws_region', label: 'AWS Region', type: 'text', placeholder: 'ap-northeast-2', required: true },
      { key: 'aws_access_key', label: 'Access Key ID', type: 'text', placeholder: 'AKIA...' },
      { key: 'aws_secret_key', label: 'Secret Access Key', type: 'password', placeholder: '••••••••' },
    ] },
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
  const queryClient = useQueryClient()
  const [filter, setFilter] = useState<string>('all')
  const [configOpen, setConfigOpen] = useState<string | null>(null)
  const [configValues, setConfigValues] = useState<Record<string, string>>({})
  const [configSaving, setConfigSaving] = useState(false)
  const [configError, setConfigError] = useState('')

  const openConfig = (sourceId: string) => {
    setConfigOpen(sourceId)
    setConfigValues({})
    setConfigError('')
  }

  const handleConnect = async () => {
    if (!configOpen) return
    const source = SOURCE_TEMPLATES.find(s => s.id === configOpen)
    if (!source) return

    // Validate required fields
    const missing = source.fields.filter(f => f.required && !configValues[f.key]?.trim())
    if (missing.length > 0) {
      setConfigError(`Required: ${missing.map(f => f.label).join(', ')}`)
      return
    }

    setConfigSaving(true)
    setConfigError('')
    try {
      const token = localStorage.getItem('access_token')
      const config: Record<string, string> = {}
      for (const field of source.fields) {
        const val = configValues[field.key]?.trim()
        if (val) config[field.key] = val
      }
      const resp = await fetch('/api/v1/connectors', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({
          name: source.name,
          connector_type: source.id,
          config,
          enabled: true,
        }),
      })
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({ detail: 'Connection failed' }))
        throw new Error(err.detail || `HTTP ${resp.status}`)
      }
      queryClient.invalidateQueries({ queryKey: ['connectors'] })
      setConfigOpen(null)
      setConfigValues({})
    } catch (e) {
      setConfigError(e instanceof Error ? e.message : 'Connection failed')
    } finally {
      setConfigSaving(false)
    }
  }

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

  // Fetch registered agents for built-in sources
  const { data: agents } = useQuery({
    queryKey: ['agents'],
    queryFn: async () => {
      const token = localStorage.getItem('access_token')
      if (!token) return []
      const resp = await fetch('/api/v1/agents', { headers: { Authorization: `Bearer ${token}` } })
      if (!resp.ok) return []
      return resp.json()
    },
    staleTime: 30_000,
  })

  // Merge templates with live connector/agent status
  const sources: DataSource[] = SOURCE_TEMPLATES.map(tpl => {
    if (tpl.builtin) {
      // Built-in agents: check agent registrations
      const agentType = tpl.id // 'mxwatch' or 'mxguard'
      const registered = Array.isArray(agents)
        ? agents.filter((a: Record<string, unknown>) => (a.agent_type as string) === agentType)
        : []
      const online = registered.filter((a: Record<string, unknown>) => a.status === 'online')
      return {
        ...tpl,
        status: online.length > 0 ? 'connected' as const : registered.length > 0 ? 'error' as const : 'disconnected' as const,
        agentCount: registered.length,
        lastSeen: online[0]?.last_heartbeat as string | undefined,
      } as DataSource
    }
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

                {source.builtin ? (
                  <div className="mt-3 pt-3 border-t border-border flex items-center justify-between">
                    <span className="text-[10px] font-medium text-blue bg-blue/5 px-2 py-0.5 rounded border border-blue/20">Built-in Agent</span>
                    {source.agentCount != null && source.agentCount > 0 ? (
                      <span className="text-[10px] text-text-muted">{source.agentCount} agent{source.agentCount > 1 ? 's' : ''} registered</span>
                    ) : (
                      <span className="text-[10px] text-text-muted">No agents registered — deploy with <code className="bg-page px-1 rounded">mxtac/{source.id}</code></span>
                    )}
                  </div>
                ) : source.status === 'disconnected' ? (
                  <div className="mt-3 pt-3 border-t border-border">
                    <button
                      onClick={() => openConfig(source.id)}
                      className="flex items-center gap-1 text-[11px] text-blue hover:text-blue/80 font-medium transition-colors"
                    >
                      <Plus className="w-3 h-3" />
                      Configure
                    </button>
                  </div>
                ) : null}
              </div>
            )
          })}
        </div>

        {/* Config modal — dynamic fields per source type */}
        {configOpen && (() => {
          const source = SOURCE_TEMPLATES.find(s => s.id === configOpen)
          if (!source) return null
          return (
            <div className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center" onClick={() => { setConfigOpen(null); setConfigError('') }}>
              <div className="bg-surface border border-border rounded-lg p-6 w-[480px] max-w-[90vw]" onClick={e => e.stopPropagation()}>
                <div className="flex items-center gap-2 mb-1">
                  <source.Icon className="w-4 h-4 text-blue" />
                  <h3 className="text-sm font-bold">Configure {source.name}</h3>
                  <span className={`px-1.5 py-0 text-[9px] font-bold rounded border ${TYPE_LABELS[source.type].color}`}>
                    {TYPE_LABELS[source.type].label}
                  </span>
                </div>
                <p className="text-[10px] text-text-muted mb-4">{source.description}</p>
                <div className="space-y-3">
                  {source.fields.map(field => (
                    <div key={field.key}>
                      <label className="text-[11px] font-medium text-text-muted">
                        {field.label}{field.required && <span className="text-red-500 ml-0.5">*</span>}
                      </label>
                      <input
                        type={field.type}
                        value={configValues[field.key] || ''}
                        onChange={e => setConfigValues(prev => ({ ...prev, [field.key]: e.target.value }))}
                        placeholder={field.placeholder}
                        autoComplete="off"
                        className="w-full mt-1 h-8 px-3 text-xs bg-page border border-border rounded focus:outline-none focus:border-blue"
                      />
                    </div>
                  ))}
                  {configError && (
                    <p className="text-[11px] text-red-500">{configError}</p>
                  )}
                </div>
                <div className="flex justify-end gap-2 mt-4">
                  <button onClick={() => { setConfigOpen(null); setConfigError('') }} className="px-3 py-1.5 text-xs border border-border rounded hover:bg-hover transition-colors">Cancel</button>
                  <button
                    onClick={handleConnect}
                    disabled={configSaving}
                    className="px-3 py-1.5 text-xs bg-blue text-white rounded hover:bg-blue/90 transition-colors disabled:opacity-50"
                  >
                    {configSaving ? 'Connecting...' : 'Connect'}
                  </button>
                </div>
              </div>
            </div>
          )
        })()}
      </div>
    </>
  )
}
