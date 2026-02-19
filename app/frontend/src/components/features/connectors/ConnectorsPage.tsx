import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { TopBar } from '../../layout/TopBar'
import { apiClient } from '../../../lib/api'

interface Connector {
  id: string
  name: string
  connector_type: string
  status: string
  enabled: boolean
  events_total: number
  errors_total: number
  last_seen_at: string | null
  error_message: string | null
}

const STATUS_DOT: Record<string, string> = {
  active:     'bg-[#28A745]',
  inactive:   'bg-border',
  error:      'bg-crit-text',
  connecting: 'bg-[#F0A020]',
}

const TYPE_LABELS: Record<string, string> = {
  wazuh:        'Wazuh SIEM',
  zeek:         'Zeek Network',
  suricata:     'Suricata IDS',
  prowler:      'Prowler Cloud',
  opencti:      'OpenCTI',
  velociraptor: 'Velociraptor',
  osquery:      'osquery',
  generic:      'Generic Webhook',
}

async function fetchConnectors(): Promise<Connector[]> {
  return apiClient.get('/connectors').then(r => r.data)
}

export function ConnectorsPage() {
  const queryClient = useQueryClient()
  const { data = [], isLoading } = useQuery({ queryKey: ['connectors'], queryFn: fetchConnectors })
  const [selected, setSelected] = useState<Connector | null>(null)

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      apiClient.patch(`/connectors/${id}`, { enabled }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['connectors'] }),
  })

  return (
    <>
      <TopBar crumb="Integrations" />
      <div className="pt-[46px] px-5 pb-6">

        {/* Header */}
        <div className="flex items-center justify-between py-3">
          <div>
            <h2 className="text-[13px] font-semibold text-text-primary">Data Source Connectors</h2>
            <p className="text-[11px] text-text-muted">Configure connections to your security tools</p>
          </div>
          <button className="h-[30px] px-4 bg-blue text-white text-[12px] rounded-md hover:opacity-90">
            + Add Connector
          </button>
        </div>

        {/* Connector grid */}
        {isLoading && (
          <div className="text-center text-text-muted py-16 text-sm">Loading connectors…</div>
        )}
        <div className="grid grid-cols-3 gap-3">
          {data.map((conn) => (
            <div
              key={conn.id}
              className={`bg-surface rounded-md shadow-card p-4 cursor-pointer border-2 transition-colors ${
                selected?.id === conn.id ? 'border-blue' : 'border-transparent hover:border-border'
              }`}
              onClick={() => setSelected(selected?.id === conn.id ? null : conn)}
            >
              <div className="flex items-start justify-between mb-3">
                <div className="flex items-center gap-2">
                  <span className={`w-[8px] h-[8px] rounded-full ${STATUS_DOT[conn.status] ?? 'bg-border'}`} />
                  <span className="text-[12px] font-semibold text-text-primary">{conn.name}</span>
                </div>
                <button
                  onClick={(e) => {
                    e.stopPropagation()
                    toggleMutation.mutate({ id: conn.id, enabled: !conn.enabled })
                  }}
                  className={`text-[10px] px-2 py-[2px] rounded border transition-colors ${
                    conn.enabled
                      ? 'border-[#28A745] text-[#28A745]'
                      : 'border-border text-text-muted'
                  }`}
                >
                  {conn.enabled ? 'Enabled' : 'Disabled'}
                </button>
              </div>

              <div className="text-[10px] text-text-muted mb-3">
                {TYPE_LABELS[conn.connector_type] ?? conn.connector_type}
              </div>

              <div className="flex items-center gap-4 text-[10px] text-text-muted">
                <span>{conn.events_total.toLocaleString()} events</span>
                {conn.errors_total > 0 && (
                  <span className="text-crit-text">{conn.errors_total} errors</span>
                )}
                {conn.last_seen_at && (
                  <span>Last: {new Date(conn.last_seen_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                )}
              </div>

              {conn.error_message && (
                <div className="mt-2 text-[10px] text-crit-text truncate" title={conn.error_message}>
                  ⚠ {conn.error_message}
                </div>
              )}
            </div>
          ))}

          {/* Add connector placeholder */}
          {data.length < 8 && (
            <div className="bg-surface rounded-md border-2 border-dashed border-border p-4 flex flex-col items-center justify-center gap-2 cursor-pointer hover:border-blue min-h-[120px]">
              <span className="text-[24px] text-text-muted">+</span>
              <span className="text-[11px] text-text-muted">Add connector</span>
            </div>
          )}
        </div>

        {/* Connector detail panel */}
        {selected && (
          <div className="mt-4 bg-surface rounded-md shadow-card p-4">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-[12px] font-semibold text-text-primary">{selected.name} — Configuration</h3>
              <button
                className="h-[28px] px-4 text-[11px] border border-blue text-blue rounded-md hover:bg-[#EBF3FF]"
                onClick={() => {/* TODO: test connection */}}
              >
                Test Connection
              </button>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-[10px] text-text-muted uppercase block mb-1">Type</label>
                <div className="text-[11px] text-text-primary">{TYPE_LABELS[selected.connector_type]}</div>
              </div>
              <div>
                <label className="text-[10px] text-text-muted uppercase block mb-1">Status</label>
                <div className="flex items-center gap-2">
                  <span className={`w-[6px] h-[6px] rounded-full ${STATUS_DOT[selected.status]}`} />
                  <span className="text-[11px] text-text-primary capitalize">{selected.status}</span>
                </div>
              </div>
              <div>
                <label className="text-[10px] text-text-muted uppercase block mb-1">Events Processed</label>
                <div className="text-[11px] text-text-primary">{selected.events_total.toLocaleString()}</div>
              </div>
              <div>
                <label className="text-[10px] text-text-muted uppercase block mb-1">Errors</label>
                <div className={`text-[11px] ${selected.errors_total > 0 ? 'text-crit-text' : 'text-text-primary'}`}>
                  {selected.errors_total}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </>
  )
}
