import { useState, useCallback, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { eventsApi } from '../../../lib/api'
import type { SearchResponse } from '../../../types/api'
import { SeverityPill } from '../../shared/SeverityBadge'
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from 'recharts'

const TIME_RANGES = [
  { value: '1h', label: '1H' },
  { value: '24h', label: '24H' },
  { value: '7d', label: '7D' },
]

const PROTOCOLS = ['TCP', 'UDP', 'ICMP', 'OTHER']
const PROTO_COLORS: Record<string, string> = {
  TCP: 'var(--color-blue)',
  UDP: 'var(--color-green)',
  ICMP: 'var(--color-yellow)',
  OTHER: 'var(--color-muted)',
}

export function NetworkLogsPage() {
  const [query, setQuery] = useState('')
  const [timeRange, setTimeRange] = useState('24h')
  const [selectedFlow, setSelectedFlow] = useState<Record<string, unknown> | null>(null)

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['network-logs', query, timeRange],
    queryFn: () =>
      eventsApi.search({
        query: `class_name:network_activity ${query}`.trim(),
        time_range: timeRange,
        limit: 200,
      }),
    staleTime: 30_000,
  })

  const events = useMemo(() => data?.events ?? [], [data])

  // Compute protocol histogram
  const histogram = useMemo(() => {
    const buckets: Record<string, Record<string, number>> = {}
    for (const e of events) {
      const raw = (e as Record<string, unknown>).raw as Record<string, unknown> | undefined
      const ts = (raw?.time ?? (e as Record<string, unknown>).time ?? '') as string
      const hour = ts.slice(0, 13) || 'unknown'
      const proto = ((raw?.protocol ?? 'OTHER') as string).toUpperCase()
      if (!buckets[hour]) buckets[hour] = {}
      buckets[hour][proto] = (buckets[hour][proto] || 0) + 1
    }
    return Object.entries(buckets)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([time, protos]) => ({
        time: time.slice(5).replace('T', ' ') || time,
        TCP: protos.TCP || 0,
        UDP: protos.UDP || 0,
        ICMP: protos.ICMP || 0,
        OTHER: protos.OTHER || 0,
      }))
  }, [events])

  // Extract flow fields from raw event
  const extractFlow = useCallback((e: Record<string, unknown>) => {
    const raw = (e.raw ?? e) as Record<string, unknown>
    const src = (raw.src_endpoint ?? {}) as Record<string, unknown>
    const dst = (raw.dst_endpoint ?? {}) as Record<string, unknown>
    return {
      src_ip: (src.ip ?? raw.src_ip ?? '') as string,
      src_port: (src.port ?? raw.src_port ?? '') as string,
      dst_ip: (dst.ip ?? raw.dst_ip ?? '') as string,
      dst_port: (dst.port ?? raw.dst_port ?? '') as string,
      protocol: ((raw.protocol ?? 'TCP') as string).toUpperCase(),
      bytes_in: raw.bytes_in ?? raw.traffic?.bytes_in ?? 0,
      bytes_out: raw.bytes_out ?? raw.traffic?.bytes_out ?? 0,
      action: (raw.action ?? raw.disposition ?? '') as string,
      time: (raw.time ?? e.time ?? '') as string,
      severity: (raw.severity_id ?? e.severity_id ?? 0) as number,
    }
  }, [])

  const handleSearch = useCallback(() => {
    refetch()
  }, [refetch])

  return (
    <div className="p-6 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-bold text-primary">Network Logs</h1>
          <p className="text-xs text-muted mt-0.5">Network traffic analysis and flow monitoring</p>
        </div>
        <div className="flex items-center gap-2">
          {TIME_RANGES.map(tr => (
            <button
              key={tr.value}
              onClick={() => setTimeRange(tr.value)}
              className={`px-3 py-1 text-xs font-medium rounded border transition-colors ${
                timeRange === tr.value
                  ? 'bg-blue text-white border-blue'
                  : 'bg-surface border-border text-primary hover:bg-hover'
              }`}
            >
              {tr.label}
            </button>
          ))}
        </div>
      </div>

      {/* Search */}
      <div className="flex gap-2">
        <input
          type="text"
          value={query}
          onChange={e => setQuery(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && handleSearch()}
          placeholder="Filter flows (e.g., dst_ip:10.0.0.1 protocol:TCP)"
          className="flex-1 h-8 px-3 text-xs bg-surface border border-border rounded focus:outline-none focus:border-blue"
        />
        <button
          onClick={handleSearch}
          className="h-8 px-4 text-xs font-medium bg-blue text-white rounded hover:bg-blue/90 transition-colors"
        >
          Search
        </button>
      </div>

      {/* Stats */}
      <div className="flex items-center gap-4 text-xs text-muted">
        <span>Found <strong className="text-primary">{events.length.toLocaleString()}</strong> flows</span>
        {data && <span>in {((data as unknown as Record<string, unknown>).elapsed_ms ?? 0)}ms</span>}
      </div>

      {/* Protocol Histogram */}
      {histogram.length > 0 && (
        <div className="bg-surface border border-border rounded-lg p-4">
          <h2 className="text-xs font-semibold mb-2">Traffic by Protocol</h2>
          <ResponsiveContainer width="100%" height={160}>
            <BarChart data={histogram}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" opacity={0.3} />
              <XAxis dataKey="time" tick={{ fontSize: 9, fill: 'var(--color-muted)' }} />
              <YAxis tick={{ fontSize: 9, fill: 'var(--color-muted)' }} />
              <Tooltip contentStyle={{ fontSize: 10, background: 'var(--color-surface)', border: '1px solid var(--color-border)' }} />
              {PROTOCOLS.map(proto => (
                <Bar key={proto} dataKey={proto} stackId="a" fill={PROTO_COLORS[proto]} />
              ))}
            </BarChart>
          </ResponsiveContainer>
          <div className="flex items-center gap-4 mt-2 text-[10px] text-muted">
            {PROTOCOLS.map(p => (
              <span key={p} className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full" style={{ background: PROTO_COLORS[p] }} />
                {p}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Flow Table */}
      <div className="bg-surface border border-border rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border bg-hover/30">
                <th className="text-left p-2 font-medium text-muted">Time</th>
                <th className="text-left p-2 font-medium text-muted">Source</th>
                <th className="text-left p-2 font-medium text-muted">Destination</th>
                <th className="text-left p-2 font-medium text-muted">Protocol</th>
                <th className="text-left p-2 font-medium text-muted">Action</th>
                <th className="text-right p-2 font-medium text-muted">Bytes</th>
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <tr><td colSpan={6} className="p-8 text-center text-muted">Loading flows...</td></tr>
              ) : events.length === 0 ? (
                <tr><td colSpan={6} className="p-8 text-center text-muted">No network flows found</td></tr>
              ) : (
                events.slice(0, 100).map((event, i) => {
                  const e = event as Record<string, unknown>
                  const f = extractFlow(e)
                  const isSelected = selectedFlow === e
                  return (
                    <tr
                      key={i}
                      onClick={() => setSelectedFlow(isSelected ? null : e)}
                      className={`border-b border-border/50 cursor-pointer transition-colors ${
                        isSelected ? 'bg-blue/5' : 'hover:bg-hover/50'
                      }`}
                    >
                      <td className="p-2 font-mono text-muted tabular-nums">{f.time.slice(11, 19)}</td>
                      <td className="p-2 font-mono">
                        <span className="text-primary">{f.src_ip}</span>
                        {f.src_port ? <span className="text-muted">:{f.src_port}</span> : null}
                      </td>
                      <td className="p-2 font-mono">
                        <span className="text-primary">{f.dst_ip}</span>
                        {f.dst_port ? <span className="text-muted">:{f.dst_port}</span> : null}
                      </td>
                      <td className="p-2">
                        <span className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                          f.protocol === 'TCP' ? 'bg-blue/10 text-blue' :
                          f.protocol === 'UDP' ? 'bg-green-500/10 text-green-500' :
                          'bg-yellow-500/10 text-yellow-500'
                        }`}>
                          {f.protocol}
                        </span>
                      </td>
                      <td className="p-2 capitalize text-muted">{f.action || '—'}</td>
                      <td className="p-2 text-right font-mono tabular-nums text-muted">
                        {formatBytes(Number(f.bytes_in) + Number(f.bytes_out))}
                      </td>
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${(bytes / Math.pow(k, i)).toFixed(i > 0 ? 1 : 0)} ${sizes[i]}`
}
