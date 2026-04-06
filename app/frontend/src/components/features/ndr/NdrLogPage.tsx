import { useState, useCallback, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { eventsApi } from '../../../lib/api'
import { TopBar } from '../../layout/TopBar'
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
  { value: '6h', label: '6H' },
  { value: '24h', label: '24H' },
  { value: '7d', label: '7D' },
]

const PROTO_COLORS: Record<string, string> = {
  TCP: 'var(--color-blue, #3b82f6)',
  UDP: 'var(--color-green, #22c55e)',
  ICMP: 'var(--color-yellow, #eab308)',
  DNS: '#8b5cf6',
  HTTP: '#f97316',
  TLS: '#06b6d4',
  SSH: '#ec4899',
  OTHER: 'var(--color-muted, #94a3b8)',
}

export function NdrLogPage() {
  const [query, setQuery] = useState('')
  const [timeRange, setTimeRange] = useState('24h')
  const [selectedRow, setSelectedRow] = useState<number | null>(null)

  const hasToken = !!localStorage.getItem('access_token')

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['ndr-logs', query, timeRange],
    queryFn: () =>
      eventsApi.search({
        query: `class_name:network_activity ${query}`.trim(),
        time_range: timeRange,
        limit: 500,
      }),
    enabled: hasToken,
    staleTime: 30_000,
    retry: 2,
  })

  const events = useMemo(() => (data?.events ?? []) as Record<string, unknown>[], [data])

  // Extract flow fields
  const flows = useMemo(() => events.map(e => {
    const raw = (e.raw ?? e) as Record<string, unknown>
    const src = (raw.src_endpoint ?? {}) as Record<string, unknown>
    const dst = (raw.dst_endpoint ?? {}) as Record<string, unknown>
    const traffic = (raw.traffic ?? {}) as Record<string, unknown>
    return {
      time: String(raw.time ?? e.time ?? '').slice(11, 19),
      src_ip: String(src.ip ?? raw.src_ip ?? e.src_ip ?? ''),
      src_port: src.port ?? raw.src_port ?? '',
      dst_ip: String(dst.ip ?? raw.dst_ip ?? e.dst_ip ?? ''),
      dst_port: dst.port ?? raw.dst_port ?? '',
      protocol: String(raw.protocol ?? 'TCP').toUpperCase(),
      action: String(raw.action ?? raw.disposition ?? '—'),
      bytes_in: Number(traffic.bytes_in ?? raw.bytes_in ?? 0),
      bytes_out: Number(traffic.bytes_out ?? raw.bytes_out ?? 0),
      duration_ms: Number(raw.duration_ms ?? raw.duration ?? 0),
      severity: Number(raw.severity_id ?? e.severity_id ?? 0),
      class_name: String(raw.class_name ?? e.class_name ?? ''),
      summary: String(raw.summary ?? (raw as Record<string, unknown>).unmapped?.summary ?? e.summary ?? ''),
      raw,
    }
  }), [events])

  // Protocol distribution for histogram
  const histogram = useMemo(() => {
    const buckets: Record<string, Record<string, number>> = {}
    for (const f of flows) {
      const hour = String(f.time).slice(0, 2) + ':00'
      if (!buckets[hour]) buckets[hour] = {}
      const proto = ['TCP', 'UDP', 'ICMP', 'DNS', 'HTTP', 'TLS', 'SSH'].includes(f.protocol) ? f.protocol : 'OTHER'
      buckets[hour][proto] = (buckets[hour][proto] || 0) + 1
    }
    return Object.entries(buckets)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([time, protos]) => ({ time, ...protos }))
  }, [flows])

  // Stats
  const totalBytes = flows.reduce((s, f) => s + f.bytes_in + f.bytes_out, 0)
  const protoCounts = flows.reduce((acc, f) => {
    acc[f.protocol] = (acc[f.protocol] || 0) + 1
    return acc
  }, {} as Record<string, number>)
  const topProtos = Object.entries(protoCounts).sort(([, a], [, b]) => b - a)

  const handleSearch = useCallback(() => { refetch() }, [refetch])

  return (
    <>
      <TopBar crumb="NDR Logs" />
      <div className="pt-[46px] p-5 space-y-4">

        {/* Controls */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1">
            {TIME_RANGES.map(tr => (
              <button
                key={tr.value}
                onClick={() => setTimeRange(tr.value)}
                className={`px-2.5 py-1 text-[11px] font-medium rounded border transition-colors ${
                  timeRange === tr.value
                    ? 'bg-blue text-white border-blue'
                    : 'bg-surface border-border text-text-primary hover:bg-hover'
                }`}
              >
                {tr.label}
              </button>
            ))}
          </div>
          <input
            type="text"
            value={query}
            onChange={e => setQuery(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleSearch()}
            placeholder="Filter: src_ip:10.0.0.* dst_port:443 protocol:TCP"
            className="flex-1 h-8 px-3 text-[11px] bg-surface border border-border rounded focus:outline-none focus:border-blue"
          />
          <button
            onClick={handleSearch}
            className="h-8 px-4 text-[11px] font-medium bg-blue text-white rounded hover:bg-blue/90 transition-colors"
          >
            Search
          </button>
        </div>

        {/* Stats row */}
        <div className="grid grid-cols-4 gap-3">
          <div className="bg-surface border border-border rounded-lg p-3">
            <p className="text-[10px] font-medium text-text-muted uppercase tracking-wider">Total Flows</p>
            <p className="text-lg font-bold mt-0.5">{flows.length.toLocaleString()}</p>
          </div>
          <div className="bg-surface border border-border rounded-lg p-3">
            <p className="text-[10px] font-medium text-text-muted uppercase tracking-wider">Traffic</p>
            <p className="text-lg font-bold mt-0.5">{formatBytes(totalBytes)}</p>
          </div>
          <div className="bg-surface border border-border rounded-lg p-3">
            <p className="text-[10px] font-medium text-text-muted uppercase tracking-wider">Protocols</p>
            <p className="text-lg font-bold mt-0.5">{topProtos.length}</p>
          </div>
          <div className="bg-surface border border-border rounded-lg p-3">
            <p className="text-[10px] font-medium text-text-muted uppercase tracking-wider">Top Protocol</p>
            <p className="text-lg font-bold mt-0.5">{topProtos[0]?.[0] ?? '—'}</p>
          </div>
        </div>

        {/* Protocol histogram */}
        {histogram.length > 0 && (
          <div className="bg-surface border border-border rounded-lg p-4">
            <div className="flex items-center justify-between mb-2">
              <h2 className="text-[11px] font-semibold">Traffic by Protocol</h2>
              <div className="flex items-center gap-3">
                {topProtos.slice(0, 6).map(([proto]) => (
                  <span key={proto} className="flex items-center gap-1 text-[9px] text-text-muted">
                    <span className="w-2 h-2 rounded-full" style={{ background: PROTO_COLORS[proto] || PROTO_COLORS.OTHER }} />
                    {proto}
                  </span>
                ))}
              </div>
            </div>
            <ResponsiveContainer width="100%" height={140}>
              <BarChart data={histogram}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" opacity={0.3} />
                <XAxis dataKey="time" tick={{ fontSize: 9, fill: 'var(--color-text-muted)' }} />
                <YAxis tick={{ fontSize: 9, fill: 'var(--color-text-muted)' }} />
                <Tooltip contentStyle={{ fontSize: 10, background: 'var(--color-surface)', border: '1px solid var(--color-border)' }} />
                {topProtos.map(([proto]) => (
                  <Bar key={proto} dataKey={proto} stackId="a" fill={PROTO_COLORS[proto] || PROTO_COLORS.OTHER} />
                ))}
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}

        {/* Flow table */}
        <div className="bg-surface border border-border rounded-lg overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-[11px]">
              <thead>
                <tr className="border-b border-border bg-hover/30 text-[10px] font-medium text-text-muted uppercase tracking-wider">
                  <th className="text-left p-2.5 w-[70px]">Time</th>
                  <th className="text-left p-2.5">Source</th>
                  <th className="text-left p-2.5">Destination</th>
                  <th className="text-left p-2.5 w-[70px]">Protocol</th>
                  <th className="text-left p-2.5 w-[70px]">Action</th>
                  <th className="text-right p-2.5 w-[80px]">Bytes In</th>
                  <th className="text-right p-2.5 w-[80px]">Bytes Out</th>
                  <th className="text-right p-2.5 w-[70px]">Duration</th>
                </tr>
              </thead>
              <tbody>
                {isLoading ? (
                  <tr><td colSpan={8} className="p-8 text-center text-text-muted text-[11px]">Loading NDR flows...</td></tr>
                ) : flows.length === 0 ? (
                  <tr><td colSpan={8} className="p-8 text-center text-text-muted text-[11px]">No network flows found. Connect an NDR source to start capturing.</td></tr>
                ) : (
                  flows.slice(0, 200).map((f, i) => (
                    <tr
                      key={i}
                      onClick={() => setSelectedRow(selectedRow === i ? null : i)}
                      className={`border-b border-border/50 cursor-pointer transition-colors ${
                        selectedRow === i ? 'bg-blue/5' : 'hover:bg-hover/50'
                      } ${f.severity >= 4 ? 'border-l-2 border-l-red-500' : ''}`}
                    >
                      <td className="p-2.5 font-mono text-text-muted tabular-nums">{f.time}</td>
                      <td className="p-2.5 font-mono">
                        <span className="text-text-primary">{f.src_ip}</span>
                        {f.src_port ? <span className="text-text-muted">:{String(f.src_port)}</span> : null}
                      </td>
                      <td className="p-2.5 font-mono">
                        <span className="text-text-primary">{f.dst_ip}</span>
                        {f.dst_port ? <span className="text-text-muted">:{String(f.dst_port)}</span> : null}
                      </td>
                      <td className="p-2.5">
                        <span className={`inline-block px-1.5 py-0.5 rounded text-[9px] font-semibold`}
                          style={{ background: (PROTO_COLORS[f.protocol] || PROTO_COLORS.OTHER) + '15', color: PROTO_COLORS[f.protocol] || PROTO_COLORS.OTHER }}>
                          {f.protocol}
                        </span>
                      </td>
                      <td className="p-2.5 text-text-muted capitalize">{f.action}</td>
                      <td className="p-2.5 text-right font-mono tabular-nums text-text-muted">{formatBytes(f.bytes_in)}</td>
                      <td className="p-2.5 text-right font-mono tabular-nums text-text-muted">{formatBytes(f.bytes_out)}</td>
                      <td className="p-2.5 text-right font-mono tabular-nums text-text-muted">{f.duration_ms > 0 ? `${f.duration_ms}ms` : '—'}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          {flows.length > 200 && (
            <div className="p-2 text-center text-[10px] text-text-muted border-t border-border">
              Showing 200 of {flows.length.toLocaleString()} flows
            </div>
          )}
        </div>
      </div>
    </>
  )
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(Math.abs(bytes)) / Math.log(k))
  return `${(bytes / Math.pow(k, i)).toFixed(i > 0 ? 1 : 0)} ${sizes[i]}`
}
