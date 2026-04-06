import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { overviewApi, coverageApi, eventsApi } from '../../../lib/api'
import type { HeatRow, CoverageTrend } from '../../../types/api'
import { SeverityPill } from '../../shared/SeverityBadge'
import { TopBar } from '../../layout/TopBar'
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from 'recharts'

// MITRE ATT&CK 14 Tactics (Enterprise)
const TACTICS = [
  { id: 'TA0043', name: 'Reconnaissance' },
  { id: 'TA0042', name: 'Resource Development' },
  { id: 'TA0001', name: 'Initial Access' },
  { id: 'TA0002', name: 'Execution' },
  { id: 'TA0003', name: 'Persistence' },
  { id: 'TA0004', name: 'Privilege Escalation' },
  { id: 'TA0005', name: 'Defense Evasion' },
  { id: 'TA0006', name: 'Credential Access' },
  { id: 'TA0007', name: 'Discovery' },
  { id: 'TA0008', name: 'Lateral Movement' },
  { id: 'TA0009', name: 'Collection' },
  { id: 'TA0011', name: 'Command and Control' },
  { id: 'TA0010', name: 'Exfiltration' },
  { id: 'TA0040', name: 'Impact' },
]

export function CoveragePage() {
  const [selectedTactic, setSelectedTactic] = useState<string | null>(null)
  const [activeTactic, setActiveTactic] = useState<{ id: string; name: string } | null>(null)
  const hasToken = !!localStorage.getItem('access_token')

  // Fetch finding logs when a tactic is clicked
  const { data: tacticLogs, isLoading: logsLoading } = useQuery({
    queryKey: ['tactic-logs', activeTactic?.name],
    queryFn: () => eventsApi.search({
      query: `tactic:${activeTactic!.name.toLowerCase().replace(/ /g, '_')} OR mitre_tactic:${activeTactic!.id}`,
      time_range: '30d',
      limit: 50,
    }),
    enabled: hasToken && !!activeTactic,
    staleTime: 30_000,
  })

  const { data: heatmap, isLoading: heatmapLoading } = useQuery({
    queryKey: ['coverage-heatmap'],
    queryFn: () => overviewApi.heatmap(),
    staleTime: 60_000,
  })

  const { data: trend } = useQuery({
    queryKey: ['coverage-trend'],
    queryFn: () => coverageApi.trend(30),
    staleTime: 60_000,
  })

  // Compute coverage stats
  const stats = useMemo(() => {
    if (!heatmap) return { total: 0, covered: 0, pct: 0, byTactic: {} as Record<string, { covered: number; total: number }> }
    let total = 0
    let covered = 0
    const byTactic: Record<string, { covered: number; total: number }> = {}

    for (const row of heatmap) {
      for (const cell of row.cells) {
        total += cell.total
        covered += cell.covered
        if (!byTactic[cell.tactic]) byTactic[cell.tactic] = { covered: 0, total: 0 }
        byTactic[cell.tactic].covered += cell.covered
        byTactic[cell.tactic].total += cell.total
      }
    }

    return { total, covered, pct: total > 0 ? Math.round((covered / total) * 100) : 0, byTactic }
  }, [heatmap])

  // Trend chart data
  const trendData = useMemo(() => {
    if (!trend?.points) return []
    return trend.points.map(p => ({
      date: new Date(p.date).toLocaleDateString(undefined, { month: 'short', day: 'numeric' }),
      pct: p.coverage_pct,
      covered: p.covered_count,
    }))
  }, [trend])

  return (
    <>
      <TopBar crumb="ATT&CK Matrix" />
      <div className="pt-[46px] px-5 pb-6">

      {/* Search bar + tactic filter chips — matches Hunt/NDR layout */}
      <div className="flex items-center gap-2 py-3 flex-wrap">
        <div className="relative flex-1 min-w-[280px]">
          <span className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted text-[13px] select-none">⌕</span>
          <input
            type="text"
            value={selectedTactic ?? ''}
            onChange={e => setSelectedTactic(e.target.value || null)}
            placeholder="Filter by tactic — e.g. Execution, Persistence, Lateral Movement"
            className="w-full h-[32px] pl-8 pr-3 text-[12px] border border-border rounded-md bg-surface text-text-primary placeholder-text-muted focus:outline-none focus:border-blue"
          />
        </div>
        <div className="flex items-center border border-border rounded-md overflow-hidden">
          {['All', 'Covered', 'Gaps'].map(f => (
            <button
              key={f}
              className={`px-3 h-[32px] text-[11px] font-medium border-r border-border last:border-r-0 transition-colors ${
                (f === 'All' && !selectedTactic) ? 'bg-blue text-white' : 'bg-surface text-text-secondary hover:bg-page'
              }`}
              onClick={() => setSelectedTactic(f === 'All' ? null : f === 'Covered' ? 'covered' : 'gaps')}
            >
              {f}
            </button>
          ))}
        </div>
      </div>

      {/* Stats bar */}
      <div className="flex items-center gap-3 text-[11px] text-text-muted mb-3">
        <span className={`font-bold text-[14px] ${stats.pct >= 80 ? 'text-green-500' : stats.pct >= 60 ? 'text-yellow-500' : 'text-red-500'}`}>
          {stats.pct}%
        </span>
        <span>coverage</span>
        <span>·</span>
        <span><strong className="text-text-primary">{stats.covered}</strong> / {stats.total} techniques</span>
        <span>·</span>
        <span><strong className="text-text-primary">{heatmap?.length ?? 0}</strong> rules mapped</span>
        <span>·</span>
        <span><strong className="text-text-primary">{TACTICS.length}</strong> tactics</span>
      </div>

      {/* Coverage Trend — full width, single column */}
      <div className="bg-surface border border-border rounded-lg p-4 mb-4">
        <h2 className="text-[11px] font-semibold mb-3">Coverage Trend (30 days)</h2>
        {trendData.length > 0 ? (
          <ResponsiveContainer width="100%" height={160}>
            <AreaChart data={trendData}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" opacity={0.3} />
              <XAxis dataKey="date" tick={{ fontSize: 10, fill: 'var(--color-muted)' }} />
              <YAxis domain={[0, 100]} tick={{ fontSize: 10, fill: 'var(--color-muted)' }} unit="%" />
              <Tooltip contentStyle={{ fontSize: 11, background: 'var(--color-surface)', border: '1px solid var(--color-border)' }} />
              <Area type="monotone" dataKey="pct" stroke="var(--color-blue)" fill="var(--color-blue)" fillOpacity={0.1} strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        ) : (
          <div className="h-[160px] flex items-center justify-center text-[11px] text-text-muted">No trend data</div>
        )}
      </div>

      {/* Tactic Breakdown — horizontal bar list, single column */}
      <div className="bg-surface border border-border rounded-lg p-4 mb-4">
        <h2 className="text-[11px] font-semibold mb-3">Coverage by Tactic</h2>
        <div className="grid grid-cols-2 gap-x-6 gap-y-1.5">
          {TACTICS.map(tactic => {
            const data = stats.byTactic[tactic.name] || { covered: 0, total: 0 }
            const pct = data.total > 0 ? Math.round((data.covered / data.total) * 100) : 0
            return (
              <div key={tactic.id} className="flex items-center gap-2">
                <span className="text-[10px] text-text-muted font-mono w-[46px] shrink-0">{tactic.id}</span>
                <span className="text-[11px] flex-1 truncate">{tactic.name}</span>
                <div className="w-[80px] h-1.5 rounded-full bg-border overflow-hidden shrink-0">
                  <div
                    className={`h-full rounded-full ${pct >= 80 ? 'bg-green-500' : pct >= 50 ? 'bg-yellow-500' : pct > 0 ? 'bg-red-500' : 'bg-border'}`}
                    style={{ width: `${pct}%` }}
                  />
                </div>
                <span className="text-[10px] font-medium w-[28px] text-right text-text-muted">{pct}%</span>
              </div>
            )
          })}
        </div>
      </div>

      {/* MITRE ATT&CK Enterprise Matrix */}
      <div className="bg-surface border border-border rounded-lg p-4">
        <h2 className="text-[11px] font-semibold mb-3">MITRE ATT&CK Enterprise Matrix</h2>
        <div className="overflow-x-auto">
          <div className="flex gap-[3px] min-w-max">
            {TACTICS.map(tactic => {
              const tacticData = stats.byTactic[tactic.name] || { covered: 0, total: 0 }
              const tacticPct = tacticData.total > 0 ? Math.round((tacticData.covered / tacticData.total) * 100) : 0
              // Get techniques for this tactic from heatmap data
              const techniques: { id: string; covered: boolean }[] = []
              if (heatmap) {
                for (const row of heatmap) {
                  const cell = row.cells.find(c => c.tactic === tactic.name || c.tactic === tactic.id.replace('TA00', ''))
                  if (cell) {
                    techniques.push({ id: row.technique_id, covered: cell.covered > 0 })
                  }
                }
              }
              // Show at least some technique slots
              const slots = techniques.length > 0 ? techniques : Array.from({ length: 8 }, (_, i) => ({ id: `T${1000 + i}`, covered: false }))

              return (
                <div key={tactic.id} className="flex flex-col w-[105px] shrink-0">
                  {/* Tactic header — click to show finding logs */}
                  <button
                    onClick={() => setActiveTactic(activeTactic?.id === tactic.id ? null : { id: tactic.id, name: tactic.name })}
                    className={`px-2 py-1.5 rounded-t text-center border-b-2 w-full transition-colors cursor-pointer ${
                      activeTactic?.id === tactic.id ? 'bg-blue/10 border-blue ring-1 ring-blue/30' :
                      tacticPct >= 80 ? 'bg-green-500/10 border-green-500 hover:bg-green-500/20' :
                      tacticPct >= 50 ? 'bg-yellow-500/10 border-yellow-500 hover:bg-yellow-500/20' :
                      tacticPct > 0 ? 'bg-red-500/10 border-red-500 hover:bg-red-500/20' :
                      'bg-page border-border hover:bg-hover'
                    }`}
                  >
                    <p className="text-[9px] font-bold text-text-primary leading-tight truncate" title={tactic.name}>{tactic.name}</p>
                    <p className="text-[8px] text-text-muted font-mono">{tactic.id}</p>
                  </button>
                  {/* Technique cells */}
                  <div className="flex flex-col gap-[2px] mt-[2px]">
                    {slots.slice(0, 12).map((tech, i) => (
                      <div
                        key={i}
                        className={`px-1.5 py-1 rounded-[3px] text-[8px] font-mono truncate cursor-default transition-colors ${
                          tech.covered
                            ? 'bg-green-500/20 text-green-700 hover:bg-green-500/30'
                            : 'bg-page text-text-muted/50 hover:bg-border/30'
                        }`}
                        title={tech.id}
                      >
                        {tech.id}
                      </div>
                    ))}
                    {slots.length > 12 && (
                      <div className="text-[8px] text-text-muted text-center py-0.5">+{slots.length - 12} more</div>
                    )}
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        {/* Legend */}
        <div className="flex items-center gap-4 mt-3 text-[10px] text-text-muted">
          <span className="flex items-center gap-1"><span className="w-3 h-3 rounded-[2px] bg-green-500/20 border border-green-500/30" /> Covered</span>
          <span className="flex items-center gap-1"><span className="w-3 h-3 rounded-[2px] bg-page border border-border" /> Not Covered</span>
          <span className="ml-auto text-text-muted">Click a tactic header to view finding logs</span>
        </div>
      </div>

      {/* Finding Logs Panel — shows when a tactic is clicked */}
      {activeTactic && (
        <div className="bg-surface border border-border rounded-lg p-4">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-[11px] font-semibold">
              Finding Logs — <span className="text-blue">{activeTactic.name}</span>
              <span className="text-text-muted font-mono ml-1">({activeTactic.id})</span>
            </h2>
            <button
              onClick={() => setActiveTactic(null)}
              className="text-[10px] text-text-muted hover:text-text-primary transition-colors"
            >
              ✕ Close
            </button>
          </div>

          {logsLoading ? (
            <div className="flex items-center justify-center h-32 text-[11px] text-text-muted">Loading logs…</div>
          ) : (() => {
            const events = (tacticLogs?.events ?? []) as Record<string, unknown>[]
            if (events.length === 0) {
              return (
                <div className="flex flex-col items-center justify-center h-32">
                  <p className="text-[12px] font-semibold text-text-primary mb-1">No findings for {activeTactic.name}</p>
                  <p className="text-[10px] text-text-muted">No events matched this tactic in the last 30 days.</p>
                </div>
              )
            }
            return (
              <div className="overflow-x-auto">
                <table className="w-full text-[11px]">
                  <thead>
                    <tr className="border-b border-border text-[11px] font-medium text-text-muted">
                      <th className="text-left p-2 w-[70px]">Time</th>
                      <th className="text-left p-2">Event</th>
                      <th className="text-left p-2 w-[120px]">Source</th>
                      <th className="text-left p-2 w-[120px]">Host</th>
                      <th className="text-left p-2 w-[80px]">Severity</th>
                      <th className="text-left p-2 w-[100px]">Technique</th>
                    </tr>
                  </thead>
                  <tbody>
                    {events.slice(0, 30).map((evt, i) => {
                      const raw = (evt.raw ?? evt) as Record<string, unknown>
                      const time = String(raw.time ?? evt.time ?? '').slice(11, 19)
                      const summary = String(raw.summary ?? (raw as Record<string, unknown>).unmapped?.summary ?? evt.summary ?? evt.class_name ?? '—')
                      const source = String(raw.source ?? evt.source ?? '—')
                      const host = String((raw.src_endpoint as Record<string, unknown>)?.hostname ?? raw.hostname ?? evt.hostname ?? evt.src_ip ?? '—')
                      const severity = Number(raw.severity_id ?? evt.severity_id ?? 0)
                      const technique = String(raw.technique_id ?? evt.technique_id ?? '—')
                      const sevLabel = severity >= 4 ? 'high' : severity >= 3 ? 'medium' : severity >= 2 ? 'low' : 'info'
                      const sevColor = severity >= 4 ? 'text-red-500' : severity >= 3 ? 'text-yellow-600' : severity >= 2 ? 'text-blue' : 'text-text-muted'
                      return (
                        <tr key={i} className="border-b border-border/50 hover:bg-hover/50 transition-colors">
                          <td className="p-2 font-mono text-text-muted tabular-nums">{time}</td>
                          <td className="p-2 truncate max-w-[400px]" title={summary}>{summary}</td>
                          <td className="p-2 text-text-muted">{source}</td>
                          <td className="p-2 font-mono text-text-primary">{host}</td>
                          <td className="p-2">
                            <span className={`text-[10px] font-semibold ${sevColor}`}>{sevLabel}</span>
                          </td>
                          <td className="p-2 font-mono text-[10px] text-text-muted">{technique}</td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
                {events.length > 30 && (
                  <div className="p-2 text-center text-[10px] text-text-muted border-t border-border">
                    Showing 30 of {events.length} findings
                  </div>
                )}
              </div>
            )
          })()}
        </div>
      )}
    </div>
    </>
  )
}
