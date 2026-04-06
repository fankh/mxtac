import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { overviewApi, coverageApi } from '../../../lib/api'
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

      {/* Search bar — matches Hunt/NDR layout */}
      <div className="flex items-center gap-2 py-3 flex-wrap">
        <div className="relative flex-1 min-w-[280px]">
          <span className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted text-[13px] select-none">⌕</span>
          <input
            type="text"
            value={selectedTactic ?? ''}
            onChange={e => setSelectedTactic(e.target.value || null)}
            placeholder="Filter techniques — type a tactic name (e.g. Execution, Persistence)"
            className="w-full h-[32px] pl-8 pr-3 text-[12px] border border-border rounded-md bg-surface text-text-primary placeholder-text-muted focus:outline-none focus:border-blue"
          />
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
      </div>

      {/* Coverage Trend + Tactic Breakdown */}
      <div className="grid grid-cols-[1fr_360px] gap-4">
        {/* Trend Chart */}
        <div className="bg-surface border border-border rounded-lg p-4">
          <h2 className="text-xs font-semibold mb-3">Coverage Trend (30 days)</h2>
          {trendData.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={trendData}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" opacity={0.3} />
                <XAxis dataKey="date" tick={{ fontSize: 10, fill: 'var(--color-muted)' }} />
                <YAxis domain={[0, 100]} tick={{ fontSize: 10, fill: 'var(--color-muted)' }} unit="%" />
                <Tooltip contentStyle={{ fontSize: 11, background: 'var(--color-surface)', border: '1px solid var(--color-border)' }} />
                <Area type="monotone" dataKey="pct" stroke="var(--color-blue)" fill="var(--color-blue)" fillOpacity={0.1} strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-[200px] flex items-center justify-center text-xs text-muted">No trend data</div>
          )}
        </div>

        {/* Tactic Breakdown */}
        <div className="bg-surface border border-border rounded-lg p-4">
          <h2 className="text-xs font-semibold mb-3">Coverage by Tactic</h2>
          <div className="space-y-2">
            {TACTICS.map(tactic => {
              const data = stats.byTactic[tactic.name] || { covered: 0, total: 0 }
              const pct = data.total > 0 ? Math.round((data.covered / data.total) * 100) : 0
              const isSelected = selectedTactic === tactic.id
              return (
                <button
                  key={tactic.id}
                  onClick={() => setSelectedTactic(isSelected ? null : tactic.id)}
                  className={`w-full flex items-center gap-2 px-2 py-1.5 rounded text-left transition-colors ${
                    isSelected ? 'bg-blue/10 border border-blue/30' : 'hover:bg-hover'
                  }`}
                >
                  <span className="text-[10px] text-muted font-mono w-[50px]">{tactic.id}</span>
                  <span className="text-[11px] flex-1 truncate">{tactic.name}</span>
                  <div className="w-[60px] h-1.5 rounded-full bg-border overflow-hidden">
                    <div
                      className={`h-full rounded-full ${pct >= 80 ? 'bg-green-500' : pct >= 50 ? 'bg-yellow-500' : pct > 0 ? 'bg-red-500' : 'bg-border'}`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                  <span className="text-[10px] font-medium w-[30px] text-right">{pct}%</span>
                </button>
              )
            })}
          </div>
        </div>
      </div>

      {/* ATT&CK Heatmap Matrix */}
      <div className="bg-surface border border-border rounded-lg p-4">
        <h2 className="text-xs font-semibold mb-3">ATT&CK Matrix Heatmap</h2>
        {heatmapLoading ? (
          <div className="h-[300px] flex items-center justify-center text-xs text-muted">Loading heatmap...</div>
        ) : !heatmap || heatmap.length === 0 ? (
          <div className="h-[300px] flex items-center justify-center text-xs text-muted">No coverage data available</div>
        ) : (
          <div className="overflow-x-auto">
            {/* Tactic headers */}
            <div className="flex gap-[2px] mb-1 min-w-max">
              <div className="w-[100px] shrink-0" />
              {TACTICS.map(t => (
                <div
                  key={t.id}
                  className="w-[80px] shrink-0 text-[10px] text-muted font-medium text-center truncate px-0.5"
                  title={t.name}
                >
                  {t.name}
                </div>
              ))}
            </div>
            {/* Technique rows */}
            {heatmap.map(row => (
              <div key={row.technique_id} className="flex gap-[2px] mb-[2px] min-w-max">
                <div className="w-[100px] shrink-0 text-[10px] font-mono text-muted truncate pr-1" title={row.technique_id}>
                  {row.technique_id}
                </div>
                {row.cells.map((cell, ci) => {
                  const covered = cell.covered > 0
                  return (
                    <div
                      key={ci}
                      className={`w-[80px] h-[20px] shrink-0 rounded-[2px] transition-colors ${
                        covered
                          ? 'bg-green-500 hover:bg-green-400'
                          : 'bg-border/30 hover:bg-border/50'
                      }`}
                      style={{ opacity: covered ? Math.max(0.3, cell.opacity) : 0.15 }}
                      title={`${cell.tactic}: ${cell.covered}/${cell.total} rules`}
                    />
                  )
                })}
              </div>
            ))}
          </div>
        )}

        {/* Legend */}
        <div className="flex items-center gap-4 mt-3 text-[10px] text-muted">
          <span className="flex items-center gap-1"><span className="w-3 h-3 rounded-[2px] bg-green-500 opacity-90" /> Covered</span>
          <span className="flex items-center gap-1"><span className="w-3 h-3 rounded-[2px] bg-green-500 opacity-30" /> Partial</span>
          <span className="flex items-center gap-1"><span className="w-3 h-3 rounded-[2px] bg-border/30" /> Not Covered</span>
        </div>
      </div>
    </div>
    </>
  )
}
