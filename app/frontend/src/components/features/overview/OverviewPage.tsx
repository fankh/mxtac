import { useQuery } from '@tanstack/react-query'
import { overviewApi } from '../../../lib/api'
import { TopBar } from '../../layout/TopBar'
import { KpiCards } from './KpiCards'
import { DetectionTimeline } from './DetectionTimeline'
import { TacticsTable } from './TacticsTable'
import { AttackHeatmap } from './AttackHeatmap'
import { IntegrationStatusRow } from './IntegrationStatusRow'
import { RecentDetectionsTable } from './RecentDetectionsTable'

export function OverviewPage() {
  const kpis        = useQuery({ queryKey: ['kpis'],         queryFn: overviewApi.kpis })
  const timeline    = useQuery({ queryKey: ['timeline'],     queryFn: overviewApi.timeline })
  const tactics     = useQuery({ queryKey: ['tactics'],      queryFn: overviewApi.tactics })
  const heatmap     = useQuery({ queryKey: ['heatmap'],      queryFn: overviewApi.heatmap })
  const tacticLbls  = useQuery({ queryKey: ['tacticLabels'], queryFn: overviewApi.tacticLabels })
  const integrations = useQuery({ queryKey: ['integrations'], queryFn: overviewApi.integrations })
  const recent      = useQuery({ queryKey: ['recent'],       queryFn: overviewApi.recentDetections })

  // Only require KPIs to render — other sections degrade gracefully
  const loading = kpis.isLoading
  const error   = kpis.isError

  return (
    <>
      <TopBar crumb="Overview" updatedAt="just now" />
      <div className="pt-[46px]">
        {loading && (
          <div className="flex items-center justify-center h-64 text-text-muted text-sm">Loading…</div>
        )}
        {error && (
          <div className="flex items-center justify-center h-64 text-crit-text text-sm">
            Failed to load data. Is the backend running?
          </div>
        )}
        {!loading && !error && kpis.data && (
          <>
            {/* KPI row */}
            <KpiCards data={kpis.data} />

            {/* Middle row: timeline + tactics */}
            <div className="grid grid-cols-[1fr_340px] gap-3 px-5 pt-3">
              <DetectionTimeline data={timeline.data ?? []} />
              <TacticsTable     data={tactics.data ?? []} />
            </div>

            {/* Heatmap */}
            <div className="px-5 pt-3">
              <AttackHeatmap
                rows={heatmap.data ?? []}
                tacticLabels={tacticLbls.data ?? []}
              />
            </div>

            {/* Recent detections */}
            <div className="px-5 pt-3">
              <RecentDetectionsTable data={recent.data ?? []} />
            </div>

            {/* Integration status */}
            <div className="px-5 pt-3 pb-6">
              <IntegrationStatusRow data={integrations.data ?? []} />
            </div>
          </>
        )}
      </div>
    </>
  )
}
