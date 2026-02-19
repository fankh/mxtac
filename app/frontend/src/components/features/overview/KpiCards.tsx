import type { KpiMetrics } from '../../../types/api'

function Card({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="bg-surface rounded-md shadow-card p-4 flex flex-col gap-1">
      <span className="text-[10px] font-medium text-text-muted uppercase tracking-wide">{label}</span>
      {children}
    </div>
  )
}

interface Props { data: KpiMetrics }

export function KpiCards({ data }: Props) {
  const covPct = (data.attack_covered / data.attack_total) * 100
  const intPct = (data.integrations_active / data.integrations_total) * 100

  return (
    <div className="grid grid-cols-6 gap-3 px-5 pt-3">
      {/* Total Detections */}
      <Card label="Total Detections">
        <span className="text-[32px] font-bold text-text-primary leading-none">
          {data.total_detections.toLocaleString()}
        </span>
        <span className="text-[11px] text-text-muted">
          ↑ {data.total_detections_delta_pct}% vs prev week
        </span>
      </Card>

      {/* Critical Alerts */}
      <Card label="Critical Alerts">
        <span className="text-[32px] font-bold text-crit-text leading-none">
          {data.critical_alerts}
        </span>
        <span className="text-[11px] text-text-muted">{data.critical_alerts_new_today} new today</span>
      </Card>

      {/* ATT&CK Coverage */}
      <Card label="ATT&CK Coverage">
        <div className="flex items-center gap-3">
          {/* Ring gauge */}
          <svg width="52" height="52" viewBox="0 0 52 52" className="shrink-0">
            <circle cx="26" cy="26" r="21" fill="none" stroke="#E8ECF0" strokeWidth="5" />
            <circle
              cx="26" cy="26" r="21" fill="none"
              stroke="#0066CC" strokeWidth="5" strokeLinecap="round"
              strokeDasharray={`${(covPct / 100) * 132} 132`}
              strokeDashoffset="33"
              transform="rotate(-90 26 26)"
            />
            <text x="26" y="30" textAnchor="middle" fontSize="12" fontWeight="700" fill="#1C2D40">
              {Math.round(covPct)}%
            </text>
          </svg>
          <div>
            <div className="text-[11px] text-text-muted">{data.attack_covered} / {data.attack_total} techniques</div>
            <div className="text-[10px] text-text-muted">+{data.attack_coverage_delta} this week</div>
          </div>
        </div>
      </Card>

      {/* MTTD */}
      <Card label="Mean Time to Detect">
        <div className="flex items-baseline gap-1">
          <span className="text-[32px] font-bold text-text-primary leading-none">{data.mttd_minutes}</span>
          <span className="text-[14px] text-text-muted">min</span>
        </div>
        <span className="text-[11px] text-text-muted">
          ↓ {Math.abs(data.mttd_delta_minutes)}m improved
        </span>
      </Card>

      {/* Integrations */}
      <Card label="Integrations">
        <div className="flex items-baseline gap-1">
          <span className="text-[32px] font-bold text-text-primary leading-none">{data.integrations_active}</span>
          <span className="text-[14px] text-text-muted">/ {data.integrations_total}</span>
        </div>
        <div className="h-[5px] rounded bg-border mt-1">
          <div className="h-full rounded bg-blue" style={{ width: `${intPct}%` }} />
        </div>
        <span className="text-[10px] text-text-muted">Splunk: auth error</span>
      </Card>

      {/* Sigma Rules */}
      <Card label="Sigma Rules Active">
        <span className="text-[32px] font-bold text-text-primary leading-none">
          {data.sigma_rules_active.toLocaleString()}
        </span>
        <span className="text-[11px] text-text-muted">
          {data.sigma_rules_critical} critical · {data.sigma_rules_high} high
        </span>
        <span className="text-[10px] text-text-muted">+{data.sigma_rules_deployed_this_week} deployed this week</span>
      </Card>
    </div>
  )
}
