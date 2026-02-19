import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts'
import type { TimelinePoint } from '../../../types/api'

interface Props { data: TimelinePoint[] }

export function DetectionTimeline({ data }: Props) {
  return (
    <div className="bg-surface rounded-md shadow-card p-4">
      <div className="flex items-start justify-between mb-3">
        <div>
          <h3 className="text-[12px] font-semibold text-text-primary">Detection Timeline</h3>
          <p className="text-[11px] text-text-muted">Alerts over past 7 days</p>
        </div>
        <div className="flex items-center gap-4 text-[10px] text-text-muted">
          <span className="flex items-center gap-1"><span className="w-2 h-2 rounded bg-crit-text inline-block" />Critical</span>
          <span className="flex items-center gap-1"><span className="w-2 h-2 rounded bg-border inline-block" />Other</span>
        </div>
      </div>
      <ResponsiveContainer width="100%" height={180}>
        <AreaChart data={data} margin={{ top: 10, right: 0, left: -20, bottom: 0 }}>
          <defs>
            <linearGradient id="gradTotal" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#E8ECF0" stopOpacity={0.8} />
              <stop offset="100%" stopColor="#E8ECF0" stopOpacity={0.1} />
            </linearGradient>
            <linearGradient id="gradCrit" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#CC3333" stopOpacity={0.15} />
              <stop offset="100%" stopColor="#CC3333" stopOpacity={0.02} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 0" stroke="#F0F2F5" vertical={false} />
          <XAxis dataKey="date" tick={{ fontSize: 10, fill: '#A0AABB' }} axisLine={false} tickLine={false} />
          <YAxis tick={{ fontSize: 9, fill: '#C8D0DC' }} axisLine={false} tickLine={false} />
          <Tooltip
            contentStyle={{ fontSize: 11, border: '1px solid #E8ECF0', borderRadius: 6 }}
            labelStyle={{ color: '#1C2D40', fontWeight: 600 }}
          />
          <Area type="monotone" dataKey="total"    fill="url(#gradTotal)" stroke="#C8D0DC" strokeWidth={1.5} name="Total" />
          <Area type="monotone" dataKey="critical" fill="url(#gradCrit)"  stroke="#CC3333" strokeWidth={1.5} name="Critical" />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}
