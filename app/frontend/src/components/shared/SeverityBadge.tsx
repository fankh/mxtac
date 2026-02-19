import type { SeverityLevel } from '../../types/api'

const MAP: Record<SeverityLevel, { circle: string; pill: string; label: string }> = {
  critical: { circle: 'bg-crit-bg text-crit-text', pill: 'bg-crit-bg text-crit-text', label: 'Critical' },
  high:     { circle: 'bg-high-bg text-high-text', pill: 'bg-high-bg text-high-text', label: 'High' },
  medium:   { circle: 'bg-med-bg  text-med-text',  pill: 'bg-med-bg  text-med-text',  label: 'Medium' },
  low:      { circle: 'bg-low-bg  text-low-text',  pill: 'bg-low-bg  text-low-text',  label: 'Low' },
}

export function ScoreCircle({ score, severity }: { score: number; severity: SeverityLevel }) {
  const { circle } = MAP[severity]
  return (
    <span
      className={`inline-flex items-center justify-center w-[22px] h-[22px] rounded-full text-[9px] font-bold ${circle}`}
      aria-label={`Score ${score}, ${MAP[severity].label}`}
    >
      {score.toFixed(1)}
    </span>
  )
}

export function SeverityPill({ severity }: { severity: SeverityLevel }) {
  const { pill, label } = MAP[severity]
  return (
    <span className={`inline-block px-2 py-0.5 rounded-full text-[9px] font-medium ${pill}`}>
      {label}
    </span>
  )
}
