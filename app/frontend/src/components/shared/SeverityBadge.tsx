import type { SeverityLevel } from '../../types/api'
import { cn } from '@/lib/utils'

const MAP: Record<SeverityLevel, { cls: string; label: string }> = {
  critical: { cls: 'sev-critical', label: 'Critical' },
  high: { cls: 'sev-high', label: 'High' },
  medium: { cls: 'sev-medium', label: 'Medium' },
  low: { cls: 'sev-low', label: 'Low' },
}
const FALLBACK = { cls: 'sev-info', label: 'Info' }

export function ScoreCircle({ score, severity }: { score: number; severity: SeverityLevel }) {
  const { cls, label } = MAP[severity] ?? FALLBACK
  return (
    <span
      className={cn('inline-flex h-6 w-6 items-center justify-center rounded-full border text-[9px] font-bold tabular-nums', cls)}
      aria-label={`Score ${score}, ${label}`}
    >
      {score.toFixed(1)}
    </span>
  )
}

export function SeverityPill({ severity, className }: { severity: SeverityLevel; className?: string }) {
  const { cls, label } = MAP[severity] ?? FALLBACK
  return (
    <span className={cn('inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-medium leading-none', cls, className)}>
      {label}
    </span>
  )
}
