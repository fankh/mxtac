import type { DetectionStatus } from '../../types/api'
import { cn } from '@/lib/utils'

const MAP: Record<DetectionStatus, { cls: string; label: string }> = {
  active: { cls: 'sev-critical', label: 'Active' },
  investigating: { cls: 'sev-high', label: 'Investigating' },
  resolved: { cls: 'status-green', label: 'Resolved' },
  false_positive: { cls: 'sev-info', label: 'False positive' },
}

export function StatusPill({ status, className }: { status: DetectionStatus; className?: string }) {
  const { cls, label } = MAP[status] ?? { cls: 'sev-info', label: status }
  return (
    <span className={cn('inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-medium leading-none', cls, className)}>
      {label}
    </span>
  )
}
