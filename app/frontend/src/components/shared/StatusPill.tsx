import type { DetectionStatus } from '../../types/api'

const MAP: Record<DetectionStatus, string> = {
  active:        'bg-crit-bg text-crit-text',
  investigating: 'bg-high-bg text-high-text',
  resolved:      'bg-resolved-bg text-resolved-text',
  false_positive:'bg-low-bg text-low-text',
}

const LABELS: Record<DetectionStatus, string> = {
  active: 'Active',
  investigating: 'Investigating',
  resolved: 'Resolved',
  false_positive: 'False Positive',
}

export function StatusPill({ status }: { status: DetectionStatus }) {
  return (
    <span className={`inline-block px-2 py-0.5 rounded-full text-[9px] font-medium ${MAP[status]}`}>
      {LABELS[status]}
    </span>
  )
}
