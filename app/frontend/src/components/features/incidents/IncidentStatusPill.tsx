import type { IncidentStatus } from '@/types/api'
import { cn } from '@/lib/utils'
import { INCIDENT_STATUS_LABELS } from './incidentUtils'

const STATUS_CLASSES: Record<IncidentStatus, string> = {
  new: 'status-purple',
  investigating: 'sev-high',
  contained: 'sev-medium',
  resolved: 'status-green',
  closed: 'sev-info',
}

export function IncidentStatusPill({ status, className }: { status: IncidentStatus; className?: string }) {
  return (
    <span
      className={cn(
        'inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-medium leading-none',
        STATUS_CLASSES[status] ?? 'sev-info',
        className,
      )}
    >
      {INCIDENT_STATUS_LABELS[status] ?? status}
    </span>
  )
}
