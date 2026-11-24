import type { DetectionStatus } from '@/types/api'

export const DETECTION_STATUS_OPTIONS: DetectionStatus[] = ['active', 'investigating', 'resolved', 'false_positive']

export const DETECTION_STATUS_LABELS: Record<DetectionStatus, string> = {
  active: 'Active',
  investigating: 'Investigating',
  resolved: 'Resolved',
  false_positive: 'False positive',
}
