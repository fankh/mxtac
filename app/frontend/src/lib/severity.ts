import type { SeverityLevel } from '@/types/api'

export const SEVERITY_OPTIONS: SeverityLevel[] = ['critical', 'high', 'medium', 'low']

export const SEVERITY_LABELS: Record<SeverityLevel, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
}
