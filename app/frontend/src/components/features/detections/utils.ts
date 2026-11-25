import type { Detection, DetectionStatus } from '@/types/api'

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

export function isUuid(value: string | null | undefined): boolean {
  return typeof value === 'string' && UUID_RE.test(value)
}

/**
 * Technique name worth showing next to the technique ID. The backend answers with the ATT&CK
 * name from its bundled table. For a technique the table does not know, it answers with the
 * stored value (the rule title in older rows) or the ID, which would only repeat what is shown.
 */
export function techniqueLabel(d: Pick<Detection, 'name' | 'technique_id' | 'technique_name'>): string {
  const name = d.technique_name?.trim() ?? ''
  return name === d.name.trim() || name === d.technique_id ? '' : name
}

/** Rule name worth showing as text: not the rule's UUID and not a repeat of the detection name. */
export function ruleLabel(d: Pick<Detection, 'name' | 'rule_name'>): string {
  const rule = d.rule_name?.trim() ?? ''
  return isUuid(rule) || rule === d.name.trim() ? '' : rule
}

export const DETECTION_STATUS_OPTIONS: DetectionStatus[] = ['active', 'investigating', 'resolved', 'false_positive']

export const DETECTION_STATUS_LABELS: Record<DetectionStatus, string> = {
  active: 'Active',
  investigating: 'Investigating',
  resolved: 'Resolved',
  false_positive: 'False positive',
}
