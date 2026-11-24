import type { IncidentSortField, IncidentStatus, NoteType } from '@/types/api'

/** Backend order; a status can only move forward along this list. */
export const INCIDENT_STATUS_FLOW: IncidentStatus[] = ['new', 'investigating', 'contained', 'resolved', 'closed']

export const INCIDENT_STATUS_LABELS: Record<IncidentStatus, string> = {
  new: 'New',
  investigating: 'Investigating',
  contained: 'Contained',
  resolved: 'Resolved',
  closed: 'Closed',
}

export const INCIDENT_SORT_LABELS: Record<IncidentSortField, string> = {
  created_at: 'Newest first',
  severity: 'Severity',
  status: 'Status',
}

export const NOTE_TYPE_LABELS: Record<NoteType, string> = {
  comment: 'Comment',
  evidence: 'Evidence',
  status_change: 'Status change',
}

/** Statuses the incident may be set to: the current one and every later one. */
export function reachableStatuses(current: IncidentStatus): IncidentStatus[] {
  const index = INCIDENT_STATUS_FLOW.indexOf(current)
  return index < 0 ? [...INCIDENT_STATUS_FLOW] : INCIDENT_STATUS_FLOW.slice(index)
}

export function formatDuration(seconds: number | null | undefined): string {
  if (seconds == null) return '—'
  if (seconds < 60) return `${Math.round(seconds)}s`
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`
  if (seconds < 86400) return `${(seconds / 3600).toFixed(1)}h`
  return `${(seconds / 86400).toFixed(1)}d`
}
