import { useEffect, useState } from 'react'
import { isAxiosError } from 'axios'
import type { DetectionStatus, SeverityLevel } from '@/types/api'

export const SEVERITY_OPTIONS: SeverityLevel[] = ['critical', 'high', 'medium', 'low']
export const DETECTION_STATUS_OPTIONS: DetectionStatus[] = ['active', 'investigating', 'resolved', 'false_positive']

export const SEVERITY_LABELS: Record<SeverityLevel, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
}

export const DETECTION_STATUS_LABELS: Record<DetectionStatus, string> = {
  active: 'Active',
  investigating: 'Investigating',
  resolved: 'Resolved',
  false_positive: 'False positive',
}

/** Roles that hold the backend write permission for detections and incidents. */
const WRITE_ROLES = new Set(['analyst', 'hunter', 'engineer', 'admin'])

export function canWrite(role: string | undefined): boolean {
  return role !== undefined && WRITE_ROLES.has(role)
}

/** Best message for a failed request: the FastAPI detail, else the error text. */
export function apiErrorMessage(error: unknown, fallback = 'The request failed. Try again.'): string {
  if (isAxiosError(error)) {
    const detail: unknown = error.response?.data?.detail
    if (typeof detail === 'string' && detail) return detail
    if (Array.isArray(detail)) {
      const messages = detail
        .map((item: unknown) =>
          typeof item === 'object' && item !== null && 'msg' in item ? String(item.msg) : '',
        )
        .filter(Boolean)
      if (messages.length > 0) return messages.join('; ')
    }
    if (error.message) return error.message
  }
  if (error instanceof Error && error.message) return error.message
  return fallback
}

export function plural(count: number, noun: string): string {
  return `${count.toLocaleString('en-US')} ${noun}${count === 1 ? '' : 's'}`
}

export function formatDateTime(value: string | null | undefined): string {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '—'
  return date.toLocaleString([], {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

/** Returns the value after it has stayed the same for the given delay. */
export function useDebouncedValue<T>(value: T, delayMs = 300): T {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delayMs)
    return () => clearTimeout(timer)
  }, [value, delayMs])
  return debounced
}
