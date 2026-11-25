import { formatDateTimeSeconds } from '@/lib/format'
import type {
  AggregationInterval, EventFilter, EventItem, SavedQueryFilter, SearchRequest,
} from '@/types/api'

/** Roles the backend grants `events:search` and `hunt_queries:*` to. */
export const HUNT_ROLES = ['hunter', 'engineer', 'admin']

export const PAGE_SIZE = 50

export const TIME_RANGES = [
  { value: 'now-1h', label: 'Last hour' },
  { value: 'now-6h', label: 'Last 6 hours' },
  { value: 'now-24h', label: 'Last 24 hours' },
  { value: 'now-7d', label: 'Last 7 days' },
  { value: 'now-30d', label: 'Last 30 days' },
]

/** Filter fields the events endpoint accepts (its `_ALLOWED_FILTER_FIELDS`). */
export const FILTER_FIELDS = [
  { value: 'hostname', label: 'Host', numeric: false },
  { value: 'username', label: 'User', numeric: false },
  { value: 'src_ip', label: 'Source IP', numeric: false },
  { value: 'dst_ip', label: 'Destination IP', numeric: false },
  { value: 'source', label: 'Source', numeric: false },
  { value: 'class_name', label: 'Event class', numeric: false },
  { value: 'class_uid', label: 'Class UID', numeric: true },
  { value: 'severity_id', label: 'Severity ID', numeric: true },
  { value: 'process_hash', label: 'Process hash', numeric: false },
]

export const OPERATORS: { value: EventFilter['operator']; label: string }[] = [
  { value: 'eq', label: 'equals' },
  { value: 'ne', label: 'not equals' },
  { value: 'contains', label: 'contains' },
  { value: 'gt', label: '>' },
  { value: 'gte', label: '>=' },
  { value: 'lt', label: '<' },
  { value: 'lte', label: '<=' },
]

const OPERATOR_VALUES = OPERATORS.map((o) => o.value)

export interface FilterRow {
  id: number
  field: string
  operator: EventFilter['operator']
  value: string
}

let nextFilterId = 0

export function newFilterRow(partial: Partial<Omit<FilterRow, 'id'>> = {}): FilterRow {
  return { id: ++nextFilterId, field: 'hostname', operator: 'eq', value: '', ...partial }
}

function isNumericField(field: string): boolean {
  return FILTER_FIELDS.some((f) => f.value === field && f.numeric)
}

/** Build the body for POST /events/search (and query-dsl, export) from the form state. */
export function buildSearchRequest(query: string, filters: FilterRow[], timeFrom: string): SearchRequest {
  const cleaned: EventFilter[] = []
  for (const f of filters) {
    const raw = f.value.trim()
    if (!raw) continue
    if (isNumericField(f.field)) {
      const n = Number(raw)
      if (Number.isNaN(n)) continue
      cleaned.push({ field: f.field, operator: f.operator, value: n })
    } else {
      cleaned.push({ field: f.field, operator: f.operator, value: raw })
    }
  }
  return {
    query: query.trim() || undefined,
    filters: cleaned,
    time_from: timeFrom,
    time_to: 'now',
  }
}

/** Turn stored filters (from a saved query) back into editable rows. */
export function toFilterRows(filters: SavedQueryFilter[]): FilterRow[] {
  return filters.map((f) =>
    newFilterRow({
      field: f.field,
      operator: OPERATOR_VALUES.find((o) => o === f.operator) ?? 'eq',
      value: String(f.value ?? ''),
    }),
  )
}

export function histogramInterval(timeFrom: string): AggregationInterval {
  if (timeFrom === 'now-1h') return '1m'
  if (timeFrom === 'now-6h' || timeFrom === 'now-24h') return '1h'
  return '1d'
}

export function timeRangeLabel(timeFrom: string): string {
  return TIME_RANGES.find((t) => t.value === timeFrom)?.label ?? timeFrom
}

/** Event time to the second, in the same form as every other page. */
export function formatDateTime(iso: string | undefined): string {
  return formatDateTimeSeconds(iso)
}

export function formatBucketTime(iso: string, interval: AggregationInterval): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  if (interval === '1d') return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
  return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', hour12: false })
}

/** OCSF severity_id → label and severity class. */
const SEVERITY: Record<number, { label: string; cls: string }> = {
  0: { label: 'Unknown', cls: 'sev-info' },
  1: { label: 'Info', cls: 'sev-info' },
  2: { label: 'Low', cls: 'sev-low' },
  3: { label: 'Medium', cls: 'sev-medium' },
  4: { label: 'High', cls: 'sev-high' },
  5: { label: 'Critical', cls: 'sev-critical' },
  6: { label: 'Fatal', cls: 'sev-critical' },
}

export function severityInfo(id: number | undefined): { label: string; cls: string } | null {
  if (id === undefined || id === null) return null
  return SEVERITY[id] ?? { label: String(id), cls: 'sev-info' }
}

export type EntityType = 'ip' | 'host' | 'user' | 'hash'

export interface EntityRef {
  type: EntityType
  value: string
}

export interface EventEntity extends EntityRef {
  label: string
  /** Filter field that matches this entity on the events endpoint. */
  field: string
}

/** Entities of an event that the entity timeline endpoint can pivot on. */
export function eventEntities(event: EventItem): EventEntity[] {
  const out: EventEntity[] = []
  if (event.hostname) out.push({ type: 'host', value: event.hostname, label: 'Host', field: 'hostname' })
  if (event.username) out.push({ type: 'user', value: event.username, label: 'User', field: 'username' })
  if (event.src_ip) out.push({ type: 'ip', value: event.src_ip, label: 'Source IP', field: 'src_ip' })
  if (event.dst_ip) out.push({ type: 'ip', value: event.dst_ip, label: 'Destination IP', field: 'dst_ip' })
  if (event.process_hash) out.push({ type: 'hash', value: event.process_hash, label: 'Process hash', field: 'process_hash' })
  return out
}

/** Query parameter of /hunt that names the event whose detail is open. */
export const EVENT_PARAM = 'event'

/** Address of Hunt with the detail of one event open. */
export function eventLink(eventId: string): string {
  return `/hunt?${EVENT_PARAM}=${encodeURIComponent(eventId)}`
}
