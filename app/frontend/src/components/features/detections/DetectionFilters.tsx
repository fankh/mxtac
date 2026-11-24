import { X } from 'lucide-react'
import type { DetectionStatus, SeverityLevel } from '@/types/api'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { FilterChip, FilterGroup, SearchInput } from './ListControls'
import {
  DETECTION_STATUS_LABELS,
  DETECTION_STATUS_OPTIONS,
  SEVERITY_LABELS,
  SEVERITY_OPTIONS,
} from './utils'

export interface DetectionFilterState {
  search: string
  severities: SeverityLevel[]
  statuses: DetectionStatus[]
  tactic: string
  host: string
}

export const EMPTY_DETECTION_FILTERS: DetectionFilterState = {
  search: '',
  severities: [],
  statuses: [],
  tactic: '',
  host: '',
}

export function countActiveFilters(filters: DetectionFilterState): number {
  return (
    filters.severities.length +
    filters.statuses.length +
    (filters.search.trim() ? 1 : 0) +
    (filters.tactic.trim() ? 1 : 0) +
    (filters.host.trim() ? 1 : 0)
  )
}

function toggle<T>(list: T[], item: T): T[] {
  return list.includes(item) ? list.filter((entry) => entry !== item) : [...list, item]
}

interface DetectionFiltersProps {
  filters: DetectionFilterState
  onChange: (patch: Partial<DetectionFilterState>) => void
  onReset: () => void
}

/** Filter bar for GET /detections: search, severity, status, tactic and host. */
export function DetectionFilters({ filters, onChange, onReset }: DetectionFiltersProps) {
  const active = countActiveFilters(filters)
  return (
    <Card>
      <CardContent className="space-y-3 p-4">
        <div className="flex flex-wrap items-center gap-2">
          <SearchInput
            value={filters.search}
            onChange={(search) => onChange({ search })}
            placeholder="Search name, description, technique or host"
            label="Search detections"
            className="sm:w-80"
          />
          <SearchInput
            value={filters.tactic}
            onChange={(tactic) => onChange({ tactic })}
            placeholder="Tactic contains"
            label="Tactic filter"
            icon={false}
            className="sm:w-44"
          />
          <SearchInput
            value={filters.host}
            onChange={(host) => onChange({ host })}
            placeholder="Host contains"
            label="Host filter"
            icon={false}
            className="sm:w-44"
          />
          {active > 0 && (
            <Button variant="ghost" onClick={onReset} className="ml-auto gap-1 text-muted-foreground">
              <X className="h-3.5 w-3.5" />
              Clear filters ({active})
            </Button>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
          <FilterGroup label="Severity">
            {SEVERITY_OPTIONS.map((severity) => (
              <FilterChip
                key={severity}
                label={SEVERITY_LABELS[severity]}
                active={filters.severities.includes(severity)}
                onClick={() => onChange({ severities: toggle(filters.severities, severity) })}
              />
            ))}
          </FilterGroup>
          <FilterGroup label="Status">
            {DETECTION_STATUS_OPTIONS.map((status) => (
              <FilterChip
                key={status}
                label={DETECTION_STATUS_LABELS[status]}
                active={filters.statuses.includes(status)}
                onClick={() => onChange({ statuses: toggle(filters.statuses, status) })}
              />
            ))}
          </FilterGroup>
        </div>
      </CardContent>
    </Card>
  )
}
