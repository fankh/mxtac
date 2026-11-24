import { Plus, Search, Trash2, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { FILTER_FIELDS, OPERATORS, TIME_RANGES, newFilterRow, type FilterRow } from './huntUtils'

interface Props {
  query: string
  onQueryChange: (q: string) => void
  timeFrom: string
  onTimeFromChange: (t: string) => void
  filters: FilterRow[]
  onFiltersChange: (f: FilterRow[]) => void
  onSearch: () => void
  searching: boolean
}

export function HuntSearchForm({
  query, onQueryChange, timeFrom, onTimeFromChange, filters, onFiltersChange, onSearch, searching,
}: Props) {
  // A saved query can carry a time range that is not one of the presets.
  const ranges = TIME_RANGES.some((t) => t.value === timeFrom)
    ? TIME_RANGES
    : [...TIME_RANGES, { value: timeFrom, label: timeFrom }]

  function updateFilter(id: number, patch: Partial<FilterRow>) {
    onFiltersChange(filters.map((f) => (f.id === id ? { ...f, ...patch } : f)))
  }

  return (
    <Card>
      <CardContent className="space-y-3 p-4">
        <form
          className="flex flex-wrap items-center gap-2"
          onSubmit={(e) => { e.preventDefault(); onSearch() }}
        >
          <div className="relative min-w-[240px] flex-1">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={query}
              onChange={(e) => onQueryChange(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Escape') onQueryChange('') }}
              placeholder="Search events, for example powershell or 10.0.0.5"
              aria-label="Search query"
              maxLength={2048}
              className="h-8 px-8 text-[12px]"
            />
            {query && (
              <Button
                type="button"
                variant="ghost"
                size="icon"
                title="Clear search"
                onClick={() => onQueryChange('')}
                className="absolute right-1 top-1/2 h-6 w-6 -translate-y-1/2 text-muted-foreground"
              >
                <X className="h-3.5 w-3.5" />
              </Button>
            )}
          </div>
          <Select value={timeFrom} onValueChange={onTimeFromChange}>
            <SelectTrigger className="h-8 w-[140px]" aria-label="Time range">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {ranges.map((t) => (
                <SelectItem key={t.value} value={t.value}>{t.label}</SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button
            type="button"
            variant="outline"
            className="h-8"
            onClick={() => onFiltersChange([...filters, newFilterRow()])}
            disabled={filters.length >= 50}
          >
            <Plus className="mr-1 h-3.5 w-3.5" />
            Add filter
          </Button>
          <Button type="submit" className="h-8" disabled={searching}>
            <Search className="mr-1 h-3.5 w-3.5" />
            {searching ? 'Searching…' : 'Search'}
          </Button>
        </form>

        {filters.length > 0 && (
          <div className="space-y-2">
            {filters.map((f) => (
              <div key={f.id} className="flex flex-wrap items-center gap-2" data-testid="filter-row">
                <Select value={f.field} onValueChange={(v) => updateFilter(f.id, { field: v })}>
                  <SelectTrigger className="w-[150px]" aria-label="Filter field">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {FILTER_FIELDS.map((o) => (
                      <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Select
                  value={f.operator}
                  onValueChange={(v) => updateFilter(f.id, { operator: OPERATORS.find((o) => o.value === v)?.value ?? 'eq' })}
                >
                  <SelectTrigger className="w-[120px]" aria-label="Filter operator">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {OPERATORS.map((o) => (
                      <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Input
                  value={f.value}
                  onChange={(e) => updateFilter(f.id, { value: e.target.value })}
                  onKeyDown={(e) => { if (e.key === 'Enter') onSearch() }}
                  placeholder="Value"
                  aria-label="Filter value"
                  className="min-w-[160px] flex-1"
                />
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  title="Remove filter"
                  onClick={() => onFiltersChange(filters.filter((x) => x.id !== f.id))}
                  className="text-muted-foreground"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </Button>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  )
}
