import { ArrowDown, ArrowUp, ArrowUpDown } from 'lucide-react'
import type { Detection, DetectionSortField } from '@/types/api'
import { Button } from '@/components/ui/button'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { LiveBadge } from '@/components/shared/LiveBadge'
import { ScoreCircle, SeverityPill } from '@/components/shared/SeverityBadge'
import { StatusPill } from '@/components/shared/StatusPill'
import { formatDateTime } from './utils'

export type SortOrder = 'asc' | 'desc'

interface DetectionsTableProps {
  detections: Detection[]
  sort: DetectionSortField
  order: SortOrder
  onSort: (field: DetectionSortField) => void
  /** ID of the detection open in the detail panel. */
  activeId: string | null
  onOpen: (detection: Detection) => void
  /** Row checkboxes are shown only when the user may change detections. */
  selectable: boolean
  checkedIds: ReadonlySet<string>
  onToggle: (id: string) => void
  onToggleAll: () => void
  /** IDs that arrived over the alert stream in the last 30 seconds. */
  liveIds: ReadonlySet<string>
}

interface SortHeadProps {
  field: DetectionSortField
  label: string
  sort: DetectionSortField
  order: SortOrder
  onSort: (field: DetectionSortField) => void
  className?: string
}

function SortHead({ field, label, sort, order, onSort, className }: SortHeadProps) {
  const active = sort === field
  const Icon = !active ? ArrowUpDown : order === 'asc' ? ArrowUp : ArrowDown
  return (
    <TableHead
      className={className}
      aria-sort={active ? (order === 'asc' ? 'ascending' : 'descending') : 'none'}
    >
      <Button
        variant="ghost"
        size="sm"
        onClick={() => onSort(field)}
        className={`-ml-2.5 gap-1 text-[11px] font-medium ${active ? 'text-foreground' : 'text-muted-foreground'}`}
      >
        {label}
        <Icon className={`h-3 w-3 ${active ? '' : 'opacity-50'}`} />
      </Button>
    </TableHead>
  )
}

export function DetectionsTable({
  detections,
  sort,
  order,
  onSort,
  activeId,
  onOpen,
  selectable,
  checkedIds,
  onToggle,
  onToggleAll,
  liveIds,
}: DetectionsTableProps) {
  const allChecked = detections.length > 0 && detections.every((d) => checkedIds.has(d.id))
  const someChecked = detections.some((d) => checkedIds.has(d.id))
  const sortProps = { sort, order, onSort }

  return (
    <Table>
      <TableHeader>
        <TableRow className="hover:bg-transparent">
          {selectable && (
            <TableHead className="w-8">
              <input
                type="checkbox"
                aria-label="Select all on this page"
                className="h-3.5 w-3.5 cursor-pointer accent-primary"
                checked={allChecked}
                ref={(el) => {
                  if (el) el.indeterminate = someChecked && !allChecked
                }}
                onChange={onToggleAll}
              />
            </TableHead>
          )}
          <SortHead field="score" label="Score" className="w-16" {...sortProps} />
          <TableHead>Detection</TableHead>
          <SortHead field="severity" label="Severity" {...sortProps} />
          <TableHead>Technique</TableHead>
          <SortHead field="tactic" label="Tactic" {...sortProps} />
          <SortHead field="host" label="Host" {...sortProps} />
          <TableHead>Status</TableHead>
          <SortHead field="time" label="Time" {...sortProps} />
        </TableRow>
      </TableHeader>
      <TableBody>
        {detections.map((d) => (
          <TableRow
            key={d.id}
            tabIndex={0}
            data-state={activeId === d.id ? 'selected' : undefined}
            onClick={() => onOpen(d)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && e.target === e.currentTarget) onOpen(d)
            }}
            className="cursor-pointer text-[12px] focus-visible:bg-muted/50 focus-visible:outline-none"
          >
            {selectable && (
              <TableCell onClick={(e) => e.stopPropagation()}>
                <input
                  type="checkbox"
                  aria-label={`Select ${d.name}`}
                  className="h-3.5 w-3.5 cursor-pointer accent-primary"
                  checked={checkedIds.has(d.id)}
                  onChange={() => onToggle(d.id)}
                />
              </TableCell>
            )}
            <TableCell>
              <ScoreCircle score={d.score} severity={d.severity} />
            </TableCell>
            <TableCell className="max-w-[320px]">
              <div className="flex min-w-0 items-center gap-1.5">
                <span className="truncate font-medium text-foreground">{d.name}</span>
                {liveIds.has(d.id) && <LiveBadge />}
              </div>
              {d.rule_name && (
                <div className="truncate text-[11px] text-muted-foreground">{d.rule_name}</div>
              )}
            </TableCell>
            <TableCell>
              <SeverityPill severity={d.severity} />
            </TableCell>
            <TableCell className="max-w-[200px]">
              <div className="font-mono text-foreground">{d.technique_id}</div>
              <div className="truncate text-[11px] text-muted-foreground">{d.technique_name}</div>
            </TableCell>
            <TableCell className="text-muted-foreground">{d.tactic}</TableCell>
            <TableCell className="max-w-[160px] truncate">{d.host}</TableCell>
            <TableCell>
              <StatusPill status={d.status} />
            </TableCell>
            <TableCell className="whitespace-nowrap text-muted-foreground">{formatDateTime(d.time)}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )
}
