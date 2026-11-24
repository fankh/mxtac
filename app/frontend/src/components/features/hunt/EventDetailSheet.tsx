import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Check, ChevronLeft, Copy, Filter, History, RefreshCw } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { EmptyState } from '@/components/ui/empty-state'
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '@/components/ui/sheet'
import { Skeleton } from '@/components/ui/skeleton'
import { eventsApi } from '@/lib/api'
import { cn } from '@/lib/utils'
import type { EventItem } from '@/types/api'
import { eventEntities, formatDateTime, severityInfo, timeRangeLabel, type EntityRef } from './huntUtils'

type AddFilter = (field: string, value: string) => void

interface Props {
  /** Event row that was clicked; null closes the sheet. */
  event: EventItem | null
  timeFrom: string
  onClose: () => void
  onAddFilter: AddFilter
}

function CopyButton({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false)

  async function copy() {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      setCopied(false)
    }
  }

  return (
    <Button variant="ghost" size="icon" title={`Copy ${label}`} onClick={copy} className="h-6 w-6 text-muted-foreground">
      {copied ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
    </Button>
  )
}

function EventDetail({
  row, onPivot, onAddFilter,
}: {
  row: EventItem
  onPivot: (entity: EntityRef) => void
  onAddFilter: AddFilter
}) {
  // The search row already holds the event; GET /events/{id} refreshes it from the
  // authoritative store. Events that only exist in OpenSearch return 404, so keep the row.
  const { data } = useQuery({
    queryKey: ['hunt', 'event', row.id],
    queryFn: () => eventsApi.get(row.id),
    retry: false,
  })
  const event = data ?? row
  const sev = severityInfo(event.severity_id)
  const entities = eventEntities(event)
  const raw = JSON.stringify(event, null, 2)

  return (
    <div className="space-y-4">
      <SheetHeader className="space-y-1 pr-6">
        <SheetTitle className="text-[13px]">{event.class_name ?? 'Event'}</SheetTitle>
        <SheetDescription>
          {formatDateTime(event.time)}{event.source ? ` · ${event.source}` : ''}
        </SheetDescription>
      </SheetHeader>

      <div className="flex flex-wrap items-center gap-2">
        {sev && (
          <span className={cn('inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-medium leading-none', sev.cls)}>
            {sev.label}
          </span>
        )}
        <span className="font-mono text-[11px] text-muted-foreground">{event.id}</span>
        <CopyButton value={event.id} label="event ID" />
      </div>

      {event.summary && <p className="text-[12px] text-foreground">{event.summary}</p>}

      <section className="space-y-2">
        <h4 className="text-[12px] font-semibold">Entities</h4>
        {entities.length === 0 ? (
          <p className="text-[11px] text-muted-foreground">This event has no host, user, IP or hash.</p>
        ) : (
          <ul className="divide-y divide-border rounded-lg border border-border">
            {entities.map((en) => (
              <li key={`${en.field}:${en.value}`} className="flex items-center gap-2 px-3 py-1.5">
                <span className="w-[96px] shrink-0 text-[11px] text-muted-foreground">{en.label}</span>
                <span className="min-w-0 flex-1 truncate font-mono text-[12px]" title={en.value}>{en.value}</span>
                <CopyButton value={en.value} label={en.label.toLowerCase()} />
                <Button
                  variant="ghost"
                  size="icon"
                  title={`Filter by ${en.label.toLowerCase()}`}
                  onClick={() => onAddFilter(en.field, en.value)}
                  className="h-6 w-6 text-muted-foreground"
                >
                  <Filter className="h-3 w-3" />
                </Button>
                <Button
                  variant="ghost"
                  size="icon"
                  title={`Show timeline for ${en.label.toLowerCase()}`}
                  onClick={() => onPivot({ type: en.type, value: en.value })}
                  className="h-6 w-6 text-muted-foreground"
                >
                  <History className="h-3 w-3" />
                </Button>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="space-y-2">
        <div className="flex items-center justify-between">
          <h4 className="text-[12px] font-semibold">Raw event</h4>
          <CopyButton value={raw} label="raw event" />
        </div>
        <pre className="max-h-[420px] overflow-auto rounded-lg border border-border bg-muted/40 p-3 font-mono text-[11px] leading-relaxed text-foreground">
          {raw}
        </pre>
      </section>
    </div>
  )
}

function EntityTimelineView({
  entity, timeFrom, onBack, onOpenEvent,
}: {
  entity: EntityRef
  timeFrom: string
  onBack: () => void
  onOpenEvent: (event: EventItem) => void
}) {
  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['hunt', 'entity', entity.type, entity.value, timeFrom],
    queryFn: () => eventsApi.entity(entity.type, entity.value, timeFrom),
  })

  return (
    <div className="space-y-4">
      <Button variant="ghost" size="sm" onClick={onBack} className="-ml-2">
        <ChevronLeft className="mr-1 h-3 w-3" />
        Back to event
      </Button>
      <SheetHeader className="space-y-1 pr-6">
        <SheetTitle className="break-all font-mono text-[13px]">{entity.value}</SheetTitle>
        <SheetDescription>
          Events for this {entity.type}, {timeRangeLabel(timeFrom).toLowerCase()}
          {data ? ` · ${data.total.toLocaleString()} total` : ''}
        </SheetDescription>
      </SheetHeader>

      {isLoading ? (
        <div className="space-y-2">
          {[0, 1, 2, 3, 4].map((i) => <Skeleton key={i} className="h-10 w-full" />)}
        </div>
      ) : isError ? (
        <div className="flex flex-col items-center gap-2 rounded-lg border border-border p-6 text-center">
          <p className="text-[12px] text-destructive">Could not load the entity timeline.</p>
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="mr-1 h-3 w-3" />
            Retry
          </Button>
        </div>
      ) : !data || data.events.length === 0 ? (
        <EmptyState icon={History} title="No events for this entity" />
      ) : (
        <>
          <ul className="divide-y divide-border rounded-lg border border-border">
            {data.events.map((e) => (
              <li key={e.id}>
                <Button
                  variant="ghost"
                  onClick={() => onOpenEvent(e)}
                  className="h-auto w-full flex-col items-start gap-0.5 rounded-none px-3 py-2 text-left font-normal"
                >
                  <span className="flex w-full items-center justify-between gap-2">
                    <span className="truncate text-[12px] font-medium text-foreground">{e.class_name ?? 'Event'}</span>
                    <span className="shrink-0 text-[11px] tabular-nums text-muted-foreground">{formatDateTime(e.time)}</span>
                  </span>
                  {e.summary && <span className="w-full truncate text-[11px] text-muted-foreground">{e.summary}</span>}
                </Button>
              </li>
            ))}
          </ul>
          {data.total > data.events.length && (
            <p className="text-[11px] text-muted-foreground">
              Showing the {data.events.length.toLocaleString()} most recent of {data.total.toLocaleString()} events.
            </p>
          )}
        </>
      )}
    </div>
  )
}

function SheetBody({ event, timeFrom, onAddFilter }: { event: EventItem; timeFrom: string; onAddFilter: AddFilter }) {
  const [current, setCurrent] = useState(event)
  const [entity, setEntity] = useState<EntityRef | null>(null)

  if (entity) {
    return (
      <EntityTimelineView
        entity={entity}
        timeFrom={timeFrom}
        onBack={() => setEntity(null)}
        onOpenEvent={(e) => { setCurrent(e); setEntity(null) }}
      />
    )
  }
  return <EventDetail row={current} onPivot={setEntity} onAddFilter={onAddFilter} />
}

/** Right-side panel with one event's detail and, from there, an entity's timeline. */
export function EventDetailSheet({ event, timeFrom, onClose, onAddFilter }: Props) {
  return (
    <Sheet open={event !== null} onOpenChange={(open) => { if (!open) onClose() }}>
      <SheetContent className="w-full overflow-y-auto p-4 sm:max-w-xl">
        {event && <SheetBody key={event.id} event={event} timeFrom={timeFrom} onAddFilter={onAddFilter} />}
      </SheetContent>
    </Sheet>
  )
}
