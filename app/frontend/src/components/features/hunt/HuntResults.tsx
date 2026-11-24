import { useState } from 'react'
import { Check, ChevronLeft, ChevronRight, Copy, RefreshCw, SearchX } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { EmptyState } from '@/components/ui/empty-state'
import { TableSkeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { cn } from '@/lib/utils'
import type { EventItem, SearchResponse } from '@/types/api'
import { PAGE_SIZE, formatDateTime, severityInfo } from './huntUtils'

interface Props {
  data: SearchResponse | undefined
  loading: boolean
  error: boolean
  /** Reason the search failed, when the server gave one (for example the rate limit). */
  errorMessage?: string
  onRetry: () => void
  page: number
  onPageChange: (page: number) => void
  onSelect: (event: EventItem) => void
  /** Lucene form of the search, from POST /events/query-dsl. */
  lucene: string | undefined
}

function LuceneBar({ lucene }: { lucene: string }) {
  const [copied, setCopied] = useState(false)

  async function copy() {
    try {
      await navigator.clipboard.writeText(lucene)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      setCopied(false)
    }
  }

  return (
    <div className="flex items-center gap-2 border-b border-border bg-muted/40 px-4 py-2">
      <span className="shrink-0 text-[11px] font-medium text-muted-foreground">Lucene</span>
      <code className="min-w-0 flex-1 truncate font-mono text-[11px] text-foreground" title={lucene} data-testid="lucene-query">
        {lucene}
      </code>
      <Button variant="ghost" size="icon" title="Copy Lucene query" onClick={copy} className="h-6 w-6 text-muted-foreground">
        {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
      </Button>
    </div>
  )
}

export function HuntResults({ data, loading, error, errorMessage, onRetry, page, onPageChange, onSelect, lucene }: Props) {
  const total = data?.total ?? 0
  const items = data?.items ?? []
  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE))
  const first = total === 0 ? 0 : page * PAGE_SIZE + 1
  const last = Math.min(total, page * PAGE_SIZE + items.length)

  return (
    <Card className="overflow-hidden">
      <div className="flex items-center justify-between gap-2 border-b border-border px-4 py-3">
        <h3 className="text-[12px] font-semibold">Results</h3>
        {data && (
          <span className="text-[11px] text-muted-foreground">
            {total.toLocaleString()} {total === 1 ? 'event' : 'events'} · {data.backend === 'opensearch' ? 'OpenSearch' : 'PostgreSQL'}
          </span>
        )}
      </div>
      {lucene && <LuceneBar lucene={lucene} />}

      {loading ? (
        <CardContent className="p-4"><TableSkeleton rows={6} cols={6} /></CardContent>
      ) : error ? (
        <CardContent className="flex flex-col items-center gap-2 p-8 text-center">
          <p className="text-[12px] text-destructive">
            {errorMessage ? `The search failed: ${errorMessage}` : 'The search failed. Check the query syntax and try again.'}
          </p>
          <Button variant="outline" size="sm" onClick={onRetry}>
            <RefreshCw className="mr-1 h-3 w-3" />
            Retry
          </Button>
        </CardContent>
      ) : items.length === 0 ? (
        <EmptyState icon={SearchX} title="No events match this search" description="Widen the time range or remove a filter." />
      ) : (
        <>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Time</TableHead>
                <TableHead>Severity</TableHead>
                <TableHead>Class</TableHead>
                <TableHead>Host</TableHead>
                <TableHead>User</TableHead>
                <TableHead>Source IP</TableHead>
                <TableHead>Destination IP</TableHead>
                <TableHead>Source</TableHead>
                <TableHead>Summary</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((e) => {
                const sev = severityInfo(e.severity_id)
                return (
                  <TableRow
                    key={e.id}
                    tabIndex={0}
                    onClick={() => onSelect(e)}
                    onKeyDown={(ev) => { if (ev.key === 'Enter') onSelect(e) }}
                    className="cursor-pointer transition-colors hover:bg-muted/50"
                  >
                    <TableCell className="whitespace-nowrap py-2 text-[12px] tabular-nums">{formatDateTime(e.time)}</TableCell>
                    <TableCell className="py-2 text-[12px]">
                      {sev ? (
                        <span className={cn('inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-medium leading-none', sev.cls)}>
                          {sev.label}
                        </span>
                      ) : '-'}
                    </TableCell>
                    <TableCell className="py-2 text-[12px]">{e.class_name ?? '-'}</TableCell>
                    <TableCell className="py-2 text-[12px]">{e.hostname ?? '-'}</TableCell>
                    <TableCell className="py-2 text-[12px]">{e.username ?? '-'}</TableCell>
                    <TableCell className="py-2 font-mono text-[12px]">{e.src_ip ?? '-'}</TableCell>
                    <TableCell className="py-2 font-mono text-[12px]">{e.dst_ip ?? '-'}</TableCell>
                    <TableCell className="py-2 text-[12px]">{e.source ?? '-'}</TableCell>
                    <TableCell className="max-w-[380px] truncate py-2 text-[12px] text-muted-foreground" title={e.summary ?? undefined}>
                      {e.summary ?? '-'}
                    </TableCell>
                  </TableRow>
                )
              })}
            </TableBody>
          </Table>
          <div className="flex items-center justify-between border-t border-border px-4 py-2">
            <span className="text-[11px] text-muted-foreground">
              {first.toLocaleString()}-{last.toLocaleString()} of {total.toLocaleString()}
            </span>
            <div className="flex items-center gap-1">
              <Button variant="outline" size="icon" title="Previous page" disabled={page === 0} onClick={() => onPageChange(page - 1)}>
                <ChevronLeft className="h-3.5 w-3.5" />
              </Button>
              <span className="px-2 text-[11px] tabular-nums text-muted-foreground">Page {page + 1} of {pageCount}</span>
              <Button variant="outline" size="icon" title="Next page" disabled={page + 1 >= pageCount} onClick={() => onPageChange(page + 1)}>
                <ChevronRight className="h-3.5 w-3.5" />
              </Button>
            </div>
          </div>
        </>
      )}
    </Card>
  )
}
