import type { ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import { RefreshCw } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '@/components/ui/sheet'
import { Skeleton } from '@/components/ui/skeleton'
import { connectorsApi } from '@/lib/api'
import { cn, fmtNum } from '@/lib/utils'
import type { Connector } from '@/types/api'
import { connectorStatus, connectorTypeInfo, formatLastSeen } from './connectorTypes'

interface ConnectorDetailSheetProps {
  connector: Connector | null
  onClose: () => void
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-4 py-2">
      <dt className="text-[11px] text-muted-foreground">{label}</dt>
      <dd className="text-right text-[12px] text-foreground">{children}</dd>
    </div>
  )
}

/** Right-side panel with the live health of one source (GET /connectors/{id}/health). */
export function ConnectorDetailSheet({ connector, onClose }: ConnectorDetailSheetProps) {
  const id = connector?.id
  const health = useQuery({
    queryKey: ['connector-health', id],
    queryFn: () => connectorsApi.health(id ?? ''),
    enabled: id !== undefined,
    refetchInterval: 15_000,
  })

  const info = connector ? connectorTypeInfo(connector.connector_type) : undefined
  const data = health.data
  const status = data ? connectorStatus(data.status) : undefined

  return (
    <Sheet open={connector !== null} onOpenChange={(next) => { if (!next) onClose() }}>
      <SheetContent className="w-full overflow-y-auto sm:max-w-md">
        <SheetHeader>
          <SheetTitle className="text-[13px]">{connector?.name ?? 'Source'}</SheetTitle>
          <SheetDescription>{info?.description ?? connector?.connector_type}</SheetDescription>
        </SheetHeader>

        <div className="mt-4">
          {health.isLoading && (
            <div className="space-y-3" aria-label="Loading health">
              <Skeleton className="h-4 w-2/3" />
              <Skeleton className="h-4 w-1/2" />
              <Skeleton className="h-4 w-3/4" />
            </div>
          )}

          {health.isError && (
            <div className="space-y-2 rounded-lg border sev-critical p-3">
              <p className="text-[12px]">Could not load the health of this source.</p>
              <Button variant="outline" size="sm" className="gap-1.5" onClick={() => health.refetch()}>
                <RefreshCw className="h-3 w-3" />
                Retry
              </Button>
            </div>
          )}

          {data && status && (
            <dl className="divide-y divide-border">
              <Row label="Health">
                <span className={cn('inline-flex rounded-full border px-2 py-0.5 text-[10px] font-medium', data.healthy ? 'status-green' : 'sev-high')}>
                  {data.healthy ? 'Healthy' : 'Not healthy'}
                </span>
              </Row>
              <Row label="Status">
                <span className={cn('inline-flex rounded-full border px-2 py-0.5 text-[10px] font-medium', status.cls)}>
                  {status.label}
                </span>
              </Row>
              <Row label="Type">{info?.label ?? data.connector_type}</Row>
              <Row label="Enabled">{data.enabled ? 'Yes' : 'No'}</Row>
              <Row label="Events received">{fmtNum(data.events_total)}</Row>
              <Row label="Errors">{fmtNum(data.errors_total)}</Row>
              <Row label="Last seen">{formatLastSeen(data.last_seen_at)}</Row>
              <Row label="Source ID"><span className="font-mono text-[11px]">{data.id}</span></Row>
              {data.error_message && (
                <div className="py-2">
                  <dt className="text-[11px] text-muted-foreground">Last error</dt>
                  <dd className="mt-1 break-words rounded-md border sev-critical px-2 py-1.5 text-[11px]">{data.error_message}</dd>
                </div>
              )}
            </dl>
          )}
        </div>
      </SheetContent>
    </Sheet>
  )
}
