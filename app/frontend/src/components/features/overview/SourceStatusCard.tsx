import { Link } from 'react-router-dom'
import { Plug } from 'lucide-react'
import type { IntegrationStatus } from '../../../types/api'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { EmptyState } from '@/components/ui/empty-state'
import { cn } from '@/lib/utils'

const DOT: Record<IntegrationStatus['status'], string> = {
  connected: 'bg-status-ok',
  warning: 'bg-status-warn',
  disabled: 'bg-muted-foreground/40',
}

const STATUS_LABEL: Record<IntegrationStatus['status'], string> = {
  connected: 'Connected',
  warning: 'Warning',
  disabled: 'Disabled',
}

export function SourceStatusCard({ data }: { data: IntegrationStatus[] }) {
  return (
    <Card>
      <CardContent className="p-4">
        <div className="mb-3 flex items-start justify-between gap-3">
          <div>
            <h3 className="text-[12px] font-semibold">Data sources</h3>
            <p className="text-[11px] text-muted-foreground">Connector health</p>
          </div>
          <Link to="/sources" className="shrink-0 text-[11px] text-primary transition-colors hover:underline">
            Manage
          </Link>
        </div>
        {data.length === 0 ? (
          <EmptyState
            icon={Plug}
            title="No data sources connected"
            description="Connect Wazuh, Zeek, Suricata or a syslog feed to start detecting."
            action={<Button asChild size="sm"><Link to="/sources">Add a source</Link></Button>}
          />
        ) : (
          <ul className="divide-y divide-border">
            {data.map((item) => (
              <li key={item.id} className="flex items-center gap-2.5 py-2" title={item.detail ?? undefined}>
                <span
                  role="img"
                  aria-label={STATUS_LABEL[item.status] ?? STATUS_LABEL.disabled}
                  title={STATUS_LABEL[item.status] ?? STATUS_LABEL.disabled}
                  className={cn('h-2 w-2 shrink-0 rounded-full', DOT[item.status] ?? DOT.disabled)}
                />
                <span className="min-w-0 flex-1 truncate text-[12px] font-medium">{item.name}</span>
                <span className="max-w-[55%] truncate text-[11px] text-muted-foreground">{item.metric}</span>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  )
}
