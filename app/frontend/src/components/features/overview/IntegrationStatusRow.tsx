import type { IntegrationStatus } from '../../../types/api'

interface Props { data: IntegrationStatus[] }

const STATUS_DOT: Record<string, string> = {
  ok:       'bg-status-ok',
  warning:  'bg-status-warn',
  error:    'bg-crit-text',
  inactive: 'bg-border',
}

export function IntegrationStatusRow({ data }: Props) {
  return (
    <div className="bg-card rounded-md border shadow-sm p-4">
      <div className="mb-3">
        <h3 className="text-[12px] font-semibold text-foreground">Integration Status</h3>
        <p className="text-[11px] text-muted-foreground">Connected data sources</p>
      </div>
      <div className="flex flex-wrap gap-2">
        {data.map((item) => (
          <div
            key={item.name}
            className="flex items-center gap-[6px] px-3 py-[5px] rounded-md border border-border bg-background"
          >
            <span className={`w-[6px] h-[6px] rounded-full shrink-0 ${STATUS_DOT[item.status] ?? 'bg-border'}`} />
            <span className="text-[11px] text-foreground font-medium">{item.name}</span>
            {item.message && (
              <span className="text-[10px] text-muted-foreground">— {item.message}</span>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
