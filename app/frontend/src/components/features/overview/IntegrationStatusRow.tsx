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
    <div className="bg-surface rounded-md shadow-card p-4">
      <div className="mb-3">
        <h3 className="text-[12px] font-semibold text-text-primary">Integration Status</h3>
        <p className="text-[11px] text-text-muted">Connected data sources</p>
      </div>
      <div className="flex flex-wrap gap-2">
        {data.map((item) => (
          <div
            key={item.name}
            className="flex items-center gap-[6px] px-3 py-[5px] rounded-md border border-border bg-page"
          >
            <span className={`w-[6px] h-[6px] rounded-full shrink-0 ${STATUS_DOT[item.status] ?? 'bg-border'}`} />
            <span className="text-[11px] text-text-primary font-medium">{item.name}</span>
            {item.message && (
              <span className="text-[10px] text-text-muted">— {item.message}</span>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
