import type { ReactNode } from 'react'
import { useAlertStream } from '../../hooks/useAlertStream'
import type { ConnectionState } from '../../hooks/useAlertStream'
import { cn } from '@/lib/utils'

interface TopBarProps {
  crumb: string
  updatedAt?: string
  /** Optional one-line description shown after the title. */
  description?: string
  /** Buttons or filters on the right side of the bar. */
  actions?: ReactNode
}

const LIVE: Record<ConnectionState, { label: string; dot: string; ping: boolean }> = {
  connected: { label: 'Live', dot: 'bg-emerald-500', ping: true },
  reconnecting: { label: 'Reconnecting', dot: 'bg-amber-500 animate-pulse', ping: false },
  disconnected: { label: 'Offline', dot: 'bg-muted-foreground/50', ping: false },
}

function LiveDot({ state }: { state: ConnectionState }) {
  const s = LIVE[state] ?? LIVE.disconnected
  return (
    <span title={`Alert stream: ${s.label.toLowerCase()}`} className="flex shrink-0 items-center gap-1.5 whitespace-nowrap text-[11px] text-muted-foreground">
      <span className="relative flex h-2 w-2">
        {s.ping && <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-500 opacity-75" />}
        <span className={`relative inline-flex h-2 w-2 rounded-full ${s.dot}`} />
      </span>
      {s.label}
    </span>
  )
}

/**
 * Sticky page header bar, at least 46px tall.
 *
 * From `md` up it is one row: title, description, actions, alert-stream state. The
 * description shows from `lg` and truncates, so it gives way first. Below `md` the left end
 * is kept free for the navigation menu button (see Sidebar) and the actions move to a
 * second row, where they wrap.
 */
export function TopBar({ crumb, updatedAt, description, actions }: TopBarProps) {
  const connectionState = useAlertStream()

  return (
    <header className="sticky top-0 z-20 flex min-h-[46px] flex-wrap items-center gap-x-3 gap-y-2 border-b border-border bg-background/95 py-2 pl-[52px] pr-4 backdrop-blur md:px-5">
      <h1 className="flex min-h-[30px] min-w-0 items-center break-words text-[13px] font-semibold text-foreground">{crumb}</h1>
      {description && (
        <>
          <span aria-hidden="true" className="hidden text-muted-foreground/40 lg:inline">·</span>
          <p className="hidden min-w-0 flex-1 basis-0 truncate text-[12px] text-muted-foreground lg:block">{description}</p>
        </>
      )}
      <div className={cn('ml-auto flex shrink-0 items-center gap-3 md:order-last', actions && 'md:ml-0')}>
        {updatedAt && <span className="whitespace-nowrap text-[11px] text-muted-foreground">Updated {updatedAt}</span>}
        <LiveDot state={connectionState} />
      </div>
      {actions && (
        <div className="-ml-[36px] flex w-[calc(100%+36px)] min-w-0 flex-wrap items-center gap-2 md:ml-auto md:w-auto md:max-w-full md:justify-end md:gap-3">
          {actions}
        </div>
      )}
    </header>
  )
}
