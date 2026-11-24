import type { ReactNode } from 'react'
import { useAlertStream } from '../../hooks/useAlertStream'
import type { ConnectionState } from '../../hooks/useAlertStream'

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
    <span title={`Alert stream: ${s.label.toLowerCase()}`} className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
      <span className="relative flex h-2 w-2">
        {s.ping && <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-500 opacity-75" />}
        <span className={`relative inline-flex h-2 w-2 rounded-full ${s.dot}`} />
      </span>
      {s.label}
    </span>
  )
}

/**
 * Page header bar. It is sticky and 46px tall with a matching negative margin, so page
 * content keeps its own `pt-[46px]` offset.
 */
export function TopBar({ crumb, updatedAt, description, actions }: TopBarProps) {
  const connectionState = useAlertStream()

  return (
    <header className="sticky top-0 z-20 -mb-[46px] flex h-[46px] items-center gap-3 border-b border-border bg-background/95 px-5 backdrop-blur">
      <h1 className="text-[13px] font-semibold text-foreground">{crumb}</h1>
      {description && (
        <>
          <span className="text-muted-foreground/40">·</span>
          <p className="truncate text-[12px] text-muted-foreground">{description}</p>
        </>
      )}
      <div className="ml-auto flex items-center gap-3">
        {actions}
        {updatedAt && <span className="text-[11px] text-muted-foreground">Updated {updatedAt}</span>}
        <LiveDot state={connectionState} />
      </div>
    </header>
  )
}
