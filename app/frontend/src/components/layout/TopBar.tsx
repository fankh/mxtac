import { useAlertStream } from '../../hooks/useAlertStream'
import type { ConnectionState } from '../../hooks/useAlertStream'
import { useUIStore } from '../../stores/uiStore'

interface TopBarProps {
  crumb: string
  updatedAt?: string
}

function LiveDot({ state }: { state: ConnectionState }) {
  if (state === 'connected') {
    return (
      <span title="Live — connected" className="relative flex h-2 w-2">
        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-status-ok opacity-75" />
        <span className="relative inline-flex rounded-full h-2 w-2 bg-status-ok" />
      </span>
    )
  }
  if (state === 'reconnecting') {
    return (
      <span title="Reconnecting…" className="relative flex h-2 w-2">
        <span className="animate-pulse relative inline-flex rounded-full h-2 w-2 bg-status-warn" />
      </span>
    )
  }
  return (
    <span title="Disconnected" className="relative flex h-2 w-2">
      <span className="relative inline-flex rounded-full h-2 w-2 bg-text-muted" />
    </span>
  )
}

function SunIcon() {
  return (
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <circle cx="12" cy="12" r="5"/>
      <line x1="12" y1="1" x2="12" y2="3"/>
      <line x1="12" y1="21" x2="12" y2="23"/>
      <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/>
      <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/>
      <line x1="1" y1="12" x2="3" y2="12"/>
      <line x1="21" y1="12" x2="23" y2="12"/>
      <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/>
      <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>
    </svg>
  )
}

function MoonIcon() {
  return (
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>
    </svg>
  )
}

export function TopBar({ crumb, updatedAt }: TopBarProps) {
  const connectionState = useAlertStream()
  const { theme, toggleTheme } = useUIStore()

  return (
    <header className="fixed top-0 left-[52px] right-0 h-[46px] bg-surface border-b border-border flex items-center px-5 z-20">
      <span className="text-text-muted text-[12px]">MxTac</span>
      <span className="text-text-muted text-[12px] mx-1">/</span>
      <span className="text-text-primary text-[12px] font-semibold">{crumb}</span>

      <div className="ml-auto flex items-center gap-2">
        <LiveDot state={connectionState} />
        {updatedAt && (
          <span className="text-text-muted text-[11px]">Updated {updatedAt}</span>
        )}
        <button
          className="w-6 h-[22px] rounded-[5px] bg-page flex items-center justify-center text-text-secondary text-[12px] transition-colors hover:text-text-primary"
          title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
          onClick={toggleTheme}
        >
          {theme === 'dark' ? <SunIcon /> : <MoonIcon />}
        </button>
        <button className="w-6 h-[22px] rounded-[5px] bg-page flex items-center justify-center text-text-secondary text-[12px]" title="Refresh">
          ↻
        </button>
        <div className="relative">
          <button className="w-6 h-[22px] rounded-[5px] bg-page flex items-center justify-center text-text-secondary text-[12px]" title="Notifications">
            🔔
          </button>
          <span className="absolute -top-1 -right-1 w-2 h-2 rounded-full bg-crit-text" />
        </div>
      </div>
    </header>
  )
}
