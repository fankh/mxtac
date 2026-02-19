interface TopBarProps {
  crumb: string
  updatedAt?: string
}

export function TopBar({ crumb, updatedAt }: TopBarProps) {
  return (
    <header className="fixed top-0 left-[52px] right-0 h-[46px] bg-surface border-b border-border flex items-center px-5 z-20">
      <span className="text-text-muted text-[12px]">MxTac</span>
      <span className="text-text-muted text-[12px] mx-1">/</span>
      <span className="text-text-primary text-[12px] font-semibold">{crumb}</span>

      <div className="ml-auto flex items-center gap-2">
        {updatedAt && (
          <span className="text-text-muted text-[11px]">Updated {updatedAt}</span>
        )}
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
