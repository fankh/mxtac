import { useState, type ComponentType } from 'react'
import { NavLink } from 'react-router-dom'
import {
  Activity, AlertTriangle, ChevronsLeft, ChevronsRight, Crosshair, ExternalLink, FileCode2, HelpCircle,
  LayoutDashboard, LogOut, Moon, Plug, Search, Settings, ShieldCheck, Sun, type LucideProps,
} from 'lucide-react'
import { useUIStore } from '../../stores/uiStore'
import { useAuthStore } from '../../stores/authStore'
import { MfaSetupModal } from '../shared/MfaSetupModal'
import { KYRA_MDR_URL } from '@/lib/links'
import { cn } from '@/lib/utils'

type NavItem = { to: string; Icon: ComponentType<LucideProps>; label: string }

const NAV_SECTIONS: { title: string; items: NavItem[] }[] = [
  {
    title: 'Monitor',
    items: [
      { to: '/', Icon: LayoutDashboard, label: 'Overview' },
      { to: '/detections', Icon: AlertTriangle, label: 'Detections' },
      { to: '/incidents', Icon: Activity, label: 'Incidents' },
    ],
  },
  {
    title: 'Investigate',
    items: [
      { to: '/hunt', Icon: Search, label: 'Hunt' },
      { to: '/coverage', Icon: Crosshair, label: 'ATT&CK Coverage' },
    ],
  },
  {
    title: 'Configure',
    items: [
      { to: '/rules', Icon: FileCode2, label: 'Sigma Rules' },
      { to: '/sources', Icon: Plug, label: 'Sources' },
      { to: '/settings', Icon: Settings, label: 'Settings' },
    ],
  },
]

const iconButton =
  'flex h-8 w-8 items-center justify-center rounded-md text-[var(--sidebar-text)] transition-colors hover:bg-[var(--sidebar-hover)] hover:text-[var(--sidebar-text-active)]'

export function Sidebar() {
  const { sidebarCollapsed, toggleSidebar, theme, toggleTheme, openShortcutsModal } = useUIStore()
  const user = useAuthStore((s) => s.user)
  const logout = useAuthStore((s) => s.logout)
  const [showMfaModal, setShowMfaModal] = useState(false)
  const expanded = !sidebarCollapsed
  const initials = user?.email ? user.email.split('@')[0].slice(0, 2).toUpperCase() : '··'

  return (
    <aside
      aria-label="Main navigation"
      className={cn(
        'flex h-full shrink-0 flex-col border-r transition-[width] duration-200',
        expanded ? 'w-[220px]' : 'w-[56px]',
      )}
      style={{ background: 'var(--sidebar-bg)', borderColor: 'var(--sidebar-border)' }}
    >
      {/* Brand */}
      <div className={cn('flex h-14 shrink-0 items-center', expanded ? 'gap-2.5 px-3.5' : 'justify-center')}>
        <div
          className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg text-sm font-bold text-white"
          style={{ background: 'var(--sidebar-logo-bg)' }}
        >
          M
        </div>
        {expanded && (
          <div className="min-w-0">
            <p className="truncate text-[13px] font-semibold tracking-wide" style={{ color: 'var(--sidebar-text-active)' }}>MxTac</p>
            <p className="truncate text-[10px]" style={{ color: 'var(--sidebar-text-dim)' }}>Open-source detection</p>
          </div>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex flex-1 flex-col gap-0.5 overflow-y-auto px-2 py-2">
        {NAV_SECTIONS.map((section, i) => (
          <div key={section.title}>
            {expanded ? (
              <span className="block px-2.5 pb-1 pt-3 text-[10px] font-medium uppercase tracking-wider" style={{ color: 'var(--sidebar-text-dim)' }}>
                {section.title}
              </span>
            ) : i > 0 ? (
              <div className="mx-2 my-1.5 border-t" style={{ borderColor: 'var(--sidebar-border)' }} />
            ) : null}
            {section.items.map(({ to, Icon, label }) => (
              <NavLink
                key={to}
                to={to}
                end={to === '/'}
                title={label}
                className={({ isActive }) =>
                  cn(
                    'relative flex h-9 items-center gap-2.5 rounded-md transition-colors',
                    expanded ? 'px-2.5' : 'justify-center',
                    isActive
                      ? 'bg-[var(--sidebar-active)] font-medium text-[var(--sidebar-text-active)]'
                      : 'text-[var(--sidebar-text)] hover:bg-[var(--sidebar-hover)] hover:text-[var(--sidebar-text-active)]',
                  )
                }
              >
                <Icon className="h-[17px] w-[17px] shrink-0" strokeWidth={1.8} />
                {expanded && <span className="truncate text-[13px]">{label}</span>}
              </NavLink>
            ))}
          </div>
        ))}
      </nav>

      {/* KYRA MDR: the managed, AI-assisted product built on this core */}
      {expanded ? (
        <a
          href={KYRA_MDR_URL}
          target="_blank"
          rel="noopener noreferrer"
          className="mx-2 mb-2 rounded-lg border p-3 transition-colors hover:bg-[var(--sidebar-hover)]"
          style={{ borderColor: 'var(--sidebar-border)' }}
        >
          <span className="flex items-center gap-1.5 text-[12px] font-semibold" style={{ color: 'var(--sidebar-text-active)' }}>
            <ShieldCheck className="h-3.5 w-3.5 text-emerald-400" />
            KYRA MDR
            <ExternalLink className="ml-auto h-3 w-3" style={{ color: 'var(--sidebar-text-dim)' }} />
          </span>
          <span className="mt-1 block text-[11px] leading-snug" style={{ color: 'var(--sidebar-text)' }}>
            Need AI triage, automated response and 24/7 monitoring? See the managed service.
          </span>
        </a>
      ) : (
        <a href={KYRA_MDR_URL} target="_blank" rel="noopener noreferrer" title="KYRA MDR: managed detection and response" className={cn(iconButton, 'mx-auto mb-2')}>
          <ShieldCheck className="h-4 w-4 text-emerald-400" />
        </a>
      )}

      {/* Footer: account and preferences */}
      <div className="flex shrink-0 flex-col gap-1 border-t p-2" style={{ borderColor: 'var(--sidebar-border)' }}>
        <button
          type="button"
          onClick={() => setShowMfaModal(true)}
          title={user?.email ? `${user.email}: account security` : 'Account security'}
          className={cn('flex min-w-0 items-center gap-2 rounded-md p-1 text-left transition-colors hover:bg-[var(--sidebar-hover)]', !expanded && 'justify-center')}
        >
          <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-[var(--sidebar-active)] text-[10px] font-semibold text-white">{initials}</span>
          {expanded && (
            <span className="min-w-0">
              <span className="block truncate text-[12px]" style={{ color: 'var(--sidebar-text-active)' }}>{user?.email ?? 'Account'}</span>
              <span className="block truncate text-[10px] capitalize" style={{ color: 'var(--sidebar-text-dim)' }}>{user?.role ?? ''}</span>
            </span>
          )}
        </button>
        <div className={cn('flex gap-1', expanded ? 'items-center justify-between' : 'flex-col items-center')}>
        <button type="button" className={iconButton} onClick={toggleTheme} title={theme === 'light' ? 'Switch to dark mode' : 'Switch to light mode'}>
          {theme === 'light' ? <Moon className="h-4 w-4" /> : <Sun className="h-4 w-4" />}
        </button>
        <button type="button" className={iconButton} onClick={openShortcutsModal} title="Keyboard shortcuts">
          <HelpCircle className="h-4 w-4" />
        </button>
        <button type="button" className={iconButton} onClick={() => void logout()} title="Sign out">
          <LogOut className="h-4 w-4" />
        </button>
        <button type="button" className={iconButton} onClick={toggleSidebar} title={expanded ? 'Collapse sidebar' : 'Expand sidebar'}>
          {expanded ? <ChevronsLeft className="h-4 w-4" /> : <ChevronsRight className="h-4 w-4" />}
        </button>
        </div>
      </div>

      {showMfaModal && <MfaSetupModal onClose={() => setShowMfaModal(false)} />}
    </aside>
  )
}
