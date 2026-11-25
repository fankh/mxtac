import { useEffect, useRef, useState, type ComponentType } from 'react'
import { NavLink, useLocation } from 'react-router-dom'
import {
  Activity, AlertTriangle, ChevronsLeft, ChevronsRight, Crosshair, ExternalLink, FileCode2, HelpCircle,
  LayoutDashboard, LogOut, Menu, Moon, Plug, Search, Settings, ShieldCheck, Sun, type LucideProps,
} from 'lucide-react'
import { Sheet, SheetContent, SheetDescription, SheetTitle } from '@/components/ui/sheet'
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
  'touch-target flex h-8 w-8 items-center justify-center rounded-md text-[var(--sidebar-text)] transition-colors hover:bg-[var(--sidebar-hover)] hover:text-[var(--sidebar-text-active)]'

/** Tailwind `md`: from this width the sidebar is part of the layout; below it, a drawer. */
const DESKTOP_QUERY = '(min-width: 768px)'

interface SidebarBodyProps {
  /** Labels are shown; false renders the 56px icon rail. */
  expanded: boolean
  /** True inside the mobile drawer: no collapse button. */
  drawer?: boolean
  /** Called when a navigation link is followed. */
  onNavigate?: () => void
  onOpenAccount: () => void
  onOpenShortcuts: () => void
}

/** Brand, navigation, the KYRA MDR link and the account controls. */
function SidebarBody({ expanded, drawer = false, onNavigate, onOpenAccount, onOpenShortcuts }: SidebarBodyProps) {
  const { toggleSidebar, theme, toggleTheme } = useUIStore()
  const user = useAuthStore((s) => s.user)
  const logout = useAuthStore((s) => s.logout)
  const initials = user?.email ? user.email.split('@')[0].slice(0, 2).toUpperCase() : '··'

  return (
    <>
      {/* Brand */}
      <div className={cn('flex h-14 shrink-0 items-center', expanded ? 'gap-2.5 px-3.5' : 'justify-center', drawer && 'pr-12')}>
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
                onClick={onNavigate}
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
          onClick={onOpenAccount}
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
        <div className={cn('flex gap-1', !expanded ? 'flex-col items-center' : drawer ? 'items-center' : 'items-center justify-between')}>
        <button type="button" className={iconButton} onClick={toggleTheme} title={theme === 'light' ? 'Switch to dark mode' : 'Switch to light mode'}>
          {theme === 'light' ? <Moon className="h-4 w-4" /> : <Sun className="h-4 w-4" />}
        </button>
        <button type="button" className={iconButton} onClick={onOpenShortcuts} title="Keyboard shortcuts">
          <HelpCircle className="h-4 w-4" />
        </button>
        <button type="button" className={iconButton} onClick={() => void logout()} title="Sign out">
          <LogOut className="h-4 w-4" />
        </button>
        {!drawer && (
          <button type="button" className={iconButton} onClick={toggleSidebar} title={expanded ? 'Collapse sidebar' : 'Expand sidebar'}>
            {expanded ? <ChevronsLeft className="h-4 w-4" /> : <ChevronsRight className="h-4 w-4" />}
          </button>
        )}
        </div>
      </div>
    </>
  )
}

/**
 * Main navigation. From `md` up it is a column in the layout (220px, or a 56px icon rail
 * when collapsed). Below `md` it is out of the layout: a menu button over the left end of
 * the page header bar opens it as a drawer.
 */
export function Sidebar() {
  const sidebarCollapsed = useUIStore((s) => s.sidebarCollapsed)
  const openShortcutsModal = useUIStore((s) => s.openShortcutsModal)
  const [showMfaModal, setShowMfaModal] = useState(false)
  const [drawerOpen, setDrawerOpen] = useState(false)
  const menuButtonRef = useRef<HTMLButtonElement>(null)
  const { pathname } = useLocation()

  // Close the drawer when the route changes (link, keyboard shortcut or redirect).
  useEffect(() => {
    setDrawerOpen(false)
  }, [pathname])

  // Close it when the window grows to the desktop layout, where the column is back.
  useEffect(() => {
    const desktop = window.matchMedia?.(DESKTOP_QUERY)
    if (!desktop) return
    const onChange = (event: MediaQueryListEvent) => {
      if (event.matches) setDrawerOpen(false)
    }
    desktop.addEventListener('change', onChange)
    return () => desktop.removeEventListener('change', onChange)
  }, [])

  const openAccount = () => {
    setDrawerOpen(false)
    setShowMfaModal(true)
  }
  const openShortcuts = () => {
    setDrawerOpen(false)
    openShortcutsModal()
  }

  return (
    <>
      <aside
        aria-label="Main navigation"
        className={cn(
          'hidden h-full shrink-0 flex-col border-r transition-[width] duration-200 md:flex',
          sidebarCollapsed ? 'w-[56px]' : 'w-[220px]',
        )}
        style={{ background: 'var(--sidebar-bg)', borderColor: 'var(--sidebar-border)' }}
      >
        <SidebarBody expanded={!sidebarCollapsed} onOpenAccount={openAccount} onOpenShortcuts={openShortcuts} />
      </aside>

      {/* Sits over the left end of the sticky page header bar, which leaves room for it. */}
      <button
        ref={menuButtonRef}
        type="button"
        aria-label="Open navigation"
        aria-haspopup="dialog"
        aria-expanded={drawerOpen}
        onClick={() => setDrawerOpen(true)}
        className="fixed left-2 top-[4px] z-30 flex h-[36px] w-[36px] items-center justify-center rounded-md text-foreground transition-colors hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring md:hidden"
      >
        <Menu className="h-[18px] w-[18px]" />
      </button>

      <Sheet open={drawerOpen} onOpenChange={setDrawerOpen}>
        <SheetContent
          side="left"
          closeClassName="text-[var(--sidebar-text)] hover:bg-[var(--sidebar-hover)] hover:text-[var(--sidebar-text-active)]"
          className="flex w-[264px] max-w-[85vw] flex-col gap-0 border-r p-0 sm:max-w-[264px] md:hidden"
          style={{ background: 'var(--sidebar-bg)', borderColor: 'var(--sidebar-border)' }}
          onCloseAutoFocus={(event) => {
            // The button is always mounted, so focus goes back to it on every close.
            event.preventDefault()
            menuButtonRef.current?.focus()
          }}
        >
          <SheetTitle className="sr-only">Main navigation</SheetTitle>
          <SheetDescription className="sr-only">Pages, the KYRA MDR link and account controls.</SheetDescription>
          <SidebarBody
            expanded
            drawer
            onNavigate={() => setDrawerOpen(false)}
            onOpenAccount={openAccount}
            onOpenShortcuts={openShortcuts}
          />
        </SheetContent>
      </Sheet>

      {showMfaModal && <MfaSetupModal onClose={() => setShowMfaModal(false)} />}
    </>
  )
}
