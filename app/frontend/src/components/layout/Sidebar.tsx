import { useState, type ComponentType } from 'react'
import { NavLink, useLocation } from 'react-router-dom'
import { useUIStore, type Theme } from '../../stores/uiStore'
import { useAuthStore } from '../../stores/authStore'
// import { useDetectionStore } from '../../stores/detectionStore'
import { MfaSetupModal } from '../features/auth/MfaSetupModal'
import {
  Search,
  Wifi,
  Radio,
  Crosshair,
  Settings,
  HelpCircle,
  type LucideProps,
} from 'lucide-react'

const NAV: { to: string; Icon: ComponentType<LucideProps>; label: string }[] = [
  { to: '/',         Icon: Crosshair,       label: 'ATT&CK Matrix' },
  { to: '/hunt',     Icon: Search,          label: 'Hunt' },
  { to: '/ndr',      Icon: Radio,           label: 'NDR Logs' },
  { to: '/sources',  Icon: Wifi,            label: 'Sources' },
  { to: '/settings', Icon: Settings,        label: 'Settings' },
]

// Theme toggle removed — theme is set via user preferences

export function Sidebar() {
  const { openShortcutsModal } = useUIStore()
  const user = useAuthStore(s => s.user)
  const unreadCount = 0
  const location = useLocation()
  const [showMfaModal, setShowMfaModal] = useState(false)


  // Derive initials from email (e.g. "khchoi@..." → "KH")
  const initials = user?.email
    ? user.email.split('@')[0].slice(0, 2).toUpperCase()
    : 'KH'


  return (
    <aside className="fixed left-0 top-0 h-screen w-[52px] bg-surface border-r border-border flex flex-col z-30">
      {/* Logo */}
      <div className="flex items-center justify-center h-[46px] border-b border-border">
        <div className="w-8 h-8 rounded-[6px] bg-blue flex items-center justify-center text-white text-sm font-bold">
          M
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 flex flex-col gap-1 py-2">
        {NAV.map(({ to, Icon, label }) => {
          const badge = 0
          return (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              title={label}
              className={({ isActive }) =>
                `relative flex items-center justify-center h-[34px] mx-1.5 rounded-md transition-colors
                ${isActive
                  ? 'bg-blue-light text-blue before:absolute before:left-0 before:top-0 before:bottom-0 before:w-[3px] before:bg-blue before:rounded-sm'
                  : 'text-text-muted hover:bg-section'
                }`
              }
            >
              <Icon className="w-[18px] h-[18px]" strokeWidth={1.8} />
              {badge > 0 && (
                <span className="absolute top-0.5 right-0.5 min-w-[14px] h-[14px] bg-crit-text text-white text-[9px] font-bold rounded-full flex items-center justify-center px-0.5 leading-none pointer-events-none">
                  {badge > 99 ? '99+' : badge}
                </span>
              )}
            </NavLink>
          )
        })}
      </nav>

      {/* Bottom */}
      <div className="flex flex-col items-center gap-3 pb-3">
        <button
          className="text-text-muted hover:text-text-secondary transition-colors"
          title="Keyboard Shortcuts"
          onClick={openShortcutsModal}
        >
          <HelpCircle className="w-[16px] h-[16px]" />
        </button>
        <button
          onClick={() => setShowMfaModal(true)}
          title={user?.email ?? 'Account'}
          className="w-6 h-6 rounded-full bg-border flex items-center justify-center text-[9px] text-text-secondary font-semibold hover:bg-blue hover:text-white transition-colors"
        >
          {initials}
        </button>
      </div>

      {showMfaModal && <MfaSetupModal onClose={() => setShowMfaModal(false)} />}
    </aside>
  )
}
