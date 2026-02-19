import { NavLink } from 'react-router-dom'

const NAV = [
  { to: '/',              icon: '⊞', label: 'Overview' },
  { to: '/detections',   icon: '⚡', label: 'Detections' },
  { to: '/attack',       icon: '⬡', label: 'ATT&CK Coverage' },
  { to: '/rules',        icon: 'σ',  label: 'Sigma Rules' },
  { to: '/incidents',    icon: '🔔', label: 'Incidents' },
  { to: '/intel',        icon: '🌐', label: 'Threat Intel' },
  { to: '/integrations', icon: '⇄',  label: 'Integrations' },
  { to: '/admin',        icon: '⚙',  label: 'Admin' },
]

export function Sidebar() {
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
        {NAV.map(({ to, icon, label }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            title={label}
            className={({ isActive }) =>
              `relative flex items-center justify-center h-[34px] mx-1.5 rounded-md text-base transition-colors
              ${isActive
                ? 'bg-blue-light text-blue before:absolute before:left-0 before:top-0 before:bottom-0 before:w-[3px] before:bg-blue before:rounded-sm'
                : 'text-text-muted hover:bg-section'
              }`
            }
          >
            {icon}
          </NavLink>
        ))}
      </nav>

      {/* Bottom */}
      <div className="flex flex-col items-center gap-3 pb-3">
        <button className="text-text-muted hover:text-text-secondary text-base" title="Help">?</button>
        <button className="text-text-muted hover:text-text-secondary text-base" title="Settings">⚙</button>
        <div className="w-5 h-5 rounded-full bg-border flex items-center justify-center text-[9px] text-text-secondary font-semibold">
          KH
        </div>
      </div>
    </aside>
  )
}
