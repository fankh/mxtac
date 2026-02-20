import { useState, useRef, useEffect } from 'react'
import { NavLink } from 'react-router-dom'
import { useUIStore, type Theme } from '../../stores/uiStore'

const NAV = [
  { to: '/',              icon: '\u229E', label: 'Overview' },
  { to: '/detections',   icon: '\u26A1', label: 'Detections' },
  { to: '/attack',       icon: '\u2B21', label: 'ATT&CK Coverage' },
  { to: '/rules',        icon: '\u03C3',  label: 'Sigma Rules' },
  { to: '/incidents',    icon: '\uD83D\uDD14', label: 'Incidents' },
  { to: '/intel',        icon: '\uD83C\uDF10', label: 'Threat Intel' },
  { to: '/integrations', icon: '\u21C4',  label: 'Integrations' },
  { to: '/admin',        icon: '\u2699',  label: 'Admin' },
]

const THEMES: { value: Theme; icon: string; label: string }[] = [
  { value: 'light',  icon: '\u2600', label: 'Light' },
  { value: 'dark',   icon: '\uD83C\uDF19', label: 'Dark' },
  { value: 'matrix', icon: '\u25A8', label: 'Matrix' },
]

export function Sidebar() {
  const { theme, setTheme } = useUIStore()
  const [showThemeMenu, setShowThemeMenu] = useState(false)
  const menuRef = useRef<HTMLDivElement>(null)

  // Close menu on outside click
  useEffect(() => {
    if (!showThemeMenu) return
    function handleClick(e: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setShowThemeMenu(false)
      }
    }
    document.addEventListener('mousedown', handleClick)
    return () => document.removeEventListener('mousedown', handleClick)
  }, [showThemeMenu])

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
      <div className="flex flex-col items-center gap-3 pb-3 relative">
        {/* Theme toggle */}
        <div ref={menuRef} className="relative">
          <button
            className="text-text-muted hover:text-text-secondary text-base"
            title={`Theme: ${theme}`}
            onClick={() => setShowThemeMenu(!showThemeMenu)}
          >
            {THEMES.find(t => t.value === theme)?.icon ?? '\u2600'}
          </button>

          {showThemeMenu && (
            <div className="absolute left-[52px] bottom-0 bg-surface border border-border rounded-md shadow-panel py-1 min-w-[120px] z-50">
              {THEMES.map((t) => (
                <button
                  key={t.value}
                  onClick={() => { setTheme(t.value); setShowThemeMenu(false) }}
                  className={`w-full flex items-center gap-2 px-3 py-[6px] text-[11px] transition-colors ${
                    theme === t.value
                      ? 'text-blue bg-blue-light font-medium'
                      : 'text-text-secondary hover:bg-page'
                  }`}
                >
                  <span>{t.icon}</span>
                  <span>{t.label}</span>
                </button>
              ))}
            </div>
          )}
        </div>

        <button className="text-text-muted hover:text-text-secondary text-base" title="Help">?</button>
        <button className="text-text-muted hover:text-text-secondary text-base" title="Settings">{'\u2699'}</button>
        <div className="w-5 h-5 rounded-full bg-border flex items-center justify-center text-[9px] text-text-secondary font-semibold">
          KH
        </div>
      </div>
    </aside>
  )
}
