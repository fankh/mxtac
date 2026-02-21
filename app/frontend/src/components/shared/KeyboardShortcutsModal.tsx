import { useEffect } from 'react'
import { useUIStore } from '../../stores/uiStore'

interface ShortcutRow {
  keys: string[]
  description: string
}

interface ShortcutGroup {
  heading: string
  rows: ShortcutRow[]
}

const SHORTCUT_GROUPS: ShortcutGroup[] = [
  {
    heading: 'Navigation',
    rows: [
      { keys: ['g', 'd'], description: 'Go to Dashboard' },
      { keys: ['g', 'e'], description: 'Go to Detections' },
      { keys: ['g', 'r'], description: 'Go to Rules' },
      { keys: ['g', 'c'], description: 'Go to Connectors' },
      { keys: ['g', 'i'], description: 'Go to Incidents' },
    ],
  },
  {
    heading: 'Actions',
    rows: [
      { keys: ['/'],   description: 'Focus search bar' },
      { keys: ['?'],   description: 'Show keyboard shortcuts' },
      { keys: ['Esc'], description: 'Close panel / modal' },
    ],
  },
]

function Key({ label }: { label: string }) {
  return (
    <kbd className="inline-flex items-center justify-center min-w-[22px] h-[22px] px-1.5 rounded border border-border bg-section text-[11px] font-mono font-semibold text-text-secondary leading-none">
      {label}
    </kbd>
  )
}

export function KeyboardShortcutsModal() {
  const closeShortcutsModal = useUIStore(s => s.closeShortcutsModal)

  // Close on Escape is handled by useKeyboardShortcuts, but keep a local
  // listener as a fallback for when the hook is not mounted (e.g. login page).
  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') closeShortcutsModal()
    }
    document.addEventListener('keydown', onKeyDown)
    return () => document.removeEventListener('keydown', onKeyDown)
  }, [closeShortcutsModal])

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Keyboard Shortcuts"
      className="fixed inset-0 z-50 flex items-center justify-center"
    >
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/50"
        onClick={closeShortcutsModal}
        aria-hidden="true"
      />

      {/* Panel */}
      <div className="relative bg-surface border border-border rounded-lg shadow-panel w-full max-w-sm mx-4 p-5">
        {/* Header */}
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-semibold text-text-primary">Keyboard Shortcuts</h2>
          <button
            onClick={closeShortcutsModal}
            aria-label="Close"
            className="text-text-muted hover:text-text-secondary text-lg leading-none"
          >
            ×
          </button>
        </div>

        {/* Shortcut groups */}
        <div className="flex flex-col gap-5">
          {SHORTCUT_GROUPS.map((group) => (
            <div key={group.heading}>
              <p className="text-[10px] font-semibold uppercase tracking-wider text-text-muted mb-2">
                {group.heading}
              </p>
              <div className="flex flex-col gap-1">
                {group.rows.map((row) => (
                  <div
                    key={row.description}
                    className="flex items-center justify-between py-1"
                  >
                    <span className="text-xs text-text-secondary">{row.description}</span>
                    <div className="flex items-center gap-1">
                      {row.keys.map((k, idx) => (
                        <span key={idx} className="flex items-center gap-1">
                          {idx > 0 && (
                            <span className="text-[10px] text-text-muted">then</span>
                          )}
                          <Key label={k} />
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
