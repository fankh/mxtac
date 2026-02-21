import { useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { useUIStore } from '../stores/uiStore'

/** Returns true when the user is typing in an interactive field. */
function isTyping(): boolean {
  const el = document.activeElement
  if (!el) return false
  const tag = el.tagName
  if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return true
  // Use getAttribute for reliable contenteditable detection (isContentEditable
  // is not available in all environments, e.g. jsdom).
  const ce = el.getAttribute('contenteditable')
  return ce !== null && ce !== 'false'
}

/**
 * Global keyboard shortcut handler for power users.
 *
 * Chord shortcuts (g then …):
 *   g d → Dashboard (/)
 *   g e → Detections (/detections)
 *   g r → Rules (/rules)
 *   g c → Connectors (/integrations)
 *   g i → Incidents (/incidents)
 *
 * Single-key shortcuts:
 *   /   → Focus search bar (dispatches mxtac:focus-search)
 *   ?   → Open keyboard shortcuts modal
 *   Esc → Close shortcuts modal + dispatch mxtac:close-panel
 *
 * Shortcuts are suppressed when the user is typing in an input/textarea.
 */
export function useKeyboardShortcuts(): void {
  const navigate = useNavigate()
  const openShortcutsModal = useUIStore(s => s.openShortcutsModal)
  const closeShortcutsModal = useUIStore(s => s.closeShortcutsModal)

  // Chord state lives in refs to avoid stale-closure issues and re-renders.
  const pendingRef = useRef<string | null>(null)
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    function clearPending() {
      pendingRef.current = null
      if (timerRef.current !== null) {
        clearTimeout(timerRef.current)
        timerRef.current = null
      }
    }

    function handleKeyDown(e: KeyboardEvent) {
      // Ignore shortcuts when the user is composing text.
      if (isTyping()) return
      // Ignore modified keys (Ctrl/Meta/Alt combos).
      if (e.ctrlKey || e.metaKey || e.altKey) return

      const key = e.key

      // ── Handle chord second key ──────────────────────────────────────────
      if (pendingRef.current === 'g') {
        clearPending()
        switch (key) {
          case 'd': navigate('/'); break
          case 'e': navigate('/detections'); break
          case 'r': navigate('/rules'); break
          case 'c': navigate('/integrations'); break
          case 'i': navigate('/incidents'); break
          default: break
        }
        return
      }

      // ── Single-key shortcuts ─────────────────────────────────────────────
      switch (key) {
        case 'g':
          pendingRef.current = 'g'
          timerRef.current = setTimeout(clearPending, 1500)
          break

        case '/':
          e.preventDefault()
          document.dispatchEvent(new CustomEvent('mxtac:focus-search'))
          break

        case '?':
          openShortcutsModal()
          break

        case 'Escape':
          closeShortcutsModal()
          document.dispatchEvent(new CustomEvent('mxtac:close-panel'))
          break

        default:
          break
      }
    }

    document.addEventListener('keydown', handleKeyDown)
    return () => {
      document.removeEventListener('keydown', handleKeyDown)
      clearPending()
    }
  }, [navigate, openShortcutsModal, closeShortcutsModal])
}
