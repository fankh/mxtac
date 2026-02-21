/**
 * Tests for useKeyboardShortcuts
 *
 * Covers:
 *  - Chord navigation: g+d, g+e, g+r, g+c, g+i
 *  - Unknown chord second key is ignored
 *  - Chord times out after 1.5 s with no second key
 *  - / dispatches mxtac:focus-search event
 *  - ? opens shortcuts modal
 *  - Esc closes modal and dispatches mxtac:close-panel
 *  - Shortcuts suppressed when typing in input/textarea/contenteditable
 *  - Shortcuts suppressed for Ctrl/Meta/Alt combos
 *  - Cleanup on unmount removes event listener
 */

import { renderHook, act } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { createElement } from 'react'
import type { ReactNode } from 'react'
import { useUIStore } from '../../stores/uiStore'

// ── Mock useNavigate ───────────────────────────────────────────────────────────

const mockNavigate = vi.fn()

vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>()
  return { ...actual, useNavigate: () => mockNavigate }
})

// Import hook AFTER mock is in place
const { useKeyboardShortcuts } = await import('../../hooks/useKeyboardShortcuts')

// ── Test helpers ───────────────────────────────────────────────────────────────

function wrapper({ children }: { children: ReactNode }) {
  return createElement(MemoryRouter, null, children)
}

function fireKey(key: string, opts: Partial<KeyboardEventInit> = {}) {
  act(() => {
    document.dispatchEvent(new KeyboardEvent('keydown', { key, bubbles: true, ...opts }))
  })
}

// ── Suite ──────────────────────────────────────────────────────────────────────

describe('useKeyboardShortcuts', () => {
  beforeEach(() => {
    mockNavigate.mockReset()
    vi.useFakeTimers()
    // Reset modal state
    useUIStore.setState({ showShortcutsModal: false })
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  // ── Chord navigation ─────────────────────────────────────────────────────────

  describe('chord navigation (g → …)', () => {
    it('g then d navigates to Dashboard (/)', () => {
      renderHook(() => useKeyboardShortcuts(), { wrapper })
      fireKey('g')
      fireKey('d')
      expect(mockNavigate).toHaveBeenCalledWith('/')
    })

    it('g then e navigates to Detections (/detections)', () => {
      renderHook(() => useKeyboardShortcuts(), { wrapper })
      fireKey('g')
      fireKey('e')
      expect(mockNavigate).toHaveBeenCalledWith('/detections')
    })

    it('g then r navigates to Rules (/rules)', () => {
      renderHook(() => useKeyboardShortcuts(), { wrapper })
      fireKey('g')
      fireKey('r')
      expect(mockNavigate).toHaveBeenCalledWith('/rules')
    })

    it('g then c navigates to Connectors (/integrations)', () => {
      renderHook(() => useKeyboardShortcuts(), { wrapper })
      fireKey('g')
      fireKey('c')
      expect(mockNavigate).toHaveBeenCalledWith('/integrations')
    })

    it('g then i navigates to Incidents (/incidents)', () => {
      renderHook(() => useKeyboardShortcuts(), { wrapper })
      fireKey('g')
      fireKey('i')
      expect(mockNavigate).toHaveBeenCalledWith('/incidents')
    })

    it('unknown chord second key does not navigate', () => {
      renderHook(() => useKeyboardShortcuts(), { wrapper })
      fireKey('g')
      fireKey('z') // not a registered chord key
      expect(mockNavigate).not.toHaveBeenCalled()
    })

    it('chord clears after 1.5 s timeout — second key no longer triggers navigation', () => {
      renderHook(() => useKeyboardShortcuts(), { wrapper })
      fireKey('g')
      act(() => { vi.advanceTimersByTime(1500) })
      fireKey('d')
      expect(mockNavigate).not.toHaveBeenCalled()
    })

    it('chord does not navigate if second key arrives immediately after timeout', () => {
      renderHook(() => useKeyboardShortcuts(), { wrapper })
      fireKey('g')
      act(() => { vi.advanceTimersByTime(1499) })
      // Within timeout window — still pending, but barely
      act(() => { vi.advanceTimersByTime(1) }) // now at exactly 1500 ms
      fireKey('d')
      expect(mockNavigate).not.toHaveBeenCalled()
    })

    it('two chord sequences work independently', () => {
      renderHook(() => useKeyboardShortcuts(), { wrapper })
      fireKey('g')
      fireKey('d')
      expect(mockNavigate).toHaveBeenCalledWith('/')
      mockNavigate.mockReset()

      fireKey('g')
      fireKey('e')
      expect(mockNavigate).toHaveBeenCalledWith('/detections')
    })
  })

  // ── / shortcut ───────────────────────────────────────────────────────────────

  describe('/ shortcut', () => {
    it('dispatches mxtac:focus-search on document', () => {
      renderHook(() => useKeyboardShortcuts(), { wrapper })
      const handler = vi.fn()
      document.addEventListener('mxtac:focus-search', handler)

      fireKey('/')

      document.removeEventListener('mxtac:focus-search', handler)
      expect(handler).toHaveBeenCalledOnce()
    })
  })

  // ── ? shortcut ───────────────────────────────────────────────────────────────

  describe('? shortcut', () => {
    it('opens the shortcuts modal', () => {
      renderHook(() => useKeyboardShortcuts(), { wrapper })
      expect(useUIStore.getState().showShortcutsModal).toBe(false)

      fireKey('?')

      expect(useUIStore.getState().showShortcutsModal).toBe(true)
    })
  })

  // ── Esc shortcut ─────────────────────────────────────────────────────────────

  describe('Escape shortcut', () => {
    it('closes the shortcuts modal', () => {
      useUIStore.setState({ showShortcutsModal: true })
      renderHook(() => useKeyboardShortcuts(), { wrapper })

      fireKey('Escape')

      expect(useUIStore.getState().showShortcutsModal).toBe(false)
    })

    it('dispatches mxtac:close-panel on document', () => {
      renderHook(() => useKeyboardShortcuts(), { wrapper })
      const handler = vi.fn()
      document.addEventListener('mxtac:close-panel', handler)

      fireKey('Escape')

      document.removeEventListener('mxtac:close-panel', handler)
      expect(handler).toHaveBeenCalledOnce()
    })
  })

  // ── Typing guard ─────────────────────────────────────────────────────────────

  describe('typing guard — shortcuts suppressed inside interactive elements', () => {
    it('does not navigate when g+d is pressed while an <input> is focused', () => {
      renderHook(() => useKeyboardShortcuts(), { wrapper })

      const input = document.createElement('input')
      document.body.appendChild(input)
      input.focus()

      fireKey('g')
      fireKey('d')

      document.body.removeChild(input)
      expect(mockNavigate).not.toHaveBeenCalled()
    })

    it('does not open modal when ? is pressed while a <textarea> is focused', () => {
      renderHook(() => useKeyboardShortcuts(), { wrapper })

      const textarea = document.createElement('textarea')
      document.body.appendChild(textarea)
      textarea.focus()

      fireKey('?')

      document.body.removeChild(textarea)
      expect(useUIStore.getState().showShortcutsModal).toBe(false)
    })

    it('does not navigate when focused on a [contenteditable] element', () => {
      renderHook(() => useKeyboardShortcuts(), { wrapper })

      // jsdom does not focus contenteditable divs via focus(), so we spy on
      // Document.prototype.activeElement. We use setAttribute (not the IDL
      // property) because jsdom does not reflect the contentEditable IDL
      // property to the HTML attribute.
      const div = document.createElement('div')
      div.setAttribute('contenteditable', 'true')
      document.body.appendChild(div)
      const spy = vi.spyOn(Document.prototype, 'activeElement', 'get').mockReturnValue(div)

      fireKey('g')
      fireKey('d')

      spy.mockRestore()
      document.body.removeChild(div)
      expect(mockNavigate).not.toHaveBeenCalled()
    })
  })

  // ── Modified key guard ───────────────────────────────────────────────────────

  describe('modified-key guard — Ctrl/Meta/Alt combos are ignored', () => {
    it('ignores Ctrl+g', () => {
      renderHook(() => useKeyboardShortcuts(), { wrapper })
      fireKey('g', { ctrlKey: true })
      fireKey('d')
      expect(mockNavigate).not.toHaveBeenCalled()
    })

    it('ignores Meta+/', () => {
      renderHook(() => useKeyboardShortcuts(), { wrapper })
      const handler = vi.fn()
      document.addEventListener('mxtac:focus-search', handler)
      fireKey('/', { metaKey: true })
      document.removeEventListener('mxtac:focus-search', handler)
      expect(handler).not.toHaveBeenCalled()
    })

    it('ignores Alt+?', () => {
      renderHook(() => useKeyboardShortcuts(), { wrapper })
      fireKey('?', { altKey: true })
      expect(useUIStore.getState().showShortcutsModal).toBe(false)
    })
  })

  // ── Cleanup ──────────────────────────────────────────────────────────────────

  describe('cleanup on unmount', () => {
    it('removes keydown listener — shortcuts no longer fire after unmount', () => {
      const { unmount } = renderHook(() => useKeyboardShortcuts(), { wrapper })
      act(() => unmount())

      fireKey('?')

      expect(useUIStore.getState().showShortcutsModal).toBe(false)
    })

    it('clears pending chord timer on unmount', () => {
      const { unmount } = renderHook(() => useKeyboardShortcuts(), { wrapper })
      fireKey('g') // start a chord
      act(() => unmount())

      // Timeout fires after unmount — no effect
      act(() => { vi.advanceTimersByTime(1500) })
      // No error and navigate not called
      expect(mockNavigate).not.toHaveBeenCalled()
    })
  })
})
