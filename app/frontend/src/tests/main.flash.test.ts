import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'

// ── Flash prevention logic ────────────────────────────────────────────────
// The block below mirrors the exact code in main.tsx that runs synchronously
// before React renders.  main.tsx is excluded from coverage (it bootstraps
// the React tree), so we unit-test the algorithm in isolation here.
//
// If the logic in main.tsx ever changes, this test must be updated to match.

function runFlashPrevention() {
  try {
    const stored = JSON.parse(localStorage.getItem('mxtac-ui') || '{}')
    const savedTheme = stored?.state?.theme
    const theme = savedTheme || (window.matchMedia?.('(prefers-color-scheme: light)').matches ? 'light' : 'dark')
    document.documentElement.setAttribute('data-theme', theme)
  } catch {
    document.documentElement.setAttribute('data-theme', 'dark')
  }
}

describe('Flash prevention (main.tsx bootstrap logic)', () => {
  beforeEach(() => {
    localStorage.clear()
    document.documentElement.removeAttribute('data-theme')
  })

  afterEach(() => {
    localStorage.clear()
    document.documentElement.removeAttribute('data-theme')
    vi.restoreAllMocks()
  })

  // ── Default / empty storage ──────────────────────────────────────────────

  it('defaults to "dark" when localStorage is empty and no system preference', () => {
    runFlashPrevention()
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark')
  })

  it('defaults to "dark" when mxtac-ui key does not exist and no system preference', () => {
    localStorage.setItem('some-other-key', 'irrelevant')
    runFlashPrevention()
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark')
  })

  it('defaults to "light" when system prefers light and localStorage is empty', () => {
    vi.spyOn(window, 'matchMedia').mockReturnValue({
      matches: true,
      media: '(prefers-color-scheme: light)',
      onchange: null,
      addListener: vi.fn(),
      removeListener: vi.fn(),
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      dispatchEvent: vi.fn(),
    } as MediaQueryList)
    runFlashPrevention()
    expect(document.documentElement.getAttribute('data-theme')).toBe('light')
  })

  it('localStorage override takes precedence over system light preference', () => {
    vi.spyOn(window, 'matchMedia').mockReturnValue({
      matches: true,
      media: '(prefers-color-scheme: light)',
      onchange: null,
      addListener: vi.fn(),
      removeListener: vi.fn(),
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      dispatchEvent: vi.fn(),
    } as MediaQueryList)
    localStorage.setItem('mxtac-ui', JSON.stringify({ state: { theme: 'dark' } }))
    runFlashPrevention()
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark')
  })

  // ── Stored theme values ──────────────────────────────────────────────────

  it('applies "light" theme from stored mxtac-ui state', () => {
    localStorage.setItem('mxtac-ui', JSON.stringify({ state: { theme: 'light' } }))
    runFlashPrevention()
    expect(document.documentElement.getAttribute('data-theme')).toBe('light')
  })

  it('applies "dark" theme from stored mxtac-ui state', () => {
    localStorage.setItem('mxtac-ui', JSON.stringify({ state: { theme: 'dark' } }))
    runFlashPrevention()
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark')
  })

  it('applies "matrix" theme from stored mxtac-ui state', () => {
    localStorage.setItem('mxtac-ui', JSON.stringify({ state: { theme: 'matrix' } }))
    runFlashPrevention()
    expect(document.documentElement.getAttribute('data-theme')).toBe('matrix')
  })

  // ── Error / edge cases ───────────────────────────────────────────────────

  it('falls back to "dark" on malformed JSON', () => {
    localStorage.setItem('mxtac-ui', 'not-valid-{json')
    runFlashPrevention()
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark')
  })

  it('falls back to "dark" when state.theme key is absent', () => {
    localStorage.setItem('mxtac-ui', JSON.stringify({ state: {} }))
    runFlashPrevention()
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark')
  })

  it('falls back to "dark" when the state key itself is absent', () => {
    localStorage.setItem('mxtac-ui', JSON.stringify({ version: 0 }))
    runFlashPrevention()
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark')
  })

  it('falls back to "dark" when theme value is an empty string', () => {
    localStorage.setItem('mxtac-ui', JSON.stringify({ state: { theme: '' } }))
    runFlashPrevention()
    // Empty string is falsy — system preference check kicks in (defaults to dark in jsdom)
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark')
  })

  // ── Target element ───────────────────────────────────────────────────────

  it('sets data-theme on document.documentElement, not document.body', () => {
    localStorage.setItem('mxtac-ui', JSON.stringify({ state: { theme: 'matrix' } }))
    runFlashPrevention()
    expect(document.documentElement.hasAttribute('data-theme')).toBe(true)
    expect(document.body.hasAttribute('data-theme')).toBe(false)
  })

  it('overwrites a pre-existing data-theme attribute', () => {
    document.documentElement.setAttribute('data-theme', 'light')
    localStorage.setItem('mxtac-ui', JSON.stringify({ state: { theme: 'dark' } }))
    runFlashPrevention()
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark')
  })

  it('is idempotent — calling it twice with the same storage yields the same result', () => {
    localStorage.setItem('mxtac-ui', JSON.stringify({ state: { theme: 'matrix' } }))
    runFlashPrevention()
    runFlashPrevention()
    expect(document.documentElement.getAttribute('data-theme')).toBe('matrix')
  })
})
