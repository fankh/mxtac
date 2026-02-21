import { describe, it, expect, beforeEach, afterEach } from 'vitest'

// ── Flash prevention logic ────────────────────────────────────────────────
// The block below mirrors the exact code in main.tsx that runs synchronously
// before React renders.  main.tsx is excluded from coverage (it bootstraps
// the React tree), so we unit-test the algorithm in isolation here.
//
// If the logic in main.tsx ever changes, this test must be updated to match.

function runFlashPrevention() {
  try {
    const stored = JSON.parse(localStorage.getItem('mxtac-ui') || '{}')
    const theme = stored?.state?.theme || 'light'
    document.documentElement.setAttribute('data-theme', theme)
  } catch {
    document.documentElement.setAttribute('data-theme', 'light')
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
  })

  // ── Default / empty storage ──────────────────────────────────────────────

  it('defaults to "light" when localStorage is empty', () => {
    runFlashPrevention()
    expect(document.documentElement.getAttribute('data-theme')).toBe('light')
  })

  it('defaults to "light" when mxtac-ui key does not exist', () => {
    localStorage.setItem('some-other-key', 'irrelevant')
    runFlashPrevention()
    expect(document.documentElement.getAttribute('data-theme')).toBe('light')
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

  it('falls back to "light" on malformed JSON', () => {
    localStorage.setItem('mxtac-ui', 'not-valid-{json')
    runFlashPrevention()
    expect(document.documentElement.getAttribute('data-theme')).toBe('light')
  })

  it('falls back to "light" when state.theme key is absent', () => {
    localStorage.setItem('mxtac-ui', JSON.stringify({ state: {} }))
    runFlashPrevention()
    expect(document.documentElement.getAttribute('data-theme')).toBe('light')
  })

  it('falls back to "light" when the state key itself is absent', () => {
    localStorage.setItem('mxtac-ui', JSON.stringify({ version: 0 }))
    runFlashPrevention()
    expect(document.documentElement.getAttribute('data-theme')).toBe('light')
  })

  it('falls back to "light" when theme value is an empty string', () => {
    localStorage.setItem('mxtac-ui', JSON.stringify({ state: { theme: '' } }))
    runFlashPrevention()
    // Empty string is falsy — || 'light' kicks in
    expect(document.documentElement.getAttribute('data-theme')).toBe('light')
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
