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
    document.documentElement.classList.toggle('dark', theme !== 'light')
  } catch {
    document.documentElement.setAttribute('data-theme', 'dark')
    document.documentElement.classList.add('dark')
  }
}

const root = document.documentElement

function store(value: unknown) {
  localStorage.setItem('mxtac-ui', typeof value === 'string' ? value : JSON.stringify(value))
}

function preferLight() {
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
}

function expectTheme(theme: 'light' | 'dark') {
  expect(root).toHaveAttribute('data-theme', theme)
  expect(root.classList.contains('dark')).toBe(theme === 'dark')
}

describe('Flash prevention (main.tsx bootstrap logic)', () => {
  beforeEach(() => {
    localStorage.clear()
    root.removeAttribute('data-theme')
    root.classList.remove('dark')
  })

  afterEach(() => {
    localStorage.clear()
    root.removeAttribute('data-theme')
    root.classList.remove('dark')
    vi.restoreAllMocks()
  })

  it('defaults to dark when nothing is stored and the system has no light preference', () => {
    runFlashPrevention()
    expectTheme('dark')
  })

  it('follows a system light preference when nothing is stored', () => {
    preferLight()
    runFlashPrevention()
    expectTheme('light')
  })

  it.each(['light', 'dark'] as const)('applies a stored %s theme', (theme) => {
    store({ state: { theme } })
    runFlashPrevention()
    expectTheme(theme)
  })

  it('prefers the stored theme over the system preference', () => {
    preferLight()
    store({ state: { theme: 'dark' } })
    runFlashPrevention()
    expectTheme('dark')
  })

  it('removes a dark class left on <html> when the stored theme is light', () => {
    root.classList.add('dark')
    root.setAttribute('data-theme', 'dark')
    store({ state: { theme: 'light' } })
    runFlashPrevention()
    expectTheme('light')
  })

  it('renders a stored theme that no longer exists (the removed "matrix") with the dark class', () => {
    store({ state: { theme: 'matrix' } })
    runFlashPrevention()
    expect(root).toHaveClass('dark')
  })

  it.each([
    ['malformed JSON', 'not-valid-{json'],
    ['a state without a theme', { state: {} }],
    ['no state at all', { version: 0 }],
    ['an empty theme', { state: { theme: '' } }],
  ])('falls back to dark for %s', (_name, value) => {
    store(value)
    runFlashPrevention()
    expectTheme('dark')
  })

  it('sets the theme on <html>, not on <body>', () => {
    store({ state: { theme: 'dark' } })
    runFlashPrevention()
    expect(document.body).not.toHaveAttribute('data-theme')
    expect(document.body).not.toHaveClass('dark')
  })
})
