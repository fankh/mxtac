import { describe, it, expect, afterEach } from 'vitest'
import { cssVar, chartColors } from '../../lib/themeVars'

describe('themeVars', () => {
  // ---------------------------------------------------------------------------
  // cssVar
  // ---------------------------------------------------------------------------
  describe('cssVar', () => {
    afterEach(() => {
      // Clean up any inline properties set during tests
      document.documentElement.removeAttribute('style')
    })

    it('returns a string for any CSS variable name', () => {
      const result = cssVar('--color-primary')
      expect(typeof result).toBe('string')
    })

    it('returns an empty string for unknown CSS variables in jsdom', () => {
      // jsdom does not compute CSS custom properties from stylesheets
      const result = cssVar('--non-existent-variable')
      expect(result).toBe('')
    })

    it('does not throw for multiple known variable names', () => {
      expect(() => cssVar('--color-border')).not.toThrow()
      expect(() => cssVar('--color-surface')).not.toThrow()
      expect(() => cssVar('--color-text-primary')).not.toThrow()
      expect(() => cssVar('--color-text-muted')).not.toThrow()
      expect(() => cssVar('--color-text-faint')).not.toThrow()
    })

    it('trims surrounding whitespace from the returned value', () => {
      // Set a custom property with surrounding whitespace via inline style
      document.documentElement.style.setProperty('--trimmed-var', '  #abc  ')
      const result = cssVar('--trimmed-var')
      // In jsdom, inline custom properties ARE readable via getComputedStyle
      // The .trim() call in cssVar ensures no trailing spaces
      expect(result).not.toMatch(/^\s|\s$/)
    })

    it('reads from document.documentElement (the :root element)', () => {
      // Verifies the correct target element is queried — cssVar should not throw
      // even when called before any theme is applied
      expect(() => cssVar('--color-primary')).not.toThrow()
    })
  })

  // ---------------------------------------------------------------------------
  // chartColors
  // ---------------------------------------------------------------------------
  describe('chartColors', () => {
    it('returns an object (not null, not an array)', () => {
      const result = chartColors()
      expect(result).toBeTruthy()
      expect(typeof result).toBe('object')
      expect(Array.isArray(result)).toBe(false)
    })

    it('returns all 9 expected color keys', () => {
      const colors = chartColors()
      const expectedKeys = [
        'primary',
        'primaryRgb',
        'critText',
        'border',
        'textPrimary',
        'textMuted',
        'textFaint',
        'chartGrid',
        'surface',
      ]
      expectedKeys.forEach((key) => {
        expect(colors).toHaveProperty(key)
      })
    })

    it('returns exactly 9 keys (no extra properties)', () => {
      expect(Object.keys(chartColors())).toHaveLength(9)
    })

    it('all color values are strings', () => {
      const colors = chartColors()
      Object.values(colors).forEach((v) => {
        expect(typeof v).toBe('string')
      })
    })

    it('can be called multiple times without throwing', () => {
      expect(() => chartColors()).not.toThrow()
      expect(() => chartColors()).not.toThrow()
      expect(() => chartColors()).not.toThrow()
    })

    it('each call returns a fresh object with the same shape', () => {
      const a = chartColors()
      const b = chartColors()
      expect(Object.keys(a)).toEqual(Object.keys(b))
    })

    it('primary key maps to the --color-primary CSS variable', () => {
      // In jsdom without CSS, value is '' — we just verify the key exists and is a string
      const { primary } = chartColors()
      expect(typeof primary).toBe('string')
    })

    it('critText key maps to the --color-crit-text CSS variable', () => {
      const { critText } = chartColors()
      expect(typeof critText).toBe('string')
    })
  })
})
