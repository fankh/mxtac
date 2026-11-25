import { describe, it, expect, afterEach } from 'vitest'
import { cssVar, chartColors } from '../../lib/themeVars'

const root = document.documentElement

describe('themeVars', () => {
  afterEach(() => {
    root.removeAttribute('style')
  })

  describe('cssVar', () => {
    it('reads a custom property from :root and trims it', () => {
      root.style.setProperty('--primary', '  221 83% 53%  ')
      expect(cssVar('--primary')).toBe('221 83% 53%')
    })

    it('returns an empty string for a property that is not set', () => {
      expect(cssVar('--non-existent-variable')).toBe('')
    })
  })

  describe('chartColors', () => {
    it('wraps the HSL design tokens in hsl()', () => {
      root.style.setProperty('--primary', '221 83% 53%')
      root.style.setProperty('--border', '214 32% 91%')
      root.style.setProperty('--foreground', '222 47% 11%')
      root.style.setProperty('--muted-foreground', '215 16% 47%')
      root.style.setProperty('--card', '0 0% 100%')

      expect(chartColors()).toMatchObject({
        primary: 'hsl(221 83% 53%)',
        border: 'hsl(214 32% 91%)',
        chartGrid: 'hsl(214 32% 91%)',
        textPrimary: 'hsl(222 47% 11%)',
        textMuted: 'hsl(215 16% 47%)',
        textFaint: 'hsl(215 16% 47%)',
        surface: 'hsl(0 0% 100%)',
      })
    })

    it('uses the critical severity colour as it is', () => {
      root.style.setProperty('--sev-critical-text', '#b91c1c')
      expect(chartColors().critText).toBe('#b91c1c')
    })

    it('returns the five chart series colours in order', () => {
      for (const i of [1, 2, 3, 4, 5]) root.style.setProperty(`--chart-${i}`, `${i}0 50% 50%`)
      expect(chartColors().series).toEqual([
        'hsl(10 50% 50%)', 'hsl(20 50% 50%)', 'hsl(30 50% 50%)', 'hsl(40 50% 50%)', 'hsl(50 50% 50%)',
      ])
    })

    it('re-reads the tokens on every call, so a theme change is picked up', () => {
      root.style.setProperty('--primary', '221 83% 53%')
      expect(chartColors().primary).toBe('hsl(221 83% 53%)')
      root.style.setProperty('--primary', '217 91% 60%')
      expect(chartColors().primary).toBe('hsl(217 91% 60%)')
    })
  })
})
