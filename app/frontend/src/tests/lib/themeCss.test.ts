import { describe, it, expect } from 'vitest'
import { readFileSync } from 'fs'
import { fileURLToPath } from 'url'
import { dirname, resolve } from 'path'

const __dirname = dirname(fileURLToPath(import.meta.url))

// Read source files directly — jsdom cannot process CSS from disk,
// so we validate token definitions at the source level.
const CSS      = readFileSync(resolve(__dirname, '../../index.css'), 'utf-8')
const TAILWIND = readFileSync(resolve(__dirname, '../../../tailwind.config.js'), 'utf-8')

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Extract the content of the first `selector { … }` block from CSS text.
 * Uses brace-depth counting, so nested blocks are handled correctly.
 */
function extractThemeBlock(selector: string): string {
  const start = CSS.indexOf(selector)
  if (start === -1) return ''
  let depth = 0
  for (let i = start; i < CSS.length; i++) {
    if (CSS[i] === '{') depth++
    else if (CSS[i] === '}' && --depth === 0) return CSS.slice(start, i + 1)
  }
  return CSS.slice(start)
}

const BLOCKS = {
  light:  extractThemeBlock('[data-theme="light"]'),
  dark:   extractThemeBlock('[data-theme="dark"]'),
  matrix: extractThemeBlock('[data-theme="matrix"]'),
}

// ---------------------------------------------------------------------------
// Every CSS variable that must appear in every theme block
// (matches all properties declared in index.css)
// ---------------------------------------------------------------------------
const REQUIRED_VARS = [
  '--color-primary',
  '--color-primary-dark',
  '--color-primary-light',
  '--color-primary-faint',
  '--color-primary-rgb',
  '--color-crit-bg',
  '--color-crit-text',
  '--color-high-bg',
  '--color-high-text',
  '--color-med-bg',
  '--color-med-text',
  '--color-low-bg',
  '--color-low-text',
  '--color-warn-bg',
  '--color-warn-text',
  '--color-resolved-bg',
  '--color-resolved-text',
  '--color-status-ok',
  '--color-status-ok-bg',
  '--color-status-ok-text',
  '--color-status-warn',
  '--color-status-warn-bg',
  '--color-status-warn-text',
  '--color-surface',
  '--color-page',
  '--color-section',
  '--color-border',
  '--color-border-strong',
  '--color-text-primary',
  '--color-text-secondary',
  '--color-text-muted',
  '--color-text-faint',
  '--color-chart-grid',
  '--shadow-card',
  '--shadow-panel',
  '--color-overlay',
]

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('index.css — theme token definitions', () => {

  // ── Tailwind directives ──────────────────────────────────────────────────

  describe('Tailwind directives', () => {
    it('includes @tailwind base',       () => { expect(CSS).toContain('@tailwind base') })
    it('includes @tailwind components', () => { expect(CSS).toContain('@tailwind components') })
    it('includes @tailwind utilities',  () => { expect(CSS).toContain('@tailwind utilities') })
  })

  // ── Selectors ────────────────────────────────────────────────────────────

  describe('theme selectors', () => {
    it('defines [data-theme="light"] selector',  () => { expect(CSS).toContain('[data-theme="light"]') })
    it('defines [data-theme="dark"] selector',   () => { expect(CSS).toContain('[data-theme="dark"]') })
    it('defines [data-theme="matrix"] selector', () => { expect(CSS).toContain('[data-theme="matrix"]') })

    it('light theme also targets :root for no-attribute default', () => {
      expect(CSS).toContain('[data-theme="light"], :root')
    })

    it('all three theme blocks were successfully extracted', () => {
      expect(BLOCKS.light.length).toBeGreaterThan(0)
      expect(BLOCKS.dark.length).toBeGreaterThan(0)
      expect(BLOCKS.matrix.length).toBeGreaterThan(0)
    })
  })

  // ── Per-theme required variables ─────────────────────────────────────────

  ;(['light', 'dark', 'matrix'] as const).forEach((theme) => {
    describe(`${theme} theme — required variables`, () => {
      REQUIRED_VARS.forEach((v) => {
        it(`defines ${v}`, () => {
          expect(BLOCKS[theme]).toContain(v)
        })
      })
    })
  })

  // ── Specific values ──────────────────────────────────────────────────────

  describe('light theme — specific values', () => {
    it('--color-primary is #0066CC',              () => { expect(BLOCKS.light).toContain('--color-primary: #0066CC') })
    it('--color-primary-rgb is 0, 102, 204',      () => { expect(BLOCKS.light).toContain('--color-primary-rgb: 0, 102, 204') })
    it('--color-surface is #FFFFFF (white)',       () => { expect(BLOCKS.light).toContain('--color-surface: #FFFFFF') })
    it('--color-text-primary is #1C2D40 (dark)',  () => { expect(BLOCKS.light).toContain('--color-text-primary: #1C2D40') })
    it('--color-page is #F4F6F8 (light gray)',    () => { expect(BLOCKS.light).toContain('--color-page: #F4F6F8') })
  })

  describe('dark theme — specific values', () => {
    it('--color-primary is #3B8EEA',                     () => { expect(BLOCKS.dark).toContain('--color-primary: #3B8EEA') })
    it('--color-primary-rgb is 59, 142, 234',            () => { expect(BLOCKS.dark).toContain('--color-primary-rgb: 59, 142, 234') })
    it('--color-surface is #1A1D22 (dark panel)',         () => { expect(BLOCKS.dark).toContain('--color-surface: #1A1D22') })
    it('--color-text-primary is #E8ECF2 (light on dark)', () => { expect(BLOCKS.dark).toContain('--color-text-primary: #E8ECF2') })
    it('--color-page is #111318 (dark background)',       () => { expect(BLOCKS.dark).toContain('--color-page: #111318') })
  })

  describe('matrix theme — specific values', () => {
    it('--color-primary is #00FF41 (matrix green)',    () => { expect(BLOCKS.matrix).toContain('--color-primary: #00FF41') })
    it('--color-primary-rgb is 0, 255, 65',           () => { expect(BLOCKS.matrix).toContain('--color-primary-rgb: 0, 255, 65') })
    it('--color-surface is #0A0A0A (near black)',      () => { expect(BLOCKS.matrix).toContain('--color-surface: #0A0A0A') })
    it('--color-text-primary is #00FF41 (green text)', () => { expect(BLOCKS.matrix).toContain('--color-text-primary: #00FF41') })
    it('--color-page is #050505 (darkest background)', () => { expect(BLOCKS.matrix).toContain('--color-page: #050505') })
  })

  // ── Distinctness across themes ───────────────────────────────────────────

  describe('themes have distinct primary colors', () => {
    function getPrimary(block: string): string {
      return (block.match(/--color-primary:\s*([^;]+);/) ?? [])[1]?.trim() ?? ''
    }

    it('light ≠ dark',   () => { expect(getPrimary(BLOCKS.light)).not.toBe(getPrimary(BLOCKS.dark)) })
    it('dark ≠ matrix',  () => { expect(getPrimary(BLOCKS.dark)).not.toBe(getPrimary(BLOCKS.matrix)) })
    it('light ≠ matrix', () => { expect(getPrimary(BLOCKS.light)).not.toBe(getPrimary(BLOCKS.matrix)) })
  })

  // ── Base styles ──────────────────────────────────────────────────────────

  describe('@layer base', () => {
    it('sets html font-size to 14px',                  () => { expect(CSS).toContain('font-size: 14px') })
    it('applies font-mono override for matrix theme',  () => {
      expect(CSS).toContain('[data-theme="matrix"] body')
      expect(CSS).toContain('font-mono')
    })
    it('sets box-sizing: border-box globally',         () => { expect(CSS).toContain('box-sizing: border-box') })
  })

  // ── Tailwind ↔ CSS-var integration ───────────────────────────────────────
  // Every var(--…) reference in tailwind.config.js must be defined in each
  // theme block so Tailwind utilities resolve correctly for all themes.

  describe('tailwind.config.js — CSS variable references', () => {
    const tailwindVarRefs = [
      ...TAILWIND.matchAll(/var\((--[^)]+)\)/g),
    ].map((m) => m[1])

    it('tailwind.config.js references at least one CSS variable', () => {
      expect(tailwindVarRefs.length).toBeGreaterThan(0)
    })

    it('all var() references are defined in the light theme block', () => {
      tailwindVarRefs.forEach((varName) => {
        expect(BLOCKS.light, `${varName} missing from light theme`).toContain(varName)
      })
    })

    it('all var() references are defined in the dark theme block', () => {
      tailwindVarRefs.forEach((varName) => {
        expect(BLOCKS.dark, `${varName} missing from dark theme`).toContain(varName)
      })
    })

    it('all var() references are defined in the matrix theme block', () => {
      tailwindVarRefs.forEach((varName) => {
        expect(BLOCKS.matrix, `${varName} missing from matrix theme`).toContain(varName)
      })
    })
  })
})
