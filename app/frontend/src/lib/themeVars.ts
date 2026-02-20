/**
 * Read CSS custom property values for use in JS (e.g. Recharts props).
 * Call inside a component — reads from :root computed style.
 */
export function cssVar(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim()
}

/** Commonly needed chart colors derived from CSS variables. */
export function chartColors() {
  return {
    primary:      cssVar('--color-primary'),
    primaryRgb:   cssVar('--color-primary-rgb'),
    critText:     cssVar('--color-crit-text'),
    border:       cssVar('--color-border'),
    textPrimary:  cssVar('--color-text-primary'),
    textMuted:    cssVar('--color-text-muted'),
    textFaint:    cssVar('--color-text-faint'),
    chartGrid:    cssVar('--color-chart-grid'),
    surface:      cssVar('--color-surface'),
  }
}
