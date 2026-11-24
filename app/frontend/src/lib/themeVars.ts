/** Read a CSS custom property from :root, for use in JS (for example Recharts props). */
export function cssVar(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim()
}

const hsl = (name: string) => `hsl(${cssVar(name)})`

/** Chart colours from the design tokens. Call inside a component so a theme change re-reads them. */
export function chartColors() {
  return {
    primary: hsl('--primary'),
    critText: cssVar('--sev-critical-text'),
    border: hsl('--border'),
    textPrimary: hsl('--foreground'),
    textMuted: hsl('--muted-foreground'),
    textFaint: hsl('--muted-foreground'),
    chartGrid: hsl('--border'),
    surface: hsl('--card'),
    series: [1, 2, 3, 4, 5].map((i) => hsl(`--chart-${i}`)),
  }
}
