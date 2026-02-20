/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        // Primary
        blue: {
          DEFAULT: 'var(--color-primary)',
          dark: 'var(--color-primary-dark)',
          light: 'var(--color-primary-light)',
          faint: 'var(--color-primary-faint)',
        },
        // Severity
        crit: { bg: 'var(--color-crit-bg)', text: 'var(--color-crit-text)' },
        high: { bg: 'var(--color-high-bg)', text: 'var(--color-high-text)' },
        med:  { bg: 'var(--color-med-bg)',  text: 'var(--color-med-text)' },
        low:  { bg: 'var(--color-low-bg)',  text: 'var(--color-low-text)' },
        warn: { bg: 'var(--color-warn-bg)', text: 'var(--color-warn-text)' },
        // Status
        resolved: { bg: 'var(--color-resolved-bg)', text: 'var(--color-resolved-text)' },
        'status-ok':   { DEFAULT: 'var(--color-status-ok)',   bg: 'var(--color-status-ok-bg)',   text: 'var(--color-status-ok-text)' },
        'status-warn': { DEFAULT: 'var(--color-status-warn)', bg: 'var(--color-status-warn-bg)', text: 'var(--color-status-warn-text)' },
        // Neutrals
        surface: 'var(--color-surface)',
        page: 'var(--color-page)',
        section: 'var(--color-section)',
        border: 'var(--color-border)',
        'border-strong': 'var(--color-border-strong)',
        'text-primary': 'var(--color-text-primary)',
        'text-secondary': 'var(--color-text-secondary)',
        'text-muted': 'var(--color-text-muted)',
        'text-faint': 'var(--color-text-faint)',
        'chart-grid': 'var(--color-chart-grid)',
        overlay: 'var(--color-overlay)',
      },
      fontFamily: {
        sans: ['"Segoe UI"', 'Inter', '-apple-system', 'sans-serif'],
        mono: ['"JetBrains Mono"', '"Fira Code"', 'monospace'],
      },
      boxShadow: {
        card: 'var(--shadow-card)',
        panel: 'var(--shadow-panel)',
      },
    },
  },
  plugins: [],
}
