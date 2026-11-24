/** @type {import('tailwindcss').Config} */
import animate from 'tailwindcss-animate'

export default {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      borderRadius: {
        lg: 'var(--radius)',
        md: 'calc(var(--radius) - 2px)',
        sm: 'calc(var(--radius) - 4px)',
      },
      colors: {
        // Design tokens (same system as the KYRA MDR console)
        background: 'hsl(var(--background))',
        foreground: 'hsl(var(--foreground))',
        card: { DEFAULT: 'hsl(var(--card))', foreground: 'hsl(var(--card-foreground))' },
        popover: { DEFAULT: 'hsl(var(--popover))', foreground: 'hsl(var(--popover-foreground))' },
        primary: { DEFAULT: 'hsl(var(--primary))', foreground: 'hsl(var(--primary-foreground))' },
        secondary: { DEFAULT: 'hsl(var(--secondary))', foreground: 'hsl(var(--secondary-foreground))' },
        muted: { DEFAULT: 'hsl(var(--muted))', foreground: 'hsl(var(--muted-foreground))' },
        accent: { DEFAULT: 'hsl(var(--accent))', foreground: 'hsl(var(--accent-foreground))' },
        destructive: { DEFAULT: 'hsl(var(--destructive))', foreground: 'hsl(var(--destructive-foreground))' },
        border: 'hsl(var(--border))',
        input: 'hsl(var(--input))',
        ring: 'hsl(var(--ring))',
        // Legacy names: removed once every page uses the tokens above
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
        'border-strong': 'var(--color-border-strong)',
        'text-primary': 'var(--color-text-primary)',
        'text-secondary': 'var(--color-text-secondary)',
        'text-muted': 'var(--color-text-muted)',
        'text-faint': 'var(--color-text-faint)',
        'chart-grid': 'var(--color-chart-grid)',
        overlay: 'var(--color-overlay)',
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '"Segoe UI"', 'sans-serif'],
        mono: ['"JetBrains Mono"', '"Fira Code"', 'monospace'],
      },
      boxShadow: {
        card: 'var(--shadow-card)',
        panel: 'var(--shadow-panel)',
      },
    },
  },
  plugins: [animate],
}
