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
        // Severity and status (values in src/index.css)
        crit: { bg: 'var(--sev-critical-bg)', text: 'var(--sev-critical-text)', border: 'var(--sev-critical-border)' },
        high: { bg: 'var(--sev-high-bg)', text: 'var(--sev-high-text)', border: 'var(--sev-high-border)' },
        med: { bg: 'var(--sev-medium-bg)', text: 'var(--sev-medium-text)', border: 'var(--sev-medium-border)' },
        low: { bg: 'var(--sev-low-bg)', text: 'var(--sev-low-text)', border: 'var(--sev-low-border)' },
        info: { bg: 'var(--sev-info-bg)', text: 'var(--sev-info-text)', border: 'var(--sev-info-border)' },
        warn: { bg: 'var(--sev-medium-bg)', text: 'var(--sev-medium-text)', border: 'var(--sev-medium-border)' },
        resolved: { bg: 'var(--status-green-bg)', text: 'var(--status-green-text)', border: 'var(--status-green-border)' },
        'status-ok': { DEFAULT: '#22c55e', bg: 'var(--status-green-bg)', text: 'var(--status-green-text)', border: 'var(--status-green-border)' },
        'status-warn': { DEFAULT: '#f59e0b', bg: 'var(--sev-medium-bg)', text: 'var(--sev-medium-text)', border: 'var(--sev-medium-border)' },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '"Segoe UI"', 'sans-serif'],
        mono: ['"JetBrains Mono"', '"Fira Code"', 'monospace'],
      },
    },
  },
  plugins: [animate],
}
