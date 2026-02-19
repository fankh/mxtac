/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        // Primary
        blue: {
          DEFAULT: '#0066CC',
          dark: '#0055AA',
          light: '#EBF3FF',
          faint: '#F0F6FF',
        },
        // Severity
        crit: { bg: '#FDECEA', text: '#CC3333' },
        high: { bg: '#FEF3E2', text: '#CC6600' },
        med:  { bg: '#EBF2FF', text: '#0055AA' },
        low:  { bg: '#F4F6F8', text: '#A0AABB' },
        // Status
        resolved: { bg: '#EBF5EB', text: '#2E7D32' },
        // Neutrals
        surface: '#FFFFFF',
        page: '#F4F6F8',
        section: '#F9FAFB',
        border: '#E8ECF0',
        'border-strong': '#DDE3EB',
        'text-primary': '#1C2D40',
        'text-secondary': '#5A6B82',
        'text-muted': '#A0AABB',
        'text-faint': '#C8D0DC',
      },
      fontFamily: {
        sans: ['"Segoe UI"', 'Inter', '-apple-system', 'sans-serif'],
        mono: ['"JetBrains Mono"', '"Fira Code"', 'monospace'],
      },
      boxShadow: {
        card: '0 1px 2px rgba(0,0,0,0.05)',
        panel: '-2px 0 10px rgba(0,0,0,0.08)',
      },
    },
  },
  plugins: [],
}
