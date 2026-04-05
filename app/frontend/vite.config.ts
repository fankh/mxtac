import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    allowedHosts: ['mxtac.seekerslab.com', 'localhost'],
    proxy: {
      '/api': {
        target: 'http://backend:8080',
        changeOrigin: true,
      },
      '/ingest': {
        target: 'http://backend:8080',
        changeOrigin: true,
      },
      '/ws': {
        target: 'http://backend:8080',
        changeOrigin: true,
        ws: true,
      },
    },
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./src/tests/setup.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html'],
      include: ['src/**/*.{ts,tsx}'],
      exclude: [
        'src/tests/**',
        'src/main.tsx',
        'src/types/**',
      ],
    },
  },
})
