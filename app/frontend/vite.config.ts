import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { fileURLToPath, URL } from 'node:url'

// Backend the dev server forwards /api to. The default is the port the backend
// is published on by app/docker-compose.yml; inside that Compose network the
// frontend service sets VITE_PROXY_TARGET=http://backend:8080.
const proxyTarget = process.env.VITE_PROXY_TARGET || 'http://localhost:15000'

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
  },
  server: {
    port: 5173,
    allowedHosts: ['mxtac.seekerslab.com', 'localhost'],
    proxy: {
      // REST API and the alert WebSocket (/api/v1/ws/alerts) share this prefix.
      '/api': {
        target: proxyTarget,
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
