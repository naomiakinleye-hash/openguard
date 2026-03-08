import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  build: {
    // Output to ../services/console-api/ui so Go can embed it
    outDir: '../services/console-api/ui',
    emptyOutDir: true,
  },
  server: {
    proxy: {
      // SSE stream — disable response buffering so frames arrive immediately.
      '/api/v1/events/stream': {
        target: 'http://localhost:8080',
        changeOrigin: true,
        // Prevent Vite from buffering the SSE response.
        configure: (proxy) => {
          proxy.on('proxyRes', (proxyRes) => {
            proxyRes.headers['cache-control'] = 'no-cache';
          });
        },
      },
      '/api': 'http://localhost:8080',
      '/health': 'http://localhost:8080',
    },
  },
})

