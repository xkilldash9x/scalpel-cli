// frontend/vite.config.ts
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      // Proxy WebSocket requests during development
      '/ws': {
        target: 'ws://127.0.0.1:8080', // Assuming Go backend runs on 8080
        ws: true,
        changeOrigin: true,
      },
    }
  }
})