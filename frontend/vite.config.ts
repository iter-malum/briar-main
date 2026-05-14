import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    port: 3000,
    proxy: {
      '/api': {
        target: process.env.VITE_UI_API_URL || 'http://localhost:8003',
        changeOrigin: true,
      },
      '/ws': {
        target: (process.env.VITE_UI_API_URL || 'http://localhost:8003').replace('http', 'ws'),
        ws: true,
        changeOrigin: true,
      },
    },
  },
})
