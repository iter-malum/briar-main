import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Proxy targets: when running inside Docker, use service names.
// When developing locally (outside Docker), fall back to localhost ports.
//
// Set API_TARGET / WS_TARGET env vars in docker-compose to override.
// Note: these are NOT VITE_* so they are NOT injected into the browser bundle.
const API_TARGET = process.env.API_TARGET || 'http://localhost:8000'
const WS_TARGET  = process.env.WS_TARGET  || 'ws://localhost:8003'

export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    port: 3000,
    proxy: {
      // All REST API calls go through the gateway.
      // Gateway then routes to orchestrator / ui-service / integration-service.
      '/api': {
        target: API_TARGET,
        changeOrigin: true,
      },
      // WebSocket connections go directly to ui-service
      // (httpx in gateway doesn't support WebSocket upgrade).
      '/ws': {
        target: WS_TARGET,
        ws: true,
        changeOrigin: true,
      },
    },
  },
})
