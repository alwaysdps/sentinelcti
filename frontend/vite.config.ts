import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    // Vite rejects requests whose Host header it does not recognise (a DNS
    // rebinding defence). A Cloudflare Quick Tunnel arrives as
    // *.trycloudflare.com, so without this the tunnel returns "Blocked
    // request" instead of the app. Dev-server only -- the Docker image serves
    // static files through nginx and is unaffected.
    allowedHosts: ['.trycloudflare.com'],
    // The frontend talks to a same-origin "/api" path in every environment.
    // In dev this proxy points it at the local backend; in Docker/production
    // the reverse proxy does the same job. Keeping the app's base URL relative
    // means no build-time API host baked into the bundle.
    proxy: {
      '/api': {
        target: process.env.VITE_API_TARGET ?? 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    rollupOptions: {
      output: {
        // Recharts and its d3 dependencies are roughly two thirds of the
        // bundle and change far less often than application code, so they get
        // their own long-lived cache entry.
        manualChunks: {
          charts: ['recharts'],
          vendor: ['react', 'react-dom', 'react-router-dom'],
        },
      },
    },
  },
});
