import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import tailwindcss from '@tailwindcss/vite'

// the built UI goes into the Go binary, see internal/admin
export default defineConfig({
  plugins: [vue(), tailwindcss()],
  build: {
    outDir: '../internal/admin/ui/dist',
    emptyOutDir: true,
  },
  server: {
    // npm run dev, with the server started with -admin-tls=false -admin-listen 127.0.0.1:8443
    proxy: { '/api': 'http://127.0.0.1:8443' },
  },
})
