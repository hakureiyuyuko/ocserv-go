import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// 产物直接输出到 Go 包里的 webdist/，由 go:embed 打进二进制
export default defineConfig({
  plugins: [vue()],
  build: { outDir: '../ocserv-go/panel/webdist', emptyOutDir: true },
  server: { proxy: { '/api': 'http://127.0.0.1:19999' } }
})
