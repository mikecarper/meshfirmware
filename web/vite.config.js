import { defineConfig } from 'vite';
export default defineConfig({
  base: './',
  build: { target: 'es2022', sourcemap: false },
  optimizeDeps: { exclude: ['@probe-web/client'] },
  worker: { format: 'es' },
});
