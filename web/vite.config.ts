import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { fileURLToPath, URL } from 'node:url'

/**
 * Build du module Calendar en bundle ESM autonome :
 *   npm run build  →  dist/{entry.js, entry.css, chunks/*}
 *
 * Tous les specifiers fournis par le host (react, zustand, i18next, @ui,
 * @kubuno/sdk…) sont `external` : au runtime, l'import map du host les résout
 * vers ses instances uniques. `entry.js` exporte `register()` + `sdkVersion`.
 * `lucide-react`, `date-fns`, `dompurify` sont bundlés (consomment le React
 * partagé via l'external `react`).
 */
const SHARED = new Set([
  'react', 'react-dom', 'react-dom/client',
  'react/jsx-runtime', 'react/jsx-dev-runtime',
  'react-router-dom', '@tanstack/react-query',
  'zustand', 'react-i18next', 'i18next',
  '@ui', '@kubuno/sdk', '@kubuno/drive',
  '@radix-ui/react-dropdown-menu',
])
const isExternal = (s: string) =>
  SHARED.has(s) || s.startsWith('@ui/') || s.startsWith('@kubuno/sdk/') || s.startsWith('@kubuno/drive/')

// Les specifiers partagés ci-dessus sont `external` : jamais bundlés, résolus au
// runtime par l'import map du host. Les TYPES viennent des paquets npm
// @kubuno/sdk / @kubuno/ui / @kubuno/drive (cf. tsconfig.json `paths` pour `@ui`,
// dont le specifier diffère du nom de paquet). Plus aucun alias vers un checkout
// kubuno-core voisin n'est nécessaire.
export default defineConfig({
  base: './',
  plugins: [react(), tailwindcss()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    cssCodeSplit: false,
    rollupOptions: {
      input: fileURLToPath(new URL('./src/entry.ts', import.meta.url)),
      external: isExternal,
      preserveEntrySignatures: 'strict',
      output: {
        format: 'es',
        entryFileNames: 'entry.js',
        chunkFileNames: 'chunks/[name]-[hash].js',
        assetFileNames: (info: { name?: string }) =>
          info.name?.endsWith('.css') ? 'entry.css' : 'assets/[name][extname]',
      },
    },
  },
})
