/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        briar: {
          // ── Carbon Pro palette ───────────────────────────────────────────
          // Warm near-black backgrounds (slight brown undertone, not cold navy)
          bg:             '#111010',
          surface:        '#1c1a1a',
          'surface-2':    '#242121',
          border:         '#2e2b2b',
          'border-light': '#3a3636',
          // Amber — primary brand accent
          accent:         '#f59e0b',
          'accent-hover': '#d97706',
          'accent-muted': 'rgba(245,158,11,0.12)',
          'accent-glow':  'rgba(245,158,11,0.20)',
          // Semantic
          success:        '#10b981',
          danger:         '#ef4444',
          warn:           '#f97316',
          caution:        '#eab308',
          info:           '#38bdf8',
        },
      },
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'monospace'],
      },
      animation: {
        'pulse-slow': 'pulse 2.5s cubic-bezier(0.4,0,0.6,1) infinite',
      },
    },
  },
  plugins: [],
}
