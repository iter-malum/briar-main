/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        briar: {
          bg: '#0f1117',
          surface: '#1a1d27',
          border: '#2a2d3e',
          accent: '#6366f1',
          'accent-hover': '#4f46e5',
        },
      },
    },
  },
  plugins: [],
}
