/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Palette: Deep blacks, Cyan, Neon Green, Tinted Blues
        'dark-bg': '#0a0f1a',
        'dark-surface': '#1c2333',
        'cyber-cyan': '#00ffea',
        'neon-green': '#39ff14',
        'deep-blue': '#0d3b66',
        'accent-blue': '#0077FF',
        'text-primary': '#e0e0e0',
      },
      fontFamily: {
        sans: ['"Exo 2"', 'sans-serif'], // Futuristic headings
        mono: ['"Fira Code"', 'monospace'], // Technical content
      },
      keyframes: {
        // Subtle glitch effect
        glitch: {
          '0%': { transform: 'translate(0)' },
          '20%': { transform: 'translate(-2px, 2px)' },
          '40%': { transform: 'translate(2px, -2px)' },
          '60%': { transform: 'translate(-2px, -2px)' },
          '80%': { transform: 'translate(2px, 2px)' },
          '100%': { transform: 'translate(0)' },
        },
        // Ambient flicker
        flicker: {
          '0%, 100%': { opacity: 1 },
          '50%': { opacity: 0.7 },
        }
      },
      animation: {
        'glitch-short': 'glitch 0.5s linear both',
        flicker: 'flicker 5s linear infinite',
      },
      boxShadow: {
        'glow-cyan': '0 0 12px rgba(0, 255, 234, 0.5)',
        'glow-green': '0 0 12px rgba(57, 255, 20, 0.5)',
        'glow-blue': '0 0 12px rgba(0, 119, 255, 0.5)',
        'glow-red': '0 0 15px rgba(255, 0, 0, 0.6)',
     },
    },
  },
  plugins: [],
}
