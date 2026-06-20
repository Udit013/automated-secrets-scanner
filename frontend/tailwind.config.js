/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Geist', 'system-ui', 'sans-serif'],
        mono: ['"Geist Mono"', 'ui-monospace', 'SFMono-Regular', 'monospace'],
      },
      colors: {
        // GitHub-style high-contrast dark surfaces. Existing markup uses the
        // Tailwind gray scale, so we remap it to the enterprise palette.
        gray: {
          950: '#0D1117', // app background
          900: '#161B22', // cards
          850: '#1C2128', // elevated surfaces
          800: '#21262D', // hover / inset surfaces
          700: '#30363D', // borders
          600: '#484F58', // muted icons
          500: '#8B949E', // secondary text
          400: '#8B949E', // secondary text
          300: '#C9D1D9', // body text
          200: '#E6EDF3',
          100: '#F0F6FC', // primary text
        },
        brand: {
          50: '#cae8ff',
          100: '#a5d6ff',
          400: '#79C0FF', // accent hover
          500: '#58A6FF', // accent
          600: '#388BFD',
          700: '#1F6FEB',
          900: '#0d2d6b',
        },
        sev: {
          critical: '#F85149',
          high: '#FF7B72',
          medium: '#D29922',
          low: '#3FB950',
        },
      },
      borderRadius: {
        DEFAULT: '6px',
        lg: '6px',
        xl: '8px',
      },
    },
  },
  plugins: [],
}
