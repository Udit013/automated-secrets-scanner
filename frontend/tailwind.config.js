/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    // Replace Tailwind's palette entirely: every color in the app is a
    // deliberate token. Severity is the ONLY place hue carries meaning.
    colors: {
      transparent: 'transparent',
      current: 'currentColor',

      // Ink — warm near-black surface steps (no borders-as-boxes; depth
      // comes from background steps and hairline rules).
      ink: {
        DEFAULT: '#101014', // app canvas
        raised: '#17171C', // panels, table headers
        overlay: '#1E1E24', // hover, expanded rows
        inset: '#0B0B0E', // wells: code, inputs
      },

      // Hairlines
      line: {
        DEFAULT: '#26262C',
        strong: '#3B3B44',
      },

      // Ivory text ramp — warm, not blue-gray
      ivory: {
        DEFAULT: '#ECEAE6', // primary text & interactive accent
        dim: '#A8A5A0', // secondary text
        mute: '#888681', // tertiary — 4.5:1+ on every ink surface (WCAG AA)
        faint: '#3E3D39', // decorative glyphs
      },

      // Severity — status palette. Shipped with text labels, never
      // color alone. CVD-separation and contrast validated on #101014.
      sev: {
        critical: '#F2545B',
        high: '#EE7A3B',
        medium: '#D9A514',
        low: '#7E9CC9',
      },

      ok: '#57AB5A', // resolved / clean / success
    },
    fontFamily: {
      sans: ['"Instrument Sans"', 'system-ui', 'sans-serif'],
      mono: ['"IBM Plex Mono"', 'ui-monospace', 'monospace'],
    },
    borderRadius: {
      none: '0',
      sm: '2px',
      DEFAULT: '3px',
      full: '9999px',
    },
    extend: {
      fontSize: {
        '2xs': ['0.6875rem', '1rem'], // 11px — table meta, mono annotations
      },
      letterSpacing: {
        kicker: '0.12em',
      },
      maxWidth: {
        page: '72rem',
      },
    },
  },
  plugins: [],
}
