import type { Config } from 'tailwindcss';

const config: Config = {
  content: [
    './app/**/*.{js,ts,jsx,tsx}',
    './components/**/*.{js,ts,jsx,tsx}',
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // ── Theme-adaptive semantic tokens (CSS variables) ─────────────────
        'bg-canvas':                'rgb(var(--bg-canvas) / <alpha-value>)',
        'bg-surface':               'rgb(var(--bg-surface) / <alpha-value>)',
        'bg-bg-canvas':             'rgb(var(--bg-canvas) / <alpha-value>)',
        'bg-bg-surface':            'rgb(var(--bg-surface) / <alpha-value>)',
        'border-grid':              'rgb(var(--border-grid) / <alpha-value>)',
        'border-border-grid':       'rgb(var(--border-grid) / <alpha-value>)',
        'on-surface':               'rgb(var(--on-surface) / <alpha-value>)',
        'on-surface-variant':       'rgb(var(--on-surface-variant) / <alpha-value>)',
        'text-primary':             'rgb(var(--text-primary) / <alpha-value>)',
        'text-muted':               'rgb(var(--text-muted) / <alpha-value>)',
        'primary':                  'rgb(var(--primary) / <alpha-value>)',
        'secondary':                'rgb(var(--secondary) / <alpha-value>)',
        'tertiary':                 'rgb(var(--tertiary) / <alpha-value>)',
        'on-primary':               'rgb(var(--on-primary) / <alpha-value>)',
        'surface-container':        'rgb(var(--surface-container) / <alpha-value>)',
        'surface-container-low':    'rgb(var(--surface-container-low) / <alpha-value>)',
        'surface-container-high':   'rgb(var(--surface-container-high) / <alpha-value>)',
        'surface-container-highest':'rgb(var(--surface-container-highest) / <alpha-value>)',
        'surface-bright':           'rgb(var(--surface-bright) / <alpha-value>)',
        'outline-variant':          'rgb(var(--outline-variant) / <alpha-value>)',

        // ── Fixed status / accent colors ───────────────────────────────────
        'accent-safe':     '#10B981',
        'accent-warning':  '#F59E0B',
        'accent-critical': '#F43F5E',
        'accent-info':     '#3B82F6',
        'error':           '#fb7185',

        // ── Legacy aliases for backward compat ─────────────────────────────
        'surface':                  'rgb(var(--bg-surface) / <alpha-value>)',
        'surface-dim':              'rgb(var(--bg-canvas) / <alpha-value>)',
        'background-obsidian':      'rgb(var(--bg-canvas) / <alpha-value>)',
        'status-critical':          '#F43F5E',
      },

      fontFamily: {
        sans:        ['var(--font-geist)', 'Inter', 'system-ui', 'sans-serif'],
        mono:        ['var(--font-mono)', 'JetBrains Mono', 'SF Mono', 'monospace'],
        'label-caps':['var(--font-geist)', 'Inter', 'system-ui', 'sans-serif'],
        'data-mono': ['var(--font-mono)', 'JetBrains Mono', 'monospace'],
        terminal:    ['var(--font-fira)', 'Fira Code', 'JetBrains Mono', 'monospace'],
      },

      fontSize: {
        'label-caps': ['10px', { letterSpacing: '0.08em', fontWeight: '600' }],
      },

      borderRadius: {
        DEFAULT: '6px',
        'none': '0px',
        'sm':   '4px',
        'md':   '6px',
        'lg':   '8px',
        'xl':   '12px',
        '2xl':  '16px',
        'full': '9999px',
      },

      spacing: {
        'header-height':    '52px',
        'sidebar-width':    '280px',
        'grid-unit':        '6px',
        'margin-sm':        '12px',
        'margin-lg':        '24px',
        'element-gap':      '8px',
        'container-padding':'16px',
      },

      boxShadow: {
        'card':       '0 1px 3px rgba(0,0,0,0.06), 0 1px 2px rgba(0,0,0,0.04)',
        'card-md':    '0 4px 12px rgba(0,0,0,0.08)',
        'modal':      '0 24px 64px rgba(0,0,0,0.28)',
        'panel':      '-8px 0 32px rgba(0,0,0,0.12)',
      },

      animation: {
        'fade-in':        'fadeIn 0.2s ease-out',
        'slide-up':       'slideUp 0.25s ease-out',
        'slide-in-right': 'slideInRight 0.25s cubic-bezier(0.16,1,0.3,1)',
        'blink':          'blink 1s infinite',
        'scan':           'scan 4s linear infinite',
      },

      keyframes: {
        fadeIn:        { from: { opacity: '0' },                          to: { opacity: '1' } },
        slideUp:       { from: { opacity: '0', transform: 'translateY(10px)' }, to: { opacity: '1', transform: 'translateY(0)' } },
        slideInRight:  { from: { transform: 'translateX(100%)' },         to: { transform: 'translateX(0)' } },
        blink:         { '0%,100%': { opacity: '1' }, '50%': { opacity: '0' } },
        scan:          { '0%': { top: '0%' }, '100%': { top: '100%' } },
      },
    },
  },
  plugins: [],
};

export default config;
