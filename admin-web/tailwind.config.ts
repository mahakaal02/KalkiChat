import type { Config } from 'tailwindcss';

const config: Config = {
  content: ['./src/**/*.{ts,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        bg:      '#0A0E14',
        surface: '#11161F',
        line:    '#1F2937',
        accent:  '#7AE2CF',
        accent2: '#3FB5A1',
        danger:  '#F87171',
      },
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui'],
      },
    },
  },
  plugins: [],
};
export default config;
