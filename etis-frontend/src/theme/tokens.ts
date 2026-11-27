/**
 * ETIS console design tokens (docs/design/console-redesign-v1.md).
 *
 * Calm navy/slate base, one teal accent, soft neutrals. Verdict colours
 * carry meaning only: LOW teal-green, MEDIUM amber, HIGH muted red.
 * `text` verdict values meet WCAG AA (>= 4.5:1) on both `surface` and
 * their own `tint`; `solid` values are for graphics (mascot body, rings).
 */
export type ColorMode = 'light' | 'dark';
export type VerdictKey = 'LOW' | 'MEDIUM' | 'HIGH';

export interface VerdictTone { text: string; solid: string; tint: string; border: string }

export interface ModeTokens {
  bg: string;
  surface: string;
  surface2: string;
  border: string;
  text: string;
  textMuted: string;
  navy: string;
  onNavy: string;
  accentOnNavy: string;
  accent: string;
  onAccent: string;
  accentSoft: string;
  incomplete: string;
  visor: string;
  eye: string;
  verdict: Record<VerdictKey, VerdictTone>;
}

export const TOKENS: Record<ColorMode, ModeTokens> = {
  light: {
    bg: '#F4F6F9',
    surface: '#FFFFFF',
    surface2: '#EEF2F6',
    border: '#D8E0EA',
    text: '#0F1B2D',
    textMuted: '#4A5A70',
    navy: '#14304F',
    onNavy: '#FFFFFF',
    accentOnNavy: '#5EEAD4',
    accent: '#0F766E',
    onAccent: '#FFFFFF',
    accentSoft: '#E3F3F1',
    incomplete: '#52606F',
    visor: '#0F1B2D',
    eye: '#E6FFFB',
    verdict: {
      LOW: { text: '#1D7357', solid: '#2A8C6A', tint: '#E7F4EF', border: '#A9D8C6' },
      MEDIUM: { text: '#8F5500', solid: '#C98A1B', tint: '#FBF1E0', border: '#EDCB8E' },
      HIGH: { text: '#A93A3A', solid: '#B9494A', tint: '#FAECEC', border: '#E7B3B3' },
    },
  },
  dark: {
    bg: '#0B1424',
    surface: '#111C2E',
    surface2: '#17253A',
    border: '#24364F',
    text: '#E6EDF5',
    textMuted: '#A3B3C7',
    navy: '#0E1A2B',
    onNavy: '#E6EDF5',
    accentOnNavy: '#4CC9B8',
    accent: '#4CC9B8',
    onAccent: '#0B1424',
    accentSoft: '#13302F',
    incomplete: '#94A3B8',
    visor: '#0B1424',
    eye: '#E6FFFB',
    verdict: {
      LOW: { text: '#5CCB9F', solid: '#4DB98E', tint: '#13312C', border: '#2C6B57' },
      MEDIUM: { text: '#E9B45A', solid: '#E0A443', tint: '#30291A', border: '#6E5526' },
      HIGH: { text: '#F08A84', solid: '#E06F6A', tint: '#33202A', border: '#73393F' },
    },
  },
};

/** Motion: three durations, two easings. Reduced motion turns movement into fades. */
export const MOTION = {
  fast: 150,
  base: 220,
  slow: 300,
  scanCycle: 2400,
  easeStandard: 'cubic-bezier(0.2, 0, 0, 1)',
  easeExit: 'cubic-bezier(0.4, 0, 1, 1)',
} as const;

/** Type scale in px (Cairo for Arabic + Latin, IBM Plex Mono for data). */
export const TYPE_SCALE = { caption: 12, small: 13, body: 15, lead: 18, h3: 22, h2: 28, h1: 34 } as const;

/** 4 px spacing base; MUI spacing(1) = 4 px in the console theme. */
export const SPACE = [0, 4, 8, 12, 16, 24, 32, 48, 64] as const;

export const RADIUS = { sm: 8, md: 12, lg: 16 } as const;

/** CSS custom properties consumed by src/design/motion.css. */
export function cssVars(mode: ColorMode): Record<string, string> {
  const t = TOKENS[mode];
  return {
    '--etis-bg': t.bg,
    '--etis-surface': t.surface,
    '--etis-surface2': t.surface2,
    '--etis-border': t.border,
    '--etis-text': t.text,
    '--etis-muted': t.textMuted,
    '--etis-accent': t.accent,
    '--etis-accent-soft': t.accentSoft,
    '--etis-visor': t.visor,
    '--etis-eye': t.eye,
    '--etis-incomplete': t.incomplete,
    '--etis-low-text': t.verdict.LOW.text,
    '--etis-medium-text': t.verdict.MEDIUM.text,
    '--etis-high-text': t.verdict.HIGH.text,
    '--etis-low': t.verdict.LOW.solid,
    '--etis-low-tint': t.verdict.LOW.tint,
    '--etis-low-border': t.verdict.LOW.border,
    '--etis-medium': t.verdict.MEDIUM.solid,
    '--etis-medium-tint': t.verdict.MEDIUM.tint,
    '--etis-medium-border': t.verdict.MEDIUM.border,
    '--etis-high': t.verdict.HIGH.solid,
    '--etis-high-tint': t.verdict.HIGH.tint,
    '--etis-high-border': t.verdict.HIGH.border,
    '--etis-fast': `${MOTION.fast}ms`,
    '--etis-base': `${MOTION.base}ms`,
    '--etis-slow': `${MOTION.slow}ms`,
    '--etis-scan': `${MOTION.scanCycle}ms`,
    '--etis-ease': MOTION.easeStandard,
  };
}
