import { createTheme, type Direction } from '@mui/material/styles';
import { cssVars, MOTION, RADIUS, TOKENS, TYPE_SCALE, type ColorMode } from './tokens';

/**
 * Console redesign v1 theme (docs/design/console-redesign-v1.md).
 */
export function createConsoleTheme(mode: ColorMode, direction: Direction) {
  const t = TOKENS[mode];
  const px = (n: number) => `${n / 16}rem`;
  return createTheme({
    direction,
    spacing: 4,
    palette: {
      mode,
      primary: { main: t.accent, contrastText: t.onAccent },
      secondary: { main: t.navy, contrastText: t.onNavy },
      background: { default: t.bg, paper: t.surface },
      text: { primary: t.text, secondary: t.textMuted },
      divider: t.border,
      success: { main: t.verdict.LOW.text, contrastText: mode === 'light' ? '#FFFFFF' : t.bg },
      warning: { main: t.verdict.MEDIUM.text, contrastText: mode === 'light' ? '#FFFFFF' : t.bg },
      error: { main: t.verdict.HIGH.text, contrastText: mode === 'light' ? '#FFFFFF' : t.bg },
      info: { main: t.accent, contrastText: t.onAccent },
    },
    shape: { borderRadius: RADIUS.sm },
    typography: {
      fontFamily: ['Cairo', 'system-ui', 'Segoe UI', 'sans-serif'].join(','),
      fontSize: 15,
      h1: { fontSize: px(TYPE_SCALE.h1), fontWeight: 700, lineHeight: 1.25 },
      h2: { fontSize: px(TYPE_SCALE.h2), fontWeight: 700, lineHeight: 1.3 },
      h3: { fontSize: px(TYPE_SCALE.h3), fontWeight: 600, lineHeight: 1.35 },
      h4: { fontSize: px(TYPE_SCALE.lead), fontWeight: 600, lineHeight: 1.4 },
      h5: { fontSize: px(TYPE_SCALE.lead), fontWeight: 600, lineHeight: 1.4 },
      h6: { fontSize: px(TYPE_SCALE.body + 1), fontWeight: 600, lineHeight: 1.45 },
      body1: { fontSize: px(TYPE_SCALE.body), lineHeight: 1.65 },
      body2: { fontSize: px(TYPE_SCALE.small), lineHeight: 1.6 },
      caption: { fontSize: px(TYPE_SCALE.caption), lineHeight: 1.5 },
      overline: { fontSize: px(TYPE_SCALE.caption), fontWeight: 600, letterSpacing: '0.08em' },
      button: { textTransform: 'none', fontWeight: 600 },
    },
    transitions: {
      duration: { shortest: MOTION.fast, shorter: MOTION.fast, short: MOTION.base, standard: MOTION.base, complex: MOTION.slow, enteringScreen: MOTION.slow, leavingScreen: MOTION.base },
      easing: { easeInOut: MOTION.easeStandard, easeOut: MOTION.easeStandard, easeIn: MOTION.easeExit, sharp: MOTION.easeExit },
    },
    components: {
      MuiCssBaseline: {
        styleOverrides: {
          ':root': { ...cssVars(mode), colorScheme: mode },
          body: { backgroundColor: t.bg, transition: `background-color ${MOTION.slow}ms ${MOTION.easeStandard}` },
          '@media (prefers-reduced-motion: reduce)': {
            '*, *::before, *::after': { transitionDuration: `${MOTION.fast}ms !important` },
          },
        },
      },
      MuiPaper: {
        defaultProps: { elevation: 0 },
        styleOverrides: {
          root: { backgroundImage: 'none' },
          outlined: { borderColor: t.border, borderRadius: RADIUS.md },
        },
      },
      MuiCard: {
        defaultProps: { variant: 'outlined' },
        styleOverrides: {
          root: {
            borderRadius: RADIUS.md,
            transition: `border-color ${MOTION.base}ms ${MOTION.easeStandard}, box-shadow ${MOTION.base}ms ${MOTION.easeStandard}, transform ${MOTION.base}ms ${MOTION.easeStandard}`,
          },
        },
      },
      MuiTable: { styleOverrides: { root: { overflowWrap: 'normal' } } },
      MuiTableCell: {
        styleOverrides: {
          head: { whiteSpace: 'nowrap', backgroundColor: t.surface2, color: t.textMuted, fontWeight: 600 },
          sizeSmall: { paddingBlock: 12, paddingInline: 16 },
        },
      },
      MuiAlert: { styleOverrides: { message: { minWidth: 0, overflowWrap: 'anywhere' } } },
      MuiButton: {
        defaultProps: { disableElevation: true },
        styleOverrides: { root: { borderRadius: RADIUS.sm, paddingInline: 16 } },
      },
      MuiChip: { styleOverrides: { root: { fontWeight: 600, borderRadius: 999 } } },
      MuiAppBar: {
        defaultProps: { elevation: 0, color: 'secondary' },
        styleOverrides: { root: { borderBottom: `1px solid ${t.border}` } },
      },
      MuiTab: { styleOverrides: { root: { textTransform: 'none', fontWeight: 600, minHeight: 44 } } },
    },
  });
}
