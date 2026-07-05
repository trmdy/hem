import * as stylex from '@stylexjs/stylex';

/**
 * Design tokens extracted from design/hem-desk-v3.dc.html — the visual
 * source of truth. Every hex/shadow/size below appears verbatim in that
 * file; do not invent values here without a note in the implementation
 * report.
 */

export const colors = stylex.defineVars({
  // text ramp
  ink: '#26282c',
  textSecondary: '#4a4f55',
  textTertiary: '#6b7075',
  textMuted: '#82878e',
  textFaint: '#9ca1a8',
  // border ramp (strong → hairline)
  borderStrong: '#c2c7cd',
  borderFocus: '#c7cbd1',
  borderInput: '#dadde0',
  borderFrame: '#e3e5e8',
  border: '#e6e8eb',
  borderFaint: '#f0f1f3',
  borderHair: '#f6f7f8',
  // surfaces
  bgWindow: '#ffffff',
  bgContent: '#fafafa',
  bgSidebar: '#f4f5f6',
  bgInset: '#f7f8f9',
  bgSelected: '#eeeff2',
  bgActiveNav: '#e7e9ec',
  bgMaskChip: '#f0f1f3',
  trafficLight: '#dfe2e5',
  // accents (the only chroma in the app)
  green: '#3e9b63',
  amber: '#d9a514',
  // not in the design file (it shows no critical state); desaturated to
  // match the calm idiom — noted in the implementation report
  red: '#b0453f',
  // on-dark
  onInk: '#ffffff',
  onInkFaint: 'rgba(255,255,255,0.65)',
  // overlays
  overlay: 'rgba(38,40,44,0.16)',
});

export const fonts = stylex.defineVars({
  sans: "'Geist Sans','Geist','Helvetica Neue',sans-serif",
  mono: "'Geist Mono',ui-monospace,monospace",
});

export const shadows = stylex.defineVars({
  card: '0 1px 2px rgba(16,24,40,0.04)',
  frame: '0 4px 20px rgba(16,24,40,0.05)',
  modal: '0 8px 24px rgba(0,0,0,0.07)',
  palette: '0 8px 24px rgba(0,0,0,0.07), 0 24px 64px rgba(16,24,40,0.12)',
  focusCard: '0 0 0 1.5px #c7cbd1, 0 0 0 4px #e7e9ec, 0 1px 2px rgba(16,24,40,0.04)',
  focusInput: '0 0 0 1.5px #c7cbd1, 0 0 0 4px #eef0f3',
});
