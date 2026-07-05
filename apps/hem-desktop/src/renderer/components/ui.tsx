import * as stylex from '@stylexjs/stylex';
import type { ReactNode } from 'react';
import { colors, fonts, shadows } from '../theme/tokens.stylex';

const s = stylex.create({
  kbd: {
    fontFamily: fonts.mono,
    fontSize: 10,
    lineHeight: '17px',
    paddingInline: 6,
    borderWidth: 1,
    borderStyle: 'solid',
    borderColor: colors.borderInput,
    borderRadius: 4,
    color: colors.textTertiary,
    backgroundColor: colors.bgWindow,
    whiteSpace: 'nowrap',
  },
  kbdBare: {
    fontFamily: fonts.mono,
    fontSize: 10,
    color: colors.textFaint,
    whiteSpace: 'nowrap',
  },
  kbdOnDark: {
    fontFamily: fonts.mono,
    fontSize: 10,
    color: colors.onInkFaint,
    whiteSpace: 'nowrap',
    borderWidth: 0,
    backgroundColor: 'transparent',
  },
  kbdChip: {
    fontFamily: fonts.mono,
    fontSize: 10,
    lineHeight: '16px',
    paddingInline: 5,
    borderWidth: 1,
    borderStyle: 'solid',
    borderColor: colors.borderFocus,
    backgroundColor: colors.bgWindow,
    borderRadius: 4,
    color: colors.textTertiary,
    whiteSpace: 'nowrap',
  },
  dot: {
    width: 7,
    height: 7,
    borderRadius: '50%',
    flexShrink: 0,
  },
  dotSmall: { width: 6, height: 6 },
  dotLarge: { width: 8, height: 8 },
  dotGreen: { backgroundColor: colors.green },
  dotAmber: { backgroundColor: colors.amber },
  dotRed: { backgroundColor: colors.red },
  dotGray: { backgroundColor: colors.textFaint },
  sectionLabel: {
    fontFamily: fonts.mono,
    fontSize: 10,
    letterSpacing: '0.08em',
    textTransform: 'uppercase',
    color: colors.textFaint,
  },
  card: {
    backgroundColor: colors.bgWindow,
    borderWidth: 1,
    borderStyle: 'solid',
    borderColor: colors.border,
    borderRadius: 8,
    boxShadow: shadows.card,
  },
  button: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: 7,
    fontFamily: fonts.sans,
    fontSize: 12.5,
    borderRadius: 6,
    cursor: 'default',
    userSelect: 'none',
    whiteSpace: 'nowrap',
    borderWidth: 0,
    outline: { default: 'none', ':focus-visible': `1.5px solid ${'#c7cbd1'}` },
  },
  buttonPrimary: {
    fontWeight: 500,
    color: colors.onInk,
    backgroundColor: colors.ink,
    paddingBlock: 7,
    paddingInline: 15,
    opacity: { default: 1, ':hover': 0.9, ':active': 0.8 },
  },
  buttonSecondary: {
    color: colors.textSecondary,
    borderWidth: 1,
    borderStyle: 'solid',
    borderColor: colors.borderInput,
    backgroundColor: { default: colors.bgWindow, ':hover': colors.bgInset },
    paddingBlock: 5,
    paddingInline: 15,
  },
  buttonConfirm: {
    fontWeight: 600,
    color: colors.ink,
    borderWidth: 1,
    borderStyle: 'solid',
    borderColor: colors.borderStrong,
    backgroundColor: { default: colors.bgWindow, ':hover': colors.bgInset },
    paddingBlock: 5,
    paddingInline: 13,
  },
  buttonGhost: {
    color: colors.textMuted,
    backgroundColor: 'transparent',
    paddingBlock: 5,
    paddingInline: 6,
    fontSize: 12,
  },
  buttonSmallPrimary: {
    fontSize: 12,
    fontWeight: 500,
    paddingBlock: 4,
    paddingInline: 10,
  },
  buttonSmallSecondary: {
    fontSize: 12,
    paddingBlock: 3,
    paddingInline: 10,
  },
  disabled: {
    opacity: 0.45,
    pointerEvents: 'none',
  },
});

export function Kbd({
  children,
  variant = 'chip',
}: {
  children: ReactNode;
  variant?: 'chip' | 'bare' | 'onDark' | 'selChip';
}) {
  const style =
    variant === 'bare' ? s.kbdBare : variant === 'onDark' ? s.kbdOnDark : variant === 'selChip' ? s.kbdChip : s.kbd;
  return <span {...stylex.props(style)}>{children}</span>;
}

export type DotTone = 'green' | 'amber' | 'red' | 'gray';

export function Dot({ tone, size = 7 }: { tone: DotTone; size?: 6 | 7 | 8 }) {
  return (
    <span
      {...stylex.props(
        s.dot,
        size === 6 && s.dotSmall,
        size === 8 && s.dotLarge,
        tone === 'green' && s.dotGreen,
        tone === 'amber' && s.dotAmber,
        tone === 'red' && s.dotRed,
        tone === 'gray' && s.dotGray,
      )}
    />
  );
}

export function SectionLabel({ children }: { children: ReactNode }) {
  return <span {...stylex.props(s.sectionLabel)}>{children}</span>;
}

export function Card({ children, style }: { children: ReactNode; style?: stylex.StyleXStyles }) {
  return <div {...stylex.props(s.card, style)}>{children}</div>;
}

export type ButtonVariant = 'primary' | 'secondary' | 'confirm' | 'ghost' | 'smallPrimary' | 'smallSecondary';

export function Button({
  variant = 'secondary',
  onClick,
  children,
  shortcut,
  disabled,
  autoFocus,
}: {
  variant?: ButtonVariant;
  onClick?: () => void;
  children: ReactNode;
  shortcut?: string;
  disabled?: boolean;
  autoFocus?: boolean;
}) {
  const isDarkKbd = variant === 'primary' || variant === 'smallPrimary';
  return (
    <button
      type="button"
      autoFocus={autoFocus}
      onClick={onClick}
      disabled={disabled}
      {...stylex.props(
        s.button,
        (variant === 'primary' || variant === 'smallPrimary') && s.buttonPrimary,
        (variant === 'secondary' || variant === 'smallSecondary') && s.buttonSecondary,
        variant === 'confirm' && s.buttonConfirm,
        variant === 'ghost' && s.buttonGhost,
        variant === 'smallPrimary' && s.buttonSmallPrimary,
        variant === 'smallSecondary' && s.buttonSmallSecondary,
        disabled && s.disabled,
      )}
    >
      {children}
      {shortcut ? <Kbd variant={isDarkKbd ? 'onDark' : 'bare'}>{shortcut}</Kbd> : null}
    </button>
  );
}
