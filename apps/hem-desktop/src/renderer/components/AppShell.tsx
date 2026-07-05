import * as stylex from '@stylexjs/stylex';
import type { ReactNode } from 'react';
import { colors, fonts } from '../theme/tokens.stylex';
import { Dot, Kbd } from './ui';

export type ViewId = 'overview' | 'vault' | 'mesh' | 'approvals' | 'tokens' | 'audit';

export const VIEWS: Array<{ id: ViewId; label: string; shortcut: string }> = [
  { id: 'overview', label: 'Overview', shortcut: '⌘1' },
  { id: 'vault', label: 'Vault', shortcut: '⌘2' },
  { id: 'mesh', label: 'Mesh', shortcut: '⌘3' },
  { id: 'approvals', label: 'Approvals', shortcut: '⌘4' },
  { id: 'tokens', label: 'Tokens', shortcut: '⌘5' },
  { id: 'audit', label: 'Audit', shortcut: '⌘6' },
];

const s = stylex.create({
  shell: {
    display: 'flex',
    flexDirection: 'column',
    height: '100vh',
    backgroundColor: colors.bgWindow,
    fontFamily: fonts.sans,
    overflow: 'hidden',
  },
  titlebar: {
    height: 44,
    display: 'flex',
    alignItems: 'center',
    gap: 7,
    paddingInline: 16,
    borderBottomWidth: 1,
    borderBottomStyle: 'solid',
    borderBottomColor: colors.border,
    flexShrink: 0,
    // native traffic lights sit at x:16 (hiddenInset)
    paddingLeft: 76,
    WebkitAppRegion: 'drag',
  },
  titlebarTitle: {
    fontSize: 13,
    fontWeight: 600,
    color: colors.ink,
  },
  titlebarSearch: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: 6,
    fontSize: 12,
    color: colors.textMuted,
    WebkitAppRegion: 'no-drag',
    cursor: 'default',
    backgroundColor: 'transparent',
    borderWidth: 0,
    padding: 0,
  },
  spacer: { flex: 1 },
  body: {
    flex: 1,
    display: 'flex',
    minHeight: 0,
  },
  sidebar: {
    width: 200,
    backgroundColor: colors.bgSidebar,
    borderRightWidth: 1,
    borderRightStyle: 'solid',
    borderRightColor: colors.border,
    display: 'flex',
    flexDirection: 'column',
    paddingBlock: 12,
    paddingInline: 10,
    flexShrink: 0,
  },
  nav: {
    display: 'flex',
    flexDirection: 'column',
    gap: 2,
  },
  navItem: {
    display: 'flex',
    alignItems: 'center',
    gap: 8,
    paddingBlock: 7,
    paddingInline: 10,
    borderRadius: 6,
    fontSize: 13,
    color: colors.textSecondary,
    backgroundColor: { default: 'transparent', ':hover': colors.bgActiveNav },
    borderWidth: 0,
    width: '100%',
    textAlign: 'left',
    cursor: 'default',
  },
  navItemActive: {
    backgroundColor: colors.bgActiveNav,
    color: colors.ink,
    fontWeight: 600,
  },
  navLabel: { flex: 1 },
  navBadge: {
    fontFamily: fonts.mono,
    fontSize: 10,
    fontWeight: 600,
    color: colors.ink,
  },
  daemonLine: {
    display: 'flex',
    alignItems: 'center',
    gap: 7,
    paddingInline: 10,
    fontSize: 12,
    color: colors.textTertiary,
  },
  statusbar: {
    height: 30,
    borderTopWidth: 1,
    borderTopStyle: 'solid',
    borderTopColor: colors.border,
    display: 'flex',
    alignItems: 'center',
    gap: 18,
    paddingInline: 16,
    fontFamily: fonts.mono,
    fontSize: 10.5,
    color: colors.textFaint,
    flexShrink: 0,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
  },
});

export function AppShell({
  view,
  onNavigate,
  onOpenPalette,
  approvalsBadge,
  daemonOk,
  statusLeft,
  statusRight,
  children,
}: {
  view: ViewId;
  onNavigate: (view: ViewId) => void;
  onOpenPalette: () => void;
  approvalsBadge: number;
  daemonOk: boolean | null;
  statusLeft: ReactNode;
  statusRight: ReactNode;
  children: ReactNode;
}) {
  return (
    <div {...stylex.props(s.shell)}>
      <div {...stylex.props(s.titlebar)}>
        <span {...stylex.props(s.titlebarTitle)}>Hem Desk</span>
        <span {...stylex.props(s.spacer)} />
        <button type="button" {...stylex.props(s.titlebarSearch)} onClick={onOpenPalette}>
          Search
          <Kbd>⌘K</Kbd>
        </button>
      </div>
      <div {...stylex.props(s.body)}>
        <nav {...stylex.props(s.sidebar)}>
          <div {...stylex.props(s.nav)}>
            {VIEWS.map((v) => (
              <button
                key={v.id}
                type="button"
                {...stylex.props(s.navItem, view === v.id && s.navItemActive)}
                onClick={() => onNavigate(v.id)}
              >
                <span {...stylex.props(s.navLabel)}>{v.label}</span>
                {v.id === 'approvals' && approvalsBadge > 0 ? (
                  <span {...stylex.props(s.navBadge)}>{approvalsBadge}</span>
                ) : null}
                <Kbd variant="bare">{v.shortcut}</Kbd>
              </button>
            ))}
          </div>
          <span {...stylex.props(s.spacer)} />
          <div {...stylex.props(s.daemonLine)}>
            <Dot tone={daemonOk === null ? 'gray' : daemonOk ? 'green' : 'red'} size={6} />
            {daemonOk === false ? 'hemd unreachable' : 'hemd running'}
          </div>
        </nav>
        {children}
      </div>
      <div {...stylex.props(s.statusbar)}>
        {statusLeft}
        <span {...stylex.props(s.spacer)} />
        {statusRight}
      </div>
    </div>
  );
}
