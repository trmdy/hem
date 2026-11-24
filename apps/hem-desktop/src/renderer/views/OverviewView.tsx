import * as stylex from '@stylexjs/stylex';
import { useMemo } from 'react';
import { useApprovals, useAudit, useDaemonHealth, useMeshHealth, useVaultList } from '../lib/api';
import { greeting, relTime, timeOrDate } from '../lib/fmt';
import { colors, fonts, shadows } from '../theme/tokens.stylex';
import { Dot, Kbd, type DotTone } from '../components/ui';

const s = stylex.create({
  pane: {
    flex: 1,
    backgroundColor: colors.bgContent,
    paddingBlock: 32,
    paddingInline: 36,
    display: 'flex',
    flexDirection: 'column',
    gap: 20,
    minWidth: 0,
    overflowY: 'auto',
  },
  greeting: {
    fontSize: 18,
    fontWeight: 600,
    color: colors.ink,
    letterSpacing: '-0.01em',
  },
  grid: {
    display: 'grid',
    gridTemplateColumns: '1fr 1fr 1fr',
    gap: 14,
  },
  card: {
    backgroundColor: colors.bgWindow,
    borderWidth: 1,
    borderStyle: 'solid',
    borderColor: colors.border,
    borderRadius: 8,
    paddingBlock: 20,
    paddingInline: 22,
    boxShadow: shadows.card,
    display: 'flex',
    flexDirection: 'column',
    gap: 6,
    cursor: 'default',
    textAlign: 'left',
  },
  cardLabel: { fontSize: 12, color: colors.textMuted },
  cardValue: {
    display: 'flex',
    alignItems: 'center',
    gap: 8,
    fontSize: 16,
    fontWeight: 600,
    color: colors.ink,
  },
  cardSub: { fontSize: 12.5, color: colors.textFaint },
  mono: { fontFamily: fonts.mono, fontSize: 11.5 },
  monoDim: { fontFamily: fonts.mono, fontSize: 11.5, color: colors.textTertiary },
  activityCard: {
    backgroundColor: colors.bgWindow,
    borderWidth: 1,
    borderStyle: 'solid',
    borderColor: colors.border,
    borderRadius: 8,
    boxShadow: shadows.card,
    display: 'flex',
    flexDirection: 'column',
    overflow: 'hidden',
  },
  activityHeader: {
    display: 'flex',
    alignItems: 'center',
    paddingBlock: 14,
    paddingInline: 22,
    borderBottomWidth: 1,
    borderBottomStyle: 'solid',
    borderBottomColor: colors.borderFaint,
  },
  activityTitle: { flex: 1, fontSize: 12, fontWeight: 500, color: colors.textTertiary },
  activityLink: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: 6,
    fontSize: 11.5,
    color: colors.textFaint,
    backgroundColor: 'transparent',
    borderWidth: 0,
    padding: 0,
    cursor: 'default',
  },
  activityRow: {
    display: 'flex',
    alignItems: 'baseline',
    gap: 16,
    paddingBlock: 11,
    paddingInline: 22,
    borderTopWidth: 1,
    borderTopStyle: 'solid',
    borderTopColor: colors.borderHair,
  },
  activityRowFirst: { borderTopWidth: 0 },
  activityTime: { fontFamily: fonts.mono, fontSize: 11, color: colors.textFaint, width: 52, flexShrink: 0 },
  activityAction: { fontSize: 12.5, color: colors.textSecondary, width: 120, flexShrink: 0 },
  activityRef: { flex: 1, fontFamily: fonts.mono, fontSize: 11.5, color: colors.ink, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' },
  statsLine: { fontSize: 12.5, color: colors.textFaint },
  empty: { paddingBlock: 18, paddingInline: 22, fontSize: 12.5, color: colors.textFaint },
});

export function OverviewView({ onNavigate }: { onNavigate: (view: 'mesh' | 'approvals' | 'audit') => void }) {
  const daemon = useDaemonHealth();
  const mesh = useMeshHealth();
  const approvals = useApprovals();
  const vault = useVaultList();
  const audit = useAudit({ limit: 5 });

  const stats = useMemo(() => {
    const rows = vault.data ?? [];
    if (!rows.length) return null;
    const bySection = new Map<string, number>();
    for (const row of rows) bySection.set(row.section, (bySection.get(row.section) ?? 0) + 1);
    const top = [...bySection.entries()].sort((a, b) => b[1] - a[1]).slice(0, 2);
    return { total: rows.length, scopes: bySection.size, top };
  }, [vault.data]);

  const meshTone: DotTone =
    mesh.data?.status === 'ok' ? 'green' : mesh.data?.status === 'critical' ? 'red' : mesh.data ? 'amber' : 'gray';
  const laggard = mesh.data?.peers.find((p) => p.status === 'lagging' || p.status === 'offline');

  const pending = approvals.data ?? [];
  const oldest = pending.length
    ? pending.reduce((a, b) => (a.createdAt < b.createdAt ? a : b))
    : null;

  return (
    <div {...stylex.props(s.pane)}>
      <div {...stylex.props(s.greeting)}>{greeting()}</div>

      <div {...stylex.props(s.grid)}>
        <div {...stylex.props(s.card)}>
          <span {...stylex.props(s.cardLabel)}>Daemon</span>
          <span {...stylex.props(s.cardValue)}>
            <Dot tone={daemon.data?.ok ? 'green' : daemon.isError ? 'red' : 'gray'} />
            {daemon.data?.ok ? 'Running' : daemon.isError ? 'Unreachable' : '…'}
          </span>
          <span {...stylex.props(s.cardSub)}>
            {daemon.data ? `v${daemon.data.version} · ${daemon.data.endpoint.replace(/^https?:\/\//, '')}` : ' '}
          </span>
        </div>

        <button type="button" {...stylex.props(s.card)} onClick={() => onNavigate('mesh')}>
          <span {...stylex.props(s.cardLabel)}>Mesh</span>
          <span {...stylex.props(s.cardValue)}>
            <Dot tone={meshTone} />
            {mesh.data
              ? mesh.data.status === 'ok'
                ? 'Healthy'
                : mesh.data.status.charAt(0).toUpperCase() + mesh.data.status.slice(1)
              : 'Probing…'}
          </span>
          <span {...stylex.props(s.cardSub)}>
            {laggard ? (
              <>
                <span {...stylex.props(s.mono)}>{laggard.nodeId.replace(/^hmn_/, '')}</span>
                {laggard.status === 'lagging' ? ` ${relTime(laggard.lastSeen ?? '') || 'a while'} behind` : ' offline'} ·{' '}
                <span {...stylex.props(s.monoDim)}>⌘3</span>
              </>
            ) : mesh.data ? (
              <>
                {mesh.data.healthyPeers} nodes caught up · <span {...stylex.props(s.monoDim)}>⌘3</span>
              </>
            ) : (
              '~30 s probe'
            )}
          </span>
        </button>

        <button type="button" {...stylex.props(s.card)} onClick={() => onNavigate('approvals')}>
          <span {...stylex.props(s.cardLabel)}>Approvals</span>
          <span {...stylex.props(s.cardValue)}>
            {approvals.data ? (pending.length ? `${pending.length} pending` : 'None pending') : '…'}
          </span>
          <span {...stylex.props(s.cardSub)}>
            {oldest ? (
              <>
                oldest {relTime(oldest.createdAt)} · <span {...stylex.props(s.monoDim)}>⌘4</span>
              </>
            ) : (
              <>
                nothing needs you · <span {...stylex.props(s.monoDim)}>⌘4</span>
              </>
            )}
          </span>
        </button>
      </div>

      <div {...stylex.props(s.activityCard)}>
        <div {...stylex.props(s.activityHeader)}>
          <span {...stylex.props(s.activityTitle)}>Recent activity</span>
          <button type="button" {...stylex.props(s.activityLink)} onClick={() => onNavigate('audit')}>
            Audit
            <Kbd variant="bare">⌘6</Kbd>
          </button>
        </div>
        {(audit.data ?? []).map((entry, i) => (
          <div key={entry.auditId} {...stylex.props(s.activityRow, i === 0 && s.activityRowFirst)}>
            <span {...stylex.props(s.activityTime)}>{timeOrDate(entry.ts)}</span>
            <span {...stylex.props(s.activityAction)}>{entry.action.replaceAll('_', ' ')}</span>
            <span {...stylex.props(s.activityRef)}>{entry.ref ?? entry.details}</span>
          </div>
        ))}
        {audit.data && audit.data.length === 0 ? (
          <div {...stylex.props(s.empty)}>No audit entries yet.</div>
        ) : null}
        {audit.isError ? <div {...stylex.props(s.empty)}>Audit unavailable.</div> : null}
      </div>

      {stats ? (
        <div {...stylex.props(s.statsLine)}>
          {stats.total} secrets across {stats.scopes} scopes
          {stats.top.length >= 2 ? (
            <>
              {' '}
              · most in <span {...stylex.props(s.mono)}>{stats.top[0][0]}</span> ({stats.top[0][1]}) and{' '}
              <span {...stylex.props(s.mono)}>{stats.top[1][0]}</span> ({stats.top[1][1]})
            </>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
