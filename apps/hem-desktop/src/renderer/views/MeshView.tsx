import * as stylex from '@stylexjs/stylex';
import { useCallback, useMemo, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import type { MeshPeerHealth } from '../../shared/types';
import { errorText, invoke, useCollisions, useMeshHealth, useMeshSnapshot } from '../lib/api';
import { relTimeSeconds } from '../lib/fmt';
import { useKeys } from '../lib/keys';
import { Button, Dot, Kbd, SectionLabel, type DotTone } from '../components/ui';
import { colors, fonts, shadows } from '../theme/tokens.stylex';

const s = stylex.create({
  pane: {
    flex: 1,
    backgroundColor: colors.bgContent,
    display: 'flex',
    flexDirection: 'column',
    minWidth: 0,
    overflowY: 'auto',
  },
  header: {
    display: 'flex',
    alignItems: 'center',
    paddingTop: 28,
    paddingInline: 36,
    gap: 16,
  },
  headerText: { display: 'flex', flexDirection: 'column', gap: 4 },
  headerTitle: {
    display: 'flex',
    alignItems: 'center',
    gap: 9,
    fontSize: 18,
    fontWeight: 600,
    color: colors.ink,
    letterSpacing: '-0.01em',
  },
  headerSub: { fontSize: 13, color: colors.textTertiary },
  mono: { fontFamily: fonts.mono, fontSize: 12 },
  spacer: { flex: 1 },
  grid: {
    paddingBlock: 28,
    paddingInline: 36,
    display: 'grid',
    gridTemplateColumns: 'repeat(3, 1fr)',
    gridAutoRows: 'min-content',
    gap: 14,
    alignContent: 'start',
  },
  nodeCard: {
    backgroundColor: colors.bgWindow,
    borderWidth: 1,
    borderStyle: 'solid',
    borderColor: colors.border,
    borderRadius: 8,
    paddingBlock: 18,
    paddingInline: 20,
    boxShadow: shadows.card,
    display: 'flex',
    flexDirection: 'column',
    gap: 8,
    textAlign: 'left',
    cursor: 'default',
  },
  nodeCardAttention: { borderColor: colors.borderStrong },
  nodeCardFocused: { boxShadow: shadows.focusCard },
  nodeHead: { display: 'flex', alignItems: 'center', gap: 8 },
  nodeId: {
    flex: 1,
    fontFamily: fonts.mono,
    fontSize: 13,
    fontWeight: 600,
    color: colors.ink,
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
  },
  nodeTag: { fontSize: 11, color: colors.textFaint },
  nodeStatus: { fontSize: 12.5, color: colors.textTertiary },
  nodeStatusWarn: { color: colors.ink, fontWeight: 500 },
  nodeMono: { fontFamily: fonts.mono, fontSize: 11.5 },
  nodeAction: {
    display: 'flex',
    alignItems: 'center',
    gap: 6,
    fontSize: 12,
    color: colors.textTertiary,
    paddingTop: 2,
    backgroundColor: 'transparent',
    borderWidth: 0,
    padding: 0,
    cursor: 'default',
  },
  nodeDetailLine: { fontSize: 12, color: colors.textMuted, lineHeight: 1.6 },
  footer: { paddingInline: 36, paddingBottom: 24, fontSize: 12, color: colors.textFaint },
  footerMono: { fontFamily: fonts.mono, fontSize: 11 },
  collisions: {
    marginInline: 36,
    marginBottom: 20,
    backgroundColor: colors.bgWindow,
    borderWidth: 1,
    borderStyle: 'solid',
    borderColor: colors.borderStrong,
    borderRadius: 8,
    boxShadow: shadows.card,
    padding: 20,
    display: 'flex',
    flexDirection: 'column',
    gap: 10,
  },
  collisionRow: { display: 'flex', alignItems: 'center', gap: 12, fontSize: 12.5, color: colors.textSecondary },
  collisionCmd: {
    flex: 1,
    fontFamily: fonts.mono,
    fontSize: 11.5,
    color: colors.ink,
    backgroundColor: colors.bgInset,
    borderWidth: 1,
    borderStyle: 'solid',
    borderColor: colors.borderInput,
    borderRadius: 6,
    paddingBlock: 8,
    paddingInline: 12,
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
  },
  syncNote: { fontSize: 12, color: colors.textMuted },
});

function toneFor(status: MeshPeerHealth['status']): DotTone {
  switch (status) {
    case 'caught_up':
      return 'green';
    case 'lagging':
      return 'amber';
    case 'divergent':
    case 'offline':
      return 'red';
    default:
      return 'gray';
  }
}

function statusLine(peer: MeshPeerHealth): string {
  switch (peer.status) {
    case 'caught_up':
      return `caught up · ${peer.cursorPosition} · ${relTimeSeconds(peer.lastSeen) || 'now'}`;
    case 'lagging':
      return `${peer.lag.toLocaleString('en-US')} behind · last seen ${relTimeSeconds(peer.lastSeen) || 'unknown'}`;
    case 'offline':
      return `offline · last seen ${relTimeSeconds(peer.lastSeen) || 'unknown'}`;
    case 'divergent':
      return `divergent at ${peer.cursorPosition} — see runbook`;
    default:
      return 'status unknown';
  }
}

export function MeshView({ keysEnabled }: { keysEnabled: boolean }) {
  const snapshot = useMeshSnapshot();
  const health = useMeshHealth();
  const collisions = useCollisions((health.data?.collisions ?? 0) > 0);
  const queryClient = useQueryClient();

  const [focusIdx, setFocusIdx] = useState(0);
  const [expandedNode, setExpandedNode] = useState<string | null>(null);
  const [syncState, setSyncState] = useState<string | null>(null);

  // Node list: instant from the snapshot (local first), enriched by the
  // ~30 s probe when it lands. Never block the view on health.
  const nodes: MeshPeerHealth[] = useMemo(() => {
    const localId = snapshot.data?.nodeId ?? '';
    const probed = new Map((health.data?.peers ?? []).map((p) => [p.nodeId, p]));
    const configured = snapshot.data?.peers ?? [];
    const local: MeshPeerHealth = probed.get(localId) ?? {
      nodeId: localId,
      status: 'caught_up',
      endpoint: snapshot.data?.scalars.listen ?? '',
      cursorPosition: snapshot.data?.latestCheckpointPosition ?? 0,
      lag: 0,
      lastSeen: null,
      error: null,
      local: true,
    };
    const rest = configured
      .filter((p) => p.nodeId !== localId)
      .map(
        (p) =>
          probed.get(p.nodeId) ?? {
            nodeId: p.nodeId,
            status: 'unknown' as const,
            endpoint: p.endpoint,
            cursorPosition: 0,
            lag: 0,
            lastSeen: null,
            error: null,
            local: false,
          },
      );
    return localId || rest.length ? [{ ...local, local: true }, ...rest] : [];
  }, [snapshot.data, health.data]);

  const probing = health.isLoading;
  const status = health.data?.status;
  const laggard = health.data?.peers.find((p) => p.status === 'lagging');
  const offline = health.data?.peers.filter((p) => p.status === 'offline') ?? [];

  const syncNow = useCallback(async () => {
    setSyncState('Syncing…');
    try {
      const res = await invoke('mesh:syncOnce');
      setSyncState(res.exitCode === 0 ? `Synced · ${res.summary}` : `Sync exited ${res.exitCode} · ${res.summary}`);
      void queryClient.invalidateQueries({ queryKey: ['mesh:snapshot'] });
    } catch (err) {
      setSyncState(errorText(err));
    }
  }, [queryClient]);

  const copyWake = useCallback((peer: MeshPeerHealth) => {
    void invoke(
      'clipboard:copyText',
      `hem cluster health · node ${peer.nodeId} (${peer.endpoint}) ${peer.status}, lag ${peer.lag}, last seen ${peer.lastSeen ?? 'unknown'}${peer.error ? `, error: ${peer.error}` : ''}`,
      {},
    );
  }, []);

  useKeys(
    [
      { combo: 'arrowright', handler: () => setFocusIdx((i) => Math.min(nodes.length - 1, i + 1)) },
      { combo: 'arrowleft', handler: () => setFocusIdx((i) => Math.max(0, i - 1)) },
      { combo: 'arrowdown', handler: () => setFocusIdx((i) => Math.min(nodes.length - 1, i + 3)) },
      { combo: 'arrowup', handler: () => setFocusIdx((i) => Math.max(0, i - 3)) },
      { combo: 's', handler: () => void syncNow() },
      {
        combo: 'enter',
        handler: () => {
          const node = nodes[focusIdx];
          if (node) setExpandedNode((cur) => (cur === node.nodeId ? null : node.nodeId));
        },
      },
      { combo: 'mod+.', handler: () => nodes[focusIdx] && copyWake(nodes[focusIdx]) },
      {
        combo: 'mod+shift+h',
        handler: () => health.data && void invoke('clipboard:copyText', health.data.raw, {}),
      },
      { combo: 'escape', handler: () => setExpandedNode(null) },
    ],
    keysEnabled,
  );

  const headerTone: DotTone = probing ? 'gray' : status === 'ok' ? 'green' : status === 'critical' ? 'red' : 'amber';
  const headerLabel = probing
    ? 'Probing'
    : status === 'ok'
      ? 'Healthy'
      : status
        ? status.charAt(0).toUpperCase() + status.slice(1)
        : 'Unknown';

  const caughtUp = health.data?.healthyPeers ?? 0;
  const totalNodes = nodes.length;
  const position = health.data?.latestPosition ?? snapshot.data?.latestCheckpointPosition ?? 0;

  return (
    <div {...stylex.props(s.pane)}>
      <div {...stylex.props(s.header)}>
        <div {...stylex.props(s.headerText)}>
          <span {...stylex.props(s.headerTitle)}>
            <Dot tone={headerTone} size={8} />
            {headerLabel}
          </span>
          <span {...stylex.props(s.headerSub)}>
            {probing ? (
              <>
                snapshot loaded · probing peers, ~30 s — position <span {...stylex.props(s.mono)}>{position}</span>
              </>
            ) : (
              <>
                {caughtUp} of {totalNodes} nodes at position <span {...stylex.props(s.mono)}>{position}</span>
                {laggard ? (
                  <>
                    {' '}
                    · <span {...stylex.props(s.mono)}>{laggard.nodeId.replace(/^hmn_/, '')}</span>{' '}
                    {laggard.lag.toLocaleString('en-US')} behind
                  </>
                ) : null}
                {offline.length ? (
                  <>
                    {' '}
                    · {offline.length} offline
                  </>
                ) : null}
              </>
            )}
          </span>
        </div>
        <span {...stylex.props(s.spacer)} />
        {syncState ? <span {...stylex.props(s.syncNote)}>{syncState}</span> : null}
        <Button variant="primary" shortcut="S" onClick={() => void syncNow()}>
          Sync now
        </Button>
      </div>

      <div {...stylex.props(s.grid)}>
        {nodes.map((node, i) => {
          const attention = node.status === 'lagging' || node.status === 'offline' || node.status === 'divergent';
          const expanded = expandedNode === node.nodeId;
          return (
            <button
              key={node.nodeId || i}
              type="button"
              {...stylex.props(s.nodeCard, attention && s.nodeCardAttention, i === focusIdx && s.nodeCardFocused)}
              onClick={() => {
                setFocusIdx(i);
                setExpandedNode((cur) => (cur === node.nodeId ? null : node.nodeId));
              }}
            >
              <div {...stylex.props(s.nodeHead)}>
                <Dot tone={node.status === 'unknown' && probing ? 'gray' : toneFor(node.status)} />
                <span {...stylex.props(s.nodeId)}>{node.nodeId || 'unknown node'}</span>
                {node.local ? <span {...stylex.props(s.nodeTag)}>this machine</span> : null}
              </div>
              <div {...stylex.props(s.nodeStatus, attention && s.nodeStatusWarn)}>
                {node.status === 'unknown' && probing ? 'probing…' : statusLine(node)}
              </div>
              {attention ? (
                <span
                  {...stylex.props(s.nodeAction)}
                  onClick={(e) => {
                    e.stopPropagation();
                    copyWake(node);
                  }}
                >
                  Copy diagnosis
                  <Kbd variant="bare">⌘.</Kbd>
                </span>
              ) : null}
              {expanded ? (
                <div {...stylex.props(s.nodeDetailLine)}>
                  endpoint <span {...stylex.props(s.nodeMono)}>{node.endpoint || 'unknown'}</span>
                  <br />
                  cursor <span {...stylex.props(s.nodeMono)}>{node.cursorPosition}</span> · lag{' '}
                  <span {...stylex.props(s.nodeMono)}>{node.lag}</span>
                  {node.error ? (
                    <>
                      <br />
                      {node.error}
                    </>
                  ) : null}
                </div>
              ) : null}
            </button>
          );
        })}
      </div>

      {(collisions.data?.length ?? 0) > 0 ? (
        <div {...stylex.props(s.collisions)}>
          <SectionLabel>Unresolved collisions — resolution stays in the terminal</SectionLabel>
          {collisions.data?.map((c, i) => (
            <div key={i} {...stylex.props(s.collisionRow)}>
              <span {...stylex.props(s.collisionCmd)}>{c.resolveCommand}</span>
              <Button
                variant="smallSecondary"
                onClick={() => void invoke('clipboard:copyText', c.resolveCommand, {})}
              >
                Copy command
              </Button>
            </div>
          ))}
        </div>
      ) : null}

      <span {...stylex.props(s.spacer)} />
      <div {...stylex.props(s.footer)}>
        Cluster <span {...stylex.props(s.footerMono)}>{snapshot.data?.clusterId ?? '…'}</span>
        {snapshot.data ? (
          <>
            {' '}
            · checkpoint #{snapshot.data.checkpoints}
            {health.data ? (
              <>
                , {health.data.checkpointStatus || 'quorum met'} · {health.data.collisions} collisions
              </>
            ) : null}
          </>
        ) : null}
      </div>
    </div>
  );
}
