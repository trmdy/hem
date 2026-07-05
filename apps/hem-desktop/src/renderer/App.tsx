import * as stylex from '@stylexjs/stylex';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import type { SecretRow } from '../shared/types';
import { AppShell, type ViewId } from './components/AppShell';
import { SecretFormModal } from './components/SecretFormModal';
import { Palette, type PaletteAction } from './palette/Palette';
import { invoke, useApprovals, useDaemonHealth, useHemEvents, useVaultList } from './lib/api';
import { clockNow, relTime } from './lib/fmt';
import { useKeys } from './lib/keys';
import { Button } from './components/ui';
import { OverviewView } from './views/OverviewView';
import { VaultView } from './views/VaultView';
import { MeshView } from './views/MeshView';
import { ApprovalsView } from './views/ApprovalsView';
import { TokensView } from './views/TokensView';
import { AuditView } from './views/AuditView';
import { colors, fonts, shadows } from './theme/tokens.stylex';

const PRIMARY_KEY_GUESS = ['api_key', 'api_token', 'token', 'key', 'password', 'secret'];

const s = stylex.create({
  errorPane: {
    flex: 1,
    backgroundColor: colors.bgContent,
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
  },
  errorCard: {
    width: 460,
    backgroundColor: colors.bgWindow,
    borderWidth: 1,
    borderStyle: 'solid',
    borderColor: colors.borderStrong,
    borderRadius: 8,
    boxShadow: shadows.card,
    padding: 24,
    display: 'flex',
    flexDirection: 'column',
    gap: 12,
    alignItems: 'flex-start',
  },
  errorTitle: { fontSize: 14.5, fontWeight: 600, color: colors.ink },
  errorBody: { fontSize: 12.5, color: colors.textTertiary, lineHeight: 1.6 },
  errorCmd: {
    alignSelf: 'stretch',
    borderWidth: 1,
    borderStyle: 'solid',
    borderColor: colors.border,
    backgroundColor: colors.bgInset,
    borderRadius: 6,
    paddingBlock: 10,
    paddingInline: 14,
    fontFamily: fonts.mono,
    fontSize: 12,
    color: colors.ink,
    userSelect: 'text',
  },
  errorButtons: { display: 'flex', gap: 12 },
});

const RESTART_CMD = 'launchctl kickstart -k gui/$UID/io.valhall.hemd';

function DaemonDownPane({ endpoint, onRetry }: { endpoint: string; onRetry: () => void }) {
  return (
    <div {...stylex.props(s.errorPane)}>
      <div {...stylex.props(s.errorCard)}>
        <span {...stylex.props(s.errorTitle)}>
          hemd isn&apos;t reachable at {endpoint.replace(/^https?:\/\//, '')}.
        </span>
        <span {...stylex.props(s.errorBody)}>Your vault is intact on disk. Relaunch the daemon:</span>
        <div {...stylex.props(s.errorCmd)}>{RESTART_CMD}</div>
        <div {...stylex.props(s.errorButtons)}>
          <Button variant="primary" shortcut="⌘C" onClick={() => void invoke('clipboard:copyText', RESTART_CMD, {})}>
            Copy command
          </Button>
          <Button variant="secondary" shortcut="⏎" onClick={onRetry}>
            Retry
          </Button>
        </div>
      </div>
    </div>
  );
}

export function App() {
  const [view, setView] = useState<ViewId>('overview');
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<SecretRow | null>(null);
  const [selectedRef, setSelectedRef] = useState<string | null>(null);
  const [vaultCount, setVaultCount] = useState(0);
  const [deleteRetry, setDeleteRetry] = useState<{ requestId: string; ref: string } | null>(null);
  const [clock, setClock] = useState(clockNow());

  const daemon = useDaemonHealth();
  const approvals = useApprovals();
  const vault = useVaultList();
  const queryClient = useQueryClient();
  const filterRef = useRef<HTMLInputElement | null>(null);

  useHemEvents();

  useEffect(() => {
    const iv = setInterval(() => setClock(clockNow()), 30_000);
    return () => clearInterval(iv);
  }, []);

  // Default vault selection: first row once loaded.
  useEffect(() => {
    if (!selectedRef && vault.data?.length) setSelectedRef(vault.data[0].ref);
  }, [vault.data, selectedRef]);

  const modalOpen = paletteOpen || formOpen;
  const viewKeysEnabled = !modalOpen;

  const openSecret = useCallback((ref: string) => {
    setSelectedRef(ref || null);
    setView('vault');
  }, []);

  const copyPrimary = useCallback(
    async (ref: string) => {
      try {
        const detail = await invoke('vault:get', ref);
        const keys = detail.keys.map((k) => k.key);
        const primary = PRIMARY_KEY_GUESS.find((g) => keys.includes(g)) ?? keys[0];
        if (primary) await invoke('vault:copy', ref, primary);
      } catch {
        // surfaced in the vault view when the user lands there
      }
    },
    [],
  );

  const paletteActions = useMemo<PaletteAction[]>(
    () => [
      { id: 'new-secret', label: 'New secret', shortcut: '⌘N', run: () => { setEditing(null); setFormOpen(true); } },
      { id: 'open-overview', label: 'Open Overview', shortcut: '⌘1', run: () => setView('overview') },
      { id: 'open-vault', label: 'Open Vault', shortcut: '⌘2', run: () => setView('vault') },
      { id: 'open-mesh', label: 'Open Mesh', shortcut: '⌘3', run: () => setView('mesh') },
      { id: 'open-approvals', label: 'Open Approvals', shortcut: '⌘4', run: () => setView('approvals') },
      { id: 'open-tokens', label: 'Open Tokens', shortcut: '⌘5', run: () => setView('tokens') },
      { id: 'open-audit', label: 'Open Audit', shortcut: '⌘6', run: () => setView('audit') },
      {
        id: 'sync-mesh',
        label: 'Sync mesh now',
        shortcut: 'S',
        run: () => {
          setView('mesh');
          void invoke('mesh:syncOnce').then(() =>
            queryClient.invalidateQueries({ queryKey: ['mesh:snapshot'] }),
          );
        },
      },
      {
        id: 'copy-health',
        label: 'Copy mesh health report',
        run: () => void invoke('mesh:health', {}).then((h) => invoke('clipboard:copyText', h.raw, {})),
      },
      {
        id: 'issue-service-token',
        label: 'Issue service token…',
        shortcut: 'I',
        run: () => setView('tokens'),
      },
      {
        id: 'refresh',
        label: 'Refresh everything',
        run: () => void queryClient.invalidateQueries(),
      },
    ],
    [queryClient],
  );

  useKeys(
    [
      { combo: 'mod+1', handler: () => setView('overview'), inInputs: true },
      { combo: 'mod+2', handler: () => setView('vault'), inInputs: true },
      { combo: 'mod+3', handler: () => setView('mesh'), inInputs: true },
      { combo: 'mod+4', handler: () => setView('approvals'), inInputs: true },
      { combo: 'mod+5', handler: () => setView('tokens'), inInputs: true },
      { combo: 'mod+6', handler: () => setView('audit'), inInputs: true },
      { combo: 'mod+k', handler: () => setPaletteOpen((o) => !o), inInputs: true },
      {
        combo: 'mod+n',
        handler: () => {
          setEditing(null);
          setFormOpen(true);
        },
        inInputs: true,
      },
      { combo: 'g o', handler: () => setView('overview') },
      { combo: 'g v', handler: () => setView('vault') },
      { combo: 'g m', handler: () => setView('mesh') },
      { combo: 'g a', handler: () => setView('approvals') },
      { combo: 'g t', handler: () => setView('tokens') },
      { combo: 'g l', handler: () => setView('audit') },
    ],
    true,
  );

  const pendingCount = approvals.data?.length ?? 0;
  const daemonOk = daemon.isError ? false : daemon.data ? daemon.data.ok : null;

  const oldestPending = useMemo(() => {
    const rows = approvals.data ?? [];
    if (!rows.length) return null;
    return rows.reduce((a, b) => (a.createdAt < b.createdAt ? a : b));
  }, [approvals.data]);

  const status = useMemo(() => {
    switch (view) {
      case 'vault':
        return {
          left: (
            <>
              <span>↑↓ move</span>
              <span>⌘C copy</span>
              <span>⌘R reveal</span>
              <span>⌘N new</span>
            </>
          ),
          right: <span>{vaultCount} secrets</span>,
        };
      case 'mesh':
        return {
          left: (
            <>
              <span>↑↓←→ nodes</span>
              <span>⏎ detail</span>
              <span>S sync</span>
            </>
          ),
          right: <span>{clock.split('·')[1]?.trim() ?? ''}</span>,
        };
      case 'approvals':
        return {
          left: (
            <>
              <span>↑↓ requests</span>
              <span>A approve</span>
              <span>D deny</span>
            </>
          ),
          right: <span>{oldestPending ? `oldest ${relTime(oldestPending.createdAt)}` : 'none pending'}</span>,
        };
      case 'tokens':
        return {
          left: (
            <>
              <span>↑↓ tokens</span>
              <span>I issue</span>
              <span>R revoke</span>
            </>
          ),
          right: <span>{clock}</span>,
        };
      case 'audit':
        return {
          left: (
            <>
              <span>/ filter</span>
              <span>⏎ detail</span>
              <span>M older</span>
            </>
          ),
          right: <span>{clock}</span>,
        };
      default:
        return {
          left: (
            <>
              <span>⌘K palette</span>
              <span>⌘1–6 sections</span>
            </>
          ),
          right: <span>{clock}</span>,
        };
    }
  }, [view, vaultCount, clock, oldestPending]);

  const daemonDown = daemon.isError;

  return (
    <>
      <AppShell
        view={view}
        onNavigate={setView}
        onOpenPalette={() => setPaletteOpen(true)}
        approvalsBadge={pendingCount}
        daemonOk={daemonOk}
        statusLeft={status.left}
        statusRight={status.right}
      >
        {daemonDown && (view === 'vault' || view === 'overview') ? (
          <DaemonDownPane
            endpoint={daemon.data?.endpoint ?? 'http://127.0.0.1:50091'}
            onRetry={() => void queryClient.invalidateQueries()}
          />
        ) : view === 'overview' ? (
          <OverviewView onNavigate={setView} />
        ) : view === 'vault' ? (
          <VaultView
            selectedRef={selectedRef}
            onSelect={(ref) => setSelectedRef(ref || null)}
            onEdit={(row) => {
              setEditing(row);
              setFormOpen(true);
            }}
            onDeleteApprovalCreated={(requestId) => {
              if (selectedRef) setDeleteRetry({ requestId, ref: selectedRef });
              setView('approvals');
            }}
            filterRef={filterRef}
            keysEnabled={viewKeysEnabled && view === 'vault'}
            onCountChange={setVaultCount}
          />
        ) : view === 'mesh' ? (
          <MeshView keysEnabled={viewKeysEnabled && view === 'mesh'} />
        ) : view === 'approvals' ? (
          <ApprovalsView
            keysEnabled={viewKeysEnabled && view === 'approvals'}
            deleteRetry={deleteRetry}
            onDeleteRetryDone={() => setDeleteRetry(null)}
          />
        ) : view === 'tokens' ? (
          <TokensView keysEnabled={viewKeysEnabled && view === 'tokens'} />
        ) : (
          <AuditView keysEnabled={viewKeysEnabled && view === 'audit'} />
        )}
      </AppShell>

      <Palette
        open={paletteOpen}
        onClose={() => setPaletteOpen(false)}
        onOpenSecret={openSecret}
        onCopySecret={(ref) => void copyPrimary(ref)}
        actions={paletteActions}
      />

      <SecretFormModal
        open={formOpen}
        onClose={() => setFormOpen(false)}
        editing={editing}
        onSaved={(ref) => {
          setSelectedRef(ref);
          setView('vault');
        }}
      />
    </>
  );
}
