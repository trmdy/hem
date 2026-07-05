import * as stylex from '@stylexjs/stylex';
import { useCallback, useEffect, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import type { ApprovalRow } from '../../shared/types';
import { errorText, invoke, useApprovals, useAudit } from '../lib/api';
import { relTime, timeOrDate } from '../lib/fmt';
import { useKeys } from '../lib/keys';
import { Button, Kbd } from '../components/ui';
import { colors, fonts, shadows } from '../theme/tokens.stylex';

const s = stylex.create({
  pane: {
    flex: 1,
    backgroundColor: colors.bgContent,
    paddingBlock: 32,
    paddingInline: 36,
    display: 'flex',
    flexDirection: 'column',
    gap: 16,
    minWidth: 0,
    overflowY: 'auto',
  },
  title: { fontSize: 18, fontWeight: 600, color: colors.ink, letterSpacing: '-0.01em' },
  card: {
    backgroundColor: colors.bgWindow,
    borderWidth: 1,
    borderStyle: 'solid',
    borderColor: colors.border,
    borderRadius: 8,
    boxShadow: shadows.card,
    paddingBlock: 20,
    paddingInline: 24,
    display: 'flex',
    flexDirection: 'column',
    gap: 12,
  },
  cardFocused: {
    borderWidth: 0,
    boxShadow: shadows.focusCard,
    paddingBlock: 21,
    paddingInline: 25,
  },
  reqLine: { display: 'flex', alignItems: 'center', gap: 10 },
  reqText: { flex: 1, fontSize: 13.5, color: colors.ink },
  reqMono: { fontFamily: fonts.mono, fontSize: 12.5, fontWeight: 600 },
  reqBold: { fontWeight: 600 },
  reqAge: { fontFamily: fonts.mono, fontSize: 11, color: colors.textFaint },
  reqMeta: { fontSize: 12.5, color: colors.textTertiary },
  metaMono: { fontFamily: fonts.mono, fontSize: 11.5 },
  actions: { display: 'flex', alignItems: 'center', gap: 12, paddingTop: 2 },
  confirmRow: {
    display: 'flex',
    alignItems: 'center',
    gap: 14,
    borderTopWidth: 1,
    borderTopStyle: 'solid',
    borderTopColor: colors.borderFaint,
    paddingTop: 12,
  },
  confirmText: { flex: 1, fontSize: 12.5, color: colors.ink },
  receiptRow: { display: 'flex', gap: 16, alignItems: 'center' },
  receiptBox: {
    flex: 1,
    backgroundColor: colors.bgInset,
    borderWidth: 1,
    borderStyle: 'solid',
    borderColor: colors.borderInput,
    borderRadius: 6,
    paddingBlock: 11,
    paddingInline: 15,
    fontFamily: fonts.mono,
    fontSize: 12,
    color: colors.ink,
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
  },
  receiptNote: { fontSize: 11.5, color: colors.textFaint },
  resolvedLine: { fontSize: 13, color: colors.textTertiary },
  resolvedMono: { fontFamily: fonts.mono, fontSize: 12, color: colors.ink },
  emptyCard: {
    backgroundColor: colors.bgWindow,
    borderWidth: 1,
    borderStyle: 'solid',
    borderColor: colors.borderFrame,
    borderRadius: 8,
    boxShadow: shadows.card,
    paddingBlock: 36,
    paddingInline: 28,
    display: 'flex',
    flexDirection: 'column',
    gap: 8,
    alignItems: 'flex-start',
    maxWidth: 400,
  },
  emptyTitle: { fontSize: 17, fontWeight: 600, color: colors.ink },
  emptyBody: { fontSize: 12.5, color: colors.textTertiary, lineHeight: 1.6 },
  errNote: { fontSize: 12.5, color: colors.textTertiary },
});

interface ReceiptState {
  requestId: string;
  ref: string;
  action: string;
  grantee: string;
  receipt: string;
  resolvedAt: string;
  /** Set when the receipt was auto-consumed by a delete retry. */
  consumed?: string;
}

function actionVerb(action: string): string {
  if (action.includes('delete')) return 'delete';
  if (action.includes('set')) return 'set';
  return 'get';
}

export function ApprovalsView({
  keysEnabled,
  deleteRetry,
  onDeleteRetryDone,
}: {
  keysEnabled: boolean;
  /** Set when the Vault delete flow created this approval request. */
  deleteRetry: { requestId: string; ref: string } | null;
  onDeleteRetryDone: () => void;
}) {
  const approvals = useApprovals();
  const audit = useAudit({ limit: 40 });
  const queryClient = useQueryClient();

  const [focusIdx, setFocusIdx] = useState(0);
  const [confirming, setConfirming] = useState<{ requestId: string; kind: 'approve' | 'deny' } | null>(null);
  const [receipts, setReceipts] = useState<ReceiptState[]>([]);
  const [error, setError] = useState<string | null>(null);

  const pending = approvals.data ?? [];
  const focused: ApprovalRow | undefined = pending[Math.min(focusIdx, Math.max(pending.length - 1, 0))];

  useEffect(() => {
    if (focusIdx >= pending.length) setFocusIdx(Math.max(0, pending.length - 1));
  }, [pending.length, focusIdx]);

  const resolve = useCallback(
    async (row: ApprovalRow, kind: 'approve' | 'deny') => {
      setConfirming(null);
      setError(null);
      try {
        if (kind === 'deny') {
          await invoke('approvals:deny', row.requestId, 'denied by owner');
        } else {
          const res = await invoke('approvals:approve', row.requestId);
          const entry: ReceiptState = {
            requestId: row.requestId,
            ref: row.ref,
            action: row.action,
            grantee: row.requesterTokenId,
            receipt: res.receipt,
            resolvedAt: new Date().toISOString(),
          };
          // Delete requests we initiated: consume the action-bound receipt
          // immediately by retrying the delete (tech doc §2.4).
          if (deleteRetry && deleteRetry.requestId === row.requestId) {
            try {
              const del = await invoke('vault:delete', deleteRetry.ref, { approvalReceipt: res.receipt });
              entry.consumed = del.deleted ? `receipt consumed — ${deleteRetry.ref} deleted` : 'delete retry did not complete';
              void queryClient.invalidateQueries({ queryKey: ['vault:list'] });
            } catch (err) {
              entry.consumed = `delete retry failed: ${errorText(err)}`;
            }
            onDeleteRetryDone();
          }
          setReceipts((prev) => [entry, ...prev].slice(0, 5));
        }
        void queryClient.invalidateQueries({ queryKey: ['approvals:list'] });
        void queryClient.invalidateQueries({ queryKey: ['audit:query'] });
      } catch (err) {
        setError(errorText(err));
      }
    },
    [deleteRetry, onDeleteRetryDone, queryClient],
  );

  useKeys(
    [
      { combo: 'arrowdown', handler: () => setFocusIdx((i) => Math.min(pending.length - 1, i + 1)) },
      { combo: 'j', handler: () => setFocusIdx((i) => Math.min(pending.length - 1, i + 1)) },
      { combo: 'arrowup', handler: () => setFocusIdx((i) => Math.max(0, i - 1)) },
      { combo: 'k', handler: () => setFocusIdx((i) => Math.max(0, i - 1)) },
      { combo: 'a', handler: () => focused && setConfirming({ requestId: focused.requestId, kind: 'approve' }) },
      { combo: 'd', handler: () => focused && setConfirming({ requestId: focused.requestId, kind: 'deny' }) },
      {
        combo: 'enter',
        handler: () => {
          if (confirming && focused && confirming.requestId === focused.requestId) {
            void resolve(focused, confirming.kind);
          }
        },
      },
      { combo: 'escape', handler: () => setConfirming(null) },
      {
        combo: 'mod+c',
        handler: () => {
          const latest = receipts[0];
          if (latest) void invoke('clipboard:copyText', latest.receipt, { concealed: true });
        },
      },
    ],
    keysEnabled,
  );

  const lastResolved = (audit.data ?? []).find((e) => e.action.toLowerCase().includes('approv'));

  return (
    <div {...stylex.props(s.pane)}>
      <div {...stylex.props(s.title)}>
        {approvals.data ? (pending.length ? `${pending.length} pending` : 'Approvals') : 'Approvals'}
      </div>

      {error ? <div {...stylex.props(s.errNote)}>{error}</div> : null}

      {pending.map((row, i) => {
        const isFocused = i === focusIdx;
        const isConfirming = confirming?.requestId === row.requestId;
        return (
          <div key={row.requestId} {...stylex.props(s.card, isFocused && s.cardFocused)}>
            <div {...stylex.props(s.reqLine)}>
              <span {...stylex.props(s.reqText)}>
                <span {...stylex.props(s.reqMono)}>{row.requesterTokenId || row.requesterIdentityId || 'unknown'}</span>{' '}
                wants to <span {...stylex.props(s.reqBold)}>{actionVerb(row.action)}</span>{' '}
                <span {...stylex.props(s.reqMono)}>{row.ref}</span>
              </span>
              <span {...stylex.props(s.reqAge)}>{relTime(row.createdAt)}</span>
            </div>
            {row.reason || row.requesterProject ? (
              <div {...stylex.props(s.reqMeta)}>
                {row.reason ? `"${row.reason}"` : ''}
                {row.reason && row.requesterProject ? ' · ' : ''}
                {row.requesterProject ? (
                  <>
                    from <span {...stylex.props(s.metaMono)}>{row.requesterProject}</span>
                  </>
                ) : null}
              </div>
            ) : null}
            {isConfirming ? (
              <div {...stylex.props(s.confirmRow)}>
                <span {...stylex.props(s.confirmText)}>
                  {confirming.kind === 'deny'
                    ? 'Deny this request? The token will see "denied by owner".'
                    : `Approve ${actionVerb(row.action)} of ${row.ref}? The receipt is single-use and action-bound.`}
                </span>
                <Button
                  variant="confirm"
                  shortcut="⏎"
                  autoFocus
                  onClick={() => void resolve(row, confirming.kind)}
                >
                  Confirm {confirming.kind}
                </Button>
                <Button variant="ghost" shortcut="esc" onClick={() => setConfirming(null)}>
                  Keep
                </Button>
              </div>
            ) : (
              <div {...stylex.props(s.actions)}>
                <Button
                  variant="primary"
                  shortcut="A"
                  onClick={() => {
                    setFocusIdx(i);
                    setConfirming({ requestId: row.requestId, kind: 'approve' });
                  }}
                >
                  Approve
                </Button>
                <Button
                  variant="secondary"
                  shortcut="D"
                  onClick={() => {
                    setFocusIdx(i);
                    setConfirming({ requestId: row.requestId, kind: 'deny' });
                  }}
                >
                  Deny
                </Button>
              </div>
            )}
          </div>
        );
      })}

      {approvals.data && pending.length === 0 && receipts.length === 0 ? (
        <div {...stylex.props(s.emptyCard)}>
          <span {...stylex.props(s.emptyTitle)}>Nothing needs you.</span>
          <span {...stylex.props(s.emptyBody)}>
            {lastResolved ? (
              <>
                Last approval activity {timeOrDate(lastResolved.ts)}.
                <br />
              </>
            ) : null}
            Past decisions are in Audit <Kbd variant="bare">⌘6</Kbd>
          </span>
        </div>
      ) : null}

      {receipts.map((r) => (
        <div key={r.requestId} {...stylex.props(s.card)}>
          <div {...stylex.props(s.resolvedLine)}>
            Approved {timeOrDate(r.resolvedAt)} — <span {...stylex.props(s.resolvedMono)}>{r.ref}</span> →{' '}
            <span {...stylex.props(s.resolvedMono)}>{r.grantee || 'requester'}</span>
          </div>
          {r.consumed ? (
            <div {...stylex.props(s.reqMeta)}>{r.consumed}</div>
          ) : (
            <>
              <div {...stylex.props(s.receiptRow)}>
                <span {...stylex.props(s.receiptBox)}>
                  {r.receipt} · one {actionVerb(r.action)}
                </span>
                <Button
                  variant="confirm"
                  shortcut="⌘C"
                  onClick={() => void invoke('clipboard:copyText', r.receipt, { concealed: true })}
                >
                  Copy receipt
                </Button>
              </div>
              <span {...stylex.props(s.receiptNote)}>Shown once. hem doesn&apos;t store it.</span>
            </>
          )}
        </div>
      ))}

      {approvals.isError ? (
        <div {...stylex.props(s.errNote)}>Approvals unavailable — {errorText(approvals.error)}</div>
      ) : null}
    </div>
  );
}
