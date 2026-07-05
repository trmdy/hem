import * as stylex from '@stylexjs/stylex';
import { useCallback, useEffect, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import type { IssueTokenResult, TokenRow } from '../../shared/types';
import { errorText, invoke, useTokens } from '../lib/api';
import { untilTime } from '../lib/fmt';
import { useKeys } from '../lib/keys';
import { Button, Dot, Kbd, SectionLabel } from '../components/ui';
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
  titleRow: { display: 'flex', alignItems: 'center', gap: 12 },
  title: { flex: 1, fontSize: 18, fontWeight: 600, color: colors.ink, letterSpacing: '-0.01em' },
  card: {
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
  row: {
    display: 'flex',
    alignItems: 'center',
    gap: 16,
    paddingBlock: 13,
    paddingInline: 22,
    borderTopWidth: 1,
    borderTopStyle: 'solid',
    borderTopColor: colors.borderFaint,
  },
  rowFirst: { borderTopWidth: 0 },
  rowFocused: {
    backgroundColor: colors.bgSelected,
    borderRadius: 6,
    margin: 4,
    paddingBlock: 11,
    paddingInline: 18,
    borderTopWidth: 0,
  },
  tokenId: {
    fontFamily: fonts.mono,
    fontSize: 12.5,
    fontWeight: 500,
    color: colors.ink,
    width: 280,
    flexShrink: 0,
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
  },
  tokenType: { fontSize: 12, color: colors.textTertiary, width: 80, flexShrink: 0 },
  tokenWho: {
    flex: 1,
    fontFamily: fonts.mono,
    fontSize: 11.5,
    color: colors.textSecondary,
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
  },
  tokenDates: { fontFamily: fonts.mono, fontSize: 10.5, color: colors.textFaint, flexShrink: 0 },
  expiringSoon: { color: colors.amber },
  confirmText: { flex: 1, fontSize: 12.5, color: colors.ink },
  confirmMono: { fontFamily: fonts.mono, fontSize: 11.5, fontWeight: 600 },
  formCard: {
    backgroundColor: colors.bgWindow,
    borderWidth: 1,
    borderStyle: 'solid',
    borderColor: colors.border,
    borderRadius: 8,
    boxShadow: shadows.card,
    padding: 20,
    display: 'flex',
    flexDirection: 'column',
    gap: 14,
  },
  formRow: { display: 'flex', alignItems: 'center', gap: 10 },
  input: {
    flex: 1,
    fontSize: 13,
    fontFamily: fonts.mono,
    color: colors.ink,
    borderWidth: 1,
    borderStyle: 'solid',
    borderColor: colors.border,
    borderRadius: 6,
    paddingBlock: 8,
    paddingInline: 13,
    outline: { default: 'none', ':focus': 'none' },
    boxShadow: { default: 'none', ':focus': shadows.focusInput },
    backgroundColor: colors.bgWindow,
    '::placeholder': { color: colors.textFaint, fontFamily: fonts.sans },
  },
  segmented: {
    display: 'inline-flex',
    borderWidth: 1,
    borderStyle: 'solid',
    borderColor: colors.border,
    borderRadius: 6,
    overflow: 'hidden',
    backgroundColor: colors.bgInset,
  },
  segment: {
    fontSize: 12,
    color: colors.textTertiary,
    paddingBlock: 6,
    paddingInline: 15,
    borderWidth: 0,
    backgroundColor: 'transparent',
    cursor: 'default',
  },
  segmentActive: {
    fontWeight: 600,
    color: colors.ink,
    backgroundColor: colors.bgWindow,
    borderLeftWidth: 1,
    borderLeftStyle: 'solid',
    borderLeftColor: colors.border,
    borderRightWidth: 1,
    borderRightStyle: 'solid',
    borderRightColor: colors.border,
  },
  hint: { fontSize: 12, color: colors.textFaint },
  issuedBox: {
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
  note: { fontSize: 11.5, color: colors.textFaint },
  errNote: { fontSize: 12.5, color: colors.textTertiary },
  empty: { paddingBlock: 18, paddingInline: 22, fontSize: 12.5, color: colors.textFaint },
});

const SERVICE_TTLS = [
  { label: '7 d', seconds: 7 * 86400 },
  { label: '30 d', seconds: 30 * 86400 },
  { label: '90 d', seconds: 90 * 86400 },
];
const AGENT_TTLS = [
  { label: '1 h', seconds: 3600 },
  { label: '8 h', seconds: 8 * 3600 },
  { label: '24 h', seconds: 24 * 3600 },
];

export function TokensView({ keysEnabled }: { keysEnabled: boolean }) {
  const tokens = useTokens();
  const queryClient = useQueryClient();

  const [focusIdx, setFocusIdx] = useState(0);
  const [confirmingRevoke, setConfirmingRevoke] = useState<string | null>(null);
  const [issuing, setIssuing] = useState<'service' | 'agent' | null>(null);
  const [serviceName, setServiceName] = useState('');
  const [agentProject, setAgentProject] = useState('');
  const [ttlIdx, setTtlIdx] = useState(1);
  const [issued, setIssued] = useState<IssueTokenResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const rows = tokens.data ?? [];
  const focused: TokenRow | undefined = rows[Math.min(focusIdx, Math.max(rows.length - 1, 0))];

  useEffect(() => {
    if (focusIdx >= rows.length) setFocusIdx(Math.max(0, rows.length - 1));
  }, [rows.length, focusIdx]);

  const doRevoke = useCallback(
    async (tokenId: string) => {
      setConfirmingRevoke(null);
      setError(null);
      try {
        await invoke('tokens:revoke', tokenId);
        void queryClient.invalidateQueries({ queryKey: ['tokens:list'] });
      } catch (err) {
        setError(errorText(err));
      }
    },
    [queryClient],
  );

  const doIssue = useCallback(async () => {
    setError(null);
    try {
      let res: IssueTokenResult;
      if (issuing === 'service') {
        if (!serviceName.trim()) return;
        res = await invoke('tokens:issueService', serviceName.trim(), SERVICE_TTLS[ttlIdx].seconds);
      } else {
        res = await invoke('tokens:issueAgent', {
          project: agentProject.trim() || undefined,
          ttlSeconds: AGENT_TTLS[ttlIdx].seconds,
        });
      }
      setIssued(res);
      setIssuing(null);
      setServiceName('');
      setAgentProject('');
      void queryClient.invalidateQueries({ queryKey: ['tokens:list'] });
    } catch (err) {
      setError(errorText(err));
    }
  }, [issuing, serviceName, agentProject, ttlIdx, queryClient]);

  useKeys(
    [
      { combo: 'arrowdown', handler: () => setFocusIdx((i) => Math.min(rows.length - 1, i + 1)) },
      { combo: 'j', handler: () => setFocusIdx((i) => Math.min(rows.length - 1, i + 1)) },
      { combo: 'arrowup', handler: () => setFocusIdx((i) => Math.max(0, i - 1)) },
      { combo: 'k', handler: () => setFocusIdx((i) => Math.max(0, i - 1)) },
      { combo: 'r', handler: () => focused && setConfirmingRevoke(focused.tokenId) },
      { combo: 'i', handler: () => setIssuing('service') },
      { combo: 'shift+i', handler: () => setIssuing('agent') },
      {
        combo: 'enter',
        handler: () => {
          if (confirmingRevoke) void doRevoke(confirmingRevoke);
        },
      },
      {
        combo: 'mod+enter',
        handler: () => {
          if (issuing) void doIssue();
        },
        inInputs: true,
      },
      {
        combo: 'escape',
        handler: () => {
          setConfirmingRevoke(null);
          setIssuing(null);
          setIssued(null);
        },
      },
    ],
    keysEnabled,
  );

  const ttls = issuing === 'agent' ? AGENT_TTLS : SERVICE_TTLS;

  return (
    <div {...stylex.props(s.pane)}>
      <div {...stylex.props(s.titleRow)}>
        <span {...stylex.props(s.title)}>{rows.length ? `${rows.length} active tokens` : 'Tokens'}</span>
        <Button variant="secondary" shortcut="I" onClick={() => setIssuing('service')}>
          Issue service token
        </Button>
        <Button variant="secondary" shortcut="⇧I" onClick={() => setIssuing('agent')}>
          Issue agent token
        </Button>
      </div>

      {error ? <div {...stylex.props(s.errNote)}>{error}</div> : null}

      {issuing ? (
        <div {...stylex.props(s.formCard)}>
          <SectionLabel>{issuing === 'service' ? 'New service token' : 'New agent token (≤ 24 h)'}</SectionLabel>
          <div {...stylex.props(s.formRow)}>
            {issuing === 'service' ? (
              <input
                {...stylex.props(s.input)}
                placeholder="service name, e.g. ci-deploy"
                value={serviceName}
                autoFocus
                onChange={(e) => setServiceName(e.target.value)}
              />
            ) : (
              <input
                {...stylex.props(s.input)}
                placeholder="project scope (optional)"
                value={agentProject}
                autoFocus
                onChange={(e) => setAgentProject(e.target.value)}
              />
            )}
            <div {...stylex.props(s.segmented)}>
              {ttls.map((t, i) => (
                <button
                  key={t.label}
                  type="button"
                  {...stylex.props(s.segment, i === ttlIdx && s.segmentActive)}
                  onClick={() => setTtlIdx(i)}
                >
                  {t.label}
                </button>
              ))}
            </div>
          </div>
          <div {...stylex.props(s.formRow)}>
            <span {...stylex.props(s.hint)}>
              {issuing === 'service'
                ? 'Service tokens get global reads plus their grants.'
                : 'Agent tokens are scoped and capped at 24 hours.'}
            </span>
            <span style={{ flex: 1 }} />
            <Button variant="ghost" shortcut="esc" onClick={() => setIssuing(null)}>
              Cancel
            </Button>
            <Button variant="primary" shortcut="⌘⏎" onClick={() => void doIssue()}>
              Issue token
            </Button>
          </div>
        </div>
      ) : null}

      {issued ? (
        <div {...stylex.props(s.formCard)}>
          <SectionLabel>token issued — {issued.info.tokenId}</SectionLabel>
          <div {...stylex.props(s.formRow)}>
            <span {...stylex.props(s.issuedBox)}>{issued.token}</span>
            <Button
              variant="confirm"
              shortcut="⌘C"
              onClick={() => void invoke('clipboard:copyText', issued.token, { concealed: true })}
            >
              Copy token
            </Button>
          </div>
          <span {...stylex.props(s.note)}>Shown once. hem doesn&apos;t return it again — copy it now.</span>
        </div>
      ) : null}

      <div {...stylex.props(s.card)}>
        {rows.map((t, i) => {
          const isFocused = i === focusIdx;
          const expSoon = t.expiresAt && Date.parse(t.expiresAt) - Date.now() < 3 * 86400_000;
          if (confirmingRevoke === t.tokenId) {
            return (
              <div key={t.tokenId} {...stylex.props(s.row, i === 0 && s.rowFirst, s.rowFocused)}>
                <span {...stylex.props(s.confirmText)}>
                  Revoke <span {...stylex.props(s.confirmMono)}>{t.tokenId}</span>
                  {t.serviceName ? ` (${t.serviceName})` : ''}? Anything using it loses access now.
                </span>
                <Button variant="smallPrimary" shortcut="⏎" onClick={() => void doRevoke(t.tokenId)}>
                  Revoke
                </Button>
                <Button variant="ghost" shortcut="esc" onClick={() => setConfirmingRevoke(null)}>
                  Keep
                </Button>
              </div>
            );
          }
          return (
            <div
              key={t.tokenId}
              {...stylex.props(s.row, i === 0 && s.rowFirst, isFocused && s.rowFocused)}
              onClick={() => setFocusIdx(i)}
            >
              <span {...stylex.props(s.tokenId)}>{t.tokenId}</span>
              <span {...stylex.props(s.tokenType)}>{t.tokenType}</span>
              <span {...stylex.props(s.tokenWho)}>
                {t.serviceName || t.identityId || t.project || (t.tokenType === 'operator' ? 'this machine' : '')}
                {t.scopes.length
                  ? ` · ${t.scopes.map((sc) => sc.replace(/^SECRET_SCOPE_/, '').toLowerCase()).join(', ')}`
                  : ''}
              </span>
              <span {...stylex.props(s.tokenDates, Boolean(expSoon) && s.expiringSoon)}>
                {t.expiresAt ? `expires ${untilTime(t.expiresAt)}` : ''}
              </span>
              {isFocused ? (
                <Button variant="smallSecondary" shortcut="R" onClick={() => setConfirmingRevoke(t.tokenId)}>
                  Revoke
                </Button>
              ) : null}
            </div>
          );
        })}
        {tokens.data && rows.length === 0 ? <div {...stylex.props(s.empty)}>No active tokens.</div> : null}
        {tokens.isError ? (
          <div {...stylex.props(s.empty)}>Tokens unavailable — {errorText(tokens.error)}</div>
        ) : null}
      </div>

      <div {...stylex.props(s.formRow)}>
        <Dot tone="gray" size={6} />
        <span {...stylex.props(s.note)}>
          Per-secret grants live in the secret&apos;s detail pane (Vault <Kbd variant="bare">⌘2</Kbd> → Access).
        </span>
      </div>
    </div>
  );
}
