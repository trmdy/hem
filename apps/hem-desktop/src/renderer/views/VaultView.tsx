import * as stylex from '@stylexjs/stylex';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import type { MaskedKey, SecretRow } from '../../shared/types';
import { errorText, invoke, useSecretDetail, useVaultList, useVersionHistory } from '../lib/api';
import { dateShort, relTime } from '../lib/fmt';
import { useKeys } from '../lib/keys';
import { Button, Dot, Kbd, SectionLabel } from '../components/ui';
import { colors, fonts, shadows } from '../theme/tokens.stylex';

const PRIMARY_KEY_GUESS = ['api_key', 'api_token', 'token', 'key', 'password', 'secret'];

export function primaryKey(keys: MaskedKey[]): string | null {
  if (!keys.length) return null;
  for (const guess of PRIMARY_KEY_GUESS) {
    const hit = keys.find((k) => k.key === guess);
    if (hit) return hit.key;
  }
  return keys[0].key;
}

/** Substring first, then subsequence — cheap fuzzy in the palette's spirit. */
export function fuzzyMatch(query: string, text: string): boolean {
  const q = query.toLowerCase();
  const t = text.toLowerCase();
  if (!q) return true;
  if (t.includes(q)) return true;
  let i = 0;
  for (const ch of t) {
    if (ch === q[i]) i += 1;
    if (i === q.length) return true;
  }
  return false;
}

const s = stylex.create({
  listPane: {
    width: 300,
    borderRightWidth: 1,
    borderRightStyle: 'solid',
    borderRightColor: colors.border,
    display: 'flex',
    flexDirection: 'column',
    flexShrink: 0,
    overflow: 'hidden',
  },
  filterWrap: { paddingBlock: 12, paddingInline: 14 },
  filterBox: {
    display: 'flex',
    alignItems: 'center',
    gap: 8,
    borderWidth: 1,
    borderStyle: 'solid',
    borderColor: colors.border,
    borderRadius: 6,
    paddingBlock: 7,
    paddingInline: 11,
    backgroundColor: colors.bgWindow,
  },
  filterInput: {
    flex: 1,
    fontSize: 13,
    color: colors.ink,
    borderWidth: 0,
    outline: 'none',
    padding: 0,
    backgroundColor: 'transparent',
    '::placeholder': { color: colors.textFaint },
  },
  list: { flex: 1, overflowY: 'auto', paddingInline: 10, paddingBottom: 10 },
  sectionHeader: { paddingTop: 14, paddingBottom: 6, paddingInline: 10 },
  sectionHeaderFirst: { paddingTop: 10 },
  row: {
    display: 'flex',
    alignItems: 'baseline',
    gap: 8,
    paddingBlock: 8,
    paddingInline: 10,
    borderRadius: 6,
    width: '100%',
    borderWidth: 0,
    backgroundColor: { default: 'transparent', ':hover': colors.bgSelected },
    cursor: 'default',
    textAlign: 'left',
  },
  rowSelected: { backgroundColor: colors.bgSelected },
  rowName: {
    flex: 1,
    fontSize: 13,
    fontWeight: 500,
    color: colors.ink,
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
  },
  rowNameSelected: { fontWeight: 600 },
  rowTime: { fontFamily: fonts.mono, fontSize: 10.5, color: colors.textFaint },
  detailPane: {
    flex: 1,
    backgroundColor: colors.bgContent,
    overflowY: 'auto',
    paddingBlock: 32,
    paddingInline: 36,
    display: 'flex',
    flexDirection: 'column',
    gap: 24,
    minWidth: 0,
  },
  headerBlock: { display: 'flex', flexDirection: 'column', gap: 8 },
  headerRow: { display: 'flex', alignItems: 'center', gap: 12 },
  refTitle: {
    flex: 1,
    fontFamily: fonts.mono,
    fontSize: 19,
    fontWeight: 600,
    color: colors.ink,
    letterSpacing: '-0.01em',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
    cursor: 'default',
  },
  metaLine: { fontSize: 12.5, color: colors.textMuted },
  metaMono: { fontFamily: fonts.mono, fontSize: 11.5, color: colors.textTertiary },
  keysCard: {
    backgroundColor: colors.bgWindow,
    borderWidth: 1,
    borderStyle: 'solid',
    borderColor: colors.border,
    borderRadius: 8,
    boxShadow: shadows.card,
  },
  keyRow: {
    display: 'flex',
    alignItems: 'center',
    gap: 16,
    paddingBlock: 14,
    paddingInline: 22,
    borderTopWidth: 1,
    borderTopStyle: 'solid',
    borderTopColor: colors.borderFaint,
  },
  keyRowFirst: { borderTopWidth: 0 },
  keyRowFocused: {
    paddingBlock: 12,
    paddingInline: 12,
    margin: 4,
    borderRadius: 6,
    backgroundColor: colors.bgSelected,
    borderTopWidth: 0,
  },
  keyName: {
    width: 120,
    fontFamily: fonts.mono,
    fontSize: 13,
    color: colors.ink,
    flexShrink: 0,
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  keyNameFocused: { paddingLeft: 6 },
  keyMasked: {
    flex: 1,
    fontFamily: fonts.mono,
    fontSize: 13,
    color: colors.textTertiary,
    letterSpacing: '0.05em',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
  },
  keyRevealed: {
    flex: 1,
    fontFamily: fonts.mono,
    fontSize: 12.5,
    color: colors.ink,
    backgroundColor: colors.bgMaskChip,
    borderRadius: 4,
    paddingBlock: 1,
    paddingInline: 7,
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
    userSelect: 'text',
  },
  keyCopied: { flex: 1, fontSize: 12.5, color: colors.ink, fontWeight: 500 },
  keyHint: { fontSize: 11, color: colors.textFaint, flexShrink: 0 },
  section: { display: 'flex', flexDirection: 'column', gap: 10 },
  accessRow: { display: 'flex', alignItems: 'center', gap: 10, fontSize: 12.5, color: colors.textSecondary },
  accessId: { fontFamily: fonts.mono, fontSize: 12, color: colors.ink },
  accessDim: { color: colors.textFaint },
  historyRow: { display: 'flex', alignItems: 'baseline', gap: 12, fontSize: 12.5, color: colors.textSecondary },
  historySeq: { fontFamily: fonts.mono, fontSize: 11.5, color: colors.textMuted },
  historySeqLatest: { fontWeight: 600, color: colors.ink },
  historyWhat: { flex: 1 },
  historyDate: { fontFamily: fonts.mono, fontSize: 10.5, color: colors.textFaint },
  historyMore: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: 6,
    fontSize: 12,
    color: colors.textMuted,
    paddingTop: 2,
    backgroundColor: 'transparent',
    borderWidth: 0,
    cursor: 'default',
    padding: 0,
  },
  confirmBar: {
    display: 'flex',
    alignItems: 'center',
    gap: 12,
    borderRadius: 6,
    paddingBlock: 11,
    paddingInline: 13,
    backgroundColor: colors.bgSelected,
  },
  confirmText: { flex: 1, fontSize: 12.5, color: colors.ink },
  confirmMono: { fontFamily: fonts.mono, fontSize: 11.5, fontWeight: 600 },
  pendingNote: {
    fontSize: 12.5,
    color: colors.textTertiary,
    lineHeight: 1.6,
  },
  emptyDetail: {
    flex: 1,
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    color: colors.textFaint,
    fontSize: 13,
  },
  errorCard: {
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
});

type KeyState =
  | { mode: 'masked' }
  | { mode: 'revealed'; value: string; secondsLeft: number }
  | { mode: 'copied'; secondsLeft: number };

export interface VaultViewProps {
  selectedRef: string | null;
  onSelect: (ref: string) => void;
  onEdit: (row: SecretRow) => void;
  onDeleteApprovalCreated: (requestId: string) => void;
  filterRef: React.RefObject<HTMLInputElement | null>;
  keysEnabled: boolean;
  onCountChange: (count: number) => void;
}

export function VaultView({
  selectedRef,
  onSelect,
  onEdit,
  onDeleteApprovalCreated,
  filterRef,
  keysEnabled,
  onCountChange,
}: VaultViewProps) {
  const vault = useVaultList();
  const detail = useSecretDetail(selectedRef);
  const history = useVersionHistory(selectedRef);
  const queryClient = useQueryClient();

  const [filter, setFilter] = useState('');
  const [focusedKeyIdx, setFocusedKeyIdx] = useState(0);
  const [keyStates, setKeyStates] = useState<Record<string, KeyState>>({});
  const [confirmingDelete, setConfirmingDelete] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [showAllVersions, setShowAllVersions] = useState(false);
  const listRef = useRef<HTMLDivElement>(null);

  const rows = useMemo(() => {
    const all = vault.data ?? [];
    const filtered = filter
      ? all.filter((r) => fuzzyMatch(filter, `${r.section}/${r.name} ${r.description} ${r.group}`))
      : all;
    const yes = [...filtered].sort((a, b) =>
      a.section === b.section ? a.name.localeCompare(b.name) : a.section.localeCompare(b.section),
    );
    // global first, then project/*, then identity/*
    const rank = (s: string) => (s === 'global' ? 0 : s.startsWith('project/') ? 1 : 2);
    yes.sort((a, b) => rank(a.section) - rank(b.section) || a.section.localeCompare(b.section));
    return yes;
  }, [vault.data, filter]);

  useEffect(() => onCountChange(vault.data?.length ?? 0), [vault.data, onCountChange]);

  // reset transient state when switching secrets
  useEffect(() => {
    setFocusedKeyIdx(0);
    setKeyStates({});
    setConfirmingDelete(false);
    setDeleteError(null);
    setShowAllVersions(false);
  }, [selectedRef]);

  // countdown ticker for revealed/copied states
  useEffect(() => {
    const iv = setInterval(() => {
      setKeyStates((prev) => {
        let changed = false;
        const next: Record<string, KeyState> = {};
        for (const [k, st] of Object.entries(prev)) {
          if (st.mode === 'masked') {
            next[k] = st;
          } else if (st.secondsLeft <= 1) {
            next[k] = { mode: 'masked' };
            changed = true;
          } else {
            next[k] = { ...st, secondsLeft: st.secondsLeft - 1 };
            changed = true;
          }
        }
        return changed ? next : prev;
      });
    }, 1000);
    return () => clearInterval(iv);
  }, []);

  const selectedIdx = rows.findIndex((r) => r.ref === selectedRef);

  const moveSelection = useCallback(
    (delta: number) => {
      if (!rows.length) return;
      const next = Math.min(rows.length - 1, Math.max(0, (selectedIdx < 0 ? 0 : selectedIdx) + delta));
      onSelect(rows[next].ref);
      const el = listRef.current?.querySelector(`[data-ref="${CSS.escape(rows[next].ref)}"]`);
      el?.scrollIntoView({ block: 'nearest' });
    },
    [rows, selectedIdx, onSelect],
  );

  const keys = detail.data?.keys ?? [];
  const focusedKey = keys[Math.min(focusedKeyIdx, Math.max(keys.length - 1, 0))] ?? null;

  const copyKey = useCallback(
    async (key: string | null) => {
      if (!selectedRef || !key) return;
      try {
        const res = await invoke('vault:copy', selectedRef, key);
        setKeyStates((prev) => ({ ...prev, [key]: { mode: 'copied', secondsLeft: res.clearedAfter || 5 } }));
      } catch (err) {
        setDeleteError(errorText(err));
      }
    },
    [selectedRef],
  );

  const revealKey = useCallback(
    async (key: string | null) => {
      if (!selectedRef || !key) return;
      const current = keyStates[key];
      if (current?.mode === 'revealed') {
        setKeyStates((prev) => ({ ...prev, [key]: { mode: 'masked' } }));
        return;
      }
      try {
        const res = await invoke('vault:reveal', selectedRef, key);
        setKeyStates((prev) => ({
          ...prev,
          [key]: { mode: 'revealed', value: res.value, secondsLeft: res.remaskAfter || 30 },
        }));
      } catch (err) {
        setDeleteError(errorText(err));
      }
    },
    [selectedRef, keyStates],
  );

  const doDelete = useCallback(async () => {
    if (!selectedRef) return;
    setConfirmingDelete(false);
    try {
      const res = await invoke('vault:delete', selectedRef, {});
      if (res.deleted) {
        void queryClient.invalidateQueries({ queryKey: ['vault:list'] });
        onSelect('');
      } else if (res.approvalRequired) {
        onDeleteApprovalCreated(res.approvalRequired.requestId);
      }
    } catch (err) {
      setDeleteError(errorText(err));
    }
  }, [selectedRef, queryClient, onSelect, onDeleteApprovalCreated]);

  useKeys(
    [
      { combo: 'arrowdown', handler: () => moveSelection(1) },
      { combo: 'j', handler: () => moveSelection(1) },
      { combo: 'arrowup', handler: () => moveSelection(-1) },
      { combo: 'k', handler: () => moveSelection(-1) },
      {
        combo: '/',
        handler: () => filterRef.current?.focus(),
      },
      {
        combo: 'escape',
        handler: () => {
          if (confirmingDelete) setConfirmingDelete(false);
          else if (document.activeElement === filterRef.current) {
            setFilter('');
            filterRef.current?.blur();
          }
        },
      },
      { combo: 'mod+c', handler: () => void copyKey(focusedKey?.key ?? primaryKey(keys)) },
      { combo: 'mod+r', handler: () => void revealKey(focusedKey?.key ?? primaryKey(keys)) },
      { combo: 'mod+shift+c', handler: () => selectedRef && void invoke('clipboard:copyText', selectedRef, {}) },
      { combo: 'tab', handler: () => keys.length && setFocusedKeyIdx((i) => (i + 1) % keys.length) },
      { combo: 'e', handler: () => detail.data && onEdit(detail.data.row) },
      { combo: 'h', handler: () => setShowAllVersions((v) => !v) },
      {
        combo: 'mod+backspace',
        handler: () => {
          if (selectedRef) setConfirmingDelete(true);
        },
      },
      {
        combo: 'enter',
        handler: () => {
          if (confirmingDelete) void doDelete();
        },
      },
    ],
    keysEnabled,
  );

  const versions = history.data ?? [];
  const shownVersions = showAllVersions ? versions : versions.slice(0, 2);

  let lastSection: string | null = null;

  return (
    <>
      <div {...stylex.props(s.listPane)}>
        <div {...stylex.props(s.filterWrap)}>
          <div {...stylex.props(s.filterBox)}>
            <input
              ref={filterRef}
              {...stylex.props(s.filterInput)}
              placeholder="Filter"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'ArrowDown' || e.key === 'ArrowUp' || e.key === 'Enter') {
                  e.currentTarget.blur();
                }
              }}
            />
            <Kbd>/</Kbd>
          </div>
        </div>
        <div {...stylex.props(s.list)} ref={listRef}>
          {rows.map((row) => {
            const header = row.section !== lastSection ? row.section : null;
            lastSection = row.section;
            const selected = row.ref === selectedRef;
            return (
              <div key={row.ref}>
                {header ? (
                  <div {...stylex.props(s.sectionHeader)}>
                    <SectionLabel>{header}</SectionLabel>
                  </div>
                ) : null}
                <button
                  type="button"
                  data-ref={row.ref}
                  {...stylex.props(s.row, selected && s.rowSelected)}
                  onClick={() => onSelect(row.ref)}
                >
                  <span {...stylex.props(s.rowName, selected && s.rowNameSelected)}>{row.name}</span>
                  {selected ? (
                    <>
                      <Kbd variant="selChip">⏎</Kbd>
                      <Kbd variant="selChip">⌘C</Kbd>
                    </>
                  ) : (
                    <span {...stylex.props(s.rowTime)}>{relTime(row.updatedAt)}</span>
                  )}
                </button>
              </div>
            );
          })}
          {vault.isError ? (
            <div {...stylex.props(s.sectionHeader)}>
              <SectionLabel>daemon unreachable</SectionLabel>
            </div>
          ) : null}
        </div>
      </div>

      <div {...stylex.props(s.detailPane)}>
        {!selectedRef || !detail.data ? (
          <div {...stylex.props(s.emptyDetail)}>
            {vault.data?.length ? 'Select a secret — ↑↓ to move, / to filter' : ' '}
          </div>
        ) : (
          <>
            <div {...stylex.props(s.headerBlock)}>
              {confirmingDelete ? (
                <div {...stylex.props(s.confirmBar)}>
                  <span {...stylex.props(s.confirmText)}>
                    Delete <span {...stylex.props(s.confirmMono)}>{detail.data.row.ref}</span>? Deletion runs the
                    server-side approval flow.
                  </span>
                  <Button variant="smallPrimary" shortcut="⏎" onClick={() => void doDelete()}>
                    Delete
                  </Button>
                  <Button variant="ghost" shortcut="esc" onClick={() => setConfirmingDelete(false)}>
                    Keep
                  </Button>
                </div>
              ) : (
                <div {...stylex.props(s.headerRow)}>
                  <span
                    {...stylex.props(s.refTitle)}
                    title="⌘⇧C copies the ref"
                    onClick={() => void invoke('clipboard:copyText', detail.data.row.ref, {})}
                  >
                    {detail.data.row.ref}
                  </span>
                  <Button variant="smallSecondary" shortcut="E" onClick={() => onEdit(detail.data.row)}>
                    Edit
                  </Button>
                  <Button variant="smallSecondary" shortcut="⌘⌫" onClick={() => setConfirmingDelete(true)}>
                    Delete
                  </Button>
                </div>
              )}
              <div {...stylex.props(s.metaLine)}>
                {detail.data.row.requiresApproval ? 'Requires approval · ' : ''}
                {detail.data.row.group ? (
                  <>
                    group <span {...stylex.props(s.metaMono)}>{detail.data.row.group}</span> ·{' '}
                  </>
                ) : null}
                updated {dateShort(detail.data.row.updatedAt)}
                {detail.data.row.createdBy ? (
                  <>
                    {' '}
                    by <span {...stylex.props(s.metaMono)}>{detail.data.row.createdBy}</span>
                  </>
                ) : null}
                {detail.data.row.description ? ` · ${detail.data.row.description}` : ''}
              </div>
              {deleteError ? <div {...stylex.props(s.metaLine)}>{deleteError}</div> : null}
            </div>

            {detail.data.policyError ? (
              <div {...stylex.props(s.errorCard)}>
                <span {...stylex.props(s.errorTitle)}>Values unavailable under the cluster read policy.</span>
                <span {...stylex.props(s.errorBody)}>{detail.data.policyError}</span>
              </div>
            ) : detail.data.pending ? (
              <div {...stylex.props(s.errorCard)}>
                <span {...stylex.props(s.errorTitle)}>Read is approval-gated.</span>
                <span {...stylex.props(s.errorBody)}>
                  Request <span {...stylex.props(s.metaMono)}>{detail.data.pending.requestId}</span> is pending —
                  resolve it in Approvals (⌘4).
                </span>
              </div>
            ) : (
              <div {...stylex.props(s.keysCard)}>
                {keys.map((k, i) => {
                  const st = keyStates[k.key] ?? { mode: 'masked' };
                  const focused = i === focusedKeyIdx;
                  return (
                    <div
                      key={k.key}
                      {...stylex.props(s.keyRow, i === 0 && s.keyRowFirst, focused && s.keyRowFocused)}
                      onClick={() => setFocusedKeyIdx(i)}
                    >
                      <span {...stylex.props(s.keyName, focused && s.keyNameFocused)}>{k.key}</span>
                      {st.mode === 'revealed' ? (
                        <span {...stylex.props(s.keyRevealed)}>{st.value}</span>
                      ) : st.mode === 'copied' ? (
                        <span {...stylex.props(s.keyCopied)}>
                          Copied — clipboard clears in {st.secondsLeft}s
                        </span>
                      ) : (
                        <span {...stylex.props(s.keyMasked)}>{k.masked}</span>
                      )}
                      {st.mode === 'revealed' ? (
                        <span {...stylex.props(s.keyHint)}>remasks in {st.secondsLeft}s</span>
                      ) : null}
                      {focused ? (
                        <>
                          <Button variant="smallPrimary" shortcut="⌘C" onClick={() => void copyKey(k.key)}>
                            Copy
                          </Button>
                          <Button variant="smallSecondary" shortcut="⌘R" onClick={() => void revealKey(k.key)}>
                            {st.mode === 'revealed' ? 'Mask' : 'Reveal'}
                          </Button>
                        </>
                      ) : null}
                    </div>
                  );
                })}
                {!keys.length ? (
                  <div {...stylex.props(s.keyRow, s.keyRowFirst)}>
                    <span {...stylex.props(s.keyMasked)}>no values</span>
                  </div>
                ) : null}
              </div>
            )}

            {detail.data.grants.length ? (
              <div {...stylex.props(s.section)}>
                <SectionLabel>Access</SectionLabel>
                {detail.data.grants.map((g) => (
                  <div key={`${g.granteeScope}-${g.granteeId}`} {...stylex.props(s.accessRow)}>
                    <span {...stylex.props(s.accessId)}>{g.granteeId}</span>
                    <span {...stylex.props(s.accessDim)}>
                      get{detail.data.row.requiresApproval ? ', via approval' : ''}
                    </span>
                  </div>
                ))}
              </div>
            ) : null}

            {versions.length ? (
              <div {...stylex.props(s.section)}>
                <SectionLabel>History</SectionLabel>
                {shownVersions.map((v, i) => (
                  <div key={`${v.versionSeq}-${v.createdAt}`} {...stylex.props(s.historyRow)}>
                    <span {...stylex.props(s.historySeq, i === 0 && s.historySeqLatest)}>v{v.versionSeq}</span>
                    <span {...stylex.props(s.historyWhat)}>
                      {v.kind}
                      {v.node ? ` · ${v.node}` : ''}
                    </span>
                    <span {...stylex.props(s.historyDate)}>{dateShort(v.createdAt)}</span>
                  </div>
                ))}
                {versions.length > 2 ? (
                  <button
                    type="button"
                    {...stylex.props(s.historyMore)}
                    onClick={() => setShowAllVersions((v) => !v)}
                  >
                    {showAllVersions ? 'Fewer versions' : 'All versions'}
                    <Kbd variant="bare">H</Kbd>
                  </button>
                ) : null}
              </div>
            ) : null}

            <div {...stylex.props(s.pendingNote)}>
              <Dot tone="gray" size={6} /> Values are fetched on demand and never stored by this app.
            </div>
          </>
        )}
      </div>
    </>
  );
}
