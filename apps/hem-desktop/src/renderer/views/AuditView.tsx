import * as stylex from '@stylexjs/stylex';
import { useCallback, useMemo, useState } from 'react';
import type { AuditRow } from '../../shared/types';
import { errorText, invoke } from '../lib/api';
import { useQuery } from '@tanstack/react-query';
import { timeOrDate } from '../lib/fmt';
import { useKeys } from '../lib/keys';
import { fuzzyMatch } from './VaultView';
import { Button, Kbd } from '../components/ui';
import { colors, fonts, shadows } from '../theme/tokens.stylex';

const PAGE = 100;

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
    overflow: 'hidden',
  },
  titleRow: { display: 'flex', alignItems: 'center', gap: 14 },
  title: { fontSize: 18, fontWeight: 600, color: colors.ink, letterSpacing: '-0.01em' },
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
    width: 280,
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
  spacer: { flex: 1 },
  tableCard: {
    backgroundColor: colors.bgWindow,
    borderWidth: 1,
    borderStyle: 'solid',
    borderColor: colors.border,
    borderRadius: 8,
    boxShadow: shadows.card,
    display: 'flex',
    flexDirection: 'column',
    overflowY: 'auto',
    flex: 1,
  },
  row: {
    display: 'flex',
    alignItems: 'baseline',
    gap: 16,
    paddingBlock: 10,
    paddingInline: 22,
    borderTopWidth: 1,
    borderTopStyle: 'solid',
    borderTopColor: colors.borderHair,
    cursor: 'default',
    width: '100%',
    textAlign: 'left',
    backgroundColor: { default: 'transparent', ':hover': colors.bgInset },
    borderLeftWidth: 0,
    borderRightWidth: 0,
    borderBottomWidth: 0,
  },
  rowFirst: { borderTopWidth: 0 },
  rowExpanded: { backgroundColor: colors.bgSelected },
  time: { fontFamily: fonts.mono, fontSize: 11, color: colors.textFaint, width: 52, flexShrink: 0 },
  action: { fontSize: 12.5, color: colors.textSecondary, width: 130, flexShrink: 0 },
  ref: {
    flex: 1,
    fontFamily: fonts.mono,
    fontSize: 11.5,
    color: colors.ink,
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
  },
  actor: {
    fontFamily: fonts.mono,
    fontSize: 10.5,
    color: colors.textFaint,
    width: 130,
    flexShrink: 0,
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
  },
  result: { fontSize: 11, width: 56, flexShrink: 0, color: colors.textFaint },
  resultBad: { color: colors.ink, fontWeight: 600 },
  detail: {
    paddingBlock: 12,
    paddingInline: 22,
    backgroundColor: colors.bgInset,
    borderTopWidth: 1,
    borderTopStyle: 'solid',
    borderTopColor: colors.borderFaint,
    display: 'flex',
    flexDirection: 'column',
    gap: 8,
  },
  detailText: {
    fontFamily: fonts.mono,
    fontSize: 11,
    color: colors.textSecondary,
    lineHeight: 1.7,
    whiteSpace: 'pre-wrap',
    wordBreak: 'break-all',
    userSelect: 'text',
  },
  detailActions: { display: 'flex', gap: 10 },
  footRow: { display: 'flex', alignItems: 'center', gap: 12 },
  note: { fontSize: 12, color: colors.textFaint },
});

export function AuditView({ keysEnabled }: { keysEnabled: boolean }) {
  const [pages, setPages] = useState(1);
  const [filter, setFilter] = useState('');
  const [expanded, setExpanded] = useState<string | null>(null);

  // Paged via `until` cursors: page N queries entries older than the last
  // entry of page N-1. Pages are cached individually by query key.
  const audit = useQuery({
    queryKey: ['audit:query', 'paged', pages],
    queryFn: async () => {
      const all: AuditRow[] = [];
      let until: string | undefined;
      for (let i = 0; i < pages; i += 1) {
        const batch = await invoke('audit:query', { limit: PAGE, until });
        all.push(...batch);
        if (batch.length < PAGE) break;
        until = batch[batch.length - 1].ts;
      }
      return all;
    },
    retry: false,
    refetchInterval: 60_000,
  });

  const rows = useMemo(() => {
    const all = audit.data ?? [];
    const sorted = [...all].sort((a, b) => (a.ts < b.ts ? 1 : -1));
    if (!filter) return sorted;
    return sorted.filter((r) => fuzzyMatch(filter, `${r.action} ${r.actor} ${r.ref ?? ''} ${r.result} ${r.details}`));
  }, [audit.data, filter]);

  const copyJson = useCallback((row: AuditRow) => {
    void invoke('clipboard:copyText', JSON.stringify(row, null, 2), {});
  }, []);

  useKeys(
    [
      { combo: '/', handler: () => (document.getElementById('audit-filter') as HTMLInputElement | null)?.focus() },
      { combo: 'm', handler: () => setPages((p) => p + 1) },
      { combo: 'escape', handler: () => setExpanded(null) },
    ],
    keysEnabled,
  );

  return (
    <div {...stylex.props(s.pane)}>
      <div {...stylex.props(s.titleRow)}>
        <span {...stylex.props(s.title)}>Audit</span>
        <div {...stylex.props(s.filterBox)}>
          <input
            id="audit-filter"
            {...stylex.props(s.filterInput)}
            placeholder="Filter action, actor, ref"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
          <Kbd>/</Kbd>
        </div>
        <span {...stylex.props(s.spacer)} />
        <span {...stylex.props(s.note)}>
          {rows.length} entries{filter ? ' (filtered)' : ''} · newest first
        </span>
      </div>

      <div {...stylex.props(s.tableCard)}>
        {rows.map((row, i) => {
          const isExpanded = expanded === row.auditId;
          const bad = row.result && !/^(ok|success)/i.test(row.result);
          return (
            <div key={row.auditId}>
              <button
                type="button"
                {...stylex.props(s.row, i === 0 && s.rowFirst, isExpanded && s.rowExpanded)}
                onClick={() => setExpanded(isExpanded ? null : row.auditId)}
              >
                <span {...stylex.props(s.time)}>{timeOrDate(row.ts)}</span>
                <span {...stylex.props(s.action)}>{row.action.replaceAll('_', ' ')}</span>
                <span {...stylex.props(s.ref)}>{row.ref ?? row.details.slice(0, 80)}</span>
                <span {...stylex.props(s.actor)}>{row.actor || row.tokenId}</span>
                <span {...stylex.props(s.result, Boolean(bad) && s.resultBad)}>{row.result}</span>
              </button>
              {isExpanded ? (
                <div {...stylex.props(s.detail)}>
                  <span {...stylex.props(s.detailText)}>
                    {row.ts}
                    {'\n'}action={row.action} actor={row.actor} token={row.tokenId} result={row.result}
                    {row.ref ? `\nref=${row.ref}` : ''}
                    {row.details ? `\n${row.details}` : ''}
                  </span>
                  <div {...stylex.props(s.detailActions)}>
                    <Button variant="smallSecondary" onClick={() => copyJson(row)}>
                      Copy as JSON
                    </Button>
                  </div>
                </div>
              ) : null}
            </div>
          );
        })}
        {audit.data && rows.length === 0 ? (
          <div {...stylex.props(s.row, s.rowFirst)}>
            <span {...stylex.props(s.note)}>No matching entries.</span>
          </div>
        ) : null}
        {audit.isError ? (
          <div {...stylex.props(s.row, s.rowFirst)}>
            <span {...stylex.props(s.note)}>Audit unavailable — {errorText(audit.error)}</span>
          </div>
        ) : null}
      </div>

      <div {...stylex.props(s.footRow)}>
        <Button variant="smallSecondary" shortcut="M" onClick={() => setPages((p) => p + 1)}>
          Load older
        </Button>
        {audit.isFetching ? <span {...stylex.props(s.note)}>loading…</span> : null}
      </div>
    </div>
  );
}
