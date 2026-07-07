import * as stylex from '@stylexjs/stylex';
import { Dialog } from '@base-ui/react/dialog';
import { useEffect, useMemo, useRef, useState } from 'react';
import type { SecretRow } from '../../shared/types';
import { useVaultList } from '../lib/api';
import { rankBy } from '../lib/fuzzy';
import type { ViewId } from '../components/AppShell';
import { Kbd } from '../components/ui';
import { colors, fonts, shadows } from '../theme/tokens.stylex';

export interface PaletteAction {
  id: string;
  label: string;
  /** Bold-matched prefix rendering is handled by fuzzy highlight; hint only. */
  shortcut?: string;
  run: () => void;
}

interface SecretResult {
  kind: 'secret';
  row: SecretRow;
}

interface ActionResult {
  kind: 'action';
  action: PaletteAction;
}

type Result = SecretResult | ActionResult;

const s = stylex.create({
  backdrop: { position: 'fixed', inset: 0, backgroundColor: colors.overlay },
  popup: {
    position: 'fixed',
    left: '50%',
    top: 120,
    transform: 'translateX(-50%)',
    width: 580,
    backgroundColor: colors.bgWindow,
    borderWidth: 1,
    borderStyle: 'solid',
    borderColor: colors.border,
    borderRadius: 10,
    boxShadow: shadows.palette,
    display: 'flex',
    flexDirection: 'column',
    overflow: 'hidden',
    fontFamily: fonts.sans,
    outline: 'none',
  },
  inputRow: {
    display: 'flex',
    alignItems: 'center',
    gap: 8,
    paddingBlock: 15,
    paddingInline: 20,
    borderBottomWidth: 1,
    borderBottomStyle: 'solid',
    borderBottomColor: colors.borderFaint,
  },
  input: {
    flex: 1,
    fontFamily: fonts.mono,
    fontSize: 15,
    color: colors.ink,
    borderWidth: 0,
    outline: 'none',
    padding: 0,
    backgroundColor: 'transparent',
    '::placeholder': { fontFamily: fonts.sans, color: colors.textFaint },
  },
  results: { padding: 8, display: 'flex', flexDirection: 'column', maxHeight: 420, overflowY: 'auto' },
  groupLabel: { paddingBlock: 8, paddingInline: 12, paddingBottom: 4, fontSize: 11, color: colors.textFaint },
  item: {
    display: 'flex',
    alignItems: 'center',
    gap: 12,
    paddingBlock: 9,
    paddingInline: 12,
    borderRadius: 6,
    width: '100%',
    borderWidth: 0,
    backgroundColor: 'transparent',
    textAlign: 'left',
    cursor: 'default',
  },
  itemActive: { backgroundColor: colors.bgSelected },
  itemName: { fontFamily: fonts.mono, fontSize: 13, color: colors.ink },
  itemNameSans: { fontFamily: fonts.sans },
  itemSection: { fontFamily: fonts.mono, fontSize: 11, color: colors.textFaint },
  spacer: { flex: 1 },
  copyHint: { display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 11, color: colors.textTertiary },
  footer: {
    display: 'flex',
    alignItems: 'center',
    gap: 16,
    paddingBlock: 10,
    paddingInline: 20,
    borderTopWidth: 1,
    borderTopStyle: 'solid',
    borderTopColor: colors.borderFaint,
    fontFamily: fonts.mono,
    fontSize: 10.5,
    color: colors.textFaint,
  },
  empty: { paddingBlock: 16, paddingInline: 12, fontSize: 12.5, color: colors.textFaint },
});

export function Palette({
  open,
  onClose,
  onOpenSecret,
  onCopySecret,
  actions,
}: {
  open: boolean;
  onClose: () => void;
  onOpenSecret: (ref: string) => void;
  onCopySecret: (ref: string) => void;
  actions: PaletteAction[];
}) {
  const vault = useVaultList();
  const [query, setQuery] = useState('');
  const [activeIdx, setActiveIdx] = useState(0);
  const listRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (open) {
      setQuery('');
      setActiveIdx(0);
    }
  }, [open]);

  const results = useMemo<Result[]>(() => {
    // Ranked, not just filtered: name matches outrank ref matches, which
    // outrank description/group matches; within a field, consecutive and
    // word-boundary matches win (lib/fuzzy).
    const secrets: Result[] = rankBy(vault.data ?? [], query, (r) => [
      [r.name, 1],
      [`${r.section}/${r.name}`, 0.9],
      [r.description, 0.5],
      [r.group, 0.5],
    ])
      .slice(0, query ? 8 : 5)
      .map(({ item }) => ({ kind: 'secret', row: item }));
    const acts: Result[] = rankBy(actions, query, (a) => [[a.label, 1]])
      .slice(0, query ? 6 : 4)
      .map(({ item }) => ({ kind: 'action', action: item }));
    return [...secrets, ...acts];
  }, [vault.data, query, actions]);

  useEffect(() => {
    if (activeIdx >= results.length) setActiveIdx(Math.max(0, results.length - 1));
  }, [results.length, activeIdx]);

  const run = (result: Result | undefined, copy: boolean): void => {
    if (!result) return;
    onClose();
    if (result.kind === 'secret') {
      if (copy) onCopySecret(result.row.ref);
      else onOpenSecret(result.row.ref);
    } else {
      result.action.run();
    }
  };

  const firstSecretIdx = results.findIndex((r) => r.kind === 'secret');
  const firstActionIdx = results.findIndex((r) => r.kind === 'action');

  return (
    <Dialog.Root open={open} onOpenChange={(o) => !o && onClose()}>
      <Dialog.Portal>
        <Dialog.Backdrop {...stylex.props(s.backdrop)} />
        <Dialog.Popup
          {...stylex.props(s.popup)}
          onKeyDown={(e) => {
            if (e.key === 'ArrowDown') {
              e.preventDefault();
              setActiveIdx((i) => Math.min(results.length - 1, i + 1));
              queueMicrotask(() =>
                listRef.current?.querySelector('[data-active="true"]')?.scrollIntoView({ block: 'nearest' }),
              );
            } else if (e.key === 'ArrowUp') {
              e.preventDefault();
              setActiveIdx((i) => Math.max(0, i - 1));
              queueMicrotask(() =>
                listRef.current?.querySelector('[data-active="true"]')?.scrollIntoView({ block: 'nearest' }),
              );
            } else if (e.key === 'Enter') {
              e.preventDefault();
              run(results[activeIdx], e.metaKey || e.ctrlKey);
            }
          }}
        >
          <div {...stylex.props(s.inputRow)}>
            <input
              {...stylex.props(s.input)}
              placeholder="Search secrets and actions"
              value={query}
              autoFocus
              onChange={(e) => {
                setQuery(e.target.value);
                setActiveIdx(0);
              }}
            />
            <Kbd>esc</Kbd>
          </div>
          <div {...stylex.props(s.results)} ref={listRef}>
            {results.map((result, i) => {
              const active = i === activeIdx;
              if (result.kind === 'secret') {
                return (
                  <div key={`s-${result.row.ref}`}>
                    {i === firstSecretIdx ? <div {...stylex.props(s.groupLabel)}>Secrets</div> : null}
                    <button
                      type="button"
                      data-active={active}
                      {...stylex.props(s.item, active && s.itemActive)}
                      onClick={(e) => run(result, e.metaKey)}
                      onMouseMove={() => setActiveIdx(i)}
                    >
                      <span {...stylex.props(s.itemName)}>{result.row.name}</span>
                      <span {...stylex.props(s.itemSection)}>{result.row.section}</span>
                      <span {...stylex.props(s.spacer)} />
                      {active ? (
                        <span {...stylex.props(s.copyHint)}>
                          <Kbd variant="selChip">⌘⏎</Kbd>
                          copy value
                        </span>
                      ) : null}
                    </button>
                  </div>
                );
              }
              return (
                <div key={`a-${result.action.id}`}>
                  {i === firstActionIdx ? <div {...stylex.props(s.groupLabel)}>Actions</div> : null}
                  <button
                    type="button"
                    data-active={active}
                    {...stylex.props(s.item, active && s.itemActive)}
                    onClick={() => run(result, false)}
                    onMouseMove={() => setActiveIdx(i)}
                  >
                    <span {...stylex.props(s.itemName, s.itemNameSans)}>{result.action.label}</span>
                    <span {...stylex.props(s.spacer)} />
                    {result.action.shortcut ? <Kbd variant="bare">{result.action.shortcut}</Kbd> : null}
                  </button>
                </div>
              );
            })}
            {!results.length ? <div {...stylex.props(s.empty)}>Nothing matches.</div> : null}
          </div>
          <div {...stylex.props(s.footer)}>
            <span>↑↓</span>
            <span>⏎ open</span>
            <span>⌘⏎ copy value</span>
          </div>
        </Dialog.Popup>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

export type { ViewId };
