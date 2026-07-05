import * as stylex from '@stylexjs/stylex';
import { Dialog } from '@base-ui/react/dialog';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import type { ScopeKind, SecretRow } from '../../shared/types';
import { errorText, invoke, useVaultList } from '../lib/api';
import { Button, Kbd } from './ui';
import { colors, fonts, shadows } from '../theme/tokens.stylex';

// Ported normalization rules (hem-raycast src/hem/env.ts / refs.ts):
export function slugify(input: string): string {
  return input
    .toLowerCase()
    .replace(/[\s_.]+/g, '-')
    .replace(/[^a-z0-9-]/g, '')
    .replace(/-{2,}/g, '-');
}

export function normalizeEnvKey(raw: string): string {
  const normalized = raw
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_]+/g, '_')
    .replace(/^_+|_+$/g, '');
  return normalized || 'value';
}

export function parseEnvText(text: string): Array<{ key: string; value: string }> {
  const entries: Array<{ key: string; value: string }> = [];
  for (const rawLine of text.split(/\r?\n/)) {
    let line = rawLine.trim();
    if (!line || line.startsWith('#') || line.startsWith('//')) continue;
    if (line.startsWith('export ')) line = line.slice('export '.length).trimStart();
    const eq = line.indexOf('=');
    if (eq <= 0) continue;
    const originalKey = line.slice(0, eq).trim();
    if (!originalKey || /\s/.test(originalKey)) continue;
    let value = line.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"') && value.length >= 2) ||
      (value.startsWith("'") && value.endsWith("'") && value.length >= 2)
    ) {
      value = value.slice(1, -1);
    } else {
      const hash = value.indexOf(' #');
      if (hash >= 0) value = value.slice(0, hash).trim();
    }
    if (!value) continue;
    entries.push({ key: normalizeEnvKey(originalKey), value });
  }
  return entries;
}

const s = stylex.create({
  backdrop: {
    position: 'fixed',
    inset: 0,
    backgroundColor: colors.overlay,
  },
  popup: {
    position: 'fixed',
    left: '50%',
    top: 96,
    transform: 'translateX(-50%)',
    width: 560,
    maxHeight: 'calc(100vh - 140px)',
    overflowY: 'auto',
    backgroundColor: colors.bgWindow,
    borderWidth: 1,
    borderStyle: 'solid',
    borderColor: colors.border,
    borderRadius: 10,
    boxShadow: shadows.modal,
    display: 'flex',
    flexDirection: 'column',
    fontFamily: fonts.sans,
    outline: 'none',
  },
  header: {
    display: 'flex',
    alignItems: 'center',
    paddingBlock: 18,
    paddingInline: 24,
    borderBottomWidth: 1,
    borderBottomStyle: 'solid',
    borderBottomColor: colors.borderFaint,
  },
  headerTitle: { flex: 1, fontSize: 14, fontWeight: 600, color: colors.ink },
  body: { padding: 24, display: 'flex', flexDirection: 'column', gap: 22 },
  group: { display: 'flex', flexDirection: 'column', gap: 8 },
  groupLabel: { fontSize: 12, fontWeight: 500, color: colors.textTertiary },
  scopeRow: { display: 'flex', gap: 10, alignItems: 'center' },
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
  comboWrap: { position: 'relative', display: 'inline-flex', flexDirection: 'column' },
  comboInput: {
    fontFamily: fonts.mono,
    fontSize: 12,
    color: colors.ink,
    borderWidth: 1,
    borderStyle: 'solid',
    borderColor: colors.border,
    borderRadius: 6,
    paddingBlock: 6,
    paddingInline: 13,
    width: 170,
    outline: 'none',
    backgroundColor: colors.bgWindow,
    '::placeholder': { fontFamily: fonts.sans, color: colors.textFaint },
  },
  comboMenu: {
    position: 'absolute',
    top: 34,
    left: 0,
    width: 210,
    backgroundColor: colors.bgWindow,
    borderWidth: 1,
    borderStyle: 'solid',
    borderColor: colors.border,
    borderRadius: 8,
    boxShadow: shadows.modal,
    padding: 6,
    display: 'flex',
    flexDirection: 'column',
    zIndex: 2,
  },
  comboItem: {
    display: 'flex',
    alignItems: 'center',
    gap: 8,
    paddingBlock: 7,
    paddingInline: 10,
    borderRadius: 6,
    fontSize: 12.5,
    color: colors.textTertiary,
    fontFamily: fonts.mono,
    backgroundColor: { default: 'transparent', ':hover': colors.bgSelected },
    borderWidth: 0,
    textAlign: 'left',
    cursor: 'default',
  },
  comboItemActive: { backgroundColor: colors.bgSelected, color: colors.ink },
  comboCreate: { fontFamily: fonts.sans, flex: 1 },
  comboCreateName: { fontFamily: fonts.mono, fontWeight: 600, fontSize: 12 },
  hint: { fontSize: 12, color: colors.textFaint },
  hintOk: { fontSize: 12, color: colors.textTertiary },
  hintMono: { fontFamily: fonts.mono, fontSize: 11.5 },
  nameInput: {
    fontFamily: fonts.mono,
    fontSize: 13,
    color: colors.ink,
    borderWidth: 0,
    borderRadius: 6,
    paddingBlock: 9,
    paddingInline: 13,
    outline: 'none',
    backgroundColor: colors.bgWindow,
    boxShadow: { default: `0 0 0 1px ${'#e6e8eb'}`, ':focus': shadows.focusInput },
    '::placeholder': { fontFamily: fonts.sans, color: colors.textFaint },
  },
  keyRow: { display: 'flex', gap: 8 },
  keyInput: {
    width: 170,
    borderWidth: 1,
    borderStyle: 'solid',
    borderColor: colors.border,
    borderRadius: 6,
    paddingBlock: 8,
    paddingInline: 13,
    fontFamily: fonts.mono,
    fontSize: 12.5,
    color: colors.ink,
    outline: { default: 'none' },
    boxShadow: { default: 'none', ':focus': shadows.focusInput },
    '::placeholder': { fontFamily: fonts.sans, color: colors.textFaint },
  },
  valueInput: {
    flex: 1,
    borderWidth: 1,
    borderStyle: 'solid',
    borderColor: colors.border,
    borderRadius: 6,
    paddingBlock: 8,
    paddingInline: 13,
    fontFamily: fonts.mono,
    fontSize: 12.5,
    color: colors.textTertiary,
    letterSpacing: '0.05em',
    outline: 'none',
    boxShadow: { default: 'none', ':focus': shadows.focusInput },
    '::placeholder': { fontFamily: fonts.sans, color: colors.textFaint, letterSpacing: 'normal' },
  },
  addKeyRow: { display: 'flex', alignItems: 'center', gap: 6, paddingBlock: 2 },
  addKeyBtn: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: 6,
    fontSize: 12,
    color: colors.textTertiary,
    backgroundColor: 'transparent',
    borderWidth: 0,
    padding: 0,
    cursor: 'default',
  },
  detailsRow: { display: 'flex', gap: 10, alignItems: 'center' },
  descInput: {
    flex: 1,
    fontSize: 12.5,
    color: colors.ink,
    borderWidth: 1,
    borderStyle: 'solid',
    borderColor: colors.border,
    borderRadius: 6,
    paddingBlock: 7,
    paddingInline: 13,
    outline: 'none',
    boxShadow: { default: 'none', ':focus': shadows.focusInput },
    backgroundColor: colors.bgWindow,
    '::placeholder': { color: colors.textFaint },
  },
  checkLabel: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: 7,
    fontSize: 12,
    color: colors.textTertiary,
    whiteSpace: 'nowrap',
    cursor: 'default',
  },
  footer: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'flex-end',
    gap: 16,
    paddingBlock: 16,
    paddingInline: 24,
    borderTopWidth: 1,
    borderTopStyle: 'solid',
    borderTopColor: colors.borderFaint,
  },
  errNote: { fontSize: 12, color: colors.textTertiary, flex: 1 },
  spacer: { flex: 1 },
});

const SCOPES: ScopeKind[] = ['global', 'project', 'identity'];

export interface SecretFormProps {
  open: boolean;
  onClose: () => void;
  /** When set, the form edits this secret: scope+name locked, values replace. */
  editing: SecretRow | null;
  onSaved: (ref: string) => void;
}

export function SecretFormModal({ open, onClose, editing, onSaved }: SecretFormProps) {
  const vault = useVaultList();
  const queryClient = useQueryClient();

  const [scope, setScope] = useState<ScopeKind>('project');
  const [container, setContainer] = useState('');
  const [comboOpen, setComboOpen] = useState(false);
  const [name, setName] = useState('');
  const [rows, setRows] = useState<Array<{ key: string; value: string }>>([{ key: '', value: '' }]);
  const [description, setDescription] = useState('');
  const [requiresApproval, setRequiresApproval] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!open) return;
    setError(null);
    setSaving(false);
    if (editing) {
      setScope(editing.scope);
      const segments = editing.ref.split('/');
      setContainer(segments.length === 3 ? segments[1] : '');
      setName(editing.name);
      setDescription(editing.description);
      setRequiresApproval(editing.requiresApproval);
      setRows([{ key: '', value: '' }]);
    } else {
      setScope('project');
      setContainer('');
      setName('');
      setDescription('');
      setRequiresApproval(false);
      setRows([{ key: '', value: '' }]);
    }
  }, [open, editing]);

  const containers = useMemo(() => {
    const prefix = scope === 'project' ? 'project/' : 'identity/';
    const set = new Set<string>();
    for (const row of vault.data ?? []) {
      if (row.section.startsWith(prefix)) set.add(row.section.slice(prefix.length));
    }
    return [...set].sort();
  }, [vault.data, scope]);

  const filteredContainers = containers.filter((c) => c.includes(slugify(container)));
  const containerIsNew = container && !containers.includes(slugify(container));

  const fullRef = useMemo(() => {
    const slug = slugify(name);
    if (!slug) return null;
    if (scope === 'global') return `global/${slug}`;
    const c = slugify(container);
    if (!c) return null;
    return `${scope}/${c}/${slug}`;
  }, [scope, container, name]);

  const refTaken = useMemo(
    () => Boolean(fullRef && (vault.data ?? []).some((r) => r.ref === fullRef)),
    [fullRef, vault.data],
  );

  const validRows = rows.filter((r) => r.key.trim() && r.value);
  const canSave = Boolean(fullRef) && validRows.length > 0 && (!refTaken || Boolean(editing)) && !saving;

  const handlePaste = useCallback((text: string, rowIdx: number): boolean => {
    const entries = parseEnvText(text);
    if (entries.length < 2) return false;
    setRows((prev) => {
      const next = prev.filter((_, i) => i !== rowIdx || prev[i].key || prev[i].value);
      return [...next.filter((r) => r.key || r.value), ...entries];
    });
    return true;
  }, []);

  const save = useCallback(async () => {
    if (!fullRef || !canSave) return;
    setSaving(true);
    setError(null);
    try {
      await invoke('vault:set', {
        ref: fullRef,
        values: validRows.map((r) => ({ key: normalizeEnvKey(r.key), value: r.value })),
        description: description.trim() || undefined,
        requiresApproval,
      });
      void queryClient.invalidateQueries({ queryKey: ['vault:list'] });
      void queryClient.invalidateQueries({ queryKey: ['vault:get', fullRef] });
      onSaved(fullRef);
      onClose();
    } catch (err) {
      setError(errorText(err));
      setSaving(false);
    }
  }, [fullRef, canSave, validRows, description, requiresApproval, queryClient, onSaved, onClose]);

  return (
    <Dialog.Root open={open} onOpenChange={(o) => !o && onClose()}>
      <Dialog.Portal>
        <Dialog.Backdrop {...stylex.props(s.backdrop)} />
        <Dialog.Popup
          {...stylex.props(s.popup)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) {
              e.preventDefault();
              void save();
            }
            if (e.key === 'Enter' && e.shiftKey) {
              e.preventDefault();
              setRows((prev) => [...prev, { key: '', value: '' }]);
            }
          }}
        >
          <div {...stylex.props(s.header)}>
            <Dialog.Title {...stylex.props(s.headerTitle)}>
              {editing ? `Edit ${editing.ref}` : 'New secret'}
            </Dialog.Title>
            <Kbd>esc</Kbd>
          </div>

          <div {...stylex.props(s.body)}>
            {!editing ? (
              <div {...stylex.props(s.group)}>
                <span {...stylex.props(s.groupLabel)}>Scope</span>
                <div {...stylex.props(s.scopeRow)}>
                  <div {...stylex.props(s.segmented)}>
                    {SCOPES.map((sc) => (
                      <button
                        key={sc}
                        type="button"
                        {...stylex.props(s.segment, scope === sc && s.segmentActive)}
                        onClick={() => setScope(sc)}
                      >
                        {sc}
                      </button>
                    ))}
                  </div>
                  {scope !== 'global' ? (
                    <div {...stylex.props(s.comboWrap)}>
                      <input
                        {...stylex.props(s.comboInput)}
                        placeholder={scope === 'project' ? 'project' : 'identity'}
                        value={container}
                        onChange={(e) => {
                          setContainer(e.target.value);
                          setComboOpen(true);
                        }}
                        onFocus={() => setComboOpen(true)}
                        onBlur={() => setTimeout(() => setComboOpen(false), 150)}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter') {
                            setContainer(slugify(container) || (filteredContainers[0] ?? ''));
                            setComboOpen(false);
                          }
                        }}
                      />
                      {comboOpen && (filteredContainers.length || containerIsNew) ? (
                        <div {...stylex.props(s.comboMenu)}>
                          {containerIsNew ? (
                            <button
                              type="button"
                              {...stylex.props(s.comboItem, s.comboItemActive)}
                              onMouseDown={() => {
                                setContainer(slugify(container));
                                setComboOpen(false);
                              }}
                            >
                              <span {...stylex.props(s.comboCreate)}>
                                Create &quot;<span {...stylex.props(s.comboCreateName)}>{slugify(container)}</span>&quot;
                              </span>
                              <Kbd variant="bare">⏎</Kbd>
                            </button>
                          ) : null}
                          {filteredContainers.map((c) => (
                            <button
                              key={c}
                              type="button"
                              {...stylex.props(s.comboItem)}
                              onMouseDown={() => {
                                setContainer(c);
                                setComboOpen(false);
                              }}
                            >
                              {c}
                            </button>
                          ))}
                        </div>
                      ) : null}
                    </div>
                  ) : null}
                </div>
                {scope !== 'global' ? (
                  <span {...stylex.props(s.hint)}>
                    Type to filter {scope === 'project' ? 'projects' : 'identities'} — a new name creates one.
                  </span>
                ) : null}
              </div>
            ) : null}

            {!editing ? (
              <div {...stylex.props(s.group)}>
                <span {...stylex.props(s.groupLabel)}>Name</span>
                <input
                  {...stylex.props(s.nameInput)}
                  placeholder="secret-name"
                  value={name}
                  autoFocus
                  onChange={(e) => setName(e.target.value)}
                />
                {fullRef ? (
                  refTaken ? (
                    <span {...stylex.props(s.hint)}>
                      <span {...stylex.props(s.hintMono)}>{fullRef}</span> already exists — saving replaces its
                      values
                    </span>
                  ) : (
                    <span {...stylex.props(s.hintOk)}>
                      <span {...stylex.props(s.hintMono)}>{fullRef}</span> is available
                    </span>
                  )
                ) : (
                  <span {...stylex.props(s.hint)}>lowercase slug: a–z, 0–9, dashes</span>
                )}
              </div>
            ) : null}

            <div {...stylex.props(s.group)}>
              <span {...stylex.props(s.groupLabel)}>Keys</span>
              {editing ? (
                <span {...stylex.props(s.hint)}>
                  Saving replaces the full value set — enter every key the secret should keep.
                </span>
              ) : null}
              {rows.map((row, i) => (
                <div key={i} {...stylex.props(s.keyRow)}>
                  <input
                    {...stylex.props(s.keyInput)}
                    placeholder="key"
                    value={row.key}
                    autoFocus={Boolean(editing) && i === 0}
                    onChange={(e) =>
                      setRows((prev) => prev.map((r, j) => (j === i ? { ...r, key: e.target.value } : r)))
                    }
                    onPaste={(e) => {
                      if (handlePaste(e.clipboardData.getData('text'), i)) e.preventDefault();
                    }}
                  />
                  <input
                    {...stylex.props(s.valueInput)}
                    placeholder="value"
                    type="password"
                    value={row.value}
                    onChange={(e) =>
                      setRows((prev) => prev.map((r, j) => (j === i ? { ...r, value: e.target.value } : r)))
                    }
                    onPaste={(e) => {
                      if (handlePaste(e.clipboardData.getData('text'), i)) e.preventDefault();
                    }}
                  />
                </div>
              ))}
              <div {...stylex.props(s.addKeyRow)}>
                <button
                  type="button"
                  {...stylex.props(s.addKeyBtn)}
                  onClick={() => setRows((prev) => [...prev, { key: '', value: '' }])}
                >
                  Add key
                  <Kbd>⇧⏎</Kbd>
                </button>
                <span {...stylex.props(s.spacer)} />
                <span {...stylex.props(s.hint)}>or paste a .env — it splits into keys</span>
              </div>
            </div>

            <div {...stylex.props(s.group)}>
              <span {...stylex.props(s.groupLabel)}>Details</span>
              <div {...stylex.props(s.detailsRow)}>
                <input
                  {...stylex.props(s.descInput)}
                  placeholder="description (optional)"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                />
                <label {...stylex.props(s.checkLabel)}>
                  <input
                    type="checkbox"
                    checked={requiresApproval}
                    onChange={(e) => setRequiresApproval(e.target.checked)}
                  />
                  requires approval
                </label>
              </div>
            </div>
          </div>

          <div {...stylex.props(s.footer)}>
            {error ? <span {...stylex.props(s.errNote)}>{error}</span> : null}
            <Button variant="ghost" shortcut="esc" onClick={onClose}>
              Cancel
            </Button>
            <Button variant="primary" shortcut="⌘⏎" disabled={!canSave} onClick={() => void save()}>
              {editing ? 'Save values' : 'Create secret'}
            </Button>
          </div>
        </Dialog.Popup>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
