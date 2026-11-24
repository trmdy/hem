import { describe, expect, it } from 'vitest';
import { matches } from '../../src/renderer/lib/keys';

type Mods = Partial<Record<'metaKey' | 'ctrlKey' | 'shiftKey' | 'altKey', boolean>>;
const ev = (key: string, mods: Mods = {}): Parameters<typeof matches>[0] =>
  ({ key, metaKey: false, ctrlKey: false, shiftKey: false, altKey: false, ...mods }) as unknown as Parameters<
    typeof matches
  >[0];

describe('matches', () => {
  it('plain letter combos require no modifiers', () => {
    expect(matches(ev('e'), 'e')).toBe(true);
    expect(matches(ev('e', { shiftKey: true }), 'e')).toBe(false);
    expect(matches(ev('e', { metaKey: true }), 'e')).toBe(false);
  });

  it('mod combos', () => {
    expect(matches(ev('c', { metaKey: true }), 'mod+c')).toBe(true);
    expect(matches(ev('c', { ctrlKey: true }), 'mod+c')).toBe(true);
    expect(matches(ev('c', { metaKey: true, shiftKey: true }), 'mod+shift+c')).toBe(true);
    expect(matches(ev('c', { metaKey: true, shiftKey: true }), 'mod+c')).toBe(false);
  });

  it('"/" matches even when the layout needs Shift (e.g. Shift+7 on Norwegian)', () => {
    expect(matches(ev('/'), '/')).toBe(true);
    expect(matches(ev('/', { shiftKey: true }), '/')).toBe(true);
  });

  it('"/" via AltGr-style layouts still matches', () => {
    expect(matches(ev('/', { altKey: true }), '/')).toBe(true);
  });

  it('punctuation with explicit shift still requires it', () => {
    expect(matches(ev('?', { shiftKey: true }), 'shift+?')).toBe(true);
    expect(matches(ev('?'), 'shift+?')).toBe(false);
  });

  it('special keys', () => {
    expect(matches(ev('Escape'), 'escape')).toBe(true);
    expect(matches(ev('Backspace', { metaKey: true }), 'mod+backspace')).toBe(true);
    expect(matches(ev('Enter'), 'enter')).toBe(true);
  });
});
