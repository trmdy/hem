import { useEffect, useRef } from 'react';

/** True when the event originates in a text-entry control. */
export function inEditable(e: KeyboardEvent): boolean {
  const t = e.target as HTMLElement | null;
  if (!t) return false;
  const tag = t.tagName;
  return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || t.isContentEditable;
}

export interface KeySpec {
  /** e.g. "mod+1", "mod+shift+c", "/", "a", "escape", "mod+enter", "g v" (chord) */
  combo: string;
  handler: (e: KeyboardEvent) => void;
  /** Fire even when focus is in an input (default false). */
  inInputs?: boolean;
}

export function matches(e: KeyboardEvent, combo: string): boolean {
  const parts = combo.toLowerCase().split('+');
  const key = parts[parts.length - 1];
  const needMod = parts.includes('mod');
  const needShift = parts.includes('shift');
  const needAlt = parts.includes('alt');
  // Punctuation keys may require Shift (or AltGr) depending on the keyboard
  // layout — e.g. "/" is Shift+7 on Norwegian. e.key already encodes the
  // produced character, so for those keys the physical modifiers must not
  // veto the match (unless the combo asks for shift explicitly).
  const layoutShifted = key.length === 1 && !/[a-z0-9]/.test(key);
  if (needMod !== (e.metaKey || e.ctrlKey)) return false;
  if (layoutShifted ? needShift && !e.shiftKey : needShift !== e.shiftKey) return false;
  if (!layoutShifted && needAlt !== e.altKey) return false;
  const eventKey = e.key.toLowerCase();
  if (key === 'enter') return eventKey === 'enter';
  if (key === 'escape') return eventKey === 'escape';
  if (key === 'backspace') return eventKey === 'backspace';
  if (key === 'delete') return eventKey === 'backspace' || eventKey === 'delete';
  return eventKey === key;
}

/**
 * Layered key handling: listeners register in mount order and the deepest
 * (last-mounted, e.g. an open dialog) gets the event first via capture-phase
 * ordering — practically, dialogs call stopPropagation via `handled`.
 */
export function useKeys(specs: KeySpec[], enabled = true): void {
  const specsRef = useRef(specs);
  specsRef.current = specs;
  const pendingChord = useRef<string | null>(null);

  useEffect(() => {
    if (!enabled) return;
    const onKey = (e: KeyboardEvent): void => {
      if (e.defaultPrevented) return;
      const editable = inEditable(e);

      // vim-style "g then x" chords
      if (pendingChord.current === 'g') {
        pendingChord.current = null;
        if (!editable) {
          for (const spec of specsRef.current) {
            if (spec.combo.startsWith('g ') && spec.combo.slice(2) === e.key.toLowerCase()) {
              e.preventDefault();
              spec.handler(e);
              return;
            }
          }
        }
      }
      if (!editable && e.key === 'g' && !e.metaKey && !e.ctrlKey && !e.altKey && !e.shiftKey) {
        const hasChords = specsRef.current.some((s) => s.combo.startsWith('g '));
        if (hasChords) {
          pendingChord.current = 'g';
          setTimeout(() => {
            pendingChord.current = null;
          }, 800);
          return;
        }
      }

      for (const spec of specsRef.current) {
        if (spec.combo.startsWith('g ')) continue;
        if (!spec.inInputs && editable) {
          // Escape and mod-combos still work from inputs
          const isModCombo = spec.combo.includes('mod+');
          const isEscape = spec.combo === 'escape';
          if (!isModCombo && !isEscape) continue;
        }
        if (matches(e, spec.combo)) {
          e.preventDefault();
          spec.handler(e);
          return;
        }
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [enabled]);
}
