import { randomBytes } from 'node:crypto';
import { beforeEach, describe, expect, it } from 'vitest';
import { logError, logInfo, registerSensitive, scrub, setSinks } from '../../src/main/log';
import { maskKeys, maskValue } from '../../src/main/redact';

let sink: string[] = [];
beforeEach(() => {
  sink = [];
  setSinks(
    (line) => sink.push(line),
    (line) => sink.push(line),
  );
});

function randomValue(): string {
  const n = 4 + Math.floor(Math.random() * 60);
  return randomBytes(n).toString('base64url').slice(0, Math.max(4, n));
}

describe('maskValue', () => {
  it('shows at most the last 4 characters', () => {
    expect(maskValue('sk-abcdefghijklmnop7f2a')).toMatch(/^•+7f2a$/);
  });

  it('fully masks short values', () => {
    for (const v of ['a', 'ab', 'abcd', 'abcdefgh']) {
      expect(maskValue(v)).toMatch(/^•+$/);
    }
  });

  it('never contains more than a 4-char suffix of the value', () => {
    for (let i = 0; i < 200; i += 1) {
      const value = randomValue();
      const masked = maskValue(value);
      if (value.length > 8) {
        expect(masked).toBe('•'.repeat(masked.length - 4) + value.slice(-4));
      } else {
        expect(masked.includes(value)).toBe(false);
      }
    }
  });

  it('maskKeys sorts keys and never leaks values', () => {
    const keys = maskKeys({ b_key: 'valuevaluevalue1', a_key: 'shortpw' });
    expect(keys.map((k) => k.key)).toEqual(['a_key', 'b_key']);
    for (const k of keys) {
      expect(k.masked.includes('valuevaluevalue1')).toBe(false);
      expect(k.masked.includes('shortpw')).toBe(false);
    }
  });
});

describe('redaction property: no value string ever reaches a log sink', () => {
  it('scrubs registered values from every log call, in any shape', () => {
    for (let i = 0; i < 100; i += 1) {
      const value = randomValue();
      // maskValue registers the value as sensitive as a side effect —
      // exactly what happens when a secret passes through the view-model.
      maskValue(value);

      logInfo('plain', value);
      logError('embedded', `prefix ${value} suffix`);
      logInfo({ nested: { deep: value } });
      logError(new Error(`grpc failed for ${value}`));

      for (const line of sink) {
        expect(line.includes(value), `sink leaked a registered value: ${line}`).toBe(false);
      }
      sink = [];
    }
  });

  it('scrub replaces every occurrence', () => {
    registerSensitive('super-secret-value');
    expect(scrub('a super-secret-value b super-secret-value c')).toBe('a [redacted] b [redacted] c');
  });

  it('does not register trivially short strings (would shred messages)', () => {
    registerSensitive('ab');
    expect(scrub('lab table')).toBe('lab table');
  });
});
