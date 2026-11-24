import type { MaskedKey } from '../shared/types';
import { registerSensitive } from './log';

/**
 * View-model mapping for secret values: the renderer only ever sees the
 * masked form. Matches the design file's idiom — a run of bullets with the
 * last four characters visible, or all bullets for short values.
 */
export function maskValue(value: string): string {
  registerSensitive(value);
  if (value.length <= 8) return '•'.repeat(Math.max(value.length, 4));
  const tailLength = 4;
  const bullets = Math.min(Math.max(value.length - tailLength, 8), 16);
  return '•'.repeat(bullets) + value.slice(-tailLength);
}

export function maskKeys(values: Record<string, string>): MaskedKey[] {
  return Object.entries(values)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => ({ key, masked: maskValue(value), length: value.length }));
}
