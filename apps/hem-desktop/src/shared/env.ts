/**
 * `.env` paste parsing and slug normalization, shared by the renderer form
 * and tests. Ported from hem-raycast src/hem/env.ts + refs.ts.
 */

export interface EnvEntry {
  /** Key exactly as it appeared in the pasted text (shown as a hint). */
  originalKey: string;
  /** Key normalized to hem's lowercase form. */
  key: string;
  value: string;
}

/** Lowercase and coerce an env var name to a valid hem value key. */
export function normalizeEnvKey(raw: string): string {
  const normalized = raw
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_]+/g, '_')
    .replace(/^_+|_+$/g, '');
  return normalized || 'value';
}

/** Lowercase and coerce arbitrary input toward a valid hem slug ([a-z0-9-]+). */
export function slugify(input: string): string {
  return input
    .toLowerCase()
    .replace(/[\s_.]+/g, '-')
    .replace(/[^a-z0-9-]/g, '')
    .replace(/-{2,}/g, '-');
}

/**
 * Parse `.env`-style text (KEY=VALUE lines) into entries. Handles `export `
 * prefixes, single/double quotes, comment lines, and trailing unquoted
 * `# comments`. Lines without `=` or with empty values are skipped.
 */
export function parseEnvText(text: string): EnvEntry[] {
  const entries: EnvEntry[] = [];
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

    entries.push({ originalKey, key: normalizeEnvKey(originalKey), value });
  }
  return entries;
}
