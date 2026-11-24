import { describe, expect, it } from 'vitest';
import { normalizeEnvKey, parseEnvText, slugify } from '../../src/shared/env';

describe('parseEnvText', () => {
  it('parses plain KEY=VALUE lines with normalization', () => {
    const entries = parseEnvText('API_KEY=sk-123\nDB_URL=postgres://x\n');
    expect(entries).toEqual([
      { originalKey: 'API_KEY', key: 'api_key', value: 'sk-123' },
      { originalKey: 'DB_URL', key: 'db_url', value: 'postgres://x' },
    ]);
  });

  it('handles export prefixes, quotes, and comments', () => {
    const text = [
      '# comment',
      '// also a comment',
      'export TOKEN="abc def"',
      "SINGLE='quoted value'",
      'TRAILING=value # comment after',
      'EMPTY=',
      'NO_EQ_LINE',
      '=nokey',
    ].join('\n');
    const entries = parseEnvText(text);
    expect(entries).toEqual([
      { originalKey: 'TOKEN', key: 'token', value: 'abc def' },
      { originalKey: 'SINGLE', key: 'single', value: 'quoted value' },
      { originalKey: 'TRAILING', key: 'trailing', value: 'value' },
    ]);
  });

  it('keeps = inside values', () => {
    expect(parseEnvText('B64=aGVsbG8=')[0].value).toBe('aGVsbG8=');
  });
});

describe('normalizeEnvKey', () => {
  it('lowercases and coerces to [a-z0-9_]', () => {
    expect(normalizeEnvKey('MY-WEIRD KEY!')).toBe('my_weird_key');
    expect(normalizeEnvKey('__X__')).toBe('x');
    expect(normalizeEnvKey('!!!')).toBe('value');
  });
});

describe('slugify', () => {
  it('coerces toward valid hem slugs', () => {
    expect(slugify('My New Project')).toBe('my-new-project');
    expect(slugify('under_scored.name')).toBe('under-scored-name');
    expect(slugify('weird!!chars')).toBe('weirdchars');
    expect(slugify('a--b')).toBe('a-b');
  });
});
