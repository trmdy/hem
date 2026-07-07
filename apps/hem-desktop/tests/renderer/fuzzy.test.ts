import { describe, expect, it } from 'vitest';
import { bestFieldScore, fuzzyMatch, fuzzyScore, rankBy } from '../../src/renderer/lib/fuzzy';

const score = (q: string, t: string): number => {
  const s = fuzzyScore(q, t);
  expect(s, `"${q}" should match "${t}"`).not.toBeNull();
  return s as number;
};

describe('fuzzyScore', () => {
  it('empty query matches everything with score 0', () => {
    expect(fuzzyScore('', 'anything')).toBe(0);
  });

  it('returns null when not a subsequence', () => {
    expect(fuzzyScore('xyz', 'anthropic-api-key')).toBeNull();
    expect(fuzzyScore('anthropicc', 'anthropic')).toBeNull();
  });

  it('is case-insensitive', () => {
    expect(fuzzyScore('ANTH', 'anthropic-api-key')).not.toBeNull();
  });

  it('consecutive match beats scattered subsequence', () => {
    // "fik" is contiguous in fiken-oauth, scattered in firecrawl-api-key.
    expect(score('fik', 'fiken-oauth')).toBeGreaterThan(score('fik', 'firecrawl-api-key'));
  });

  it('prefix beats mid-string', () => {
    expect(score('open', 'openai-prod')).toBeGreaterThan(score('open', 'acme-openai'));
  });

  it('word-boundary start beats mid-word', () => {
    expect(score('key', 'anthropic-key')).toBeGreaterThan(score('key', 'monkeys'));
  });

  it('slash boundary is rewarded (scoped refs)', () => {
    expect(score('linear', 'globex/linear')).toBeGreaterThan(score('linear', 'lindorff-nearline'));
  });
});

describe('fuzzyMatch', () => {
  it('filters like a boolean subsequence matcher', () => {
    expect(fuzzyMatch('aak', 'anthropic-api-key')).toBe(true);
    expect(fuzzyMatch('zzz', 'anthropic-api-key')).toBe(false);
    expect(fuzzyMatch('', 'anything')).toBe(true);
  });
});

describe('rankBy / bestFieldScore', () => {
  const rows = [
    { name: 'anthropic-api-key', ref: 'global/anthropic-api-key', description: 'Claude API' },
    { name: 'openai-prod', ref: 'project/acme/openai-prod', description: 'OpenAI production key' },
    { name: 'brave-api-key', ref: 'global/brave-api-key', description: 'search' },
  ];
  const fields = (r: (typeof rows)[number]): Array<[string | undefined, number]> => [
    [r.name, 1],
    [r.ref, 0.9],
    [r.description, 0.5],
  ];

  it('name match outranks description match', () => {
    // "openai" hits openai-prod's name and anthropic's description ("OpenAI…" is on openai-prod itself);
    // "claude" only exists in anthropic's description — it should still be found, but a name hit ranks first.
    const byName = rankBy(rows, 'brave', fields);
    expect(byName[0].item.name).toBe('brave-api-key');
    const byDesc = rankBy(rows, 'claude', fields);
    expect(byDesc).toHaveLength(1);
    expect(byDesc[0].item.name).toBe('anthropic-api-key');
  });

  it('drops non-matches entirely', () => {
    expect(rankBy(rows, 'qqq', fields)).toHaveLength(0);
  });

  it('empty query keeps original order', () => {
    expect(rankBy(rows, '', fields).map((r) => r.item.name)).toEqual(rows.map((r) => r.name));
  });

  it('scoped-ref queries work: acme/openai finds the project secret', () => {
    const ranked = rankBy(rows, 'acme/open', fields);
    expect(ranked[0]?.item.name).toBe('openai-prod');
  });

  it('bestFieldScore returns null when no field matches', () => {
    expect(bestFieldScore('zzz', [['abc', 1]])).toBeNull();
    expect(bestFieldScore('a', [[undefined, 1]])).toBeNull();
  });
});
