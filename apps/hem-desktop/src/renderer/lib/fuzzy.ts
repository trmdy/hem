/**
 * Scored fuzzy matching, fzy-style: an O(q·t) DP that rewards consecutive
 * runs, word-boundary starts (after / - _ . space, or camelCase), and early
 * positions, and penalizes gaps. Higher score = better match; null = the
 * query is not a subsequence of the text at all.
 */

const SCORE_MIN = -Infinity;
const GAP_LEADING = -0.005;
const GAP_TRAILING = -0.005;
const GAP_INNER = -0.01;
const BONUS_CONSECUTIVE = 1.0;
const BONUS_SLASH = 0.9;
const BONUS_WORD = 0.8;
const BONUS_CAMEL = 0.7;
const BONUS_FIRST_CHAR = 0.9;

function charBonuses(text: string): Float64Array {
  const bonus = new Float64Array(text.length);
  for (let j = 0; j < text.length; j += 1) {
    if (j === 0) {
      bonus[j] = BONUS_FIRST_CHAR;
      continue;
    }
    const prev = text[j - 1];
    const cur = text[j];
    if (prev === '/') bonus[j] = BONUS_SLASH;
    else if (prev === '-' || prev === '_' || prev === ' ' || prev === '.') bonus[j] = BONUS_WORD;
    else if (prev >= 'a' && prev <= 'z' && cur >= 'A' && cur <= 'Z') bonus[j] = BONUS_CAMEL;
  }
  return bonus;
}

export function fuzzyScore(query: string, text: string): number | null {
  if (!query) return 0;
  if (!text) return null;
  const q = query.toLowerCase();
  const t = text.toLowerCase();
  if (q.length > t.length) return null;

  // Fast subsequence gate.
  let qi = 0;
  for (let ti = 0; ti < t.length && qi < q.length; ti += 1) {
    if (t[ti] === q[qi]) qi += 1;
  }
  if (qi < q.length) return null;

  const n = q.length;
  const m = t.length;
  const bonus = charBonuses(text);

  // D[j]: best score ending with q[i] matched exactly at t[j].
  // M[j]: best score with q[0..i] consumed somewhere in t[0..j].
  let D = new Float64Array(m).fill(SCORE_MIN);
  let M = new Float64Array(m).fill(SCORE_MIN);
  let prevD = new Float64Array(m);
  let prevM = new Float64Array(m);

  for (let i = 0; i < n; i += 1) {
    [prevD, D] = [D, prevD];
    [prevM, M] = [M, prevM];
    D.fill(SCORE_MIN);
    M.fill(SCORE_MIN);
    const gap = i === n - 1 ? GAP_TRAILING : GAP_INNER;
    for (let j = 0; j < m; j += 1) {
      if (q[i] === t[j]) {
        let score = SCORE_MIN;
        if (i === 0) {
          score = j * GAP_LEADING + bonus[j];
        } else if (j > 0) {
          const fromM = prevM[j - 1] === SCORE_MIN ? SCORE_MIN : prevM[j - 1] + bonus[j];
          const fromD = prevD[j - 1] === SCORE_MIN ? SCORE_MIN : prevD[j - 1] + BONUS_CONSECUTIVE;
          score = Math.max(fromM, fromD);
        }
        D[j] = score;
        M[j] = j > 0 && M[j - 1] !== SCORE_MIN ? Math.max(score, M[j - 1] + gap) : score;
      } else {
        M[j] = j > 0 && M[j - 1] !== SCORE_MIN ? M[j - 1] + gap : SCORE_MIN;
      }
    }
  }
  const final = M[m - 1];
  return final === SCORE_MIN ? null : final;
}

/** Boolean convenience for plain filtering (vault list, audit). */
export function fuzzyMatch(query: string, text: string): boolean {
  return fuzzyScore(query, text) !== null;
}

export interface Ranked<T> {
  item: T;
  score: number;
}

/**
 * Score an item across weighted fields; the best field wins. Use higher
 * weights for identity fields (name) and lower for descriptive ones.
 */
export function bestFieldScore(query: string, fields: Array<[text: string | undefined, weight: number]>): number | null {
  let best: number | null = null;
  for (const [text, weight] of fields) {
    if (!text) continue;
    const s = fuzzyScore(query, text);
    if (s === null) continue;
    // Weight shifts the whole score band so a weak name match still beats
    // a strong description match only when weights say so.
    const weighted = s * weight - (1 - weight);
    if (best === null || weighted > best) best = weighted;
  }
  return best;
}

export function rankBy<T>(items: T[], query: string, fieldsOf: (item: T) => Array<[string | undefined, number]>): Ranked<T>[] {
  const out: Ranked<T>[] = [];
  for (const item of items) {
    const score = bestFieldScore(query, fieldsOf(item));
    if (score !== null) out.push({ item, score });
  }
  out.sort((a, b) => b.score - a.score);
  return out;
}
