const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

/**
 * Relative time in the design file's idiom: "now", "3s ago"-style seconds
 * only where the design shows them (mesh), otherwise "2h", "1d", then
 * "Jun 30" past a week.
 */
export function relTime(iso: string | null | undefined): string {
  if (!iso) return '';
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return '';
  const seconds = Math.floor((Date.now() - t) / 1000);
  if (seconds < 60) return 'now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`;
  if (seconds < 7 * 86400) return `${Math.floor(seconds / 86400)}d`;
  const d = new Date(t);
  return `${MONTHS[d.getMonth()]} ${d.getDate()}`;
}

/** Longer relative form for the mesh cards: "now", "3s ago", "2m ago", "last seen Jun 3". */
export function relTimeSeconds(iso: string | null | undefined): string {
  if (!iso) return '';
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return iso ?? '';
  const seconds = Math.floor((Date.now() - t) / 1000);
  if (seconds < 3) return 'now';
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  const d = new Date(t);
  return `${MONTHS[d.getMonth()]} ${d.getDate()}`;
}

/** Future-facing horizon for expiries: "in 23h", "in 29d", or a date. */
export function untilTime(iso: string | null | undefined): string {
  if (!iso) return '';
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return '';
  const seconds = Math.floor((t - Date.now()) / 1000);
  if (seconds <= 0) return 'expired';
  if (seconds < 3600) return `in ${Math.max(1, Math.floor(seconds / 60))}m`;
  if (seconds < 86400) return `in ${Math.floor(seconds / 3600)}h`;
  if (seconds < 60 * 86400) return `in ${Math.floor(seconds / 86400)}d`;
  const d = new Date(t);
  return `${MONTHS[d.getMonth()]} ${d.getDate()} ${d.getFullYear()}`;
}

/** "14:22" for today, "Jul 3" otherwise — the Overview activity idiom. */
export function timeOrDate(iso: string | null | undefined): string {
  if (!iso) return '';
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return '';
  const d = new Date(t);
  const now = new Date();
  if (d.toDateString() === now.toDateString()) {
    return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
  }
  return `${MONTHS[d.getMonth()]} ${d.getDate()}`;
}

export function dateShort(iso: string | null | undefined): string {
  if (!iso) return '';
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return '';
  const d = new Date(t);
  return `${MONTHS[d.getMonth()]} ${d.getDate()}`;
}

export function clockNow(): string {
  const d = new Date();
  const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  return `${days[d.getDay()]} ${MONTHS[d.getMonth()]} ${d.getDate()} · ${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
}

export function greeting(): string {
  const h = new Date().getHours();
  if (h < 5) return 'Up late.';
  if (h < 12) return 'Good morning.';
  if (h < 18) return 'Good afternoon.';
  return 'Good evening.';
}

export function formatCount(n: number, noun: string): string {
  return `${n} ${noun}${n === 1 ? '' : 's'}`;
}
