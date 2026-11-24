import { execa } from 'execa';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import type { VersionRow } from '../../shared/types';
import { parseRef, scopeSectionKey } from './refs';

/**
 * Read-only value-version history from the cluster ledger
 * (`distributed/ledger.sqlite3`, metadata columns only — the DB holds no
 * plaintext anywhere, and we never SELECT encrypted_value_json).
 *
 * Uses the macOS-bundled sqlite3 CLI with `mode=ro&immutable=1` instead of a
 * native Node binding: no Electron ABI rebuilds, and the immutable URI flag
 * guarantees we cannot take even a read lock on the live daemon's DB.
 */

interface RawVersionRow {
  key_name: string;
  version_seq: number;
  created_at: string;
  created_by: string;
  operation_id: string;
  position: number;
}

export function ledgerPath(dataDir: string): string {
  return join(dataDir, 'distributed', 'ledger.sqlite3');
}

async function queryJson<T>(dbPath: string, sql: string, params: string[]): Promise<T[]> {
  // sqlite3 CLI has no bind-parameter flag; inline after strict validation.
  // Every param here is a hem slug/section (validated by parseRef) — but
  // quote-escape anyway, defense in depth.
  let inlined = sql;
  for (const p of params) {
    inlined = inlined.replace('?', `'${p.replaceAll("'", "''")}'`);
  }
  const result = await execa(
    '/usr/bin/sqlite3',
    ['-json', '-readonly', `file:${dbPath}?mode=ro&immutable=1`, inlined],
    { reject: false, timeout: 10_000 },
  );
  if (result.exitCode !== 0 || !result.stdout.trim()) return [];
  return JSON.parse(result.stdout) as T[];
}

/**
 * Version timeline for one secret, newest first. Rows in the ledger are
 * per-key; one SetSecret shows up as one operation_id spanning the keys it
 * wrote, so group by operation and summarize the keys.
 */
export async function getVersionHistory(dataDir: string, ref: string): Promise<VersionRow[]> {
  const parsed = parseRef(ref);
  if (!parsed) return [];
  const dbPath = ledgerPath(dataDir);
  if (!existsSync(dbPath)) return [];

  const rows = await queryJson<RawVersionRow>(
    dbPath,
    `SELECT key_name, version_seq, created_at, created_by, operation_id, position
     FROM ledger_secret_value_versions
     WHERE scope = ? AND name = ?
     ORDER BY position DESC, version_seq DESC
     LIMIT 200;`,
    [scopeSectionKey(parsed), parsed.name],
  );

  const byOperation = new Map<string, RawVersionRow[]>();
  for (const row of rows) {
    const group = byOperation.get(row.operation_id);
    if (group) group.push(row);
    else byOperation.set(row.operation_id, [row]);
  }

  const versions: VersionRow[] = [];
  for (const group of byOperation.values()) {
    const first = group[0];
    const keys = group.map((r) => r.key_name).sort();
    versions.push({
      versionSeq: Math.max(...group.map((r) => r.version_seq)),
      node: first.created_by,
      createdAt: first.created_at,
      kind: group.some((r) => r.version_seq > 1)
        ? `updated ${keys.join(', ')}`
        : `set ${keys.join(', ')}`,
    });
  }
  versions.sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));
  return versions;
}
