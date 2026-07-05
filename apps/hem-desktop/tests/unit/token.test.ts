import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { discoverToken, tokenSearchPaths } from '../../src/main/hem/token';

const home = mkdtempSync(join(tmpdir(), 'hem-desk-token-'));

afterAll(() => rmSync(home, { recursive: true, force: true }));

function writeToken(path: string, value: string): void {
  mkdirSync(join(path, '..'), { recursive: true });
  writeFileSync(path, `${value}\n`);
}

describe('token discovery chain (CLI-compatible order)', () => {
  it('explicit token wins over everything', () => {
    const res = discoverToken({ explicit: '  tok_explicit  ', env: { VALHALL_HEM_TOKEN: 'tok_env' }, home });
    expect(res.token).toBe('tok_explicit');
    expect(res.source).toBe('preference');
  });

  it('VALHALL_HEM_TOKEN beats files', () => {
    writeToken(join(home, '.valhall', 'hem', 'operator.token'), 'tok_file');
    const res = discoverToken({ env: { VALHALL_HEM_TOKEN: 'tok_env' }, home });
    expect(res.token).toBe('tok_env');
    expect(res.source).toBe('env:VALHALL_HEM_TOKEN');
  });

  it('search path order: HEM_DATA_DIR, VALHALL_SYSTEM_DAEMONS_DIR, ~/.valhall/hem, ~/.valhall/system-daemons', () => {
    const paths = tokenSearchPaths({
      env: { HEM_DATA_DIR: '/data', VALHALL_SYSTEM_DAEMONS_DIR: '/daemons' },
      home,
    });
    expect(paths).toEqual([
      '/data/operator.token',
      '/daemons/data/hem/operator.token',
      join(home, '.valhall', 'hem', 'operator.token'),
      join(home, '.valhall', 'system-daemons', 'data', 'hem', 'operator.token'),
    ]);
  });

  it('HEM_DATA_DIR file beats the home-dir files', () => {
    const dataDir = join(home, 'custom-data');
    writeToken(join(dataDir, 'operator.token'), 'tok_datadir');
    writeToken(join(home, '.valhall', 'hem', 'operator.token'), 'tok_home');
    const res = discoverToken({ env: { HEM_DATA_DIR: dataDir }, home });
    expect(res.token).toBe('tok_datadir');
    expect(res.source).toBe(join(dataDir, 'operator.token'));
  });

  it('falls through to ~/.valhall/system-daemons and trims whitespace', () => {
    const isolated = mkdtempSync(join(tmpdir(), 'hem-desk-token2-'));
    try {
      writeToken(join(isolated, '.valhall', 'system-daemons', 'data', 'hem', 'operator.token'), '  tok_sysd  ');
      const res = discoverToken({ env: {}, home: isolated });
      expect(res.token).toBe('tok_sysd');
    } finally {
      rmSync(isolated, { recursive: true, force: true });
    }
  });

  it('returns null when nothing exists, with the searched paths listed', () => {
    const empty = mkdtempSync(join(tmpdir(), 'hem-desk-token3-'));
    try {
      const res = discoverToken({ env: {}, home: empty });
      expect(res.token).toBeNull();
      expect(res.source).toBeNull();
      expect(res.searchedPaths).toHaveLength(2);
    } finally {
      rmSync(empty, { recursive: true, force: true });
    }
  });

  it('empty files are skipped', () => {
    const isolated = mkdtempSync(join(tmpdir(), 'hem-desk-token4-'));
    try {
      writeToken(join(isolated, '.valhall', 'hem', 'operator.token'), '   ');
      writeToken(join(isolated, '.valhall', 'system-daemons', 'data', 'hem', 'operator.token'), 'tok_fallback');
      const res = discoverToken({ env: {}, home: isolated });
      expect(res.token).toBe('tok_fallback');
    } finally {
      rmSync(isolated, { recursive: true, force: true });
    }
  });
});
