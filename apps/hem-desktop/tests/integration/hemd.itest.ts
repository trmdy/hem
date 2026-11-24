/**
 * Integration: boots an ISOLATED hemd on 127.0.0.1:59092 with a throwaway
 * data dir (never the production daemon on 50091 — see the safety
 * rules) and drives the full IPC handler surface end to end:
 * init → set → list → get → reveal/copy → scan → gated read → approve/deny
 * → receipt retry → delete loop → audit. Tears the daemon down and removes
 * the tmpdir afterwards.
 */
import { spawn, type ChildProcess } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { ClipboardAdapter } from '../../src/main/clipboard';
import { HemClient } from '../../src/main/hem/client';
import { createHandlers, type Handlers } from '../../src/main/ipc';

const ENDPOINT = 'http://127.0.0.1:59092';
const HEMD = join(homedir(), '.valhall', 'system-daemons', 'bin', 'hemd');
const PROTO = join(__dirname, '..', '..', 'proto', 'hem.proto');

let dataDir: string;
let daemon: ChildProcess;
let operatorToken: string;
let client: HemClient;
let serviceClient: HemClient | null = null;
let handlers: Handlers;

interface ClipboardCall {
  kind: 'concealed' | 'plain' | 'clear';
  value: string;
  seconds?: number;
}
const clipboardCalls: ClipboardCall[] = [];
const fakeClipboard: ClipboardAdapter = {
  async copyConcealed(value) {
    clipboardCalls.push({ kind: 'concealed', value });
  },
  async copyPlain(text) {
    clipboardCalls.push({ kind: 'plain', value: text });
  },
  scheduleClear(value, seconds) {
    clipboardCalls.push({ kind: 'clear', value, seconds });
  },
};

async function waitForHealth(c: HemClient, attempts = 60): Promise<void> {
  for (let i = 0; i < attempts; i += 1) {
    try {
      await c.health();
      return;
    } catch {
      await new Promise((r) => setTimeout(r, 250));
    }
  }
  throw new Error('isolated hemd never became healthy on :59092');
}

beforeAll(async () => {
  dataDir = mkdtempSync(join(tmpdir(), 'hem-desk-itest-'));
  // Keep every fallback path inside the tmpdir so nothing can touch the
  // real vault or ledger from this test.
  process.env.HEM_DATA_DIR = dataDir;

  daemon = spawn(HEMD, ['--bind', '127.0.0.1:59092', '--data-dir', dataDir], {
    stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, NO_COLOR: '1' },
  });

  const boot = new HemClient({ endpoint: ENDPOINT, protoPath: PROTO });
  await waitForHealth(boot);
  const init = await boot.initHem();
  expect(init.initialized).toBe(true);
  operatorToken = init.operator_token;
  expect(operatorToken.length).toBeGreaterThan(10);
  boot.close();

  client = new HemClient({ endpoint: ENDPOINT, token: operatorToken, protoPath: PROTO });
  handlers = createHandlers({
    client,
    config: {
      endpoint: ENDPOINT,
      tokenDiscovery: { token: operatorToken, source: 'itest', searchedPaths: [] },
      // /usr/bin/false: any accidental `hem cluster …` shell-out fails fast
      // instead of reading the real machine's cluster config.
      hemBinary: '/usr/bin/false',
      clipboardClearSeconds: 90,
      revealRemaskSeconds: 30,
      protoPath: PROTO,
    },
    clipboard: fakeClipboard,
  });
}, 60_000);

afterAll(async () => {
  client?.close();
  serviceClient?.close();
  daemon?.kill('SIGTERM');
  await new Promise((r) => setTimeout(r, 300));
  if (daemon && daemon.exitCode === null) daemon.kill('SIGKILL');
  if (dataDir) rmSync(dataDir, { recursive: true, force: true });
});

const ALPHA_VALUE = 'sk-alpha-value-0123456789abcdef';
const seenPlaintext = [ALPHA_VALUE, 'org-alpha-37vt', 'beta-value-xyzt', 'gamma-value-qrst', 'gated-value-secret9'];

describe('isolated hemd end-to-end', () => {
  it('daemon:health reports ok', async () => {
    const health = await handlers['daemon:health']();
    expect(health.ok).toBe(true);
    expect(health.version).toBeTruthy();
  });

  it('vault:set creates secrets in all three scopes', async () => {
    await handlers['vault:set']({
      ref: 'global/itest-alpha',
      values: [
        { key: 'api_key', value: ALPHA_VALUE },
        { key: 'org_id', value: 'org-alpha-37vt' },
      ],
      description: 'integration alpha',
    });
    await handlers['vault:set']({
      ref: 'project/desk/itest-beta',
      values: [{ key: 'token', value: 'beta-value-xyzt' }],
    });
    await handlers['vault:set']({
      ref: 'identity/idz/itest-gamma',
      values: [{ key: 'password', value: 'gamma-value-qrst' }],
    });
  });

  it('vault:list returns all scopes from one call, with sections', async () => {
    const rows = await handlers['vault:list']();
    const refs = rows.map((r) => r.ref).sort();
    expect(refs).toEqual(['global/itest-alpha', 'identity/idz/itest-gamma', 'project/desk/itest-beta']);
    expect(rows.find((r) => r.ref === 'project/desk/itest-beta')?.section).toBe('project/desk');
    expect(rows.find((r) => r.ref === 'global/itest-alpha')?.description).toBe('integration alpha');
  });

  it('vault:get masks values — nothing crossing this boundary contains plaintext', async () => {
    const detail = await handlers['vault:get']('global/itest-alpha');
    expect(detail.keys.map((k) => k.key)).toEqual(['api_key', 'org_id']);
    const apiKey = detail.keys[0];
    expect(apiKey.masked.endsWith(ALPHA_VALUE.slice(-4))).toBe(true);
    expect(apiKey.masked.startsWith('•')).toBe(true);
    const serialized = JSON.stringify(detail);
    for (const plaintext of seenPlaintext) {
      expect(serialized.includes(plaintext)).toBe(false);
    }
  });

  it('vault:reveal returns the value one-shot with remask deadline', async () => {
    const res = await handlers['vault:reveal']('global/itest-alpha', 'api_key');
    expect(res.value).toBe(ALPHA_VALUE);
    expect(res.remaskAfter).toBe(30);
  });

  it('vault:reveal of a missing key maps to not-found', async () => {
    await expect(handlers['vault:reveal']('global/itest-alpha', 'nope')).rejects.toThrow(/no key/);
  });

  it('vault:copy keeps the value in main: concealed copy + scheduled clear', async () => {
    clipboardCalls.length = 0;
    const res = await handlers['vault:copy']('global/itest-alpha', 'api_key');
    expect(res.clearedAfter).toBe(90);
    expect(clipboardCalls).toEqual([
      { kind: 'concealed', value: ALPHA_VALUE },
      { kind: 'clear', value: ALPHA_VALUE, seconds: 90 },
    ]);
  });

  it('set replaces the whole value map (hem semantics)', async () => {
    await handlers['vault:set']({
      ref: 'project/desk/itest-beta',
      values: [{ key: 'rotated', value: 'beta-value-2-abcd' }],
    });
    const detail = await handlers['vault:get']('project/desk/itest-beta');
    expect(detail.keys.map((k) => k.key)).toEqual(['rotated']);
  });

  it('groups:list reflects a created group', async () => {
    await client.setGroup('itest-group', 'created by integration test');
    const groups = await handlers['groups:list']();
    expect(groups.map((g) => g.name)).toContain('itest-group');
  });

  it('scan:text finds a known value and stays clean otherwise', async () => {
    const hit = await handlers['scan:text'](`deploy log: ${ALPHA_VALUE} leaked here`);
    expect(hit.clean).toBe(false);
    expect(hit.matches.some((m) => m.ref.includes('itest-alpha'))).toBe(true);
    const clean = await handlers['scan:text']('nothing to see here');
    expect(clean.clean).toBe(true);
  });

  it('tokens:issueService issues a usable token, visible in tokens:list', async () => {
    const issued = await handlers['tokens:issueService']('itest-svc', 3600);
    expect(issued.token.length).toBeGreaterThan(10);
    expect(issued.info.tokenType).toBe('service');
    const list = await handlers['tokens:list']();
    expect(list.some((t) => t.tokenId === issued.info.tokenId)).toBe(true);
    serviceClient = new HemClient({ endpoint: ENDPOINT, token: issued.token, protoPath: PROTO });
  });

  it('gated read: service token gets pending, operator approves, receipt unlocks exactly once', async () => {
    await handlers['vault:set']({
      ref: 'global/itest-gated',
      values: [{ key: 'api_key', value: 'gated-value-secret9' }],
      requiresApproval: true,
    });

    // async_read is required: without it the RPC blocks server-side
    const first = await serviceClient!.getSecret(
      { secret: { scope: { scope: 'SECRET_SCOPE_GLOBAL' }, name: 'itest-gated' } },
      { asyncRead: true, reason: 'integration gated read' },
    );
    expect(first.pending?.request_id).toBeTruthy();
    const requestId = first.pending!.request_id;

    const pending = await handlers['approvals:list']();
    const row = pending.find((p) => p.requestId === requestId);
    expect(row).toBeTruthy();
    expect(row!.ref).toBe('global/itest-gated');
    expect(row!.action).toContain('get');
    expect(row!.reason).toBe('integration gated read');

    const approved = await handlers['approvals:approve'](requestId, 'ok from itest');
    expect(approved.receipt.length).toBeGreaterThan(5);
    expect(approved.request.state).toBe('approved');

    const retry = await serviceClient!.getSecret(
      { secret: { scope: { scope: 'SECRET_SCOPE_GLOBAL' }, name: 'itest-gated' } },
      { approvalReceipt: approved.receipt },
    );
    expect(retry.secret?.values?.api_key).toBe('gated-value-secret9');

    // single-use: the same receipt must not work twice
    await expect(
      serviceClient!.getSecret(
        { secret: { scope: { scope: 'SECRET_SCOPE_GLOBAL' }, name: 'itest-gated' } },
        { approvalReceipt: approved.receipt },
      ),
    ).rejects.toThrow();
  });

  it('deny: the requester sees the denial, not a value', async () => {
    const req = await serviceClient!.getSecret(
      { secret: { scope: { scope: 'SECRET_SCOPE_GLOBAL' }, name: 'itest-gated' } },
      { asyncRead: true, reason: 'second attempt' },
    );
    const requestId = req.pending!.request_id;
    const denied = await handlers['approvals:deny'](requestId, 'denied by owner');
    expect(denied.request.state).toBe('denied');
  });

  it('delete loop: approval_required → approve → receipt retry deletes', async () => {
    const first = await handlers['vault:delete']('global/itest-alpha', { reason: 'itest cleanup' });
    expect(first.deleted).toBe(false);
    expect(first.approvalRequired?.requestId).toBeTruthy();
    const requestId = first.approvalRequired!.requestId;

    const pending = await handlers['approvals:list']();
    expect(pending.some((p) => p.requestId === requestId && p.action.includes('delete'))).toBe(true);

    const approved = await handlers['approvals:approve'](requestId);
    const second = await handlers['vault:delete']('global/itest-alpha', {
      approvalReceipt: approved.receipt,
    });
    expect(second.deleted).toBe(true);

    const rows = await handlers['vault:list']();
    expect(rows.some((r) => r.ref === 'global/itest-alpha')).toBe(false);
  });

  it('grants:grant + list + revoke round-trip', async () => {
    const grant = await handlers['grants:grant']('project/desk/itest-beta', {
      kind: 'identity',
      identityId: 'idz',
      id: 'idz',
    });
    expect(grant.granteeId).toBe('idz');
    const grants = await handlers['grants:list']('project/desk/itest-beta');
    expect(grants).toHaveLength(1);
    const revoked = await handlers['grants:revoke']('project/desk/itest-beta', {
      kind: 'identity',
      identityId: 'idz',
      id: 'idz',
    });
    expect(revoked.revoked).toBe(true);
  });

  it('tokens:revoke kills the service token', async () => {
    const list = await handlers['tokens:list']();
    const svc = list.find((t) => t.serviceName === 'itest-svc');
    expect(svc).toBeTruthy();
    const res = await handlers['tokens:revoke'](svc!.tokenId);
    expect(res.revoked).toBe(true);
    await expect(serviceClient!.listSecrets()).rejects.toThrow();
  });

  it('audit:query has the whole story — and never a plaintext value', async () => {
    const entries = await handlers['audit:query']({ limit: 200 });
    expect(entries.length).toBeGreaterThan(5);
    const actions = new Set(entries.map((e) => e.action));
    expect([...actions].join(',')).toMatch(/set|write/);
    const serialized = JSON.stringify(entries);
    for (const plaintext of seenPlaintext) {
      expect(serialized.includes(plaintext)).toBe(false);
    }
  });

  it('errors map: not-found, invalid ref, unauthenticated', async () => {
    await expect(handlers['vault:get']('global/never-existed')).rejects.toMatchObject({ kind: 'not-found' });
    await expect(handlers['vault:get']('not a ref')).rejects.toMatchObject({ kind: 'invalid-argument' });
    const anon = new HemClient({ endpoint: ENDPOINT, protoPath: PROTO });
    await expect(anon.listSecrets()).rejects.toMatchObject({ kind: 'unauthenticated' });
    anon.close();
  });

  it('history:versions degrades to [] without a cluster ledger', async () => {
    const versions = await handlers['history:versions']('project/desk/itest-beta');
    expect(versions).toEqual([]);
  });
});
