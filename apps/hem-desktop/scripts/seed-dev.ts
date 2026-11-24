/**
 * Seed an already-running ISOLATED hemd (127.0.0.1:59092) with
 * representative fake data for GUI verification. Prints the operator token
 * on stdout (single line) for the caller to export as VALHALL_HEM_TOKEN.
 * Never point this at 50091.
 */
import { join } from 'node:path';
import { HemClient } from '../src/main/hem/client.ts';

const ENDPOINT = 'http://127.0.0.1:59092';
const proto = join(import.meta.dirname, '..', 'proto', 'hem.proto');

const boot = new HemClient({ endpoint: ENDPOINT, protoPath: proto });
for (let i = 0; i < 40; i += 1) {
  try {
    await boot.health();
    break;
  } catch {
    await new Promise((r) => setTimeout(r, 250));
  }
}
const init = await boot.initHem();
const token = init.operator_token;
// print immediately so the caller has it even if later seeding fails
console.log(token);
boot.close();

const client = new HemClient({ endpoint: ENDPOINT, token, protoPath: proto });

const set = (ref: string, values: Record<string, string>, extra: object = {}) => {
  const [scope, ...rest] = ref.split('/');
  const name = rest[rest.length - 1];
  const selector =
    scope === 'global'
      ? { scope: 'SECRET_SCOPE_GLOBAL' }
      : scope === 'project'
        ? { scope: 'SECRET_SCOPE_PROJECT', project: rest[0] }
        : { scope: 'SECRET_SCOPE_IDENTITY', identity_id: rest[0] };
  return client.setSecret({
    secret: { scope: selector, name },
    values: Object.entries(values).map(([key, value]) => ({ key, value })),
    actor: 'seed',
    ...extra,
  });
};

await set('global/anthropic-api-key', { api_key: 'sk-ant-fake-0000000000007f2a' });
await set('global/fiken-oauth', { client_id: 'fake-client-id-37vt', client_secret: 'fake-client-secret-pk04' });
await set('global/tailscale-authkey', { authkey: 'tskey-fake-000000000000abcd' });
await set('project/globex/linear', { api_key: 'lin_api_fake_000000000000cdef' });
await set('project/globex/vercel-deploy', { token: 'vercel-fake-token-0000ghij' });
await set(
  'project/acme/openai-prod',
  { api_key: 'sk-fake-openai-prod-00000000007f2a', org_id: 'org-fake-000037vt', project_id: 'proj_fake0000pk04' },
  { requires_approval: true, description: 'production OpenAI credentials' },
);
await set('project/acme/openai-stg', { api_key: 'sk-fake-openai-stg-000000000cdab' });
await set('project/acme/postgres-main', { url: 'postgres://fake:fake@localhost/main' });
await set('identity/vis-7f31/github', { token: 'ghp_fake00000000000000000000wxyz' });
await set('identity/vis-7f31/ssh-signing', { private_key: 'fake-ssh-key-material-000000qrst' });

// a service token (Tokens view content) + a grant on the gated secret
const svc = await client.issueServiceToken('ci-deploy', 24 * 3600, 'seed');
const gated = { scope: { scope: 'SECRET_SCOPE_PROJECT', project: 'acme' }, name: 'openai-prod' };
try {
  await client.grantAccess(gated, { scope: 'SECRET_SCOPE_GLOBAL' }, svc.info.token_id, 'seed');
} catch (err) {
  console.error('grant skipped:', (err as Error).message);
}

// pending approvals for the Approvals view: a gated read (if the grant
// held) and a delete request (always approval-gated)
try {
  const svcClient = new HemClient({ endpoint: ENDPOINT, token: svc.token, protoPath: proto });
  await svcClient.getSecret({ secret: gated }, { asyncRead: true, reason: 'release build 2026.27' });
  svcClient.close();
} catch (err) {
  console.error('gated read skipped:', (err as Error).message);
}
await client.deleteSecret(
  { scope: { scope: 'SECRET_SCOPE_PROJECT', project: 'globex' }, name: 'vercel-deploy' },
  { actor: 'seed', reason: 'cleanup requested' },
);
client.close();
