/**
 * Read-only smoke against the production daemon, restricted to the
 * AGENT_BRIEF allowlist: Health, ListSecrets, GetSecretInfo, ListGroups.
 * Prints counts and section names only — never values, never mutations.
 */
import { join } from 'node:path';
import { HemClient } from '../src/main/hem/client.ts';
import { discoverToken } from '../src/main/hem/token.ts';
import { protoToRef, scopeSectionKey } from '../src/main/hem/refs.ts';

const endpoint = process.env.VALHALL_HEM_ADDR ?? 'http://127.0.0.1:50091';
const discovery = discoverToken();
const client = new HemClient({
  endpoint,
  token: discovery.token,
  protoPath: join(import.meta.dirname, '..', 'proto', 'hem.proto'),
});

const health = await client.health();
console.log(`health: ${health.status.split(' ')[0]} · version ${health.version}`);
console.log(`token source: ${discovery.source}`);

const secrets = await client.listSecrets();
const sections = new Map<string, number>();
for (const s of secrets) {
  const key = scopeSectionKey(protoToRef(s.scope, s.name));
  sections.set(key, (sections.get(key) ?? 0) + 1);
}
console.log(`secrets: ${secrets.length} across ${sections.size} sections`);
for (const [section, count] of [...sections.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5)) {
  console.log(`  ${section}: ${count}`);
}

const first = secrets[0];
if (first) {
  const info = await client.getSecretInfo({ secret: { scope: first.scope, name: first.name } });
  console.log(`getSecretInfo(first): ok · updated ${info.updated_at}`);
}

const groups = await client.listGroups();
console.log(`groups: ${groups.length}`);

client.close();
