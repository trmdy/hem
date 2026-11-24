import { join } from 'node:path';
import { expandTilde } from './hem/cluster';
import { discoverToken, TokenDiscovery } from './hem/token';

export interface HemDeskConfig {
  endpoint: string;
  tokenDiscovery: TokenDiscovery;
  hemBinary: string;
  clipboardClearSeconds: number;
  revealRemaskSeconds: number;
  protoPath: string;
}

export const DEFAULT_ENDPOINT = 'http://127.0.0.1:50091';

/** Actor string recorded in hem audit entries for writes from this app. */
export const ACTOR = 'hem-desk';

function intEnv(name: string, fallback: number): number {
  const parsed = Number.parseInt(process.env[name] ?? '', 10);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback;
}

/**
 * Endpoint resolution mirrors the client libraries (reference 0004 §Auth):
 * VALHALL_HEM_ADDR → VALHALL_HEMD_ENDPOINT → default localhost:50091.
 */
export function resolveEndpoint(env: Record<string, string | undefined> = process.env): string {
  return env.VALHALL_HEM_ADDR?.trim() || env.VALHALL_HEMD_ENDPOINT?.trim() || DEFAULT_ENDPOINT;
}

export function loadConfig(appPath: string): HemDeskConfig {
  return {
    endpoint: resolveEndpoint(),
    tokenDiscovery: discoverToken(),
    hemBinary: expandTilde(process.env.HEM_DESK_BINARY?.trim() || '~/.valhall/system-daemons/bin/hem'),
    clipboardClearSeconds: intEnv('HEM_DESK_CLIPBOARD_CLEAR_SECONDS', 90),
    revealRemaskSeconds: intEnv('HEM_DESK_REVEAL_REMASK_SECONDS', 30),
    protoPath: join(appPath, 'proto', 'hem.proto'),
  };
}
