import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export interface TokenDiscoveryOptions {
  /** Explicit token (Raycast preference / --token). Wins over everything. */
  explicit?: string | null;
  env?: Record<string, string | undefined>;
  home?: string;
}

export interface TokenDiscovery {
  token: string | null;
  /** Where the token came from: "preference", "env:VALHALL_HEM_TOKEN", or a file path. */
  source: string | null;
  /** File paths that were (or would be) searched, in order. */
  searchedPaths: string[];
}

/**
 * File locations searched for an operator token, in CLI-compatible order
 * (spec §2): $HEM_DATA_DIR, $VALHALL_SYSTEM_DAEMONS_DIR/data/hem,
 * ~/.valhall/hem, ~/.valhall/system-daemons/data/hem.
 */
export function tokenSearchPaths(opts: TokenDiscoveryOptions = {}): string[] {
  const env = opts.env ?? process.env;
  const home = opts.home ?? homedir();
  const paths: string[] = [];
  if (env.HEM_DATA_DIR) {
    paths.push(join(env.HEM_DATA_DIR, "operator.token"));
  }
  if (env.VALHALL_SYSTEM_DAEMONS_DIR) {
    paths.push(join(env.VALHALL_SYSTEM_DAEMONS_DIR, "data", "hem", "operator.token"));
  }
  paths.push(join(home, ".valhall", "hem", "operator.token"));
  paths.push(join(home, ".valhall", "system-daemons", "data", "hem", "operator.token"));
  return paths;
}

export function discoverToken(opts: TokenDiscoveryOptions = {}): TokenDiscovery {
  const env = opts.env ?? process.env;
  const searchedPaths = tokenSearchPaths(opts);

  const explicit = opts.explicit?.trim();
  if (explicit) {
    return { token: explicit, source: "preference", searchedPaths };
  }

  const fromEnv = env.VALHALL_HEM_TOKEN?.trim();
  if (fromEnv) {
    return { token: fromEnv, source: "env:VALHALL_HEM_TOKEN", searchedPaths };
  }

  for (const path of searchedPaths) {
    let contents: string;
    try {
      contents = readFileSync(path, "utf8");
    } catch {
      continue;
    }
    const token = contents.trim();
    if (token) {
      return { token, source: path, searchedPaths };
    }
  }

  return { token: null, source: null, searchedPaths };
}
