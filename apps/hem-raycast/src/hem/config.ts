import { environment, getPreferenceValues } from "@raycast/api";
import { join } from "node:path";
import { HemClient } from "./client";
import { expandTilde } from "./cluster";
import { discoverToken, TokenDiscovery } from "./token";

export interface Preferences {
  endpoint?: string;
  token?: string;
  hemBinary?: string;
  clipboardClearSeconds?: string;
  primaryKeyGuess?: string;
}

export interface HemConfig {
  endpoint: string;
  tokenDiscovery: TokenDiscovery;
  hemBinary: string;
  clipboardClearSeconds: number;
  primaryKeyGuess: string[];
}

export const DEFAULT_ENDPOINT = "http://127.0.0.1:50091";

/** Actor string recorded in hem audit entries for writes from this extension. */
export const ACTOR = "raycast";

export function getConfig(): HemConfig {
  const prefs = getPreferenceValues<Preferences>();
  const clear = Number.parseInt(prefs.clipboardClearSeconds ?? "90", 10);
  return {
    endpoint: prefs.endpoint?.trim() || DEFAULT_ENDPOINT,
    tokenDiscovery: discoverToken({ explicit: prefs.token }),
    hemBinary: expandTilde(prefs.hemBinary?.trim() || "~/.valhall/system-daemons/bin/hem"),
    clipboardClearSeconds: Number.isFinite(clear) && clear >= 0 ? clear : 90,
    primaryKeyGuess: (prefs.primaryKeyGuess?.trim() || "api_key,token,key,password,secret")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
  };
}

let clientSingleton: HemClient | null = null;

/** Per-command-process HemClient built from preferences + token discovery. */
export function getClient(): HemClient {
  if (!clientSingleton) {
    const config = getConfig();
    clientSingleton = new HemClient({
      endpoint: config.endpoint,
      token: config.tokenDiscovery.token,
      protoPath: join(environment.assetsPath, "hem.proto"),
    });
  }
  return clientSingleton;
}
