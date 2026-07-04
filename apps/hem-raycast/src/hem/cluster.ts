import { homedir } from "node:os";
import { execa } from "execa";

// --- parsing (pure; unit-tested against captured fixtures) ---

export interface KvRecord {
  type: string;
  fields: Record<string, string>;
}

export interface ParsedKvOutput {
  /** Bare `key=value` lines. */
  scalars: Record<string, string>;
  /** `<type> k=v k=v …` lines, e.g. peer_health / peer / collision. */
  records: KvRecord[];
}

/**
 * Parse hem's machine-readable `key=value` output (valhall docs 1021).
 * A line is a scalar if its first `=` comes before its first space,
 * otherwise the first token is a record type followed by k=v pairs.
 * Values containing spaces are re-joined onto the preceding key.
 */
export function parseKvOutput(text: string): ParsedKvOutput {
  const scalars: Record<string, string> = {};
  const records: KvRecord[] = [];

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;

    const firstSpace = line.indexOf(" ");
    const firstEq = line.indexOf("=");

    if (firstEq > 0 && (firstSpace === -1 || firstEq < firstSpace)) {
      scalars[line.slice(0, firstEq)] = line.slice(firstEq + 1);
      continue;
    }
    if (firstSpace > 0) {
      const type = line.slice(0, firstSpace);
      const fields: Record<string, string> = {};
      let lastKey: string | null = null;
      for (const token of line.slice(firstSpace + 1).split(/\s+/)) {
        const eq = token.indexOf("=");
        if (eq > 0) {
          lastKey = token.slice(0, eq);
          fields[lastKey] = token.slice(eq + 1);
        } else if (lastKey) {
          fields[lastKey] += ` ${token}`;
        }
      }
      records.push({ type, fields });
    }
  }
  return { scalars, records };
}

export type PeerStatus = "caught_up" | "lagging" | "offline" | "divergent" | "unknown";

export interface PeerHealth {
  nodeId: string;
  status: PeerStatus;
  endpoint: string;
  cursorPosition: number;
  lag: number;
  lastSeen: string | null;
  error: string | null;
}

function dashToNull(v: string | undefined): string | null {
  return !v || v === "-" ? null : v;
}

export function peerHealthFromRecord(record: KvRecord): PeerHealth {
  const f = record.fields;
  const status = (f.status as PeerStatus) || "unknown";
  return {
    nodeId: f.node_id ?? "",
    status: ["caught_up", "lagging", "offline", "divergent"].includes(status) ? status : "unknown",
    endpoint: f.endpoint ?? "",
    cursorPosition: Number.parseInt(f.cursor_position ?? "", 10) || 0,
    lag: Number.parseInt(f.lag ?? "", 10) || 0,
    lastSeen: dashToNull(f.last_seen),
    error: dashToNull(f.error),
  };
}

export type ClusterHealthStatus = "ok" | "warning" | "critical" | "unknown";

export interface ClusterHealth {
  status: ClusterHealthStatus;
  scalars: Record<string, string>;
  peers: PeerHealth[];
  exitCode: number;
  raw: string;
}

export function clusterHealthFromOutput(stdout: string, exitCode: number): ClusterHealth {
  const parsed = parseKvOutput(stdout);
  const reported = parsed.scalars.cluster_health_status;
  const status: ClusterHealthStatus =
    reported === "ok" || reported === "warning" || reported === "critical"
      ? reported
      : exitCode === 0
        ? "ok"
        : exitCode === 1
          ? "warning"
          : exitCode === 2
            ? "critical"
            : "unknown";
  return {
    status,
    scalars: parsed.scalars,
    peers: parsed.records.filter((r) => r.type === "peer_health").map(peerHealthFromRecord),
    exitCode,
    raw: stdout,
  };
}

// --- shell-out ---

export function expandTilde(path: string): string {
  if (path === "~") return homedir();
  if (path.startsWith("~/")) return homedir() + path.slice(1);
  return path;
}

export interface ClusterRunResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  parsed: ParsedKvOutput;
}

/**
 * Run `hem cluster <args…>` with NO_COLOR=1. Non-zero exits are returned,
 * not thrown (`hem cluster health` uses exit 1/2 as warning/critical).
 * Throws only when the binary cannot be spawned at all.
 */
export async function runCluster(binary: string, args: string[]): Promise<ClusterRunResult> {
  const result = await execa(expandTilde(binary), ["cluster", ...args], {
    env: { NO_COLOR: "1" },
    extendEnv: true,
    reject: false,
    timeout: 60_000,
  });
  if (result.exitCode === undefined) {
    throw new Error(`failed to run ${binary}: ${result.shortMessage ?? "spawn error"}`);
  }
  return {
    exitCode: result.exitCode,
    stdout: result.stdout,
    stderr: result.stderr,
    parsed: parseKvOutput(result.stdout),
  };
}

export async function getClusterHealth(binary: string): Promise<ClusterHealth> {
  const res = await runCluster(binary, ["health"]);
  return clusterHealthFromOutput(res.stdout, res.exitCode);
}
