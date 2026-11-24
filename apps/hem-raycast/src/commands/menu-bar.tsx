import { Cache, environment, Icon, launchCommand, LaunchType, MenuBarExtra, showHUD } from "@raycast/api";
import { usePromise } from "@raycast/utils";
import { useState } from "react";
import { ClusterHealthStatus, getClusterHealth, PeerHealth, runCluster } from "../hem/cluster";
import { getClient, getConfig } from "../hem/config";
import { formatRef, protoToRef } from "../hem/refs";

interface PendingItem {
  id: string;
  ref: string;
  action: string;
}

interface MenuState {
  daemonOk: boolean;
  daemonVersion: string | null;
  clusterStatus: ClusterHealthStatus | null;
  localNode: { nodeId: string; position: string } | null;
  peers: PeerHealth[];
  pendingCount: number;
  pending: PendingItem[];
  updatedAt: string;
  clusterUpdatedAt: string | null;
}

const cache = new Cache();
const STATE_KEY = "menu-bar-state";
// `hem cluster health` verifies the ledger and probes every peer (~30 s on
// this cluster) — never rerun it more often than this, even across opens.
const CLUSTER_STALE_MS = 5 * 60_000;

function readCachedState(): MenuState | null {
  try {
    return JSON.parse(cache.get(STATE_KEY) ?? "null");
  } catch {
    return null;
  }
}

function persist(state: MenuState): MenuState {
  cache.set(STATE_KEY, JSON.stringify(state));
  return state;
}

/** Fast pass: daemon Health RPC + pending approvals (both gRPC, <100 ms). */
async function loadFast(prev: MenuState | null): Promise<MenuState> {
  let daemonOk = false;
  let daemonVersion: string | null = null;
  try {
    const health = await getClient().health();
    daemonOk = true;
    daemonVersion = health.version || null;
  } catch {
    daemonOk = false;
  }

  const next: MenuState = {
    daemonOk,
    daemonVersion,
    clusterStatus: prev?.clusterStatus ?? null,
    localNode: prev?.localNode ?? null,
    peers: prev?.peers ?? [],
    pendingCount: prev?.pendingCount ?? 0,
    pending: prev?.pending ?? [],
    updatedAt: new Date().toISOString(),
    clusterUpdatedAt: prev?.clusterUpdatedAt ?? null,
  };

  if (daemonOk) {
    try {
      const approvals = await getClient().listPendingApprovals(50);
      next.pendingCount = approvals.length;
      next.pending = approvals.slice(0, 10).map((a) => ({
        id: a.request_id,
        ref: a.secret ? formatRef(protoToRef(a.secret.scope, a.secret.name)) : "?",
        action: a.action || "get",
      }));
    } catch {
      // keep previous approval state; metadata only, never values
    }
  }
  return persist(next);
}

/**
 * Slow pass (spec §4.7 + staleness guard): run `hem cluster health` only when
 * the cached probe is older than CLUSTER_STALE_MS AND the launch is
 * user-initiated, we have no probe yet, or the last known state was non-ok.
 */
function shouldProbeCluster(state: MenuState): boolean {
  const fresh = state.clusterUpdatedAt && Date.now() - Date.parse(state.clusterUpdatedAt) < CLUSTER_STALE_MS;
  if (fresh) return false;
  return (
    environment.launchType === LaunchType.UserInitiated ||
    !state.clusterUpdatedAt ||
    !state.daemonOk ||
    state.clusterStatus !== "ok"
  );
}

async function loadCluster(prev: MenuState): Promise<MenuState> {
  const next = { ...prev };
  try {
    const cluster = await getClusterHealth(getConfig().hemBinary);
    next.clusterStatus = cluster.status;
    next.localNode = {
      nodeId: cluster.scalars.node_id ?? "local",
      position: cluster.scalars.latest_position ?? "?",
    };
    next.peers = cluster.peers;
    next.clusterUpdatedAt = new Date().toISOString();
  } catch {
    next.clusterStatus = null;
  }
  return persist(next);
}

function stateIcon(state: MenuState | undefined): Icon {
  if (!state) return Icon.Circle;
  if (!state.daemonOk || state.clusterStatus === "critical") return Icon.XMarkCircle;
  if (state.clusterStatus === "warning") return Icon.CircleProgress50;
  if (state.clusterStatus === "ok") return Icon.CircleFilled;
  return Icon.Circle;
}

function peerIcon(status: PeerHealth["status"]): Icon {
  switch (status) {
    case "caught_up":
      return Icon.CheckCircle;
    case "lagging":
      return Icon.CircleProgress50;
    case "offline":
      return Icon.XMarkCircle;
    case "divergent":
      return Icon.Warning;
    default:
      return Icon.QuestionMarkCircle;
  }
}

export default function HemMenuBar() {
  const config = getConfig();
  // Render immediately from the cached state; fast pass updates it in
  // <100 ms, the ~30 s cluster probe streams in afterwards if due.
  const [data, setData] = useState<MenuState | null>(readCachedState);
  const [probing, setProbing] = useState(false);
  const { isLoading, revalidate } = usePromise(async () => {
    const fast = await loadFast(readCachedState());
    setData(fast);
    if (shouldProbeCluster(fast)) {
      setProbing(true);
      try {
        setData(await loadCluster(fast));
      } finally {
        setProbing(false);
      }
    }
  }, []);

  return (
    <MenuBarExtra
      isLoading={isLoading}
      icon={stateIcon(data ?? undefined)}
      title={data && data.pendingCount > 0 ? `${data.pendingCount}` : undefined}
      tooltip="Hem"
    >
      <MenuBarExtra.Item
        title={
          data?.daemonOk
            ? `hemd ok${data.daemonVersion ? ` · v${data.daemonVersion}` : ""} · cluster ${
                data.clusterStatus ?? (probing ? "probing…" : "unknown")
              }`
            : `hemd unreachable at ${config.endpoint}`
        }
        icon={stateIcon(data ?? undefined)}
        onAction={() => launchCommand({ name: "cluster-status", type: LaunchType.UserInitiated })}
      />
      {data && (data.localNode || data.peers.length > 0) && (
        <MenuBarExtra.Section title="Nodes">
          {data.localNode && (
            <MenuBarExtra.Item
              title={`${data.localNode.nodeId} · local @ ${data.localNode.position}`}
              icon={Icon.CheckCircle}
              onAction={() => launchCommand({ name: "cluster-status", type: LaunchType.UserInitiated })}
            />
          )}
          {data.peers.map((peer) => (
            <MenuBarExtra.Item
              key={peer.nodeId}
              title={`${peer.nodeId} · ${peer.status}${peer.lag > 0 ? ` · lag ${peer.lag}` : ""}`}
              icon={peerIcon(peer.status)}
              onAction={() => launchCommand({ name: "cluster-status", type: LaunchType.UserInitiated })}
            />
          ))}
        </MenuBarExtra.Section>
      )}
      <MenuBarExtra.Section title="Approvals">
        {data && data.pendingCount > 0 ? (
          data.pending.map((p) => (
            <MenuBarExtra.Item
              key={p.id}
              title={`${p.action} ${p.ref}`}
              icon={Icon.Hourglass}
              onAction={() => launchCommand({ name: "pending-approvals", type: LaunchType.UserInitiated })}
            />
          ))
        ) : (
          <MenuBarExtra.Item title="No pending approvals" icon={Icon.CheckCircle} onAction={() => revalidate()} />
        )}
      </MenuBarExtra.Section>
      <MenuBarExtra.Section>
        <MenuBarExtra.Item
          title="Sync Now"
          icon={Icon.ArrowClockwise}
          onAction={async () => {
            const result = await runCluster(config.hemBinary, ["sync", "--once"]);
            await showHUD(result.exitCode === 0 ? "Cluster sync completed" : `Sync exited ${result.exitCode}`);
          }}
        />
        <MenuBarExtra.Item
          title="Open Search Secrets"
          icon={Icon.MagnifyingGlass}
          onAction={() => launchCommand({ name: "search-secrets", type: LaunchType.UserInitiated })}
        />
        <MenuBarExtra.Item title="Refresh" icon={Icon.RotateClockwise} onAction={() => revalidate()} />
      </MenuBarExtra.Section>
    </MenuBarExtra>
  );
}
