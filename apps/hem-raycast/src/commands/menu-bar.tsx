import { Cache, environment, Icon, launchCommand, LaunchType, MenuBarExtra, showHUD } from "@raycast/api";
import { usePromise } from "@raycast/utils";
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
}

const cache = new Cache();
const STATE_KEY = "menu-bar-state";

/**
 * Health RPC (cheap, unauthenticated) on every refresh; `hem cluster health`
 * + ListPendingApprovals only when the popover opens (user-initiated launch)
 * or on the background tick if the last known state was non-ok (spec §4.7).
 */
async function loadState(): Promise<MenuState> {
  let prev: MenuState | null = null;
  try {
    prev = JSON.parse(cache.get(STATE_KEY) ?? "null");
  } catch {
    prev = null;
  }

  let daemonOk = false;
  let daemonVersion: string | null = null;
  try {
    const health = await getClient().health();
    daemonOk = true;
    daemonVersion = health.version || null;
  } catch {
    daemonOk = false;
  }

  const heavy =
    environment.launchType === LaunchType.UserInitiated || !prev || !prev.daemonOk || prev.clusterStatus !== "ok";

  const next: MenuState = {
    daemonOk,
    daemonVersion,
    clusterStatus: prev?.clusterStatus ?? null,
    localNode: prev?.localNode ?? null,
    peers: prev?.peers ?? [],
    pendingCount: prev?.pendingCount ?? 0,
    pending: prev?.pending ?? [],
    updatedAt: new Date().toISOString(),
  };

  if (heavy) {
    try {
      const cluster = await getClusterHealth(getConfig().hemBinary);
      next.clusterStatus = cluster.status;
      next.localNode = {
        nodeId: cluster.scalars.node_id ?? "local",
        position: cluster.scalars.latest_position ?? "?",
      };
      next.peers = cluster.peers;
    } catch {
      next.clusterStatus = null;
    }
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
  }

  cache.set(STATE_KEY, JSON.stringify(next));
  return next;
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
  const { data, isLoading, revalidate } = usePromise(loadState, []);

  return (
    <MenuBarExtra
      isLoading={isLoading}
      icon={stateIcon(data)}
      title={data && data.pendingCount > 0 ? `${data.pendingCount}` : undefined}
      tooltip="Hem"
    >
      <MenuBarExtra.Item
        title={
          data?.daemonOk
            ? `hemd ok${data.daemonVersion ? ` · v${data.daemonVersion}` : ""} · cluster ${data.clusterStatus ?? "unknown"}`
            : `hemd unreachable at ${config.endpoint}`
        }
        icon={stateIcon(data)}
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
