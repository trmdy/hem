import {
  Action,
  ActionPanel,
  Color,
  Detail,
  Icon,
  List,
  showToast,
  Toast,
  useNavigation,
  Keyboard,
} from "@raycast/api";
import { usePromise } from "@raycast/utils";
import { showErrorToast } from "../components/toasts";
import { ClusterHealth, getClusterHealth, getClusterSnapshot, PeerHealth, runCluster } from "../hem/cluster";
import { getConfig } from "../hem/config";

function statusIcon(status: ClusterHealth["status"]): { source: Icon; tintColor: Color } {
  switch (status) {
    case "ok":
      return { source: Icon.CheckCircle, tintColor: Color.Green };
    case "warning":
      return { source: Icon.CircleProgress50, tintColor: Color.Orange };
    case "critical":
      return { source: Icon.XMarkCircle, tintColor: Color.Red };
    default:
      return { source: Icon.QuestionMarkCircle, tintColor: Color.SecondaryText };
  }
}

function peerStatusIcon(status: PeerHealth["status"]): { source: Icon; tintColor: Color } {
  switch (status) {
    case "caught_up":
      return { source: Icon.CheckCircle, tintColor: Color.Green };
    case "lagging":
      return { source: Icon.CircleProgress50, tintColor: Color.Orange };
    case "offline":
      return { source: Icon.XMarkCircle, tintColor: Color.Red };
    case "divergent":
      return { source: Icon.Warning, tintColor: Color.Red };
    default:
      return { source: Icon.QuestionMarkCircle, tintColor: Color.SecondaryText };
  }
}

async function syncNow() {
  const config = getConfig();
  const toast = await showToast({ style: Toast.Style.Animated, title: "Syncing cluster…" });
  try {
    const result = await runCluster(config.hemBinary, ["sync", "--once"]);
    if (result.exitCode === 0) {
      toast.style = Toast.Style.Success;
      toast.title = "Cluster sync completed";
      toast.message = result.stdout.split("\n").slice(-2).join(" · ").slice(0, 120) || undefined;
    } else {
      toast.style = Toast.Style.Failure;
      toast.title = `Sync exited ${result.exitCode}`;
      toast.message = (result.stderr || result.stdout).slice(0, 120);
    }
  } catch (e) {
    toast.hide();
    await showErrorToast(e);
  }
}

function CommonActions({ health, revalidate }: { health?: ClusterHealth; revalidate: () => void }) {
  const { push } = useNavigation();
  return (
    <ActionPanel.Section>
      <Action title="Sync Now" icon={Icon.ArrowClockwise} onAction={syncNow} />
      {health && (
        <Action.CopyToClipboard
          title="Copy Health Report"
          content={health.raw}
          shortcut={Keyboard.Shortcut.Common.Copy}
        />
      )}
      <Action
        title="Refresh"
        icon={Icon.RotateClockwise}
        shortcut={Keyboard.Shortcut.Common.Refresh}
        onAction={revalidate}
      />
      <Action
        title="Show Collisions"
        icon={Icon.ExclamationMark}
        shortcut={Keyboard.Shortcut.Common.OpenWith}
        onAction={() => push(<CollisionsList />)}
      />
    </ActionPanel.Section>
  );
}

export default function ClusterStatus() {
  const config = getConfig();
  // Instant paint: `cluster status` + `cluster peers` read local config (~10 ms).
  const snapshot = usePromise(async () => getClusterSnapshot(config.hemBinary), []);
  // Slow enrichment: `cluster health` verifies the ledger and probes every
  // peer (~30 s with a dead node) — never block first render on it.
  const healthPromise = usePromise(async () => getClusterHealth(config.hemBinary), []);

  const revalidate = () => {
    snapshot.revalidate();
    healthPromise.revalidate();
  };

  if (snapshot.error && !healthPromise.data) {
    // CLI failed to run at all (missing binary etc.) — spec §6: show raw, never crash.
    return (
      <Detail
        markdown={`# hem cluster status failed\n\n\`\`\`\n${String((snapshot.error as Error).message ?? snapshot.error)}\n\`\`\`\n\nBinary: \`${config.hemBinary}\` (configurable in preferences)`}
      />
    );
  }

  const health = healthPromise.data;
  const healthUnparseable = health && Object.keys(health.scalars).length === 0;
  const s = { ...(snapshot.data?.scalars ?? {}), ...(health?.scalars ?? {}) };
  const probing = healthPromise.isLoading;
  const peerHealthById = new Map(health?.peers.map((p) => [p.nodeId, p]) ?? []);
  // Node rows come from the instant snapshot; fall back to health's peer
  // list if the snapshot itself failed.
  const peerRows =
    snapshot.data?.peers.map((pc) => ({ config: pc, health: peerHealthById.get(pc.nodeId) })) ??
    health?.peers.map((ph) => ({ config: undefined, health: ph as PeerHealth | undefined })) ??
    [];

  const healthRow = healthUnparseable
    ? {
        icon: { source: Icon.QuestionMarkCircle, tintColor: Color.Orange },
        title: `Health: unparseable output (exit ${health.exitCode})`,
        subtitle: "Copy raw output from the action panel",
      }
    : health
      ? { icon: statusIcon(health.status), title: `Health: ${health.status}`, subtitle: s.cluster_id }
      : healthPromise.error
        ? {
            icon: { source: Icon.XMarkCircle, tintColor: Color.Red },
            title: "Health: probe failed",
            subtitle: String((healthPromise.error as Error).message ?? healthPromise.error).slice(0, 80),
          }
        : {
            icon: { source: Icon.CircleProgress25, tintColor: Color.SecondaryText },
            title: "Health: probing peers…",
            subtitle: "verifies ledger + probes all peers — ~30 s on this cluster",
          };

  return (
    <List isLoading={snapshot.isLoading || probing} searchBarPlaceholder="Filter nodes…">
      <List.Section title="Cluster">
        <List.Item
          icon={healthRow.icon}
          title={healthRow.title}
          subtitle={healthRow.subtitle ?? s.cluster_id}
          accessories={[
            { tag: { value: s.node_id ?? "?", color: Color.Blue }, tooltip: "Local node" },
            { text: `quorum ${s.quorum ?? "?"}` },
          ]}
          actions={
            <ActionPanel>
              <CommonActions health={health} revalidate={revalidate} />
              {healthUnparseable && <Action.CopyToClipboard title="Copy Raw Output" content={health.raw} />}
            </ActionPanel>
          }
        />
        <List.Item
          icon={Icon.List}
          title={
            health
              ? `Ledger position ${s.latest_position ?? "?"}`
              : `Checkpoint position ${s.latest_checkpoint_position ?? "?"}`
          }
          subtitle={
            health
              ? `checkpoint ${s.checkpoint_status ?? "?"} · ${s.latest_checkpoint_cosignatures ?? "0"} cosignature(s)`
              : `${s.checkpoints ?? "?"} checkpoints · ${s.latest_checkpoint_cosignatures ?? "0"} cosignature(s)`
          }
          accessories={[{ text: health ? `ledger_ok ${s.ledger_ok ?? "?"}` : "ledger check pending" }]}
          actions={
            <ActionPanel>
              <CommonActions health={health} revalidate={revalidate} />
            </ActionPanel>
          }
        />
        {health && !healthUnparseable && (
          <List.Item
            icon={
              s.quorum_risk === "true" || (s.collisions ?? "0") !== "0" || (s.sync_errors ?? "0") !== "0"
                ? { source: Icon.Warning, tintColor: Color.Orange }
                : { source: Icon.CheckCircle, tintColor: Color.Green }
            }
            title="Risk"
            subtitle={`quorum_risk ${s.quorum_risk ?? "?"} · collisions ${s.collisions ?? "?"} · sync_errors ${s.sync_errors ?? "?"}`}
            accessories={[
              { text: `divergence ${s.divergence_issues ?? "0"} · integrity ${s.integrity_issues ?? "0"}` },
            ]}
            actions={
              <ActionPanel>
                <CommonActions health={health} revalidate={revalidate} />
              </ActionPanel>
            }
          />
        )}
      </List.Section>
      <List.Section title="Nodes">
        {s.node_id && (
          <List.Item
            icon={{ source: Icon.CheckCircle, tintColor: Color.Green }}
            title={s.node_id}
            subtitle={s.listen}
            accessories={[
              { tag: { value: "local", color: Color.Blue } },
              { text: `@ ${s.latest_position ?? s.latest_checkpoint_position ?? "?"}` },
            ]}
            actions={
              <ActionPanel>
                <CommonActions health={health} revalidate={revalidate} />
              </ActionPanel>
            }
          />
        )}
        {peerRows.map(({ config: pc, health: ph }) => {
          const nodeId = pc?.nodeId ?? ph?.nodeId ?? "?";
          return (
            <List.Item
              key={nodeId}
              icon={ph ? peerStatusIcon(ph.status) : { source: Icon.CircleProgress25, tintColor: Color.SecondaryText }}
              title={nodeId}
              subtitle={pc?.endpoint ?? ph?.endpoint}
              accessories={
                ph
                  ? [
                      ...(ph.lag > 0
                        ? [{ tag: { value: `lag ${ph.lag}`, color: Color.Orange }, tooltip: "Operations behind" }]
                        : []),
                      { text: `@ ${ph.cursorPosition}` },
                      ...(ph.lastSeen
                        ? [{ date: new Date(ph.lastSeen), tooltip: `Last seen ${ph.lastSeen}` }]
                        : [{ text: "never seen" }]),
                    ]
                  : [{ text: probing ? "probing…" : "no health data" }]
              }
              actions={
                <ActionPanel>
                  <CommonActions health={health} revalidate={revalidate} />
                  {pc?.wrapPublicKey && (
                    <Action.CopyToClipboard title="Copy Wrap Public Key" content={pc.wrapPublicKey} />
                  )}
                </ActionPanel>
              }
            />
          );
        })}
      </List.Section>
    </List>
  );
}

function CollisionsList() {
  const config = getConfig();
  const { data, error, isLoading, revalidate } = usePromise(
    async () => runCluster(config.hemBinary, ["collisions"]),
    [],
  );

  if (error) {
    return (
      <Detail
        markdown={`# hem cluster collisions failed\n\n\`\`\`\n${String((error as Error).message ?? error)}\n\`\`\``}
      />
    );
  }

  const records = data?.parsed.records ?? [];
  const count = data?.parsed.scalars.collisions;

  return (
    <List isLoading={isLoading} navigationTitle="Cluster Collisions">
      {records.length === 0 ? (
        <List.EmptyView
          icon={Icon.CheckCircle}
          title={count === "0" ? "No unresolved collisions" : "No collision records parsed"}
          description={
            count === "0" ? undefined : data?.stdout ? `Raw output:\n${data.stdout.slice(0, 200)}` : undefined
          }
        />
      ) : (
        records.map((record, index) => {
          const id = record.fields.collision_id ?? record.fields.id ?? `collision-${index}`;
          const resolveCommand = `hem cluster resolve-collision ${id} --resolution keep-current`;
          return (
            <List.Item
              key={id}
              icon={{ source: Icon.Warning, tintColor: Color.Orange }}
              title={id}
              subtitle={[record.fields.scope, record.fields.name, record.fields.key].filter(Boolean).join(" / ")}
              accessories={Object.entries(record.fields)
                .filter(([k]) => !["collision_id", "id", "scope", "name", "key"].includes(k))
                .slice(0, 3)
                .map(([k, v]) => ({ text: `${k}=${v}` }))}
              actions={
                <ActionPanel>
                  {/* Resolution stays in the terminal (runbook: never auto-repair) — copy the ready-made command. */}
                  <Action.CopyToClipboard title="Copy Resolve Command" content={resolveCommand} />
                  <Action.CopyToClipboard
                    title="Copy Collision Details"
                    content={JSON.stringify(record.fields, null, 2)}
                  />
                  <Action title="Refresh" icon={Icon.ArrowClockwise} onAction={revalidate} />
                </ActionPanel>
              }
            />
          );
        })
      )}
    </List>
  );
}
