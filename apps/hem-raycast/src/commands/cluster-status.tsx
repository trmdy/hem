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
import { ClusterHealth, getClusterHealth, KvRecord, PeerHealth, runCluster } from "../hem/cluster";
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
  const { data, error, isLoading, revalidate } = usePromise(async () => {
    const health = await getClusterHealth(config.hemBinary);
    let peerRecords: KvRecord[] = [];
    try {
      const peers = await runCluster(config.hemBinary, ["peers"]);
      peerRecords = peers.parsed.records.filter((r) => r.type === "peer");
    } catch {
      // wrap-key info is optional decoration
    }
    return { health, peerRecords };
  }, []);

  if (error) {
    // CLI failed to run at all (missing binary etc.) — spec §6: show raw, never crash.
    return (
      <Detail
        markdown={`# hem cluster health failed\n\n\`\`\`\n${String((error as Error).message ?? error)}\n\`\`\`\n\nBinary: \`${config.hemBinary}\` (configurable in preferences)`}
      />
    );
  }

  const health = data?.health;
  const parseFailed = health && Object.keys(health.scalars).length === 0;
  if (health && parseFailed) {
    return (
      <Detail
        markdown={`# Unparseable cluster health output (exit ${health.exitCode})\n\n\`\`\`\n${health.raw || "(empty output)"}\n\`\`\``}
        actions={
          <ActionPanel>
            <Action.CopyToClipboard title="Copy Raw Output" content={health.raw} />
          </ActionPanel>
        }
      />
    );
  }

  const s = health?.scalars ?? {};
  const wrapKeyByNode = new Map(data?.peerRecords.map((r) => [r.fields.node_id, r.fields.wrap_public_key]) ?? []);

  return (
    <List isLoading={isLoading} searchBarPlaceholder="Filter nodes…">
      {health && (
        <List.Section title="Cluster">
          <List.Item
            icon={statusIcon(health.status)}
            title={`Health: ${health.status}`}
            subtitle={s.cluster_id}
            accessories={[
              { tag: { value: s.node_id ?? "?", color: Color.Blue }, tooltip: "Local node" },
              { text: `quorum ${s.quorum ?? "?"}` },
            ]}
            actions={
              <ActionPanel>
                <CommonActions health={health} revalidate={revalidate} />
              </ActionPanel>
            }
          />
          <List.Item
            icon={Icon.List}
            title={`Ledger position ${s.latest_position ?? "?"}`}
            subtitle={`checkpoint ${s.checkpoint_status ?? "?"} · ${s.latest_checkpoint_cosignatures ?? "0"} cosignature(s)`}
            accessories={[{ text: `ledger_ok ${s.ledger_ok ?? "?"}` }]}
            actions={
              <ActionPanel>
                <CommonActions health={health} revalidate={revalidate} />
              </ActionPanel>
            }
          />
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
        </List.Section>
      )}
      {health && (
        <List.Section title="Nodes">
          <List.Item
            icon={{ source: Icon.CheckCircle, tintColor: Color.Green }}
            title={s.node_id ?? "local"}
            subtitle={s.listen}
            accessories={[{ tag: { value: "local", color: Color.Blue } }, { text: `@ ${s.latest_position ?? "?"}` }]}
            actions={
              <ActionPanel>
                <CommonActions health={health} revalidate={revalidate} />
              </ActionPanel>
            }
          />
          {health.peers.map((peer) => (
            <List.Item
              key={peer.nodeId}
              icon={peerStatusIcon(peer.status)}
              title={peer.nodeId}
              subtitle={peer.endpoint}
              accessories={[
                ...(peer.lag > 0
                  ? [{ tag: { value: `lag ${peer.lag}`, color: Color.Orange }, tooltip: "Operations behind" }]
                  : []),
                { text: `@ ${peer.cursorPosition}` },
                ...(peer.lastSeen
                  ? [{ date: new Date(peer.lastSeen), tooltip: `Last seen ${peer.lastSeen}` }]
                  : [{ text: "never seen" }]),
              ]}
              actions={
                <ActionPanel>
                  <CommonActions health={health} revalidate={revalidate} />
                  {wrapKeyByNode.get(peer.nodeId) && (
                    <Action.CopyToClipboard title="Copy Wrap Public Key" content={wrapKeyByNode.get(peer.nodeId)!} />
                  )}
                </ActionPanel>
              }
            />
          ))}
        </List.Section>
      )}
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
