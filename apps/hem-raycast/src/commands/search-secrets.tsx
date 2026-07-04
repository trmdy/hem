import {
  Action,
  ActionPanel,
  Alert,
  Clipboard,
  Color,
  confirmAlert,
  Detail,
  Icon,
  List,
  showToast,
  Toast,
  useNavigation,
  Keyboard,
} from "@raycast/api";
import { useState } from "react";
import { useCachedPromise, usePromise } from "@raycast/utils";
import { ErrorEmptyView } from "../components/ErrorState";
import { SecretForm } from "../components/SecretForm";
import { showApprovalRequiredToast, showErrorToast } from "../components/toasts";
import { GrantInfo, SecretInfo } from "../hem/client";
import { copyConcealed } from "../hem/clipboard";
import { ACTOR, getClient, getConfig } from "../hem/config";
import { formatRef, protoToRef, refToProto, scopeSectionKey, SecretRefParts } from "../hem/refs";

type ValuesResult =
  { kind: "ok"; values: Record<string, string>; info: SecretInfo } | { kind: "pending"; requestId: string };

async function fetchSecretValues(refParts: SecretRefParts): Promise<ValuesResult> {
  const response = await getClient().getSecret({ secret: refToProto(refParts) });
  if (response.pending) return { kind: "pending", requestId: response.pending.request_id };
  if (!response.secret) throw new Error("empty GetSecret response");
  return { kind: "ok", values: response.secret.values ?? {}, info: response.secret.info };
}

export function pickPrimaryKey(keys: string[], guesses: string[]): string | null {
  for (const guess of guesses) {
    if (keys.includes(guess)) return guess;
  }
  return keys.length === 1 ? keys[0] : null;
}

function maskValue(value: string): string {
  return value.length >= 8 ? `••••${value.slice(-4)}` : "••••••";
}

export default function SearchSecrets() {
  const { data, error, isLoading, revalidate } = useCachedPromise(() => getClient().listSecrets({}), [], {
    keepPreviousData: true,
  });

  const sections = new Map<string, SecretInfo[]>();
  for (const info of data ?? []) {
    const key = scopeSectionKey(protoToRef(info.scope, info.name));
    const list = sections.get(key) ?? [];
    list.push(info);
    sections.set(key, list);
  }
  const sectionKeys = [...sections.keys()].sort((a, b) =>
    a === "global" ? -1 : b === "global" ? 1 : a.localeCompare(b),
  );

  return (
    <List isLoading={isLoading} searchBarPlaceholder="Search secrets across all scopes…">
      {error ? (
        <ErrorEmptyView error={error} onRetry={revalidate} />
      ) : (
        sectionKeys.map((sectionKey) => (
          <List.Section key={sectionKey} title={sectionKey} subtitle={`${sections.get(sectionKey)!.length}`}>
            {sections.get(sectionKey)!.map((info) => (
              <SecretListItem key={formatRef(protoToRef(info.scope, info.name))} info={info} revalidate={revalidate} />
            ))}
          </List.Section>
        ))
      )}
    </List>
  );
}

function SecretListItem({ info, revalidate }: { info: SecretInfo; revalidate: () => void }) {
  const { push } = useNavigation();
  const config = getConfig();
  const refParts = protoToRef(info.scope, info.name);
  const refStr = formatRef(refParts);

  const accessories: List.Item.Accessory[] = [];
  if (info.group) accessories.push({ tag: { value: info.group, color: Color.Blue }, tooltip: "Group" });
  if (info.requires_approval) accessories.push({ icon: Icon.Lock, tooltip: "Requires approval" });
  if (info.updated_at) accessories.push({ date: new Date(info.updated_at), tooltip: `Updated ${info.updated_at}` });

  async function withValues(handler: (values: Record<string, string>) => Promise<void> | void, what: string) {
    try {
      const result = await fetchSecretValues(refParts);
      if (result.kind === "pending") {
        await showApprovalRequiredToast(result.requestId, what);
        return;
      }
      await handler(result.values);
    } catch (e) {
      await showErrorToast(e);
    }
  }

  function copyPrimary() {
    return withValues(async (values) => {
      const key = pickPrimaryKey(Object.keys(values), config.primaryKeyGuess);
      if (key) {
        await copyConcealed(values[key], {
          clearAfterSeconds: config.clipboardClearSeconds,
          label: `${info.name}:${key}`,
        });
      } else {
        push(<KeyPicker refParts={refParts} values={values} />);
      }
    }, `read ${refStr}`);
  }

  function pastePrimary() {
    return withValues(async (values) => {
      const key = pickPrimaryKey(Object.keys(values), config.primaryKeyGuess);
      if (key) {
        await Clipboard.paste(values[key]);
      } else {
        push(<KeyPicker refParts={refParts} values={values} paste />);
      }
    }, `read ${refStr}`);
  }

  function copyAsCli() {
    return withValues(async (values) => {
      const key = pickPrimaryKey(Object.keys(values), config.primaryKeyGuess) ?? Object.keys(values)[0];
      await Clipboard.copy(key ? `hem get ${refStr} ${key}` : `hem get ${refStr}`);
      await showToast({ style: Toast.Style.Success, title: "Copied CLI command" });
    }, `read ${refStr}`);
  }

  return (
    <List.Item
      title={info.name}
      subtitle={info.description || undefined}
      accessories={accessories}
      icon={Icon.Key}
      keywords={[refStr, info.group, info.description].filter(Boolean).flatMap((s) => s.split(/[\s/,-]+/))}
      actions={
        <ActionPanel>
          <ActionPanel.Section>
            <Action title="Copy Primary Value" icon={Icon.Clipboard} onAction={copyPrimary} />
            <Action
              title="Pick Key…"
              icon={Icon.List}
              shortcut={{ modifiers: ["cmd"], key: "return" }}
              onAction={() =>
                withValues((values) => push(<KeyPicker refParts={refParts} values={values} />), `read ${refStr}`)
              }
            />
            <Action
              title="Paste into Frontmost App"
              icon={Icon.Text}
              shortcut={{ modifiers: ["opt"], key: "return" }}
              onAction={pastePrimary}
            />
            <Action
              title="Inspect"
              icon={Icon.Eye}
              shortcut={{ modifiers: ["cmd"], key: "i" }}
              onAction={() => push(<InspectSecret refParts={refParts} onMutated={revalidate} />)}
            />
          </ActionPanel.Section>
          <ActionPanel.Section>
            <Action.CopyToClipboard title="Copy Ref" content={refStr} shortcut={Keyboard.Shortcut.Common.Copy} />
            <Action
              title="Copy as CLI Command"
              icon={Icon.Terminal}
              shortcut={{ modifiers: ["cmd", "shift"], key: "x" }}
              onAction={copyAsCli}
            />
          </ActionPanel.Section>
          <ActionPanel.Section>
            <Action
              title="Edit…"
              icon={Icon.Pencil}
              shortcut={Keyboard.Shortcut.Common.Edit}
              onAction={() => push(<EditSecret refParts={refParts} onSaved={revalidate} />)}
            />
            <Action
              title="New Secret"
              icon={Icon.Plus}
              shortcut={Keyboard.Shortcut.Common.New}
              onAction={() => push(<SecretForm onSaved={revalidate} />)}
            />
            <Action
              title="Delete…"
              icon={Icon.Trash}
              style={Action.Style.Destructive}
              shortcut={{ modifiers: ["ctrl"], key: "x" }}
              onAction={() => deleteSecretFlow(refParts, revalidate)}
            />
          </ActionPanel.Section>
        </ActionPanel>
      }
    />
  );
}

async function deleteSecretFlow(refParts: SecretRefParts, revalidate: () => void) {
  const refStr = formatRef(refParts);
  const confirmed = await confirmAlert({
    title: `Delete ${refStr}?`,
    message: "Deletes are approval-gated server-side. This fires the delete request; it is never auto-approved.",
    icon: Icon.Trash,
    primaryAction: { title: "Delete", style: Alert.ActionStyle.Destructive },
  });
  if (!confirmed) return;
  try {
    const response = await getClient().deleteSecret(refToProto(refParts), {
      actor: ACTOR,
      reason: "deleted from Raycast",
    });
    if (response.deleted) {
      await showToast({ style: Toast.Style.Success, title: `Deleted ${refStr}` });
      revalidate();
    } else if (response.approval_request_id) {
      await showApprovalRequiredToast(response.approval_request_id, `delete ${refStr}`);
    } else {
      await showToast({
        style: Toast.Style.Failure,
        title: "Delete not applied",
        message: "Daemon returned no approval id",
      });
    }
  } catch (e) {
    await showErrorToast(e);
  }
}

export function KeyPicker({
  refParts,
  values,
  paste = false,
}: {
  refParts: SecretRefParts;
  values: Record<string, string>;
  paste?: boolean;
}) {
  const config = getConfig();
  const refStr = formatRef(refParts);
  return (
    <List navigationTitle={`${refStr} — pick key`} searchBarPlaceholder="Filter keys…">
      {Object.entries(values).map(([key, value]) => (
        <List.Item
          key={key}
          title={key}
          subtitle={maskValue(value)}
          icon={Icon.Key}
          actions={
            <ActionPanel>
              {paste ? (
                <Action title="Paste into Frontmost App" icon={Icon.Text} onAction={() => Clipboard.paste(value)} />
              ) : (
                <Action
                  title="Copy Value"
                  icon={Icon.Clipboard}
                  onAction={() => copyConcealed(value, { clearAfterSeconds: config.clipboardClearSeconds, label: key })}
                />
              )}
              <Action
                title={paste ? "Copy Value" : "Paste into Frontmost App"}
                icon={paste ? Icon.Clipboard : Icon.Text}
                onAction={() =>
                  paste
                    ? copyConcealed(value, { clearAfterSeconds: config.clipboardClearSeconds, label: key })
                    : Clipboard.paste(value)
                }
              />
              <Action.CopyToClipboard title="Copy CLI Command" content={`hem get ${refStr} ${key}`} />
            </ActionPanel>
          }
        />
      ))}
    </List>
  );
}

function EditSecret({ refParts, onSaved }: { refParts: SecretRefParts; onSaved: () => void }) {
  const { data, error, isLoading } = usePromise(async () => fetchSecretValues(refParts), []);

  if (error) {
    return (
      <List>
        <ErrorEmptyView error={error} />
      </List>
    );
  }
  if (!data || isLoading) {
    return <Detail isLoading markdown="" navigationTitle={`Edit ${formatRef(refParts)}`} />;
  }
  if (data.kind === "pending") {
    return (
      <Detail
        navigationTitle={`Edit ${formatRef(refParts)}`}
        markdown={`# Approval required\n\nReading \`${formatRef(refParts)}\` is approval-gated.\n\nRequest id: \`${data.requestId}\``}
      />
    );
  }
  return (
    <SecretForm
      initial={{
        refParts,
        description: data.info.description,
        group: data.info.group,
        requiresApproval: data.info.requires_approval,
        values: data.values,
      }}
      onSaved={onSaved}
    />
  );
}

function InspectSecret({ refParts, onMutated }: { refParts: SecretRefParts; onMutated: () => void }) {
  const config = getConfig();
  const { push } = useNavigation();
  const refStr = formatRef(refParts);
  const [revealed, setRevealed] = useState<ReadonlySet<string>>(new Set());

  const { data, error, isLoading } = usePromise(async () => {
    const values = await fetchSecretValues(refParts);
    let grants: GrantInfo[] = [];
    try {
      grants = await getClient().listGrants(refToProto(refParts));
    } catch {
      // grants are informational; keep the inspect view alive without them
    }
    return { values, grants };
  }, []);

  if (error) {
    return (
      <List>
        <ErrorEmptyView error={error} />
      </List>
    );
  }

  const pending = data?.values.kind === "pending" ? data.values : undefined;
  const ok = data?.values.kind === "ok" ? data.values : undefined;

  const lines: string[] = [`# ${refStr}`];
  if (pending) {
    lines.push("", `**Approval required** — request id \`${pending.requestId}\``);
  }
  if (ok) {
    if (ok.info.description) lines.push("", ok.info.description);
    lines.push("", "| Key | Value |", "| --- | --- |");
    for (const [key, value] of Object.entries(ok.values)) {
      lines.push(`| \`${key}\` | \`${revealed.has(key) ? value : maskValue(value)}\` |`);
    }
  }

  function toggleReveal(key: string) {
    setRevealed((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  return (
    <Detail
      isLoading={isLoading}
      navigationTitle={refStr}
      markdown={lines.join("\n")}
      metadata={
        ok && (
          <Detail.Metadata>
            <Detail.Metadata.Label title="Ref" text={refStr} />
            <Detail.Metadata.Label title="Group" text={ok.info.group || "—"} />
            <Detail.Metadata.Label title="Requires Approval" text={ok.info.requires_approval ? "yes" : "no"} />
            <Detail.Metadata.Separator />
            <Detail.Metadata.Label
              title="Created"
              text={`${ok.info.created_at || "—"} by ${ok.info.created_by || "—"}`}
            />
            <Detail.Metadata.Label title="Updated" text={ok.info.updated_at || "—"} />
            <Detail.Metadata.Label
              title="Last Accessed"
              text={
                ok.info.last_accessed_at ? `${ok.info.last_accessed_at} by ${ok.info.last_accessed_by || "—"}` : "—"
              }
            />
            <Detail.Metadata.Separator />
            {data && data.grants.length > 0 ? (
              <Detail.Metadata.TagList title="Grants">
                {data.grants.map((g, i) => (
                  <Detail.Metadata.TagList.Item
                    key={i}
                    text={`${g.grantee_scope?.scope?.replace("SECRET_SCOPE_", "").toLowerCase() ?? "?"}:${g.grantee_id || "*"}`}
                  />
                ))}
              </Detail.Metadata.TagList>
            ) : (
              <Detail.Metadata.Label title="Grants" text="none" />
            )}
          </Detail.Metadata>
        )
      }
      actions={
        <ActionPanel>
          {ok && (
            <>
              <ActionPanel.Submenu title="Copy Key Value" icon={Icon.Clipboard}>
                {Object.entries(ok.values).map(([key, value]) => (
                  <Action
                    key={key}
                    title={key}
                    onAction={() =>
                      copyConcealed(value, { clearAfterSeconds: config.clipboardClearSeconds, label: key })
                    }
                  />
                ))}
              </ActionPanel.Submenu>
              <ActionPanel.Submenu
                title="Reveal or Hide Key"
                icon={Icon.Eye}
                shortcut={Keyboard.Shortcut.Common.Refresh}
              >
                {Object.keys(ok.values).map((key) => (
                  <Action
                    key={key}
                    title={`${revealed.has(key) ? "Hide" : "Reveal"} ${key}`}
                    onAction={() => toggleReveal(key)}
                  />
                ))}
              </ActionPanel.Submenu>
              <Action
                title="Edit…"
                icon={Icon.Pencil}
                shortcut={Keyboard.Shortcut.Common.Edit}
                onAction={() => push(<EditSecret refParts={refParts} onSaved={onMutated} />)}
              />
            </>
          )}
          {pending && <Action.CopyToClipboard title="Copy Request ID" content={pending.requestId} />}
          <Action.CopyToClipboard title="Copy Ref" content={refStr} shortcut={Keyboard.Shortcut.Common.Copy} />
        </ActionPanel>
      }
    />
  );
}
