import { Action, ActionPanel, Color, Icon, List, Keyboard } from "@raycast/api";
import { useState } from "react";
import { useCachedPromise } from "@raycast/utils";
import { ErrorEmptyView } from "../components/ErrorState";
import { AuditEntry } from "../hem/client";
import { getClient } from "../hem/config";
import { formatRef, protoToRef } from "../hem/refs";

const SCOPE_FILTERS: Record<string, string | undefined> = {
  all: undefined,
  global: "SECRET_SCOPE_GLOBAL",
  project: "SECRET_SCOPE_PROJECT",
  identity: "SECRET_SCOPE_IDENTITY",
};

function actionIcon(action: string): Icon {
  if (action.includes("delete")) return Icon.Trash;
  if (action.includes("set") || action.includes("write") || action.includes("import")) return Icon.Pencil;
  if (action.includes("token")) return Icon.Key;
  if (action.includes("approval") || action.includes("approve") || action.includes("deny")) return Icon.Hourglass;
  if (action.includes("grant")) return Icon.AddPerson;
  return Icon.Eye;
}

export default function AuditLog() {
  const [scopeFilter, setScopeFilter] = useState("all");
  const { data, error, isLoading, revalidate } = useCachedPromise(
    async (filter: string) => {
      const scope = SCOPE_FILTERS[filter];
      const entries = await getClient().getAuditLog({
        limit: 200,
        ...(scope ? { scope: { scope } } : {}),
      });
      return [...entries].sort((a, b) => (a.ts < b.ts ? 1 : -1));
    },
    [scopeFilter],
    { keepPreviousData: true },
  );

  return (
    <List
      isLoading={isLoading}
      searchBarPlaceholder="Filter audit entries…"
      searchBarAccessory={
        <List.Dropdown tooltip="Scope" value={scopeFilter} onChange={setScopeFilter}>
          <List.Dropdown.Item value="all" title="All Scopes" />
          <List.Dropdown.Item value="global" title="Global" />
          <List.Dropdown.Item value="project" title="Project" />
          <List.Dropdown.Item value="identity" title="Identity" />
        </List.Dropdown>
      }
    >
      {error ? (
        <ErrorEmptyView error={error} onRetry={revalidate} />
      ) : (
        (data ?? []).map((entry: AuditEntry) => {
          const ref = entry.secret?.name ? formatRef(protoToRef(entry.secret.scope, entry.secret.name)) : "";
          const success = !entry.result || entry.result === "ok" || entry.result === "success";
          return (
            <List.Item
              key={entry.audit_id}
              icon={actionIcon(entry.action)}
              title={entry.action}
              subtitle={[ref, entry.actor && `by ${entry.actor}`].filter(Boolean).join(" · ")}
              accessories={[
                { tag: { value: entry.result || "ok", color: success ? Color.Green : Color.Red } },
                ...(entry.ts ? [{ date: new Date(entry.ts), tooltip: entry.ts }] : []),
              ]}
              actions={
                <ActionPanel>
                  <Action.CopyToClipboard title="Copy Entry as JSON" content={JSON.stringify(entry, null, 2)} />
                  {ref && <Action.CopyToClipboard title="Copy Secret Ref" content={ref} />}
                  <Action
                    title="Refresh"
                    icon={Icon.ArrowClockwise}
                    shortcut={Keyboard.Shortcut.Common.Refresh}
                    onAction={revalidate}
                  />
                </ActionPanel>
              }
            />
          );
        })
      )}
    </List>
  );
}
