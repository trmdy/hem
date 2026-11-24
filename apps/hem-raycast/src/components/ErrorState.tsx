import { Action, ActionPanel, Icon, List, openExtensionPreferences } from "@raycast/api";
import { getConfig } from "../hem/config";
import { isHemError } from "../hem/errors";

export const RESTART_COMMAND = "launchctl kickstart -k gui/$UID/io.valhall.hemd";

export interface ErrorPresentation {
  icon: Icon;
  title: string;
  description: string;
  copyContent?: { title: string; content: string };
  showPreferences?: boolean;
}

export function describeError(error: unknown): ErrorPresentation {
  const config = getConfig();
  if (isHemError(error)) {
    switch (error.kind) {
      case "unreachable":
      case "timeout":
        return {
          icon: Icon.Plug,
          title: `hemd not reachable at ${config.endpoint}`,
          description: "Restart it with launchctl — the action below copies the command.",
          copyContent: { title: "Copy Restart Command", content: RESTART_COMMAND },
        };
      case "unauthenticated":
        return {
          icon: Icon.Key,
          title: "No usable operator token",
          description:
            "Searched, in order:\n" +
            ["VALHALL_HEM_TOKEN", ...config.tokenDiscovery.searchedPaths].join("\n") +
            "\nSet a token in the extension preferences or place one on disk.",
          showPreferences: true,
        };
      case "failed-precondition":
        return {
          icon: Icon.Lock,
          title: "Blocked by cluster read policy",
          description:
            `${error.message}\n\nThe secret's read tier (peer-quorum or master) needs peers that are currently ` +
            "unreachable. This is a policy decision, not a transient fault — retrying will not help.",
        };
      case "permission-denied":
        return { icon: Icon.XMarkCircle, title: "Permission denied", description: error.message };
      case "not-found":
        return { icon: Icon.QuestionMark, title: "Not found", description: error.message };
      default:
        return { icon: Icon.Warning, title: "Hem error", description: error.message };
    }
  }
  return { icon: Icon.Warning, title: "Unexpected error", description: String((error as Error)?.message ?? error) };
}

export function ErrorEmptyView({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const p = describeError(error);
  return (
    <List.EmptyView
      icon={p.icon}
      title={p.title}
      description={p.description}
      actions={
        <ActionPanel>
          {p.copyContent && <Action.CopyToClipboard title={p.copyContent.title} content={p.copyContent.content} />}
          {p.showPreferences && (
            <Action title="Open Extension Preferences" icon={Icon.Gear} onAction={openExtensionPreferences} />
          )}
          {onRetry && <Action title="Retry" icon={Icon.ArrowClockwise} onAction={onRetry} />}
        </ActionPanel>
      }
    />
  );
}
