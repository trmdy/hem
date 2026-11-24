import {
  Action,
  ActionPanel,
  Alert,
  Clipboard,
  Color,
  confirmAlert,
  Icon,
  List,
  showToast,
  Toast,
  Keyboard,
} from "@raycast/api";
import { useCachedPromise } from "@raycast/utils";
import { ErrorEmptyView } from "../components/ErrorState";
import { showErrorToast } from "../components/toasts";
import { ApprovalRequestInfo } from "../hem/client";
import { ACTOR, getClient } from "../hem/config";
import { formatRef, protoToRef } from "../hem/refs";

function requestRef(request: ApprovalRequestInfo): string {
  return request.secret ? formatRef(protoToRef(request.secret.scope, request.secret.name)) : "?";
}

export default function PendingApprovals() {
  const { data, error, isLoading, revalidate } = useCachedPromise(() => getClient().listPendingApprovals(100), []);

  async function approve(request: ApprovalRequestInfo) {
    const ref = requestRef(request);
    // The confirmation alert is the human-confirmation step replacing the
    // CLI's typed `APPROVE <id>`.
    const confirmed = await confirmAlert({
      title: `Approve ${request.action || "access"} of ${ref}?`,
      message: `Request ${request.request_id}\nRequester: ${request.requester_token_id || "unknown"}\n${request.reason || ""}`,
      icon: Icon.CheckCircle,
      primaryAction: { title: "Approve" },
    });
    if (!confirmed) return;
    try {
      const result = await getClient().approveAccess(request.request_id, {
        actor: ACTOR,
        message: "approved from Raycast",
      });
      await showToast({
        style: Toast.Style.Success,
        title: `Approved ${request.action || "access"} of ${ref}`,
        message: `Receipt is single-use and bound to "${request.action || "get"}" — it will not work for other actions.`,
        primaryAction: result.approval_receipt
          ? {
              title: "Copy Receipt",
              onAction: () => Clipboard.copy(result.approval_receipt, { concealed: true }),
            }
          : undefined,
      });
      revalidate();
    } catch (e) {
      await showErrorToast(e);
    }
  }

  async function deny(request: ApprovalRequestInfo) {
    const ref = requestRef(request);
    const confirmed = await confirmAlert({
      title: `Deny ${request.action || "access"} of ${ref}?`,
      message: `Request ${request.request_id}`,
      icon: Icon.XMarkCircle,
      primaryAction: { title: "Deny", style: Alert.ActionStyle.Destructive },
    });
    if (!confirmed) return;
    try {
      await getClient().denyAccess(request.request_id, { actor: ACTOR, message: "denied from Raycast" });
      await showToast({ style: Toast.Style.Success, title: `Denied ${request.request_id}` });
      revalidate();
    } catch (e) {
      await showErrorToast(e);
    }
  }

  return (
    <List isLoading={isLoading} searchBarPlaceholder="Filter pending approvals…">
      {error ? (
        <ErrorEmptyView error={error} onRetry={revalidate} />
      ) : (data ?? []).length === 0 ? (
        <List.EmptyView
          icon={Icon.CheckCircle}
          title="No pending approvals"
          description="Daemon reachable and the approval queue is empty."
        />
      ) : (
        data!.map((request) => (
          <List.Item
            key={request.request_id}
            icon={Icon.Hourglass}
            title={`${request.action || "get"} ${requestRef(request)}`}
            subtitle={request.reason || undefined}
            accessories={[
              ...(request.requester_token_id
                ? [
                    {
                      tag: { value: request.requester_token_id, color: Color.SecondaryText },
                      tooltip: "Requester token",
                    },
                  ]
                : []),
              ...(request.created_at
                ? [{ date: new Date(request.created_at), tooltip: `Created ${request.created_at}` }]
                : []),
            ]}
            actions={
              <ActionPanel>
                <Action title="Approve" icon={Icon.CheckCircle} onAction={() => approve(request)} />
                <Action
                  title="Deny"
                  icon={Icon.XMarkCircle}
                  style={Action.Style.Destructive}
                  shortcut={{ modifiers: ["ctrl"], key: "x" }}
                  onAction={() => deny(request)}
                />
                <Action.CopyToClipboard
                  title="Copy Request ID"
                  content={request.request_id}
                  shortcut={Keyboard.Shortcut.Common.Copy}
                />
                <Action
                  title="Refresh"
                  icon={Icon.ArrowClockwise}
                  shortcut={Keyboard.Shortcut.Common.Refresh}
                  onAction={revalidate}
                />
              </ActionPanel>
            }
          />
        ))
      )}
    </List>
  );
}
