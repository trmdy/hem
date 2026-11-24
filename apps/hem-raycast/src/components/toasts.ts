import { Clipboard, launchCommand, LaunchType, showToast, Toast } from "@raycast/api";
import { describeError } from "./ErrorState";

export async function showErrorToast(error: unknown): Promise<Toast> {
  const p = describeError(error);
  return showToast({
    style: Toast.Style.Failure,
    title: p.title,
    message: p.description.split("\n")[0],
    primaryAction: p.copyContent
      ? { title: p.copyContent.title, onAction: () => Clipboard.copy(p.copyContent!.content) }
      : undefined,
  });
}

/** Shared receipt flow entry point: a read/delete came back approval-gated. */
export async function showApprovalRequiredToast(requestId: string, what: string): Promise<Toast> {
  return showToast({
    style: Toast.Style.Failure,
    title: `Approval required to ${what}`,
    message: `Request ${requestId}`,
    primaryAction: {
      title: "Open Pending Approvals",
      onAction: () => launchCommand({ name: "pending-approvals", type: LaunchType.UserInitiated }),
    },
    secondaryAction: {
      title: "Copy Request ID",
      onAction: () => Clipboard.copy(requestId),
    },
  });
}
