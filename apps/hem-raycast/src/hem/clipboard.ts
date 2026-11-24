import { Clipboard, showHUD } from "@raycast/api";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";

/**
 * Schedule a clipboard clear in a detached helper so it survives the
 * command process exiting. The clipboard is only cleared if it still holds
 * the copied value; the comparison uses a SHA-256 passed via stdin, so the
 * value itself never touches argv, env, or disk.
 */
export function scheduleClipboardClear(value: string, seconds: number): void {
  if (!Number.isFinite(seconds) || seconds <= 0) return;
  const hash = createHash("sha256").update(value, "utf8").digest("hex");
  const script = [
    "IFS= read -r h",
    `sleep ${Math.floor(seconds)}`,
    `cur=$(/usr/bin/pbpaste 2>/dev/null | /usr/bin/shasum -a 256 | /usr/bin/awk '{print $1}')`,
    `if [ "$cur" = "$h" ]; then printf '' | /usr/bin/pbcopy; fi`,
  ].join("; ");
  const child = spawn("/bin/sh", ["-c", script], { detached: true, stdio: ["pipe", "ignore", "ignore"] });
  child.stdin.write(`${hash}\n`);
  child.stdin.end();
  child.unref();
}

/** Copy a secret value concealed (kept out of clipboard managers) with timed clear. */
export async function copyConcealed(value: string, opts: { clearAfterSeconds: number; label?: string }): Promise<void> {
  await Clipboard.copy(value, { concealed: true });
  scheduleClipboardClear(value, opts.clearAfterSeconds);
  const suffix = opts.clearAfterSeconds > 0 ? ` · clears in ${opts.clearAfterSeconds}s` : "";
  await showHUD(`Copied ${opts.label ?? "value"}${suffix}`);
}
