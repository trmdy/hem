import { Clipboard, showHUD } from "@raycast/api";
import { describeError } from "../components/ErrorState";
import { getClient } from "../hem/config";

export default async function ScanClipboard() {
  try {
    const text = await Clipboard.readText();
    if (!text || !text.trim()) {
      await showHUD("Clipboard is empty");
      return;
    }
    const result = await getClient().scanForSecrets(text);
    if (result.clean) {
      await showHUD(`✓ Clean — checked against ${result.secrets_checked} secrets`);
      return;
    }
    // Refs only; values are never shown (spec §4.6).
    const shown = result.matches.slice(0, 3).map((m) => `${m.secret_ref}:${m.key}`);
    const more = result.matches.length - shown.length;
    await showHUD(`⚠ Contains ${shown.join(", ")}${more > 0 ? ` +${more} more` : ""}`);
  } catch (error) {
    await showHUD(`Scan failed — ${describeError(error).title}`);
  }
}
