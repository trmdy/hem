import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

interface ExtensionCommand {
  name: string;
  mode: string;
  interval?: string;
}

const manifest = JSON.parse(readFileSync(join(__dirname, "..", "package.json"), "utf8")) as {
  commands: ExtensionCommand[];
};

describe("extension manifest", () => {
  it("keeps Add Secret available", () => {
    expect(manifest.commands).toContainEqual(expect.objectContaining({ name: "add-secret", mode: "view" }));
  });

  it("registers no background or menu-bar command", () => {
    expect(manifest.commands.filter((command) => command.mode === "menu-bar" || command.interval)).toEqual([]);
  });
});
