import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { discoverToken, tokenSearchPaths } from "../src/hem/token";

let sandbox: string;
let home: string;

function writeToken(path: string, contents: string) {
  mkdirSync(join(path, ".."), { recursive: true });
  writeFileSync(path, contents);
}

beforeEach(() => {
  sandbox = mkdtempSync(join(tmpdir(), "hem-token-test-"));
  home = join(sandbox, "home");
  mkdirSync(home, { recursive: true });
});

afterEach(() => {
  rmSync(sandbox, { recursive: true, force: true });
});

describe("tokenSearchPaths", () => {
  it("orders paths per spec §2: HEM_DATA_DIR, VALHALL_SYSTEM_DAEMONS_DIR, ~/.valhall/hem, ~/.valhall/system-daemons", () => {
    const paths = tokenSearchPaths({
      env: { HEM_DATA_DIR: "/data", VALHALL_SYSTEM_DAEMONS_DIR: "/sysd" },
      home: "/home/u",
    });
    expect(paths).toEqual([
      "/data/operator.token",
      "/sysd/data/hem/operator.token",
      "/home/u/.valhall/hem/operator.token",
      "/home/u/.valhall/system-daemons/data/hem/operator.token",
    ]);
  });

  it("omits env-based paths when the env vars are unset", () => {
    const paths = tokenSearchPaths({ env: {}, home: "/home/u" });
    expect(paths).toHaveLength(2);
    expect(paths[0]).toBe("/home/u/.valhall/hem/operator.token");
  });
});

describe("discoverToken", () => {
  it("explicit preference wins over everything", () => {
    writeToken(join(home, ".valhall", "hem", "operator.token"), "file-token\n");
    const result = discoverToken({ explicit: " pref-token ", env: { VALHALL_HEM_TOKEN: "env-token" }, home });
    expect(result.token).toBe("pref-token");
    expect(result.source).toBe("preference");
  });

  it("VALHALL_HEM_TOKEN wins over token files", () => {
    writeToken(join(home, ".valhall", "hem", "operator.token"), "file-token\n");
    const result = discoverToken({ env: { VALHALL_HEM_TOKEN: "env-token" }, home });
    expect(result.token).toBe("env-token");
    expect(result.source).toBe("env:VALHALL_HEM_TOKEN");
  });

  it("reads HEM_DATA_DIR/operator.token first among files", () => {
    const dataDir = join(sandbox, "data");
    writeToken(join(dataDir, "operator.token"), "data-dir-token\n");
    writeToken(join(home, ".valhall", "hem", "operator.token"), "home-token\n");
    const result = discoverToken({ env: { HEM_DATA_DIR: dataDir }, home });
    expect(result.token).toBe("data-dir-token");
    expect(result.source).toBe(join(dataDir, "operator.token"));
  });

  it("prefers ~/.valhall/hem over ~/.valhall/system-daemons", () => {
    writeToken(join(home, ".valhall", "hem", "operator.token"), "hem-home\n");
    writeToken(join(home, ".valhall", "system-daemons", "data", "hem", "operator.token"), "sysd-home\n");
    expect(discoverToken({ env: {}, home }).token).toBe("hem-home");
  });

  it("falls through to the launchd install path (current live setup)", () => {
    writeToken(join(home, ".valhall", "system-daemons", "data", "hem", "operator.token"), "sysd-home\n");
    const result = discoverToken({ env: {}, home });
    expect(result.token).toBe("sysd-home");
    expect(result.source).toContain("system-daemons");
  });

  it("skips empty and whitespace-only token files", () => {
    writeToken(join(home, ".valhall", "hem", "operator.token"), "  \n");
    writeToken(join(home, ".valhall", "system-daemons", "data", "hem", "operator.token"), "real-token\n");
    expect(discoverToken({ env: {}, home }).token).toBe("real-token");
  });

  it("returns null with the searched paths when nothing is found", () => {
    const result = discoverToken({ env: {}, home });
    expect(result.token).toBeNull();
    expect(result.source).toBeNull();
    expect(result.searchedPaths).toHaveLength(2);
  });
});
