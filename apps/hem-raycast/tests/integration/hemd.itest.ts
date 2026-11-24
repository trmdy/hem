// End-to-end test of src/hem/client.ts against an ISOLATED hemd on
// 127.0.0.1:59091 with a disposable data dir (safety rules —
// never against the production daemon on 50091).
import { ChildProcess, spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { HemClient } from "../../src/hem/client";
import { HemError } from "../../src/hem/errors";
import { refToProto } from "../../src/hem/refs";

const HEMD_BIN = join(homedir(), ".valhall", "system-daemons", "bin", "hemd");
const BIND = "127.0.0.1:59091";
const ENDPOINT = `http://${BIND}`;
const PROTO_PATH = join(__dirname, "..", "..", "assets", "hem.proto");

let daemon: ChildProcess | undefined;
let daemonLog = "";
let dataDir: string;
let anonClient: HemClient;
let operator: HemClient;

async function waitForHealth(client: HemClient, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  let lastError: unknown;
  while (Date.now() < deadline) {
    try {
      await client.health();
      return;
    } catch (e) {
      lastError = e;
      await new Promise((r) => setTimeout(r, 250));
    }
  }
  throw new Error(`isolated hemd never became healthy: ${lastError}\ndaemon output:\n${daemonLog}`);
}

beforeAll(async () => {
  dataDir = mkdtempSync(join(tmpdir(), "hemd-itest-"));
  const env = { ...process.env };
  // Make sure the isolated daemon and client cannot see production config.
  delete env.HEM_DATA_DIR;
  delete env.VALHALL_HEM_TOKEN;
  delete env.VALHALL_HEMD_ENDPOINT;
  delete env.VALHALL_HEM_ADDR;
  delete env.VALHALL_SYSTEM_DAEMONS_DIR;

  daemon = spawn(HEMD_BIN, ["--bind", BIND, "--data-dir", dataDir], { env, stdio: ["ignore", "pipe", "pipe"] });
  daemon.stdout?.on("data", (d) => (daemonLog += d.toString()));
  daemon.stderr?.on("data", (d) => (daemonLog += d.toString()));

  anonClient = new HemClient({ endpoint: ENDPOINT, protoPath: PROTO_PATH });
  await waitForHealth(anonClient, 20_000);

  const init = await anonClient.initHem();
  expect(init.initialized).toBe(true);
  expect(init.operator_token.length).toBeGreaterThan(32);
  operator = new HemClient({ endpoint: ENDPOINT, token: init.operator_token, protoPath: PROTO_PATH });
});

afterAll(async () => {
  anonClient?.close();
  operator?.close();
  if (daemon && !daemon.killed) {
    const exited = new Promise((resolve) => daemon?.once("exit", resolve));
    daemon.kill("SIGTERM");
    await Promise.race([exited, new Promise((r) => setTimeout(r, 3000))]);
    if (daemon.exitCode === null) daemon.kill("SIGKILL");
  }
  if (dataDir) rmSync(dataDir, { recursive: true, force: true });
});

const globalRef = refToProto({ scope: "global", name: "itest-secret" });
const projectRef = refToProto({ scope: "project", project: "itest-proj", name: "proj-secret" });
const identityRef = refToProto({ scope: "identity", identityId: "itest-id", name: "id-secret" });
const gatedRef = refToProto({ scope: "global", name: "itest-gated" });

describe("hem client against isolated hemd", () => {
  it("reports health without auth", async () => {
    const health = await anonClient.health();
    expect(health.status).toContain("ok");
    expect(health.version).toBeTruthy();
  });

  it("rejects authed calls without a token, locally, with kind=unauthenticated", async () => {
    await expect(anonClient.listSecrets({})).rejects.toMatchObject({ kind: "unauthenticated" });
  });

  it("rejects garbage tokens with kind=unauthenticated from the server", async () => {
    const bad = new HemClient({ endpoint: ENDPOINT, token: "hem_garbage", protoPath: PROTO_PATH });
    try {
      await expect(bad.listSecrets({})).rejects.toMatchObject({ kind: "unauthenticated" });
    } finally {
      bad.close();
    }
  });

  it("sets secrets in all three scopes", async () => {
    const info = await operator.setSecret({
      secret: globalRef,
      values: [
        { key: "api_key", value: "itest-value-1" },
        { key: "other", value: "itest-value-2" },
      ],
      description: "integration test secret",
      actor: "itest",
    });
    expect(info.name).toBe("itest-secret");
    expect(info.scope.scope).toBe("SECRET_SCOPE_GLOBAL");

    await operator.setSecret({ secret: projectRef, values: [{ key: "k", value: "pv" }], actor: "itest" });
    await operator.setSecret({ secret: identityRef, values: [{ key: "k", value: "iv" }], actor: "itest" });
  });

  it("lists all scopes with an unspecified scope selector (search-secrets assumption)", async () => {
    const secrets = await operator.listSecrets({});
    const names = secrets.map((s) => s.name);
    expect(names).toContain("itest-secret");
    expect(names).toContain("proj-secret");
    expect(names).toContain("id-secret");
    const proj = secrets.find((s) => s.name === "proj-secret");
    expect(proj?.scope.scope).toBe("SECRET_SCOPE_PROJECT");
    expect(proj?.scope.project).toBe("itest-proj");
  });

  it("gets the full value map and single keys", async () => {
    const full = await operator.getSecret({ secret: globalRef });
    expect(full.secret?.values).toEqual({ api_key: "itest-value-1", other: "itest-value-2" });
    expect(full.secret?.info.description).toBe("integration test secret");

    const single = await operator.getSecret({ secret: globalRef }, { key: "api_key" });
    expect(single.secret?.values).toEqual({ api_key: "itest-value-1" });
  });

  it("SetSecret replaces the whole value map (secret=map semantics)", async () => {
    await operator.setSecret({ secret: projectRef, values: [{ key: "k2", value: "replaced" }], actor: "itest" });
    const after = await operator.getSecret({ secret: projectRef });
    expect(after.secret?.values).toEqual({ k2: "replaced" });
  });

  it("returns metadata without values via GetSecretInfo", async () => {
    const info = await operator.getSecretInfo({ secret: globalRef });
    expect(info.name).toBe("itest-secret");
    expect(info.created_at).toBeTruthy();
  });

  it("manages groups", async () => {
    await operator.setGroup("itest-group", "integration test group");
    await operator.addToGroup(globalRef, "itest-group");
    const groups = await operator.listGroups();
    expect(groups.map((g) => g.name)).toContain("itest-group");
    const members = await operator.listGroupSecrets("itest-group");
    expect(members.map((s) => s.name)).toContain("itest-secret");
  });

  it("scans text for known secret values", async () => {
    const dirty = await operator.scanForSecrets("here is itest-value-1 leaked in a paste");
    expect(dirty.clean).toBe(false);
    expect(dirty.matches.some((m) => m.secret_ref.includes("itest-secret") && m.key === "api_key")).toBe(true);

    const clean = await operator.scanForSecrets("nothing sensitive here");
    expect(clean.clean).toBe(true);
  });

  it("gates non-operator reads of requires_approval secrets, then honors the receipt", async () => {
    await operator.setSecret({
      secret: gatedRef,
      values: [{ key: "api_key", value: "gated-value" }],
      requires_approval: true,
      actor: "itest",
    });

    // Operator bypasses the gate.
    const asOperator = await operator.getSecret({ secret: gatedRef });
    expect(asOperator.secret?.values.api_key).toBe("gated-value");

    // A service token does not.
    const issued = await operator.issueServiceToken("itest-service", 3600, "itest");
    const service = new HemClient({ endpoint: ENDPOINT, token: issued.token, protoPath: PROTO_PATH });
    try {
      const gated = await service.getSecret({ secret: gatedRef }, { reason: "integration test read", asyncRead: true });
      expect(gated.pending).toBeTruthy();
      const requestId = gated.pending!.request_id;

      const pendingList = await operator.listPendingApprovals();
      const request = pendingList.find((r) => r.request_id === requestId);
      expect(request).toBeTruthy();
      expect(request!.action).toMatch(/get/);

      const approved = await operator.approveAccess(requestId, { actor: "itest", message: "ok" });
      expect(approved.approval_receipt).toBeTruthy();

      // Receipt retry of the original call.
      const retried = await service.getSecret({ secret: gatedRef }, { approvalReceipt: approved.approval_receipt });
      expect(retried.secret?.values.api_key).toBe("gated-value");
    } finally {
      service.close();
    }
  });

  it("denies an approval request", async () => {
    const issued = await operator.issueServiceToken("itest-service-2", 3600, "itest");
    const service = new HemClient({ endpoint: ENDPOINT, token: issued.token, protoPath: PROTO_PATH });
    try {
      const gated = await service.getSecret({ secret: gatedRef }, { reason: "to be denied", asyncRead: true });
      expect(gated.pending).toBeTruthy();
      const denied = await operator.denyAccess(gated.pending!.request_id, { actor: "itest" });
      expect(denied.request.state).toBe("APPROVAL_STATE_DENIED");
      const status = await operator.getApprovalStatus(gated.pending!.request_id);
      expect(status.request.state).toBe("APPROVAL_STATE_DENIED");
    } finally {
      service.close();
    }
  });

  it("runs the delete → approval_required → approve → receipt-retry flow", async () => {
    const del = await operator.deleteSecret(globalRef, { actor: "itest", reason: "integration cleanup" });
    expect(del.deleted).toBe(false);
    expect(del.approval_request_id).toBeTruthy();
    expect(del.approval_state).toBe("APPROVAL_STATE_PENDING");

    const pending = await operator.listPendingApprovals();
    const request = pending.find((r) => r.request_id === del.approval_request_id);
    expect(request?.action).toMatch(/delete/);

    const approved = await operator.approveAccess(del.approval_request_id, { actor: "itest", message: "confirmed" });
    expect(approved.approval_receipt).toBeTruthy();

    const retried = await operator.deleteSecret(globalRef, {
      actor: "itest",
      approvalReceipt: approved.approval_receipt,
    });
    expect(retried.deleted).toBe(true);

    await expect(operator.getSecretInfo({ secret: globalRef })).rejects.toMatchObject({ kind: "not-found" });
  });

  it("records the activity in the audit log, newest first by ts sort", async () => {
    const entries = await operator.getAuditLog({ limit: 200 });
    expect(entries.length).toBeGreaterThan(0);
    const actions = new Set(entries.map((e) => e.action));
    expect([...actions].some((a) => a.includes("set") || a.includes("write"))).toBe(true);
    expect([...actions].some((a) => a.includes("delete"))).toBe(true);
  });

  it("maps NOT_FOUND reads to kind=not-found", async () => {
    await expect(
      operator.getSecret({ secret: refToProto({ scope: "global", name: "does-not-exist" }) }),
    ).rejects.toMatchObject({ kind: "not-found" });
  });

  it("exposes typed HemError instances", async () => {
    try {
      await operator.getSecretInfo({ secret: refToProto({ scope: "global", name: "does-not-exist" }) });
      expect.unreachable();
    } catch (e) {
      expect(e).toBeInstanceOf(HemError);
      expect((e as HemError).kind).toBe("not-found");
      expect((e as HemError).method).toBe("GetSecretInfo");
    }
  });
});
