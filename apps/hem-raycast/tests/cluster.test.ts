import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { clusterHealthFromOutput, expandTilde, parseKvOutput, peerHealthFromRecord } from "../src/hem/cluster";

const fixture = (name: string) => readFileSync(join(__dirname, "fixtures", name), "utf8");

describe("parseKvOutput", () => {
  it("parses the captured cluster health output", () => {
    const { scalars, records } = parseKvOutput(fixture("cluster-health.txt"));
    expect(scalars.cluster_health_status).toBe("warning");
    expect(scalars.cluster_id).toBe("hmc_democluster000000000000000");
    expect(scalars.node_id).toBe("hmn_main");
    expect(scalars.latest_position).toBe("7882");
    expect(scalars.quorum_risk).toBe("false");
    expect(scalars.checkpoint_status).toBe("quorum_met");
    expect(scalars.latest_checkpoint_cosignatures).toBe("1");
    expect(records).toHaveLength(5);
    expect(records.every((r) => r.type === "peer_health")).toBe(true);
  });

  it("parses the captured cluster status output", () => {
    const { scalars, records } = parseKvOutput(fixture("cluster-status.txt"));
    expect(scalars.node_id).toBe("hmn_main");
    expect(scalars.master_node_id).toBe("hmn_main");
    expect(scalars.peers).toBe("5");
    expect(records).toHaveLength(0);
  });

  it("parses the captured cluster peers output with wrap keys", () => {
    const { scalars, records } = parseKvOutput(fixture("cluster-peers.txt"));
    expect(scalars.peers).toBe("5");
    expect(records).toHaveLength(5);
    const alder01 = records.find((r) => r.fields.node_id === "hmn_alder01");
    expect(alder01?.type).toBe("peer");
    expect(alder01?.fields.wrap_public_key).toMatch(/^[A-Za-z0-9+/=]+$/);
  });

  it("parses the captured collisions output (empty)", () => {
    const { scalars, records } = parseKvOutput(fixture("cluster-collisions.txt"));
    expect(scalars.collisions).toBe("0");
    expect(records).toHaveLength(0);
  });

  it("re-joins record values containing spaces onto the previous key", () => {
    const { records } = parseKvOutput("peer_health node_id=n1 error=connection refused by peer status=offline");
    expect(records[0].fields.error).toBe("connection refused by peer");
    expect(records[0].fields.status).toBe("offline");
  });

  it("keeps spaces in scalar values", () => {
    const { scalars } = parseKvOutput("message=sync failed: peer unreachable");
    expect(scalars.message).toBe("sync failed: peer unreachable");
  });

  it("ignores blank lines and comments", () => {
    const { scalars, records } = parseKvOutput("\n# comment\n  \nfoo=bar\n");
    expect(scalars).toEqual({ foo: "bar" });
    expect(records).toHaveLength(0);
  });
});

describe("peerHealthFromRecord", () => {
  const records = parseKvOutput(fixture("cluster-health.txt")).records;

  it("maps the lagging elm05 peer", () => {
    const elm = peerHealthFromRecord(records.find((r) => r.fields.node_id === "hmn_elm05")!);
    expect(elm.status).toBe("lagging");
    expect(elm.lag).toBeGreaterThan(6000);
    expect(elm.cursorPosition).toBe(1315);
    expect(elm.lastSeen).toMatch(/^2026-06-03T/);
    expect(elm.error).toBeNull();
  });

  it("maps a caught-up peer", () => {
    const alder01 = peerHealthFromRecord(records.find((r) => r.fields.node_id === "hmn_alder01")!);
    expect(alder01.status).toBe("caught_up");
    expect(alder01.lag).toBe(0);
    expect(alder01.endpoint).toMatch(/^http:\/\//);
  });

  it("treats unknown statuses and dashes defensively", () => {
    const peer = peerHealthFromRecord({
      type: "peer_health",
      fields: { node_id: "x", status: "weird", last_seen: "-", error: "-" },
    });
    expect(peer.status).toBe("unknown");
    expect(peer.lastSeen).toBeNull();
    expect(peer.error).toBeNull();
    expect(peer.lag).toBe(0);
  });
});

describe("clusterHealthFromOutput", () => {
  it("uses the reported cluster_health_status", () => {
    const health = clusterHealthFromOutput(fixture("cluster-health.txt"), 1);
    expect(health.status).toBe("warning");
    expect(health.peers).toHaveLength(5);
    expect(health.exitCode).toBe(1);
  });

  it("falls back to exit-code mapping when the status scalar is missing", () => {
    expect(clusterHealthFromOutput("foo=bar", 0).status).toBe("ok");
    expect(clusterHealthFromOutput("foo=bar", 1).status).toBe("warning");
    expect(clusterHealthFromOutput("foo=bar", 2).status).toBe("critical");
    expect(clusterHealthFromOutput("foo=bar", 3).status).toBe("unknown");
  });
});

describe("expandTilde", () => {
  it("expands ~ and ~/", () => {
    expect(expandTilde("~/bin/hem")).not.toContain("~");
    expect(expandTilde("/abs/path")).toBe("/abs/path");
  });
});
