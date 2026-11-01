import { describe, expect, it } from "vitest";
import type { Asset, Flow, GraphSnapshot, ObservedIdentifier } from "./ipc";
import { filterForNode, nodeForAddress, selectFlows, trafficFilterFor } from "./nodeFlows";

const id = (kind: string, value: string): ObservedIdentifier => ({ kind, value, source: "observed_by_mac", seen_at: "" });
const node = (nid: string, role: string, ids: ObservedIdentifier[]): Asset => ({
  id: nid,
  observed_identifiers: ids,
  role_hypothesis: role,
  epistemic_status: "observed",
  confidence: "high",
  evidence_refs: [],
});
const g: GraphSnapshot = {
  nodes: [
    node("this-mac", "this_mac", [id("ipv4", "192.0.2.108"), id("mac_address", "02:00:00:00:01:08")]),
    node("ip:192.0.2.1", "default_gateway", [id("ipv4", "192.0.2.1"), id("ipv6", "fe80::1")]),
    node("ip:192.0.2.100", "local_peer", [id("ip", "192.0.2.100"), id("ipv6", "fe80::a"), id("mac_address_private", "02:00:00:00:01:00")]),
    node("external", "external_destinations", [id("distinct_destinations", "2")]),
    node("bssid:aa", "access_point_radio", [id("bssid", "aa:bb:cc:dd:ee:ff"), id("ssid", "Guest")]),
  ],
  edges: [],
};

const flow = (remote: string, bytes: number, first = 0, last = 0): Flow => ({
  key: { transport: "tcp", local: "192.0.2.108", local_port: 1, remote, remote_port: 443 },
  direction: "outbound",
  origin: "local_interface",
  initiated_by: "unknown",
  packets_out: 1,
  packets_in: 1,
  bytes_out: bytes,
  bytes_in: 0,
  first_seen_ms: first,
  last_seen_ms: last,
});

describe("filterForNode", () => {
  it("centre → all flows", () => {
    expect(filterForNode(g, "this-mac")).toEqual({ kind: "all" });
  });
  it("a node → all of its IP addresses (merged dual-stack included), never MACs or SSIDs", () => {
    expect(filterForNode(g, "ip:192.0.2.100")).toEqual({ kind: "remotes", addresses: ["192.0.2.100", "fe80::a"] });
  });
  it("external → everything no node claims, centre addresses included in 'known'", () => {
    const f = filterForNode(g, "external");
    expect(f?.kind).toBe("external_except");
    expect(f?.kind === "external_except" && [...f.known].sort()).toEqual(["192.0.2.1", "192.0.2.100", "192.0.2.108", "fe80::1", "fe80::a"]);
  });
  it("a node without addresses (AP radio) has no flows", () => {
    expect(filterForNode(g, "bssid:aa")).toEqual({ kind: "remotes", addresses: [] });
  });
  it("unknown id → null", () => {
    expect(filterForNode(g, "nope")).toBeNull();
  });
});

describe("nodeForAddress", () => {
  it("finds the node that owns an address, including merged IPv6", () => {
    expect(nodeForAddress(g, "192.0.2.1")).toBe("ip:192.0.2.1");
    expect(nodeForAddress(g, "fe80::a")).toBe("ip:192.0.2.100");
  });
  it("other unicast addresses belong to the external node when there is one", () => {
    expect(nodeForAddress(g, "203.0.113.9")).toBe("external");
    expect(nodeForAddress({ ...g, nodes: g.nodes.filter((n) => n.id !== "external") }, "203.0.113.9")).toBeNull();
  });
  it("group addresses are never nodes", () => {
    expect(nodeForAddress(g, "224.0.0.251")).toBeNull();
    expect(nodeForAddress(g, "ff02::fb")).toBeNull();
  });
});

describe("selectFlows (preview mirror of calm_flow_engine::select)", () => {
  const flows = [flow("192.0.2.100", 50, 2_000, 3_000), flow("fe80::a", 70, 20_000, 21_000), flow("203.0.113.10", 900, 5_000, 60_000), flow("224.0.0.251", 10, 0, 100_000)];
  it("filters by node and window, largest first, with totals", () => {
    const s = selectFlows(flows, { kind: "remotes", addresses: ["192.0.2.100", "fe80::a"] }, null, 10);
    expect(s.total).toBe(2);
    expect(s.flows[0]!.key.remote).toBe("fe80::a");
    const w = selectFlows(flows, { kind: "all" }, { from_ms: 4_000, to_ms: 20_000 }, 10);
    expect(w.flows.map((f) => f.key.remote)).toEqual(["203.0.113.10", "224.0.0.251"]);
    const e = selectFlows(flows, { kind: "external_except", known: ["192.0.2.100", "fe80::a"] }, null, 1);
    expect(e.total).toBe(1);
    expect(e.bytes).toBe(900);
  });
});

const live = { kind: "live" } as const;

describe("trafficFilterFor (Open Traffic from a node)", () => {
  it("carries the node, its filter and a readable title", () => {
    expect(trafficFilterFor(g, "ip:192.0.2.100", { kind: "saved", snapshot_id: "s1" })).toEqual({
      nodeId: "ip:192.0.2.100",
      source: { kind: "saved", snapshot_id: "s1" },
      role: "local_peer",
      title: "192.0.2.100 +1",
      filter: { kind: "remotes", addresses: ["192.0.2.100", "fe80::a"] },
    });
  });
  it("no filter for a node without addresses or an unknown node", () => {
    expect(trafficFilterFor(g, "bssid:aa", live)).toBeNull();
    expect(trafficFilterFor(g, "nope", live)).toBeNull();
  });
  it("the centre means all flows: no filter needed", () => {
    expect(trafficFilterFor(g, "this-mac", live)).toBeNull();
  });
});
