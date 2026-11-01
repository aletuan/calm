import { describe, expect, it } from "vitest";
import type { Asset, GraphSnapshot, ObservedIdentifier, TopologyEdge } from "./ipc";
import { edgeId, flowOnly, isCenter, mergeFlowEdges, primaryIdentifier, radialPositions, roleKey, toElements } from "./topologyModel";

const id = (kind: string, value: string): ObservedIdentifier => ({ kind, value, source: "observed_by_mac", seen_at: "" });
const node = (nid: string, role: string, ids: ObservedIdentifier[], ev: string[], status: Asset["epistemic_status"] = "observed"): Asset => ({
  id: nid,
  observed_identifiers: ids,
  role_hypothesis: role,
  epistemic_status: status,
  confidence: "high",
  evidence_refs: ev,
});
const edge = (source: string, target: string, rel: TopologyEdge["relation_type"] = "FLOW_OBSERVED", status: TopologyEdge["epistemic_status"] = "observed"): TopologyEdge => ({
  source,
  target,
  relation_type: rel,
  epistemic_status: status,
  confidence: "high",
  evidence_ids: [rel === "FLOW_OBSERVED" ? "capture:flows" : "profile:route"],
});

const mac = node("this-mac", "this_mac", [id("ipv4", "192.0.2.108")], ["profile:ifconfig"]);
const gw = node("ip:192.0.2.1", "default_gateway", [id("ipv4", "192.0.2.1")], ["profile:route", "capture:flows"]);
const ap = node("ap:unidentified", "access_point_radio", [], ["profile:corewlan"], "unverified");
const peer = node("ip:192.0.2.100", "local_peer", [id("ipv4", "192.0.2.100"), id("ipv6", "fe80::a"), id("mac_address_private", "02:00:00:00:01:00")], ["capture:flows", "capture:link-binding"]);
const v6peer = node("ip:fe80::d", "local_peer", [id("ip", "fe80::d")], ["capture:flows"]);
const ext = node("external", "external_destinations", [id("distinct_destinations", "61")], ["capture:flows"]);

const g: GraphSnapshot = {
  nodes: [mac, gw, ap, peer, v6peer, ext],
  edges: [
    edge("this-mac", "ip:192.0.2.1", "DEFAULT_ROUTE_VIA"),
    edge("this-mac", "ap:unidentified", "ASSOCIATED_WITH", "observed"),
    edge("this-mac", "ip:192.0.2.1"),
    edge("ip:192.0.2.1", "this-mac"),
    edge("this-mac", "ip:192.0.2.100"),
    edge("ip:192.0.2.100", "this-mac"),
    edge("ip:fe80::d", "this-mac"),
    edge("this-mac", "external"),
  ],
};

const t = (k: string) => k;

describe("labels", () => {
  it("roles map to message keys, unknown roles to a neutral one", () => {
    expect(roleKey("capture_host")).toBe("role.capture_host");
    expect(roleKey("something_new")).toBe("role.unknown");
    expect(roleKey(null)).toBe("role.unknown");
  });
  it("primary identifier per role", () => {
    expect(primaryIdentifier(mac)).toBe("192.0.2.108");
    expect(primaryIdentifier(ap)).toBe("?");
    expect(primaryIdentifier(node("b", "access_point_radio", [id("bssid", "02:aa")], []))).toBe("02:aa");
    expect(primaryIdentifier(ext)).toBe("61 IP");
    expect(primaryIdentifier(v6peer)).toBe("fe80::d");
  });
  it("a merged dual-stack peer shows its IPv4 and how many more addresses", () => {
    expect(primaryIdentifier(peer)).toBe("192.0.2.100 +1");
  });
  it("falls back to the id when a peer has no address", () => {
    expect(primaryIdentifier(node("ip:x", "local_peer", [], []))).toBe("ip:x");
  });
  it("edge ids are stable and distinguish relation types", () => {
    expect(edgeId(g.edges[0]!)).toBe("this-mac|DEFAULT_ROUTE_VIA|ip:192.0.2.1");
    expect(edgeId(g.edges[0]!)).not.toBe(edgeId(g.edges[2]!));
  });
});

describe("flowOnly / isCenter", () => {
  it("traffic-only means every evidence item comes from flows or link bindings", () => {
    expect(flowOnly(peer)).toBe(true);
    expect(flowOnly(gw)).toBe(false); // the gateway is also configuration
    expect(flowOnly(node("n", "local_peer", [], []))).toBe(false);
    expect(flowOnly(node("n", "default_gateway", [], ["import:forwarding", "import:flows"]))).toBe(false);
  });
  it("this Mac and an imported capture host are centres", () => {
    expect(isCenter(mac)).toBe(true);
    expect(isCenter(node("capture-host", "capture_host", [], []))).toBe(true);
    expect(isCenter(gw)).toBe(false);
  });
});

describe("mergeFlowEdges", () => {
  it("one edge per pair, bidirectional when both directions were seen", () => {
    const m = mergeFlowEdges(g.edges);
    const flows = m.filter((x) => x.e.relation_type === "FLOW_OBSERVED");
    expect(flows).toHaveLength(4);
    const bidir = (a: string) => flows.find((x) => x.e.source === a || x.e.target === a)!.bidir;
    expect(bidir("ip:192.0.2.1")).toBe(true);
    expect(bidir("ip:192.0.2.100")).toBe(true);
    expect(bidir("ip:fe80::d")).toBe(false);
    expect(bidir("external")).toBe(false);
  });
  it("configuration edges are never merged with flows", () => {
    const m = mergeFlowEdges(g.edges);
    expect(m.filter((x) => x.e.relation_type === "DEFAULT_ROUTE_VIA")).toHaveLength(1);
  });
  it("a repeated edge in the same direction is not bidirectional", () => {
    const m = mergeFlowEdges([edge("a", "b"), edge("a", "b")]);
    expect(m).toHaveLength(1);
    expect(m[0]!.bidir).toBe(false);
  });
});

describe("radialPositions", () => {
  it("puts the centre at the origin and nobody else there", () => {
    const p = radialPositions(g, false, true);
    expect(p["this-mac"]).toEqual({ x: 0, y: 0 });
    for (const [k, v] of Object.entries(p)) if (k !== "this-mac") expect(Math.hypot(v.x, v.y)).toBeGreaterThan(100);
  });
  it("configuration on the left, traffic-only on the right", () => {
    const p = radialPositions(g, false, true);
    expect(p["ip:192.0.2.1"]!.x).toBeLessThan(0);
    expect(p["ap:unidentified"]!.x).toBeLessThan(0);
    expect(p["ip:192.0.2.100"]!.x).toBeGreaterThan(0);
    expect(p["external"]!.x).toBeGreaterThan(0);
  });
  it("no two nodes share an angle, so no edge from the centre crosses a node", () => {
    const p = radialPositions(g, false, true);
    const angles = Object.entries(p)
      .filter(([k]) => k !== "this-mac")
      .map(([, v]) => Math.round((Math.atan2(v.y, v.x) * 180) / Math.PI));
    expect(new Set(angles).size).toBe(angles.length);
  });
  it("without traffic only configuration nodes are placed", () => {
    const p = radialPositions(g, false, false);
    expect(p["ip:192.0.2.100"]).toBeUndefined();
    expect(Object.keys(p).sort()).toEqual(["ap:unidentified", "ip:192.0.2.1", "this-mac"]);
  });
  it("observed-only drops unverified nodes", () => {
    expect(radialPositions(g, true, true)["ap:unidentified"]).toBeUndefined();
  });
});

describe("toElements", () => {
  const ids = (els: ReturnType<typeof toElements>) => els.map((e) => e.data.id);
  it("hides traffic nodes and flow edges when traffic is off", () => {
    const els = toElements(g, t as never, false, false);
    expect(ids(els)).not.toContain("ip:192.0.2.100");
    expect(els.some((e) => e.data.relation === "FLOW_OBSERVED")).toBe(false);
  });
  it("never shows an edge to a hidden node", () => {
    const els = toElements(g, t as never, true, true);
    const nodes = new Set(els.filter((e) => !e.data.source).map((e) => e.data.id));
    for (const e of els.filter((x) => x.data.source)) {
      expect(nodes.has(e.data.source)).toBe(true);
      expect(nodes.has(e.data.target)).toBe(true);
    }
    expect(nodes.has("ap:unidentified")).toBe(false);
  });
  it("keeps the centre even when filtering by status", () => {
    const inferredMac = { ...g, nodes: g.nodes.map((n) => (n.id === "this-mac" ? { ...n, epistemic_status: "inferred" as const } : n)) };
    expect(ids(toElements(inferredMac, t as never, true, false))).toContain("this-mac");
  });
  it("labels carry role and identifier on two lines", () => {
    const el = toElements(g, t as never, false, true).find((e) => e.data.id === "ip:192.0.2.100")!;
    expect(el.data.label).toBe("role.local_peer\n192.0.2.100 +1");
    expect(el.data.flowOnly).toBe(true);
  });
});
