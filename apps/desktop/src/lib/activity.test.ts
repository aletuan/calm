import { describe, expect, it } from "vitest";
import type { Asset, Flow, GraphSnapshot } from "./ipc";
import { ACTIVE_MS, addressDeltas, dotCount, edgeMotions, isActive, NEW_MARK_MS, newNodes, stepActivity, stepFirstSeen, WARMUP_MS, type Activity } from "./activity";

const flow = (remote: string, bytesOut: number, bytesIn: number, port = 443): Flow => ({
  key: { transport: "tcp", local: "192.0.2.108", local_port: 50000, remote, remote_port: port },
  direction: "outbound",
  origin: "local_interface",
  initiated_by: "local",
  packets_out: 1,
  packets_in: 1,
  bytes_out: bytesOut,
  bytes_in: bytesIn,
  first_seen_ms: 0,
  last_seen_ms: 0,
});
const node = (id: string, role: string, ip: string): Asset => ({
  id,
  observed_identifiers: ip ? [{ kind: "ipv4", value: ip, source: "observed_by_mac", seen_at: "" }] : [],
  role_hypothesis: role,
  epistemic_status: "observed",
  confidence: "high",
  evidence_refs: ["capture:flows"],
});
const g: GraphSnapshot = {
  nodes: [node("this-mac", "this_mac", "192.0.2.108"), node("ip:192.0.2.1", "default_gateway", "192.0.2.1"), node("ip:192.0.2.50", "local_peer", "192.0.2.50"), node("external", "external_destinations", "")],
  edges: [],
};

describe("live activity", () => {
  it("counts only bytes that moved since the previous poll, per address and direction", () => {
    expect(addressDeltas(null, [flow("203.0.113.9", 500, 900)]).size).toBe(0);
    const d = addressDeltas([flow("203.0.113.9", 500, 900), flow("192.0.2.50", 10, 0, 5353)], [flow("203.0.113.9", 700, 900), flow("192.0.2.50", 10, 0, 5353), flow("203.0.113.9", 0, 40, 80)]);
    expect(d.get("203.0.113.9")).toEqual({ out: 200, in: 40 });
    expect(d.has("192.0.2.50")).toBe(false);
  });

  it("keeps a direction active for a few seconds after its last bytes", () => {
    let a: Activity = new Map();
    a = stepActivity(a, new Map([["192.0.2.1", { out: 2000, in: 0 }]]), 1000, 1000);
    expect(a.get("192.0.2.1")?.out).toEqual({ at: 1000, rate: 2000 });
    expect(a.get("192.0.2.1")?.in).toBeNull();
    expect(isActive(a.get("192.0.2.1")!.out, 1000 + ACTIVE_MS - 1)).toBe(true);
    expect(isActive(a.get("192.0.2.1")!.out, 1000 + ACTIVE_MS)).toBe(false);
    // A later poll in the other direction keeps the first.
    a = stepActivity(a, new Map([["192.0.2.1", { out: 0, in: 50 }]]), 2000, 1000);
    expect(a.get("192.0.2.1")?.out?.at).toBe(1000);
    expect(a.get("192.0.2.1")?.in).toEqual({ at: 2000, rate: 50 });
  });

  it("shows volume as 1 to 3 dots", () => {
    expect([dotCount(10), dotCount(9_999), dotCount(10_000), dotCount(99_999), dotCount(100_000), dotCount(5e7)]).toEqual([1, 1, 2, 2, 3, 3]);
  });

  it("maps addresses to graph nodes; internet addresses go to the external node; quiet edges do not move", () => {
    const now = 10_000;
    const a: Activity = new Map([
      ["192.0.2.1", { out: { at: now - 100, rate: 500 }, in: { at: now - 100, rate: 200_000 } }],
      ["203.0.113.9", { out: { at: now - 100, rate: 20_000 }, in: null }],
      ["203.0.113.10", { out: { at: now - 100, rate: 90_000 }, in: null }],
      ["192.0.2.50", { out: null, in: { at: now - ACTIVE_MS - 1, rate: 50 } }],
    ]);
    const m = edgeMotions(g, a, now);
    expect(m).toContainEqual({ nodeId: "ip:192.0.2.1", out: 1, in: 3 });
    expect(m).toContainEqual({ nodeId: "external", out: 3, in: 0 });
    expect(m.find((x) => x.nodeId === "ip:192.0.2.50")).toBeUndefined();
  });

  it("marks a local device new only after the warm-up, for a minute, until it is looked at", () => {
    const start = 0;
    let first = stepFirstSeen(new Map(), [flow("192.0.2.1", 1, 1)], 2000);
    first = stepFirstSeen(first, [flow("192.0.2.1", 1, 1), flow("192.0.2.50", 1, 0), flow("203.0.113.9", 1, 1)], WARMUP_MS + 5000);
    expect(first.get("192.0.2.1")).toBe(2000);
    const now = WARMUP_MS + 6000;
    expect(newNodes(g, first, start, new Set(), now)).toEqual(["ip:192.0.2.50"]);
    expect(newNodes(g, first, start, new Set(["ip:192.0.2.50"]), now)).toEqual([]);
    expect(newNodes(g, first, start, new Set(), WARMUP_MS + 5000 + NEW_MARK_MS)).toEqual([]);
    const same = stepFirstSeen(first, [flow("192.0.2.50", 9, 9)], now);
    expect(same).toBe(first);
  });
});
