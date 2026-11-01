import { isGroup } from "./format";
import { primaryIdentifier } from "./topologyModel";
import type { Flow, FlowFilter, FlowSelection, GraphSnapshot, SourceRef, TimeWindow } from "./ipc";

const IP_KINDS = new Set(["ip", "ipv4", "ipv6"]);
const CENTRE = new Set(["this_mac", "capture_host"]);

function addresses(g: GraphSnapshot, nodeId: string): string[] {
  const n = g.nodes.find((x) => x.id === nodeId);
  return n ? n.observed_identifiers.filter((i) => IP_KINDS.has(i.kind)).map((i) => i.value) : [];
}

/**
 * Which flows belong to a node: the same rule the graph engine used to draw it
 * (a node owns its address identifiers; the external node owns what no node
 * claims). Mirrors `calm_flow_engine::select::FlowFilter`.
 */
export function filterForNode(g: GraphSnapshot, nodeId: string): FlowFilter | null {
  const n = g.nodes.find((x) => x.id === nodeId);
  if (!n) return null;
  if (CENTRE.has(n.role_hypothesis ?? "")) return { kind: "all" };
  if (n.role_hypothesis === "external_destinations") {
    const known = g.nodes.filter((x) => x.id !== nodeId).flatMap((x) => addresses(g, x.id));
    return { kind: "external_except", known: [...new Set(known)] };
  }
  return { kind: "remotes", addresses: addresses(g, nodeId) };
}

/** The node that represents a remote address, for "show in Topology". */
export function nodeForAddress(g: GraphSnapshot, ip: string): string | null {
  if (isGroup(ip)) return null;
  const owner = g.nodes.find((n) => n.observed_identifiers.some((i) => IP_KINDS.has(i.kind) && i.value === ip));
  if (owner) return owner.id;
  return g.nodes.some((n) => n.id === "external") ? "external" : null;
}

const overlaps = (w: TimeWindow, f: Flow) => f.first_seen_ms < w.to_ms && f.last_seen_ms >= w.from_ms;

/** Browser-preview mirror of `calm_flow_engine::select::select`. */
export function selectFlows(flows: Flow[], filter: FlowFilter, window: TimeWindow | null, limit: number): FlowSelection {
  const remotes = filter.kind === "remotes" ? new Set(filter.addresses) : null;
  const known = filter.kind === "external_except" ? new Set(filter.known) : null;
  const out = flows
    .filter((f) => !window || overlaps(window, f))
    .filter((f) => !remotes || remotes.has(f.key.remote))
    .filter((f) => !known || (!known.has(f.key.remote) && !isGroup(f.key.remote) && f.key.remote !== "0.0.0.0" && f.key.remote !== "::"))
    .sort((a, b) => b.bytes_in + b.bytes_out - (a.bytes_in + a.bytes_out) || b.last_seen_ms - a.last_seen_ms);
  return {
    flows: out.slice(0, limit),
    total: out.length,
    bytes: out.reduce((s, f) => s + f.bytes_in + f.bytes_out, 0),
    packets: out.reduce((s, f) => s + f.packets_in + f.packets_out, 0),
  };
}

/** "Open Traffic" from a node: which flows, and which data they were taken from. */
export interface TrafficFilter {
  nodeId: string;
  source: SourceRef;
  role: string | null;
  title: string;
  filter: FlowFilter;
}

/**
 * Filter for a node, or null when there is nothing to narrow: the centre
 * (all flows) or a node without IP addresses (no flows can be attributed).
 */
export function trafficFilterFor(g: GraphSnapshot, nodeId: string, source: SourceRef): TrafficFilter | null {
  const n = g.nodes.find((x) => x.id === nodeId);
  const filter = filterForNode(g, nodeId);
  if (!n || !filter || filter.kind === "all") return null;
  if (filter.kind === "remotes" && filter.addresses.length === 0) return null;
  return { nodeId, source, role: n.role_hypothesis, title: primaryIdentifier(n), filter };
}
