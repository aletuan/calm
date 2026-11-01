import type { ElementDefinition } from "cytoscape";
import type { MessageKey } from "../i18n/en";
import type { Asset, GraphSnapshot, TopologyEdge } from "./ipc";

/**
 * Pure topology model: what the Cytoscape view shows, decided without the DOM
 * so it is unit-tested. Rules mirror the graph engine (ADR-003).
 */

export const edgeId = (e: TopologyEdge) => `${e.source}|${e.relation_type}|${e.target}`;
export const roleKey = (r: string | null) =>
  (["this_mac", "capture_host", "access_point_radio", "default_gateway", "dns_resolver", "local_peer", "external_destinations"].includes(r ?? "")
    ? `role.${r}`
    : "role.unknown") as MessageKey;

export function primaryIdentifier(a: Asset): string {
  const pick = (k: string) => a.observed_identifiers.find((i) => i.kind === k)?.value;
  switch (a.role_hypothesis) {
    case "this_mac":
    case "capture_host":
      return pick("ipv4") ?? pick("ipv6") ?? "";
    case "access_point_radio":
      return pick("ssid") ?? pick("bssid") ?? "?";
    case "external_destinations":
      return `${pick("distinct_destinations") ?? "?"} IP`;
    default: {
      // A dual-stack peer merged on its MAC shows its IPv4 plus a count.
      const ips = a.observed_identifiers.filter((i) => ["ipv4", "ipv6", "ip"].includes(i.kind)).map((i) => i.value);
      const main = pick("ipv4") ?? ips.find((v) => !v.includes(":")) ?? ips[0] ?? a.id;
      return ips.length > 1 ? `${main} +${ips.length - 1}` : main;
    }
  }
}

export const isCenter = (n: Asset) => n.role_hypothesis === "this_mac" || n.role_hypothesis === "capture_host";

export const FLOW_EVIDENCE = new Set(["capture:flows", "capture:link-binding", "import:flows", "import:link-binding"]);
/** Node known only from traffic (not from configuration or an inference). */
export const flowOnly = (n: Asset) => n.evidence_refs.length > 0 && n.evidence_refs.every((e) => FLOW_EVIDENCE.has(e));

/** One FLOW_OBSERVED edge per pair of nodes; `bidir` when traffic was seen both ways. */
export function mergeFlowEdges(edges: TopologyEdge[]): { e: TopologyEdge; bidir: boolean }[] {
  const out: { e: TopologyEdge; bidir: boolean }[] = [];
  const byPair = new Map<string, { e: TopologyEdge; bidir: boolean }>();
  for (const e of edges) {
    if (e.relation_type !== "FLOW_OBSERVED") {
      out.push({ e, bidir: false });
      continue;
    }
    const pair = [e.source, e.target].sort().join("|");
    const seen = byPair.get(pair);
    if (seen) {
      if (seen.e.source !== e.source) seen.bidir = true;
    } else {
      const item = { e, bidir: false };
      byPair.set(pair, item);
      out.push(item);
    }
  }
  return out;
}

/**
 * Deterministic layout: This Mac in the centre; configuration facts on the
 * left half of an ellipse, traffic-only peers on the right half. Every node
 * gets its own angle, so no edge from the centre passes through another node.
 */
export function radialPositions(
  g: GraphSnapshot,
  observedOnly: boolean,
  showTraffic: boolean,
): Record<string, { x: number; y: number }> {
  const keep = (s: string) => !observedOnly || s === "observed" || s === "validated";
  const shown = g.nodes.filter(
    (n) => !isCenter(n) && keep(n.epistemic_status) && (showTraffic || !flowOnly(n)),
  );
  const config = shown.filter((n) => !flowOnly(n));
  const traffic = shown.filter((n) => flowOnly(n));
  const pos: Record<string, { x: number; y: number }> = {};
  const mac = g.nodes.find(isCenter);
  if (mac) pos[mac.id] = { x: 0, y: 0 };
  const total = Math.max(shown.length, 1);
  const ry = 150 + total * 14;
  const rx = ry * 1.7;
  const place = (nodes: Asset[], from: number, to: number) => {
    nodes.forEach((n, i) => {
      const a = nodes.length === 1 ? (from + to) / 2 : from + ((to - from) * i) / (nodes.length - 1);
      const rad = (a * Math.PI) / 180;
      pos[n.id] = { x: Math.cos(rad) * rx, y: Math.sin(rad) * ry };
    });
  };
  if (traffic.length === 0) {
    // Whole ellipse for configuration nodes, starting at the top.
    config.forEach((n, i) => {
      const rad = ((-90 + (360 * i) / config.length) * Math.PI) / 180;
      pos[n.id] = { x: Math.cos(rad) * rx, y: Math.sin(rad) * ry };
    });
  } else {
    place(config, 110, 250); // left half
    place(traffic, -70, 70); // right half
  }
  return pos;
}

export function toElements(
  g: GraphSnapshot,
  t: (k: MessageKey) => string,
  observedOnly: boolean,
  showTraffic: boolean,
): ElementDefinition[] {
  const keep = (s: string) => !observedOnly || s === "observed" || s === "validated";
  const nodes = g.nodes.filter(
    (n) => (keep(n.epistemic_status) || isCenter(n)) && (showTraffic || !flowOnly(n)),
  );
  const ids = new Set(nodes.map((n) => n.id));
  return [
    ...nodes.map((n) => ({
      data: {
        id: n.id,
        role: n.role_hypothesis ?? "unknown",
        flowOnly: flowOnly(n),
        status: n.epistemic_status,
        label: `${t(roleKey(n.role_hypothesis))}\n${primaryIdentifier(n)}`.trim(),
      },
    })),
    ...mergeFlowEdges(
      g.edges.filter(
        (e) =>
          keep(e.epistemic_status) &&
          ids.has(e.source) &&
          ids.has(e.target) &&
          (showTraffic || e.relation_type !== "FLOW_OBSERVED"),
      ),
    ).map(({ e, bidir }) => ({
      data: {
        id: edgeId(e),
        source: e.source,
        target: e.target,
        status: e.epistemic_status,
        relation: e.relation_type,
        bidir,
      },
    })),
  ];
}

