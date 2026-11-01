import type { Flow, FlowFilter, FlowSelection, GraphSnapshot, GraphView, ImportView, LiveView, SourceRef, TimeWindow } from "./ipc";
import { previewData } from "./ipc";
import { selectFlows } from "./nodeFlows";
import { flowOnly } from "./topologyModel";

/**
 * Browser preview only: the app rebuilds graphs in Rust; here the demo graph
 * is kept and traffic-only nodes without a flow in the window are dropped.
 */
function data(source: SourceRef): { graph: GraphSnapshot; flows: Flow[] } | null {
  if (source.kind === "imported") {
    const v = previewData.imported();
    return v ? { graph: v.graph, flows: v.snapshot.flows } : null;
  }
  if (source.kind === "saved") {
    const s = previewData.saved(source.snapshot_id);
    if (!s) return null;
    if (s.summary.kind === "import") {
      const v = s.payload as ImportView;
      return { graph: v.graph, flows: v.snapshot.flows };
    }
    const v = s.payload as LiveView;
    return { graph: v.graph, flows: v.capture?.snapshot.flows ?? [] };
  }
  return { graph: previewData.overview().graph, flows: previewData.capture()?.snapshot.flows ?? [] };
}

export function previewGraphView(source: SourceRef, window: TimeWindow | null): GraphView {
  const d = data(source) ?? { graph: { nodes: [], edges: [] }, flows: [] };
  const inWindow = window ? d.flows.filter((f) => f.first_seen_ms < window.to_ms && f.last_seen_ms >= window.from_ms) : d.flows;
  const remotes = new Set(inWindow.map((f) => f.key.remote));
  const keep = (id: string) => {
    const n = d.graph.nodes.find((x) => x.id === id);
    if (!n || !flowOnly(n) || !window) return true;
    if (n.id === "external") return inWindow.some((f) => !d.graph.nodes.some((m) => m.observed_identifiers.some((i) => i.value === f.key.remote)));
    return n.observed_identifiers.some((i) => remotes.has(i.value));
  };
  const nodes = d.graph.nodes.filter((n) => keep(n.id));
  const ids = new Set(nodes.map((n) => n.id));
  const first = d.flows.length ? Math.min(...d.flows.map((f) => f.first_seen_ms)) : null;
  const last = d.flows.length ? Math.max(...d.flows.map((f) => f.last_seen_ms)) : null;
  return {
    graph: { nodes, edges: d.graph.edges.filter((e) => ids.has(e.source) && ids.has(e.target)) },
    span: first != null && last != null ? [first, last] : null,
    flows_in_window: inWindow.length,
    flows_total: d.flows.length,
  };
}

export function previewFlows(source: SourceRef, filter: FlowFilter, window: TimeWindow | null): FlowSelection {
  const d = data(source);
  return selectFlows(d?.flows ?? [], filter, window, 200);
}
