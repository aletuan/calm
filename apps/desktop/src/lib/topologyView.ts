/**
 * How the user set up the topology view: overlays and zoom. Kept in the
 * selection context (design §1.7) so leaving Topology for Traffic and coming
 * back shows the same picture instead of resetting.
 */

export interface Viewport {
  zoom: number;
  pan: { x: number; y: number };
}

export interface TopologyView {
  showTraffic: boolean;
  observedOnly: boolean;
  /** Last zoom and pan, tied to the graph and filters it was set on. */
  viewport: (Viewport & { key: string }) | null;
}

/** Overlays are off by default (design §5). */
export const defaultTopologyView = (): TopologyView => ({ showTraffic: false, observedOnly: false, viewport: null });

/** Same source, same graph, same filters: the saved zoom still fits what is drawn. */
export const viewportKey = (source: string, graphSignature: string, v: Pick<TopologyView, "showTraffic" | "observedOnly">) =>
  `${source}#${graphSignature}#${v.showTraffic ? "t" : "-"}${v.observedOnly ? "o" : "-"}`;

export function viewportFor(saved: TopologyView["viewport"], key: string): Viewport | null {
  return saved && saved.key === key ? { zoom: saved.zoom, pan: saved.pan } : null;
}

/** Live activity draws on traffic edges, so switching it on shows them too. */
export const setActivityLink = (v: TopologyView, activityOn: boolean): TopologyView => (activityOn ? { ...v, showTraffic: true } : v);
