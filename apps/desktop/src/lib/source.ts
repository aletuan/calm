import type { Perspective } from "./flowLabels";
import type { GraphSnapshot, ImportView, LiveView, RecordedView, SourceRef } from "./ipc";

export type Source = "live" | "imported" | "saved";

export interface Resolved {
  kind: "live" | "imported" | "saved_live" | "saved_import";
  graph: GraphSnapshot | null;
  /** Import-shaped data (an imported file, live or saved). */
  importView: ImportView | null;
  /** A saved snapshot of this Mac. */
  savedLive: LiveView | null;
  /** Only live data refreshes and offers the traffic toggle. */
  isLive: boolean;
  /** Whose point of view directions are told from. */
  perspective: Perspective;
}

/**
 * Which data Traffic and Topology show. Sources are never mixed; a requested
 * source that has no data falls back to live.
 */
export function resolveSource(
  source: Source,
  liveGraph: GraphSnapshot | null,
  imported: ImportView | null,
  saved: RecordedView | null,
): Resolved {
  if (source === "imported" && imported) {
    return { kind: "imported", graph: imported.graph, importView: imported, savedLive: null, isLive: false, perspective: "host" };
  }
  if (source === "saved" && saved?.import) {
    return { kind: "saved_import", graph: saved.import.graph, importView: saved.import, savedLive: null, isLive: false, perspective: "host" };
  }
  if (source === "saved" && saved?.live) {
    return { kind: "saved_live", graph: saved.live.graph, importView: null, savedLive: saved.live, isLive: false, perspective: "mac" };
  }
  return { kind: "live", graph: liveGraph, importView: null, savedLive: null, isLive: true, perspective: "mac" };
}

/** The backend reference for what is on screen. */
export function toSourceRef(r: Resolved, saved: RecordedView | null): SourceRef {
  if ((r.kind === "saved_live" || r.kind === "saved_import") && saved) return { kind: "saved", snapshot_id: saved.snapshot.id };
  if (r.kind === "imported") return { kind: "imported" };
  return { kind: "live" };
}

/** Whether two references name the same data (a saved snapshot by its id). */
export function sameSource(a: SourceRef, b: SourceRef): boolean {
  if (a.kind !== b.kind) return false;
  return a.kind !== "saved" || (b.kind === "saved" && a.snapshot_id === b.snapshot_id);
}
