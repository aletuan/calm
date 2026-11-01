import { fmtDuration } from "./format";

/** Mirrors `records::live_label` (Rust). */
export function liveLabel(capture: { flows: number; elapsedMs: number } | null): string {
  if (!capture) return "This Mac — network profile";
  return `This Mac — ${capture.flows} flow${capture.flows === 1 ? "" : "s"}, ${fmtDuration(capture.elapsedMs)} capture`;
}

/** Mirrors `records::import_label` (Rust). */
export function importLabel(fileName: string): string {
  return `Imported — ${fileName}`;
}
