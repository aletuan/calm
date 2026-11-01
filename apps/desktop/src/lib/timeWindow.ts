import type { TimeWindow } from "./ipc";

export type PresetKey = "all" | "last1" | "last5" | "last15";

/** Quick choices; "last N min" only when the data spans longer than N. */
export function presets(span: [number, number]): { key: PresetKey; window: TimeWindow | null }[] {
  const [from, to] = span;
  const out: { key: PresetKey; window: TimeWindow | null }[] = [{ key: "all", window: null }];
  for (const [key, min] of [["last1", 1], ["last5", 5], ["last15", 15]] as const) {
    if (to - from > min * 60_000) out.push({ key, window: { from_ms: to - min * 60_000, to_ms: to + 1 } });
  }
  return out;
}

const MIN_WIDTH_MS = 1000;

/** Two slider positions (0..1, any order) → a window inside the span. */
export function windowFromFractions(span: [number, number], a: number, b: number): TimeWindow {
  const [from, to] = span;
  const len = Math.max(to - from, 1);
  const clamp = (x: number) => Math.min(1, Math.max(0, x));
  const lo = clamp(Math.min(a, b));
  let hi = clamp(Math.max(a, b));
  if (hi === 1) hi = 1 + 1 / len; // include the last flow (end is exclusive)
  let w = { from_ms: Math.round(from + lo * len), to_ms: Math.round(from + hi * len) };
  if (w.to_ms - w.from_ms < MIN_WIDTH_MS) w = { from_ms: w.from_ms, to_ms: w.from_ms + MIN_WIDTH_MS };
  return w;
}

/** A window → slider positions; no window = the whole span. */
export function fractionsOf(span: [number, number], w: TimeWindow | null): [number, number] {
  if (!w) return [0, 1];
  const len = Math.max(span[1] - span[0], 1);
  const f = (x: number) => Math.min(1, Math.max(0, (x - span[0]) / len));
  return [f(w.from_ms), f(w.to_ms)];
}
